// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 MediaTek Inc.
 *
 * Author: Felix Fietkau <nbd@nbd.name>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 *	   Sean Wang <sean.wang@mediatek.com>
 */
#include <linux/kernel.h>
#include <linux/mmc/sdio_func.h>
#include <linux/module.h>

#include "mt7615.h"
#include "mac.h"
#include "mcu.h"
#include "regs.h"
#include "../mt76s.h"

static int
mt7663s_mcu_send_message(struct mt76_dev *mdev, struct sk_buff *skb,
			 int cmd, bool wait_resp)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	struct sdio_func *func = mdev->sdio.func;
	struct mt76_sdio *sdio = &mdev->sdio;
	int ret, seq, len;

	mutex_lock(&mdev->mcu.mutex);

	mt7615_mcu_fill_msg(dev, skb, cmd, &seq);

	ret = mt76s_skb_dma_info(skb, skb->len);
	if (ret < 0)
		goto out;

	len = skb->len;

	if (len > sdio->func->cur_blksize)
		len = roundup(len, sdio->func->cur_blksize);

	sdio_claim_host(func);
	ret = sdio_writesb(sdio->func, MCR_WTDR1, skb->data, len);
	if (ret < 0)
		dev_err(mdev->dev, "sdio write failed:%d\n", ret);

	sdio_release_host(func);

	dev_kfree_skb(skb);
	if (wait_resp)
		ret = mt7615_mcu_wait_response(dev, cmd, seq);
out:
	mutex_unlock(&mdev->mcu.mutex);

	return ret;
}

int mt7663s_mcu_init(struct mt7615_dev *dev)
{
	static const struct mt76_mcu_ops mt7663s_mcu_ops = {
		.headroom = MT_SDIO_HDR_SIZE + sizeof(struct mt7615_mcu_txd),
		.tailroom = MT_SDIO_TAIL_SIZE,
		.mcu_skb_send_msg = mt7663s_mcu_send_message,
		.mcu_send_msg = mt7615_mcu_msg_send,
		.mcu_restart = mt7615_mcu_restart,
	};
	int ret;

	dev->mt76.mcu_ops = &mt7663s_mcu_ops,

	ret = __mt7663_load_firmware(dev);
	if (ret)
		return ret;

	set_bit(MT76_STATE_MCU_RUNNING, &dev->mphy.state);

	return 0;
}
