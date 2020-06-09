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
#include "../sdio.h"

static int
mt7663s_mcu_send_message(struct mt76_dev *mdev, struct sk_buff *skb,
			 int cmd, bool wait_resp)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	struct sdio_func *func = mdev->sdio.func;
	struct mt76_sdio *sdio = &mdev->sdio;
	int ret, seq, len;

	mt7615_mutex_acquire(dev, &mdev->mcu.mutex);

	mt7615_mcu_fill_msg(dev, skb, cmd, &seq);

	ret = mt76_skb_adjust_pad(skb);
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

	if (wait_resp)
		ret = mt7615_mcu_wait_response(dev, cmd, seq);

	dev_kfree_skb(skb);
out:
	mt7615_mutex_release(dev, &mdev->mcu.mutex);

	return ret;
}

int mt7663s_driver_own(struct mt7615_dev *dev)
{
	struct sdio_func *func = dev->mt76.sdio.func;
	struct mt76_phy *mphy = &dev->mt76.phy;
	u32 status;
	int ret;

	if (!test_and_clear_bit(MT76_STATE_PM, &mphy->state))
		goto out;

	sdio_claim_host(func);

	sdio_writel(func, WHLPCR_FW_OWN_REQ_CLR, MCR_WHLPCR, 0);

	ret = readx_poll_timeout(mt76s_read_pcr, &dev->mt76, status,
				 status & WHLPCR_IS_DRIVER_OWN, 2000, 1000000);
	if (ret < 0) {
		dev_err(dev->mt76.dev, "Cannot get ownership from device");
		set_bit(MT76_STATE_PM, &mphy->state);
		sdio_release_host(func);

		return ret;
	}

	sdio_release_host(func);

out:
	dev->pm.last_activity = jiffies;

	return 0;
}

int mt7663s_firmware_own(struct mt7615_dev *dev)
{
	struct sdio_func *func = dev->mt76.sdio.func;
	struct mt76_phy *mphy = &dev->mt76.phy;
	u32 status;
	int ret;

	if (test_and_set_bit(MT76_STATE_PM, &mphy->state))
		return 0;

	sdio_claim_host(func);

	sdio_writel(func, WHLPCR_FW_OWN_REQ_SET, MCR_WHLPCR, 0);

	ret = readx_poll_timeout(mt76s_read_pcr, &dev->mt76, status,
				 !(status & WHLPCR_IS_DRIVER_OWN), 2000, 1000000);
	if (ret < 0) {
		dev_err(dev->mt76.dev, "Cannot set ownership to device");
		clear_bit(MT76_STATE_PM, &mphy->state);
	}

	sdio_release_host(func);

	return ret;
}

int mt7663s_mcu_init(struct mt7615_dev *dev)
{
	static const struct mt76_mcu_ops mt7663s_mcu_ops = {
		.headroom = sizeof(struct mt7615_mcu_txd),
		.tailroom = MT_USB_TAIL_SIZE,
		.mcu_skb_send_msg = mt7663s_mcu_send_message,
		.mcu_send_msg = mt7615_mcu_msg_send,
		.mcu_restart = mt7615_mcu_restart,
		.mcu_rr = mt7615_mcu_reg_rr,
		.mcu_wr = mt7615_mcu_reg_wr,
	};
	int ret;

	ret = mt7663s_driver_own(dev);
	if (ret)
		return ret;

	dev->mt76.mcu_ops = &mt7663s_mcu_ops,

	ret = __mt7663_load_firmware(dev);
	if (ret)
		return ret;

	set_bit(MT76_STATE_MCU_RUNNING, &dev->mphy.state);

	return 0;
}
