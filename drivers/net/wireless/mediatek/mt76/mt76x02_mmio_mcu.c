/*
 * Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
 * Copyright (C) 2018 Stanislaw Gruszka <stf_xl@wp.pl>
 * Copyright (C) 2018 Lorenzo Bianconi <lorenzo.bianconi83@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/kernel.h>
#include <linux/delay.h>

#include "mt76.h"
#include "dma.h"

static struct sk_buff *mt76x02e_mcu_msg_alloc(const void *data, int len)
{
	struct sk_buff *skb;

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return NULL;
	memcpy(skb_put(skb, len), data, len);

	return skb;
}

static struct sk_buff *
mt76x02e_mcu_get_response(struct mt76_dev *dev, unsigned long expires)
{
	struct mt76_mmio *mmio = &dev->mmio;
	unsigned long timeout;

	if (!time_is_after_jiffies(expires))
		return NULL;

	timeout = expires - jiffies;
	wait_event_timeout(mmio->mcu.wait, !skb_queue_empty(&mmio->mcu.res_q),
			   timeout);
	return skb_dequeue(&mmio->mcu.res_q);
}

static int
mt76x02e_tx_queue_mcu(struct mt76_dev *dev, enum mt76_txq_id qid,
		      struct sk_buff *skb, int cmd, int seq)
{
	struct mt76_queue *q = &dev->q_tx[qid];
	struct mt76_queue_buf buf;
	dma_addr_t addr;
	u32 tx_info;

	tx_info = MT_MCU_MSG_TYPE_CMD |
		  FIELD_PREP(MT_MCU_MSG_CMD_TYPE, cmd) |
		  FIELD_PREP(MT_MCU_MSG_CMD_SEQ, seq) |
		  FIELD_PREP(MT_MCU_MSG_PORT, CPU_TX_PORT) |
		  FIELD_PREP(MT_MCU_MSG_LEN, skb->len);

	addr = dma_map_single(dev->dev, skb->data, skb->len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev->dev, addr))
		return -ENOMEM;

	buf.addr = addr;
	buf.len = skb->len;
	spin_lock_bh(&q->lock);
	__mt76_queue_add_buf(dev, q, &buf, 1, tx_info, skb, NULL);
	__mt76_queue_kick(dev, q);
	spin_unlock_bh(&q->lock);

	return 0;
}

static int
mt76x02e_mcu_msg_send(struct mt76_dev *dev, struct sk_buff *skb,
		      int cmd, bool wait_resp)
{
	struct mt76_mmio *mmio = &dev->mmio;
	unsigned long expires = jiffies + HZ;
	int ret;
	u8 seq;

	if (!skb)
		return -EINVAL;

	mutex_lock(&mmio->mcu.mutex);

	seq = ++mmio->mcu.msg_seq & 0xf;
	if (!seq)
		seq = ++mmio->mcu.msg_seq & 0xf;

	ret = mt76x02e_tx_queue_mcu(dev, MT_TXQ_MCU, skb, cmd, seq);
	if (ret)
		goto out;

	while (1) {
		u32 *rxfce;
		bool check_seq = false;

		skb = mt76x02e_mcu_get_response(dev, expires);
		if (!skb) {
			dev_err(dev->dev,
				"MCU message %d (seq %d) timed out\n", cmd,
				seq);
			ret = -ETIMEDOUT;
			break;
		}

		rxfce = (u32 *) skb->cb;

		if (seq == FIELD_GET(MT_RX_FCE_INFO_CMD_SEQ, *rxfce))
			check_seq = true;

		dev_kfree_skb(skb);
		if (check_seq)
			break;
	}

out:
	mutex_unlock(&mmio->mcu.mutex);

	return ret;
}

void mt76x02e_init_mcu(struct mt76_dev *dev)
{
	static const struct mt76_mcu_ops mt76x02e_mcu_ops = {
		.mcu_msg_alloc = mt76x02e_mcu_msg_alloc,
		.mcu_send_msg = mt76x02e_mcu_msg_send,
	};

	dev->mcu_ops = &mt76x02e_mcu_ops;
}
EXPORT_SYMBOL_GPL(mt76x02e_init_mcu);
