/*
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

#include "mt76x2u.h"
#include "dma.h"

static void mt76x2u_remove_dma_hdr(struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	int hdr_len, len;

	len = (unsigned long)info->status.status_driver_data[0];
	skb_pull(skb, sizeof(struct mt76x2_txwi) + MT_DMA_HDR_LEN);
	hdr_len = ieee80211_get_hdrlen_from_skb(skb);
	if (hdr_len % 4) {
		memmove(skb->data + 2, skb->data, hdr_len);
		skb_pull(skb, 2);
	}
}

static int
mt76x2u_check_skb_rooms(struct sk_buff *skb)
{
	int hdr_len = ieee80211_get_hdrlen_from_skb(skb);
	u32 need_head;

	need_head = sizeof(struct mt76x2_txwi) + MT_DMA_HDR_LEN;
	if (hdr_len % 4)
		need_head += 2;
	return skb_cow(skb, need_head);
}

int mt76x2u_skb_dma_info(struct sk_buff *skb, enum dma_msg_port port,
			 u32 flags)
{
	struct sk_buff *iter, *last = skb;
	u32 info, pad;

	/* Buffer layout:
	 *	|   4B   | xfer len |      pad       |  4B  |
	 *	| TXINFO | pkt/cmd  | zero pad to 4B | zero |
	 *
	 * length field of TXINFO should be set to 'xfer len'.
	 */
	info = FIELD_PREP(MT_TXD_INFO_LEN, round_up(skb->len, 4)) |
	       FIELD_PREP(MT_TXD_INFO_DPORT, port) | flags;
	put_unaligned_le32(info, skb_push(skb, sizeof(info)));

	pad = round_up(skb->len, 4) + 4 - skb->len;
	skb_walk_frags(skb, iter) {
		last = iter;
		if (!iter->next) {
			skb->data_len += pad;
			skb->len += pad;
			break;
		}
	}
	return mt76x2u_add_pad(last, pad);
}

static int
mt76x2u_set_txinfo(struct sk_buff *skb,
		   struct mt76_wcid *wcid, u8 ep)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	enum mt76x2_qsel qsel;
	u32 flags;

	if ((info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE) ||
	    ep == MT_EP_OUT_HCCA)
		qsel = MT_QSEL_MGMT;
	else
		qsel = MT_QSEL_EDCA;

	flags = FIELD_PREP(MT_TXD_INFO_QSEL, qsel) |
		MT_TXD_INFO_80211;
	if (!wcid || wcid->hw_key_idx == 0xff || wcid->sw_iv)
		flags |= MT_TXD_INFO_WIV;

	return mt76x2u_skb_dma_info(skb, WLAN_PORT, flags);
}

static void
mt76x2u_tx_status(struct mt76x2_dev *dev, enum mt76_txq_id qid)
{
	struct mt76_queue *q = &dev->mt76.q_tx[qid];
	struct mt76_usb_buf *buf;
	struct sk_buff *skb;
	bool wake = false;

	spin_lock_bh(&q->lock);
	while (true) {
		buf = &q->entry[q->head].ubuf;
		if (!buf->done || !q->queued)
			break;

		skb = q->entry[q->head].skb;
		mt76x2u_remove_dma_hdr(skb);
		mt76x2_tx_complete(dev, skb);

		if (q->entry[q->head].schedule) {
			q->entry[q->head].schedule = false;
			q->swq_queued--;
		}

		q->head = (q->head + 1) % q->ndesc;
		q->queued--;
	}
	mt76_txq_schedule(&dev->mt76, q);
	wake = qid < IEEE80211_NUM_ACS && q->queued < q->ndesc - 8;
	if (!q->queued)
		wake_up(&dev->mt76.tx_wait);

	spin_unlock_bh(&q->lock);

	if (wake)
		ieee80211_wake_queue(mt76_hw(dev), qid);
}

void mt76x2u_tx_status_data(struct work_struct *work)
{
	struct mt76x2_tx_status stat;
	struct mt76x2_dev *dev;
	u8 update = 1;
	u16 count = 0;

	dev = container_of(work, struct mt76x2_dev, stat_work.work);

	while (!test_bit(MT76_REMOVED, &dev->mt76.state)) {
		if (!mt76x2_mac_load_tx_status(dev, &stat))
			break;

		mt76x2_send_tx_status(dev, &stat, &update);
		count++;
	}

	if (count)
		ieee80211_queue_delayed_work(mt76_hw(dev), &dev->stat_work,
					     msecs_to_jiffies(10));
	else
		clear_bit(MT76_READING_STATS, &dev->mt76.state);
}

int mt76x2u_tx_prepare_skb(struct mt76_dev *mdev, void *data,
			   struct sk_buff *skb, struct mt76_queue *q,
			   struct mt76_wcid *wcid, struct ieee80211_sta *sta,
			   u32 *tx_info)
{
	struct mt76x2_dev *dev = container_of(mdev, struct mt76x2_dev, mt76);
	struct mt76x2_txwi *txwi;
	int err, len = skb->len;

	err = mt76x2u_check_skb_rooms(skb);
	if (err < 0)
		return -ENOMEM;

	mt76x2_insert_hdr_pad(skb);

	txwi = skb_push(skb, sizeof(struct mt76x2_txwi));
	mt76x2_mac_write_txwi(dev, txwi, skb, wcid, sta, len);

	return mt76x2u_set_txinfo(skb, wcid, q2ep(q->hw_idx));
}

void mt76x2u_tx_complete_skb(struct mt76_dev *mdev, struct mt76_queue *q,
			     struct mt76_queue_entry *e, bool flush)
{
	struct mt76x2_dev *dev = container_of(mdev, struct mt76x2_dev, mt76);
	int i;

	for (i = 0; i < IEEE80211_NUM_ACS; i++)
		mt76x2u_tx_status(dev, i);

	if (!test_and_set_bit(MT76_READING_STATS, &dev->mt76.state))
		ieee80211_queue_delayed_work(mt76_hw(dev), &dev->stat_work,
					     msecs_to_jiffies(10));
}

void mt76x2u_stop_queues(struct mt76x2_dev *dev)
{
	tasklet_disable(&dev->mt76.usb.rx_tasklet);
	tasklet_disable(&dev->mt76.usb.tx_tasklet);

	mt76_usb_stop_rx(&dev->mt76);
	mt76_usb_stop_tx(&dev->mt76);
}

void mt76x2u_queues_deinit(struct mt76x2_dev *dev)
{
	mt76x2u_stop_queues(dev);

	mt76_usb_free_rx(&dev->mt76);
	mt76_usb_free_tx(&dev->mt76);
}

int mt76x2u_alloc_queues(struct mt76x2_dev *dev)
{
	int err;

	err = mt76_usb_alloc_rx(&dev->mt76);
	if (err < 0)
		goto err;

	err = mt76_usb_alloc_tx(&dev->mt76);
	if (err < 0)
		goto err;

	return 0;
err:
	mt76x2u_queues_deinit(dev);
	return err;
}

