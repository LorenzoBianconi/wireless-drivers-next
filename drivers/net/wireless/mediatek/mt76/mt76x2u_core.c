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

static void mt76x2u_enable_dma(struct mt76x2_dev *dev)
{
	u32 val = mt76_rr(dev, MT_VEND_ADDR(CFG, MT_USB_U3DMA_CFG));

	val |= FIELD_PREP(MT_USB_DMA_CFG_RX_BULK_AGG_TOUT,
			  MT_USB_AGGR_TIMEOUT) |
	       FIELD_PREP(MT_USB_DMA_CFG_RX_BULK_AGG_LMT,
			  MT_USB_AGGR_SIZE_LIMIT) |
	       MT_USB_DMA_CFG_RX_DROP_OR_PAD |
	       MT_USB_DMA_CFG_RX_BULK_EN |
	       MT_USB_DMA_CFG_TX_BULK_EN;
	if (dev->mt76.usb.in_max_packet >= 512)
		val |= MT_USB_DMA_CFG_RX_BULK_AGG_EN;
	else
		val &= ~MT_USB_DMA_CFG_RX_BULK_AGG_EN;
	mt76_wr(dev, MT_VEND_ADDR(CFG, MT_USB_U3DMA_CFG), val);
}

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
mt76x2u_check_skb_rooms(struct mt76x2_dev *dev, struct sk_buff *skb)
{
	int hdr_len = ieee80211_get_hdrlen_from_skb(skb);
	u32 need_head;

	need_head = sizeof(struct mt76x2_txwi) + MT_DMA_HDR_LEN;
	if (hdr_len % 4)
		need_head += 2;
	return skb_cow(skb, need_head);
}

static int
mt76x2u_set_txinfo(struct mt76x2_dev *dev, struct sk_buff *skb,
		   struct mt76_wcid *wcid, u8 ep, bool last)
{
	enum mt76x2_qsel qsel;
	u32 info;

	qsel = (ep == 5) ? MT_QSEL_MGMT : MT_QSEL_EDCA;
	info = FIELD_PREP(MT_TXD_INFO_LEN, round_up(skb->len, 4)) |
	       FIELD_PREP(MT_TXD_INFO_DPORT, WLAN_PORT) |
	       FIELD_PREP(MT_TXD_INFO_QSEL, qsel) |
	       MT_TXD_INFO_80211;

	if (!wcid || wcid->hw_key_idx == 0xff || wcid->sw_iv)
		info |= MT_TXD_INFO_WIV;
	if (!last)
		info |= MT_TXD_INFO_NEXT_VLD;

	put_unaligned_le32(info, skb_push(skb, sizeof(info)));
	return last ? skb_put_padto(skb, round_up(skb->len, 4) + 4) : 0;
}

static void
mt76x2u_tx_status(struct mt76x2_dev *dev, struct mt76_queue *q)
{
	struct mt76_usb_buf *buf;
	struct sk_buff_head skbs;

	__skb_queue_head_init(&skbs);

	spin_lock_bh(&q->lock);
	while (true) {
		buf = &q->entry[q->head].ubuf;
		if (!buf->done || q->head == q->tail)
			break;

		buf->len = 0;
		skb_queue_splice_init(&buf->tx_pending, &skbs);
		if (q->entry[q->head].schedule) {
			q->entry[q->head].schedule = false;
			q->swq_queued--;
		}

		q->head = (q->head + 1) % q->ndesc;
		if (--q->queued == q->ndesc - 8)
			ieee80211_wake_queue(mt76_hw(dev), q2hwq(q->hw_idx));
	}
	mt76_txq_schedule(&dev->mt76, q);
	spin_unlock_bh(&q->lock);

	while (!skb_queue_empty(&skbs)) {
		struct sk_buff *skb = __skb_dequeue(&skbs);

		mt76x2u_remove_dma_hdr(skb);
		mt76x2_tx_complete(dev, skb);
	}
}

void mt76x2u_tx_status_data(struct work_struct *work)
{
	struct mt76x2_tx_status stat;
	struct mt76x2_dev *dev;
	u8 update = 1;
	u16 count = 0;

	dev = container_of(work, struct mt76x2_dev, stat_work.work);

	while (!test_bit(MT76_REMOVED, &dev->mt76.state)) {
		stat = mt76x2_mac_load_tx_status(dev);
		if (!stat.valid)
			break;

		mt76x2_send_tx_status(dev, &stat, &update);
		count++;
	}

	if (count || test_and_clear_bit(MT76_PENDING_STATS, &dev->mt76.state))
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

	err = mt76x2u_check_skb_rooms(dev, skb);
	if (err < 0)
		return -ENOMEM;

	mt76x2_insert_hdr_pad(skb);

	txwi = skb_push(skb, sizeof(struct mt76x2_txwi));
	mt76x2_mac_write_txwi(dev, txwi, skb, wcid, sta, len);

	return mt76x2u_set_txinfo(dev, skb, wcid, q2ep(q->hw_idx), *tx_info);
}

void mt76x2u_tx_complete_skb(struct mt76_dev *mdev, struct mt76_queue *q,
			     struct mt76_queue_entry *e, bool flush)
{
	struct mt76x2_dev *dev = container_of(mdev, struct mt76x2_dev, mt76);
	int i;

	for (i = 0; i < IEEE80211_NUM_ACS; i++)
		mt76x2u_tx_status(dev, &mdev->q_tx[i]);

	if (!test_and_set_bit(MT76_READING_STATS, &dev->mt76.state))
		ieee80211_queue_delayed_work(mt76_hw(dev), &dev->stat_work,
					     msecs_to_jiffies(10));
}

void mt76x2u_dma_cleanup(struct mt76x2_dev *dev)
{
	tasklet_disable(&dev->mt76.usb.rx_tasklet);
	tasklet_disable(&dev->mt76.usb.tx_tasklet);

	mt76_usb_stop_rx(&dev->mt76);
	mt76_usb_stop_tx(&dev->mt76);

	mt76_usb_free_rx(&dev->mt76);
	mt76_usb_free_tx(&dev->mt76);
}

int mt76x2u_dma_init(struct mt76x2_dev *dev)
{
	int err;

	mt76x2u_enable_dma(dev);

	err = mt76_usb_alloc_rx(&dev->mt76);
	if (err < 0)
		goto err;

	return mt76_usb_alloc_tx(&dev->mt76);
err:
	mt76x2u_dma_cleanup(dev);
	return err;
}

