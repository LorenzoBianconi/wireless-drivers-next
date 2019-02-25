/*
 * Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
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

#include <linux/dma-mapping.h>
#include "mt76.h"
#include "dma.h"

#define DMA_DUMMY_TXWI	((void *) ~0)

static int
mt76_dma_alloc_queue(struct mt76_dev *dev, struct mt76_hw_queue *hwq,
		     int idx, int n_desc, int bufsize,
		     u32 ring_base)
{
	int size;
	int i;

	hwq = devm_kzalloc(dev->dev, sizeof(*hwq), GFP_KERNEL);
	if (!hwq)
		return -ENOMEM;

	spin_lock_init(&hwq->lock);

	hwq->regs = dev->mmio.regs + ring_base + idx * MT_RING_SIZE;
	hwq->ndesc = n_desc;
	hwq->buf_size = bufsize;
	hwq->hw_idx = idx;

	size = hwq->ndesc * sizeof(struct mt76_desc);
	hwq->desc = dmam_alloc_coherent(dev->dev, size, &hwq->desc_dma,
					GFP_KERNEL);
	if (!hwq->desc)
		return -ENOMEM;

	size = hwq->ndesc * sizeof(*hwq->entry);
	hwq->entry = devm_kzalloc(dev->dev, size, GFP_KERNEL);
	if (!hwq->entry)
		return -ENOMEM;

	/* clear descriptors */
	for (i = 0; i < hwq->ndesc; i++)
		hwq->desc[i].ctrl = cpu_to_le32(MT_DMA_CTL_DMA_DONE);

	iowrite32(hwq->desc_dma, &hwq->regs->desc_base);
	iowrite32(0, &hwq->regs->cpu_idx);
	iowrite32(0, &hwq->regs->dma_idx);
	iowrite32(hwq->ndesc, &hwq->regs->ring_size);

	return 0;
}

static int
mt76_dma_add_buf(struct mt76_dev *dev, struct mt76_hw_queue *hwq,
		 struct mt76_queue_buf *buf, int nbufs, u32 info,
		 struct sk_buff *skb, void *txwi)
{
	struct mt76_desc *desc;
	u32 ctrl;
	int i, idx = -1;

	if (txwi)
		hwq->entry[hwq->head].txwi = DMA_DUMMY_TXWI;

	for (i = 0; i < nbufs; i += 2, buf += 2) {
		u32 buf0 = buf[0].addr, buf1 = 0;

		ctrl = FIELD_PREP(MT_DMA_CTL_SD_LEN0, buf[0].len);
		if (i < nbufs - 1) {
			buf1 = buf[1].addr;
			ctrl |= FIELD_PREP(MT_DMA_CTL_SD_LEN1, buf[1].len);
		}

		if (i == nbufs - 1)
			ctrl |= MT_DMA_CTL_LAST_SEC0;
		else if (i == nbufs - 2)
			ctrl |= MT_DMA_CTL_LAST_SEC1;

		idx = hwq->head;
		hwq->head = (hwq->head + 1) % hwq->ndesc;

		desc = &hwq->desc[idx];

		WRITE_ONCE(desc->buf0, cpu_to_le32(buf0));
		WRITE_ONCE(desc->buf1, cpu_to_le32(buf1));
		WRITE_ONCE(desc->info, cpu_to_le32(info));
		WRITE_ONCE(desc->ctrl, cpu_to_le32(ctrl));

		hwq->queued++;
	}

	hwq->entry[idx].txwi = txwi;
	hwq->entry[idx].skb = skb;

	return idx;
}

static void
mt76_dma_tx_cleanup_idx(struct mt76_dev *dev, struct mt76_queue *q, int idx,
			struct mt76_queue_entry *prev_e)
{
	struct mt76_hw_queue *hwq = q->hwq;
	struct mt76_queue_entry *e = &hwq->entry[idx];
	__le32 __ctrl = READ_ONCE(hwq->desc[idx].ctrl);
	u32 ctrl = le32_to_cpu(__ctrl);

	if (!e->txwi || !e->skb) {
		__le32 addr = READ_ONCE(hwq->desc[idx].buf0);
		u32 len = FIELD_GET(MT_DMA_CTL_SD_LEN0, ctrl);

		dma_unmap_single(dev->dev, le32_to_cpu(addr), len,
				 DMA_TO_DEVICE);
	}

	if (!(ctrl & MT_DMA_CTL_LAST_SEC0)) {
		__le32 addr = READ_ONCE(hwq->desc[idx].buf1);
		u32 len = FIELD_GET(MT_DMA_CTL_SD_LEN1, ctrl);

		dma_unmap_single(dev->dev, le32_to_cpu(addr), len,
				 DMA_TO_DEVICE);
	}

	if (e->txwi == DMA_DUMMY_TXWI)
		e->txwi = NULL;

	*prev_e = *e;
	memset(e, 0, sizeof(*e));
}

static void
mt76_dma_sync_idx(struct mt76_dev *dev, struct mt76_hw_queue *hwq)
{
	hwq->head = ioread32(&hwq->regs->dma_idx);
	hwq->tail = hwq->head;
	iowrite32(hwq->head, &hwq->regs->cpu_idx);
}

static void
mt76_dma_tx_cleanup(struct mt76_dev *dev, enum mt76_txq_id qid, bool flush)
{
	struct mt76_queue *q = &dev->q_tx[qid];
	struct mt76_hw_queue *hwq = q->hwq;
	struct mt76_queue_entry entry;
	bool wake = false;
	int last;

	if (!hwq->ndesc)
		return;

	spin_lock_bh(&hwq->lock);
	if (flush)
		last = -1;
	else
		last = ioread32(&hwq->regs->dma_idx);

	while (hwq->queued && hwq->tail != last) {
		mt76_dma_tx_cleanup_idx(dev, q, hwq->tail, &entry);
		if (entry.schedule)
			dev->q_tx[entry.qid].swq_queued--;

		hwq->tail = (hwq->tail + 1) % hwq->ndesc;
		hwq->queued--;

		if (entry.skb) {
			spin_unlock_bh(&hwq->lock);
			dev->drv->tx_complete_skb(dev, q, &entry, flush);
			spin_lock_bh(&hwq->lock);
		}

		if (entry.txwi) {
			mt76_put_txwi(dev, entry.txwi);
			wake = !flush;
		}

		if (!flush && hwq->tail == last)
			last = ioread32(&hwq->regs->dma_idx);
	}

	if (!flush)
		mt76_txq_schedule(dev, q);
	else
		mt76_dma_sync_idx(dev, hwq);

	wake = wake && qid < IEEE80211_NUM_ACS && hwq->queued < hwq->ndesc - 8;

	if (!hwq->queued)
		wake_up(&dev->tx_wait);

	spin_unlock_bh(&hwq->lock);

	if (wake)
		ieee80211_wake_queue(dev->hw, qid);
}

static void *
mt76_dma_get_buf(struct mt76_dev *dev, struct mt76_hw_queue *hwq,
		 int idx, int *len, u32 *info, bool *more)
{
	struct mt76_queue_entry *e = &hwq->entry[idx];
	struct mt76_desc *desc = &hwq->desc[idx];
	dma_addr_t buf_addr;
	void *buf = e->buf;
	int buf_len = SKB_WITH_OVERHEAD(hwq->buf_size);

	buf_addr = le32_to_cpu(READ_ONCE(desc->buf0));
	if (len) {
		u32 ctl = le32_to_cpu(READ_ONCE(desc->ctrl));
		*len = FIELD_GET(MT_DMA_CTL_SD_LEN0, ctl);
		*more = !(ctl & MT_DMA_CTL_LAST_SEC0);
	}

	if (info)
		*info = le32_to_cpu(desc->info);

	dma_unmap_single(dev->dev, buf_addr, buf_len, DMA_FROM_DEVICE);
	e->buf = NULL;

	return buf;
}

static void *
mt76_dma_dequeue(struct mt76_dev *dev, struct mt76_hw_queue *hwq,
		 bool flush, int *len, u32 *info, bool *more)
{
	int idx = hwq->tail;

	*more = false;
	if (!hwq->queued)
		return NULL;

	if (!flush && !(hwq->desc[idx].ctrl &
			cpu_to_le32(MT_DMA_CTL_DMA_DONE)))
		return NULL;

	hwq->tail = (hwq->tail + 1) % hwq->ndesc;
	hwq->queued--;

	return mt76_dma_get_buf(dev, hwq, idx, len, info, more);
}

static void
mt76_dma_kick_queue(struct mt76_dev *dev, struct mt76_hw_queue *hwq)
{
	iowrite32(hwq->head, &hwq->regs->cpu_idx);
}

static int
mt76_dma_tx_queue_skb_raw(struct mt76_dev *dev, enum mt76_txq_id qid,
			  struct sk_buff *skb, u32 tx_info)
{
	struct mt76_queue *q = &dev->q_tx[qid];
	struct mt76_hw_queue *hwq = q->hwq;
	struct mt76_queue_buf buf;
	dma_addr_t addr;

	addr = dma_map_single(dev->dev, skb->data, skb->len,
			      DMA_TO_DEVICE);
	if (dma_mapping_error(dev->dev, addr))
		return -ENOMEM;

	buf.addr = addr;
	buf.len = skb->len;

	spin_lock_bh(&hwq->lock);
	mt76_dma_add_buf(dev, hwq, &buf, 1, tx_info, skb, NULL);
	mt76_dma_kick_queue(dev, hwq);
	spin_unlock_bh(&hwq->lock);

	return 0;
}

int mt76_dma_tx_queue_skb(struct mt76_dev *dev, struct mt76_queue *q,
			  struct sk_buff *skb, struct mt76_wcid *wcid,
			  struct ieee80211_sta *sta)
{
	struct mt76_hw_queue *hwq = q->hwq;
	struct mt76_queue_entry e;
	struct mt76_txwi_cache *t;
	struct mt76_queue_buf buf[32];
	struct sk_buff *iter;
	dma_addr_t addr;
	int len;
	u32 tx_info = 0;
	int n, ret;

	t = mt76_get_txwi(dev);
	if (!t) {
		ieee80211_free_txskb(dev->hw, skb);
		return -ENOMEM;
	}

	skb->prev = skb->next = NULL;
	dma_sync_single_for_cpu(dev->dev, t->dma_addr, sizeof(t->txwi),
				DMA_TO_DEVICE);
	ret = dev->drv->tx_prepare_skb(dev, &t->txwi, skb, q, wcid, sta,
				       &tx_info);
	dma_sync_single_for_device(dev->dev, t->dma_addr, sizeof(t->txwi),
				   DMA_TO_DEVICE);
	if (ret < 0)
		goto free;

	len = skb->len - skb->data_len;
	addr = dma_map_single(dev->dev, skb->data, len, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev->dev, addr))) {
		ret = -ENOMEM;
		goto free;
	}

	n = 0;
	buf[n].addr = t->dma_addr;
	buf[n++].len = dev->drv->txwi_size;
	buf[n].addr = addr;
	buf[n++].len = len;

	skb_walk_frags(skb, iter) {
		if (n == ARRAY_SIZE(buf))
			goto unmap;

		addr = dma_map_single(dev->dev, iter->data, iter->len,
				      DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(dev->dev, addr)))
			goto unmap;

		buf[n].addr = addr;
		buf[n++].len = iter->len;
	}

	if (hwq->queued + (n + 1) / 2 >= hwq->ndesc - 1)
		goto unmap;

	return mt76_dma_add_buf(dev, hwq, buf, n, tx_info, skb, t);

unmap:
	ret = -ENOMEM;
	for (n--; n > 0; n--)
		dma_unmap_single(dev->dev, buf[n].addr, buf[n].len,
				 DMA_TO_DEVICE);

free:
	e.skb = skb;
	e.txwi = t;
	dev->drv->tx_complete_skb(dev, q, &e, true);
	mt76_put_txwi(dev, t);
	return ret;
}
EXPORT_SYMBOL_GPL(mt76_dma_tx_queue_skb);

static int
mt76_dma_tx_ct_queue_skb(struct mt76_dev *dev, struct mt76_queue *q,
			 struct sk_buff *skb, struct mt76_wcid *wcid,
			 struct ieee80211_sta *sta)
{
	struct mt76_hw_queue *hwq = q->hwq;
	struct mt76_queue_entry e;
	struct mt76_txwi_cache *t;
	struct mt76_queue_buf buf[2];
	u32 tx_info = 0;
	int ret;

	if (hwq->queued + 1 >= hwq->ndesc - 1)
		return -ENOSPC;

	t = mt76_get_txwi(dev);
	if (!t) {
		ieee80211_free_txskb(dev->hw, skb);
		return -ENOMEM;
	}

	skb->prev = skb->next = NULL;
	dma_sync_single_for_cpu(dev->dev, t->dma_addr, sizeof(t->txwi),
				DMA_TO_DEVICE);
	ret = dev->drv->tx_prepare_skb(dev, &t->txwi, skb, q, wcid, sta,
				       &tx_info);
	if (ret < 0)
		goto free;

	/* the cut-through architecture just needs to move txd and
	 * partial skb header (optional) to the tx ring.
	 */
	buf[0].addr = t->dma_addr;
	buf[0].len = dev->drv->txwi_size;

	/* txp will concatenate skbs */
	ret = dev->drv->tx_prepare_txp(dev, &t->txwi, skb, &buf[1]);
	dma_sync_single_for_device(dev->dev, t->dma_addr, sizeof(t->txwi),
				   DMA_TO_DEVICE);
	if (ret < 0)
		goto free;

	return mt76_dma_add_buf(dev, hwq, buf, ret, tx_info, skb, t);

free:
	e.skb = skb;
	e.txwi = t;
	dev->drv->tx_complete_skb(dev, q, &e, true);
	mt76_put_txwi(dev, t);
	return ret;
}

static int
mt76_dma_rx_fill(struct mt76_dev *dev, struct mt76_hw_queue *hwq)
{
	dma_addr_t addr;
	void *buf;
	int frames = 0;
	int len = SKB_WITH_OVERHEAD(hwq->buf_size);
	int offset = hwq->buf_offset;
	int idx;

	spin_lock_bh(&hwq->lock);

	while (hwq->queued < hwq->ndesc - 1) {
		struct mt76_queue_buf qbuf;

		buf = page_frag_alloc(&hwq->rx_page, hwq->buf_size, GFP_ATOMIC);
		if (!buf)
			break;

		addr = dma_map_single(dev->dev, buf, len, DMA_FROM_DEVICE);
		if (unlikely(dma_mapping_error(dev->dev, addr))) {
			skb_free_frag(buf);
			break;
		}

		qbuf.addr = addr + offset;
		qbuf.len = len - offset;
		idx = mt76_dma_add_buf(dev, hwq, &qbuf, 1, 0, buf, NULL);
		frames++;
	}

	if (frames)
		mt76_dma_kick_queue(dev, hwq);

	spin_unlock_bh(&hwq->lock);

	return frames;
}

static void
mt76_dma_rx_cleanup(struct mt76_dev *dev, struct mt76_hw_queue *hwq)
{
	struct page *page;
	void *buf;
	bool more;

	spin_lock_bh(&hwq->lock);
	do {
		buf = mt76_dma_dequeue(dev, hwq, true, NULL, NULL, &more);
		if (!buf)
			break;

		skb_free_frag(buf);
	} while (1);
	spin_unlock_bh(&hwq->lock);

	if (!hwq->rx_page.va)
		return;

	page = virt_to_page(hwq->rx_page.va);
	__page_frag_cache_drain(page, hwq->rx_page.pagecnt_bias);
	memset(&hwq->rx_page, 0, sizeof(hwq->rx_page));
}

static void
mt76_dma_rx_reset(struct mt76_dev *dev, enum mt76_rxq_id qid)
{
	struct mt76_hw_queue *hwq = dev->q_rx[qid].hwq;
	int i;

	for (i = 0; i < hwq->ndesc; i++)
		hwq->desc[i].ctrl &= ~cpu_to_le32(MT_DMA_CTL_DMA_DONE);

	mt76_dma_rx_cleanup(dev, hwq);
	mt76_dma_sync_idx(dev, hwq);
	mt76_dma_rx_fill(dev, hwq);
}

static void
mt76_add_fragment(struct mt76_dev *dev, struct mt76_queue *q, void *data,
		  int len, bool more)
{
	struct page *page = virt_to_head_page(data);
	int offset = data - page_address(page);
	struct mt76_hw_queue *hwq = q->hwq;
	struct sk_buff *skb = hwq->rx_head;

	offset += hwq->buf_offset;
	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page, offset, len,
			hwq->buf_size);

	if (more)
		return;

	hwq->rx_head = NULL;
	dev->drv->rx_skb(dev, q - dev->q_rx, skb);
}

static int
mt76_dma_rx_process(struct mt76_dev *dev, struct mt76_queue *q, int budget)
{
	struct mt76_hw_queue *hwq = q->hwq;
	int len, data_len, done = 0;
	struct sk_buff *skb;
	unsigned char *data;
	bool more;

	while (done < budget) {
		u32 info;

		data = mt76_dma_dequeue(dev, hwq, false, &len, &info, &more);
		if (!data)
			break;

		if (hwq->rx_head)
			data_len = hwq->buf_size;
		else
			data_len = SKB_WITH_OVERHEAD(hwq->buf_size);

		if (data_len < len + hwq->buf_offset) {
			dev_kfree_skb(hwq->rx_head);
			hwq->rx_head = NULL;

			skb_free_frag(data);
			continue;
		}

		if (hwq->rx_head) {
			mt76_add_fragment(dev, q, data, len, more);
			continue;
		}

		skb = build_skb(data, hwq->buf_size);
		if (!skb) {
			skb_free_frag(data);
			continue;
		}
		skb_reserve(skb, hwq->buf_offset);

		if (q == &dev->q_rx[MT_RXQ_MCU]) {
			u32 *rxfce = (u32 *) skb->cb;
			*rxfce = info;
		}

		__skb_put(skb, len);
		done++;

		if (more) {
			hwq->rx_head = skb;
			continue;
		}

		dev->drv->rx_skb(dev, q - dev->q_rx, skb);
	}

	mt76_dma_rx_fill(dev, hwq);
	return done;
}

static int
mt76_dma_rx_poll(struct napi_struct *napi, int budget)
{
	struct mt76_dev *dev;
	int qid, done = 0, cur;

	dev = container_of(napi->dev, struct mt76_dev, napi_dev);
	qid = napi - dev->napi;

	rcu_read_lock();

	do {
		cur = mt76_dma_rx_process(dev, &dev->q_rx[qid], budget - done);
		mt76_rx_poll_complete(dev, qid, napi);
		done += cur;
	} while (cur && done < budget);

	rcu_read_unlock();

	if (done < budget) {
		napi_complete(napi);
		dev->drv->rx_poll_complete(dev, qid);
	}

	return done;
}

static int
mt76_dma_init(struct mt76_dev *dev)
{
	int i;

	init_dummy_netdev(&dev->napi_dev);

	for (i = 0; i < ARRAY_SIZE(dev->q_rx); i++) {
		netif_napi_add(&dev->napi_dev, &dev->napi[i], mt76_dma_rx_poll,
			       64);
		mt76_dma_rx_fill(dev, dev->q_rx[i].hwq);
		skb_queue_head_init(&dev->rx_skb[i]);
		napi_enable(&dev->napi[i]);
	}

	return 0;
}

static const struct mt76_queue_ops mt76_dma_ops = {
	.init = mt76_dma_init,
	.alloc = mt76_dma_alloc_queue,
	.tx_queue_skb_raw = mt76_dma_tx_queue_skb_raw,
	.tx_queue_skb = mt76_dma_tx_queue_skb,
	.tx_cleanup = mt76_dma_tx_cleanup,
	.rx_reset = mt76_dma_rx_reset,
	.kick = mt76_dma_kick_queue,
};

static const struct mt76_queue_ops mt76_ct_dma_ops = {
	.init = mt76_dma_init,
	.alloc = mt76_dma_alloc_queue,
	.tx_queue_skb_raw = mt76_dma_tx_queue_skb_raw,
	.tx_queue_skb = mt76_dma_tx_ct_queue_skb,
	.tx_cleanup = mt76_dma_tx_cleanup,
	.rx_reset = mt76_dma_rx_reset,
	.kick = mt76_dma_kick_queue,
};

void mt76_dma_attach(struct mt76_dev *dev)
{
	dev->queue_ops = &mt76_dma_ops;
}
EXPORT_SYMBOL_GPL(mt76_dma_attach);

void mt76_ct_dma_attach(struct mt76_dev *dev)
{
	dev->queue_ops = &mt76_ct_dma_ops;
}
EXPORT_SYMBOL_GPL(mt76_ct_dma_attach);

void mt76_dma_cleanup(struct mt76_dev *dev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dev->q_tx); i++)
		mt76_dma_tx_cleanup(dev, i, true);

	for (i = 0; i < ARRAY_SIZE(dev->q_rx); i++) {
		netif_napi_del(&dev->napi[i]);
		mt76_dma_rx_cleanup(dev, dev->q_rx[i].hwq);
	}
}
EXPORT_SYMBOL_GPL(mt76_dma_cleanup);
