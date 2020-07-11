// SPDX-License-Identifier: ISC
/* Copyright (C) 2020 MediaTek Inc.
 *
 * This file is written based on mt76/usb.c.
 *
 * Author: Felix Fietkau <nbd@nbd.name>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mmc/sdio_func.h>
#include <linux/sched.h>
#include <linux/kthread.h>

#include "mt76.h"
#include "sdio.h"

static u32 mt76s_read_whisr(struct mt76_dev *dev)
{
	return sdio_readl(dev->sdio.func, MCR_WHISR, NULL);
}

u32 mt76s_read_pcr(struct mt76_dev *dev)
{
	return sdio_readl(dev->sdio.func, MCR_WHLPCR, NULL);
}
EXPORT_SYMBOL_GPL(mt76s_read_pcr);

static u32 mt76s_rr_mailbox(struct mt76_dev *dev, u32 offset)
{
	struct sdio_func *func = dev->sdio.func;
	u32 val = ~0, status;
	int err;

	sdio_claim_host(func);

	sdio_writel(func, offset, MCR_H2DSM0R, &err);
	if (err < 0) {
		dev_err(dev->dev, "failed setting address [err=%d]\n", err);
		goto out;
	}

	sdio_writel(func, H2D_SW_INT_READ, MCR_WSICR, &err);
	if (err < 0) {
		dev_err(dev->dev, "failed setting read mode [err=%d]\n", err);
		goto out;
	}

	err = readx_poll_timeout(mt76s_read_whisr, dev, status,
				 status & H2D_SW_INT_READ, 0, 1000000);
	if (err < 0) {
		dev_err(dev->dev, "query whisr timeout\n");
		goto out;
	}

	sdio_writel(func, H2D_SW_INT_READ, MCR_WHISR, &err);
	if (err < 0) {
		dev_err(dev->dev, "failed setting read mode [err=%d]\n", err);
		goto out;
	}

	val = sdio_readl(func, MCR_H2DSM0R, &err);
	if (err < 0) {
		dev_err(dev->dev, "failed reading h2dsm0r [err=%d]\n", err);
		goto out;
	}

	if (val != offset) {
		dev_err(dev->dev, "register mismatch\n");
		val = ~0;
		goto out;
	}

	val = sdio_readl(func, MCR_D2HRM1R, &err);
	if (err < 0)
		dev_err(dev->dev, "failed reading d2hrm1r [err=%d]\n", err);

out:
	sdio_release_host(func);

	return val;
}

static void mt76s_wr_mailbox(struct mt76_dev *dev, u32 offset, u32 val)
{
	struct sdio_func *func = dev->sdio.func;
	u32 status;
	int err;

	sdio_claim_host(func);

	sdio_writel(func, offset, MCR_H2DSM0R, &err);
	if (err < 0) {
		dev_err(dev->dev, "failed setting address [err=%d]\n", err);
		goto out;
	}

	sdio_writel(func, val, MCR_H2DSM1R, &err);
	if (err < 0) {
		dev_err(dev->dev,
			"failed setting write value [err=%d]\n", err);
		goto out;
	}

	sdio_writel(func, H2D_SW_INT_WRITE, MCR_WSICR, &err);
	if (err < 0) {
		dev_err(dev->dev, "failed setting write mode [err=%d]\n", err);
		goto out;
	}

	err = readx_poll_timeout(mt76s_read_whisr, dev, status,
				 status & H2D_SW_INT_WRITE, 0, 1000000);
	if (err < 0) {
		dev_err(dev->dev, "query whisr timeout\n");
		goto out;
	}

	sdio_writel(func, H2D_SW_INT_WRITE, MCR_WHISR, &err);
	if (err < 0) {
		dev_err(dev->dev, "failed setting write mode [err=%d]\n", err);
		goto out;
	}

	val = sdio_readl(func, MCR_H2DSM0R, &err);
	if (err < 0) {
		dev_err(dev->dev, "failed reading h2dsm0r [err=%d]\n", err);
		goto out;
	}

	if (val != offset)
		dev_err(dev->dev, "register mismatch\n");

out:
	sdio_release_host(func);
}

static u32 mt76s_rr(struct mt76_dev *dev, u32 offset)
{
	if (test_bit(MT76_STATE_MCU_RUNNING, &dev->phy.state))
		return dev->mcu_ops->mcu_rr(dev, offset);
	else
		return mt76s_rr_mailbox(dev, offset);
}

static void mt76s_wr(struct mt76_dev *dev, u32 offset, u32 val)
{
	if (test_bit(MT76_STATE_MCU_RUNNING, &dev->phy.state))
		dev->mcu_ops->mcu_wr(dev, offset, val);
	else
		mt76s_wr_mailbox(dev, offset, val);
}

static u32 mt76s_rmw(struct mt76_dev *dev, u32 offset, u32 mask, u32 val)
{
	val |= mt76s_rr(dev, offset) & ~mask;
	mt76s_wr(dev, offset, val);

	return val;
}

static void mt76s_write_copy(struct mt76_dev *dev, u32 offset,
			     const void *data, int len)
{
	const u32 *val = data;
	int i;

	for (i = 0; i < len / sizeof(u32); i++) {
		mt76s_wr(dev, offset, val[i]);
		offset += sizeof(u32);
	}
}

static void mt76s_read_copy(struct mt76_dev *dev, u32 offset,
			    void *data, int len)
{
	u32 *val = data;
	int i;

	for (i = 0; i < len / sizeof(u32); i++) {
		val[i] = mt76s_rr(dev, offset);
		offset += sizeof(u32);
	}
}

static int
mt76s_wr_rp(struct mt76_dev *dev, u32 base,
	    const struct mt76_reg_pair *data, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		mt76s_wr(dev, data->reg, data->value);
		data++;
	}

	return 0;
}

static int
mt76s_rd_rp(struct mt76_dev *dev, u32 base,
	    struct mt76_reg_pair *data, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		data->value = mt76s_rr(dev, data->reg);
		data++;
	}

	return 0;
}

static void
mt76s_free_rx_queue(struct mt76_dev *dev, struct mt76_queue *q)
{
	struct page *page;
	int i;

	for (i = 0; i < q->ndesc; i++) {
		if (!q->entry[i].buf)
			continue;

		skb_free_frag(q->entry[i].buf);
		q->entry[i].buf = NULL;
	}

	if (!q->rx_page.va)
		return;

	page = virt_to_page(q->rx_page.va);
	__page_frag_cache_drain(page, q->rx_page.pagecnt_bias);
	memset(&q->rx_page, 0, sizeof(q->rx_page));
}

static int
mt76s_alloc_rx_queue(struct mt76_dev *dev, enum mt76_rxq_id qid)
{
	struct mt76_queue *q = &dev->q_rx[qid];
	int i;

	spin_lock_init(&q->lock);
	q->entry = devm_kcalloc(dev->dev,
				MT_NUM_RX_ENTRIES, sizeof(*q->entry),
				GFP_KERNEL);
	if (!q->entry)
		return -ENOMEM;

	q->ndesc = MT_NUM_RX_ENTRIES;
	q->buf_size = PAGE_SIZE;

	for (i = 0; i < q->ndesc; i++) {
		struct mt76_queue_entry *e = &q->entry[i];

		e->buf = page_frag_alloc(&q->rx_page, q->buf_size,
					 GFP_KERNEL);
		if (!e->buf) {
			mt76s_free_rx_queue(dev, q);
			return -ENOMEM;
		}
	}

	q->head = q->tail = 0;
	q->queued = 0;

	return 0;
}

static int mt76s_alloc_tx(struct mt76_dev *dev)
{
	struct mt76_queue *q;
	int i;

	for (i = 0; i < MT_TXQ_MCU_WA; i++) {
		INIT_LIST_HEAD(&dev->q_tx[i].swq);

		q = devm_kzalloc(dev->dev, sizeof(*q), GFP_KERNEL);
		if (!q)
			return -ENOMEM;

		spin_lock_init(&q->lock);
		q->hw_idx = i;
		dev->q_tx[i].q = q;

		q->entry = devm_kcalloc(dev->dev,
					MT_NUM_TX_ENTRIES, sizeof(*q->entry),
					GFP_KERNEL);
		if (!q->entry)
			return -ENOMEM;

		q->ndesc = MT_NUM_TX_ENTRIES;
	}

	return 0;
}

void mt76s_stop_txrx(struct mt76_dev *dev)
{
	struct mt76_sdio *sdio = &dev->sdio;
	int i;

	tasklet_kill(&dev->tx_tasklet);
	tasklet_kill(&sdio->rx_tasklet);

	for (i = 0; i < MT_TXQ_MCU_WA; i++) {
		struct mt76_queue_entry entry;
		struct mt76_queue *q;

		q = dev->q_tx[i].q;
		if (!q)
			continue;

		spin_lock_bh(&q->lock);
		while (q->queued) {
			entry = q->entry[q->head];
			q->head = (q->head + 1) % q->ndesc;
			q->queued--;

			if (i != MT_TXQ_MCU)
				dev->drv->tx_complete_skb(dev, i, &entry);
			else
				dev_kfree_skb(entry.skb);
		}
		spin_unlock_bh(&q->lock);
	}

	cancel_work_sync(&sdio->stat_work);
	clear_bit(MT76_READING_STATS, &dev->phy.state);

	mt76_tx_status_check(dev, NULL, true);
}
EXPORT_SYMBOL_GPL(mt76s_stop_txrx);

int mt76s_alloc_queues(struct mt76_dev *dev)
{
	int i;

	for (i = 0; i < MT_RXQ_MCU_WA; i++) {
		int err;

		err = mt76s_alloc_rx_queue(dev, i);
		if (err < 0)
			return err;
	}

	return mt76s_alloc_tx(dev);
}
EXPORT_SYMBOL_GPL(mt76s_alloc_queues);

static struct mt76_queue_entry *
mt76s_get_next_rx_entry(struct mt76_queue *q)
{
	struct mt76_queue_entry *e = NULL;

	spin_lock_bh(&q->lock);
	if (q->queued > 0) {
		e = &q->entry[q->head];
		q->head = (q->head + 1) % q->ndesc;
		q->queued--;
	}
	spin_unlock_bh(&q->lock);

	return e;
}

static struct sk_buff *
mt76s_build_rx_skb(struct mt76_dev *dev, void *data,
		   int len, int buf_size)
{
	struct sk_buff *skb;

	if (SKB_WITH_OVERHEAD(buf_size) < len) {
		struct page *page;

		/* slow path, not enough space for data and
		 * skb_shared_info
		 */
		skb = alloc_skb(MT_SKB_HEAD_LEN, GFP_ATOMIC);
		if (!skb)
			return NULL;

		skb_put_data(skb, data, MT_SKB_HEAD_LEN);
		data += MT_SKB_HEAD_LEN;
		page = virt_to_head_page(data);
		skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
				page, data - page_address(page),
				len - MT_SKB_HEAD_LEN, buf_size);
		return skb;
	}

	/* fast path */
	skb = build_skb(data, buf_size);
	if (!skb)
		return NULL;

	__skb_put(skb, len);

	return skb;
}

static int
mt76s_process_rx_entry(struct mt76_dev *dev, struct mt76_queue_entry *e,
		       int buf_size)
{
	struct sk_buff *skb;

	if (!test_bit(MT76_STATE_INITIALIZED, &dev->phy.state))
		return 0;

	skb = mt76s_build_rx_skb(dev, e->buf, e->buf_sz, buf_size);
	if (!skb)
		return 0;

	dev->drv->rx_skb(dev, MT_RXQ_MAIN, skb);

	return 1;
}

static void
mt76s_process_rx_queue(struct mt76_dev *dev, struct mt76_queue *q)
{
	int qid = q - &dev->q_rx[MT_RXQ_MAIN];

	while (true) {
		struct mt76_queue_entry *e;
		int count;

		e = mt76s_get_next_rx_entry(q);
		if (!e)
			break;

		count = mt76s_process_rx_entry(dev, e, q->buf_size);
		if (count > 0) {
			e->buf = page_frag_alloc(&q->rx_page, q->buf_size,
						 GFP_ATOMIC);
			if (!e->buf)
				break;
		}
	}
	if (qid == MT_RXQ_MAIN)
		mt76_rx_poll_complete(dev, MT_RXQ_MAIN, NULL);
}

static void mt76s_rx_tasklet(unsigned long data)
{
	struct mt76_dev *dev = (struct mt76_dev *)data;
	int i;

	rcu_read_lock();
	mt76_for_each_q_rx(dev, i)
		mt76s_process_rx_queue(dev, &dev->q_rx[i]);
	rcu_read_unlock();
}

static int mt76s_rx_run_queue(struct mt76_dev *dev, enum mt76_rxq_id qid)
{
	struct mt76_queue *q = &dev->q_rx[qid];
	int i;

	sdio_claim_host(dev->sdio.func);

	for (i = 0; i < MT76_SDIO_RX_QUOTA; i++) {
		struct mt76_queue_entry *e = &q->entry[q->tail];
		struct mt76_sdio *sdio = &dev->sdio;
		int len, err;
		u32 val;

		val = sdio_readl(sdio->func, MCR_WRPLR, &err);
		if (err < 0) {
			dev_err(dev->dev, "sdio read len failed:%d\n", err);
			i = err;
			break;
		}

		len = FIELD_GET(RX0_PACKET_LENGTH, val);
		if (!len)
			break;

		/* Assume that an entry can hold a complete packet from SDIO
		 * port.
		 */
		e->buf_sz = len;

		len = roundup(len + 4, 4);
		if (len > sdio->func->cur_blksize)
			len = roundup(len, sdio->func->cur_blksize);

		if (WARN_ON_ONCE(len > q->buf_size)) {
			len = rounddown(q->buf_size, sdio->func->cur_blksize);
			e->buf_sz = len;
		}

		err = sdio_readsb(sdio->func, e->buf, MCR_WRDR(qid), len);
		if (err < 0) {
			dev_err(dev->dev, "sdio read data failed:%d\n", err);
			i = err;
			break;
		}

		spin_lock_bh(&q->lock);
		q->tail = (q->tail + 1) % q->ndesc;
		q->queued++;
		spin_unlock_bh(&q->lock);
	}

	sdio_release_host(dev->sdio.func);

	return i;
}

static void mt76s_tx_tasklet(unsigned long data)
{
	struct mt76_dev *dev = (struct mt76_dev *)data;
	int i;

	for (i = 0; i < MT_TXQ_MCU_WA; i++) {
		struct mt76_sw_queue *sq = &dev->q_tx[i];
		u32 n_dequeued = 0, n_sw_dequeued = 0;
		bool wake, mcu = i == MT_TXQ_MCU;
		struct mt76_queue_entry entry;
		struct mt76_queue *q = sq->q;

		while (q->queued > n_dequeued) {
			if (q->entry[q->head].schedule) {
				q->entry[q->head].schedule = false;
				n_sw_dequeued++;
			}

			entry = q->entry[q->head];
			q->entry[q->head].done = false;
			q->head = (q->head + 1) % q->ndesc;
			n_dequeued++;

			if (mcu)
				dev_kfree_skb(entry.skb);
			else
				dev->drv->tx_complete_skb(dev, i, &entry);
		}

		spin_lock_bh(&q->lock);

		sq->swq_queued -= n_sw_dequeued;
		q->queued -= n_dequeued;

		wake = q->stopped && q->queued < q->ndesc - 8;
		if (wake)
			q->stopped = false;

		if (!q->queued)
			wake_up(&dev->tx_wait);

		spin_unlock_bh(&q->lock);

		if (mcu)
			continue;

		mt76_txq_schedule(&dev->phy, i);

		if (dev->drv->tx_status_data &&
		    !test_and_set_bit(MT76_READING_STATS, &dev->phy.state))
			queue_work(dev->wq, &dev->sdio.stat_work);
		if (wake)
			ieee80211_wake_queue(dev->hw, i);
	}
	wake_up_process(dev->sdio.kthread);
}

static void mt76s_tx_status_data(struct work_struct *work)
{
	struct mt76_sdio *sdio;
	struct mt76_dev *dev;
	u8 update = 1;
	u16 count = 0;

	sdio = container_of(work, struct mt76_sdio, stat_work);
	dev = container_of(sdio, struct mt76_dev, sdio);

	while (true) {
		if (test_bit(MT76_REMOVED, &dev->phy.state))
			break;

		if (!dev->drv->tx_status_data(dev, &update))
			break;
		count++;
	}

	if (count && test_bit(MT76_STATE_RUNNING, &dev->phy.state))
		queue_work(dev->wq, &sdio->stat_work);
	else
		clear_bit(MT76_READING_STATS, &dev->phy.state);
}

static int mt76s_tx_add_buff(struct mt76_sdio *sdio, struct sk_buff *skb)
{
	int err, len = skb->len;

	if (len > sdio->func->cur_blksize)
		len = roundup(len, sdio->func->cur_blksize);

	sdio_claim_host(sdio->func);

	/* TODO: skb_walk_frags and then write to SDIO port */
	err = sdio_writesb(sdio->func, MCR_WTDR1, skb->data, len);

	sdio_release_host(sdio->func);

	return err;
}

static int
mt76s_tx_update_sched(struct mt76_dev *dev,
		      struct mt76_queue_entry *e, bool mcu)
{
	struct mt76_sdio *sdio = &dev->sdio;
	struct ieee80211_hdr *hdr;
	int size, ret = -EBUSY;

	size = DIV_ROUND_UP(e->buf_sz + sdio->sched.deficit, MT_PSE_PAGE_SZ);

	if (mcu) {
		if (!test_bit(MT76_STATE_MCU_RUNNING, &dev->phy.state))
			return 0;

		mutex_lock(&sdio->sched.lock);
		if (sdio->sched.pse_mcu_quota > size) {
			sdio->sched.pse_mcu_quota -= size;
			ret = 0;
		}
		mutex_unlock(&sdio->sched.lock);

		return ret;
	}

	hdr = (struct ieee80211_hdr *)(e->skb->data + dev->drv->txwi_size);
	if (ieee80211_is_ctl(hdr->frame_control))
		return 0;

	mutex_lock(&sdio->sched.lock);
	if (sdio->sched.pse_data_quota > size &&
	    sdio->sched.ple_data_quota > 0) {
		sdio->sched.pse_data_quota -= size;
		sdio->sched.ple_data_quota--;
		ret = 0;
	}
	mutex_unlock(&sdio->sched.lock);

	return ret;
}

static int mt76s_tx_run_queue(struct mt76_dev *dev, struct mt76_queue *q)
{
	bool mcu = q == dev->q_tx[MT_TXQ_MCU].q;
	int nframes = 0;

	while (q->first != q->tail) {
		struct mt76_queue_entry *e = &q->entry[q->first];
		int err;

		if (mt76s_tx_update_sched(dev, e, mcu))
			break;

		err = mt76s_tx_add_buff(&dev->sdio, e->skb);
		if (err) {
			dev_err(dev->dev, "sdio write failed: %d\n", err);
			return -EIO;
		}

		q->first = (q->first + 1) % q->ndesc;
		nframes++;
	}

	spin_lock_bh(&q->lock);
	q->queued += nframes;
	spin_unlock_bh(&q->lock);

	return nframes;
}

static void mt76s_refill_sched_quota(struct mt76_dev *dev)
{
	struct mt76_sdio *sdio = &dev->sdio;
	u32 data[8];
	int i;

	sdio_claim_host(sdio->func);
	for (i = 0 ; i < ARRAY_SIZE(data); i++)
		data[i] = sdio_readl(sdio->func, MCR_WTQCR(i), 0);
	sdio_release_host(sdio->func);

	mutex_lock(&sdio->sched.lock);
	sdio->sched.pse_data_quota += FIELD_GET(TXQ_CNT_L, data[0]) + /* BK */
				      FIELD_GET(TXQ_CNT_H, data[0]) + /* BE */
				      FIELD_GET(TXQ_CNT_L, data[1]) + /* VI */
				      FIELD_GET(TXQ_CNT_H, data[1]);  /* VO */
	sdio->sched.ple_data_quota += FIELD_GET(TXQ_CNT_H, data[2]) + /* BK */
				      FIELD_GET(TXQ_CNT_L, data[3]) + /* BE */
				      FIELD_GET(TXQ_CNT_H, data[3]) + /* VI */
				      FIELD_GET(TXQ_CNT_L, data[4]);  /* VO */
	sdio->sched.pse_mcu_quota += FIELD_GET(TXQ_CNT_L, data[2]);
	mutex_unlock(&sdio->sched.lock);
}

static int mt76s_kthread_run(void *data)
{
	struct mt76_dev *dev = data;
	struct mt76_phy *mphy = &dev->phy;

	while (!kthread_should_stop()) {
		int i, ret, nframes = 0;

		cond_resched();

		mt76_for_each_q_rx(dev, i) {
			ret = mt76s_rx_run_queue(dev, i);
			if (ret < 0) {
				nframes = 0;
				goto out;
			}
			if (ret)
				tasklet_schedule(&dev->sdio.rx_tasklet);
			nframes += ret;
		}

		mt76s_refill_sched_quota(dev);
		for (i = 0; i < MT_TXQ_MCU_WA; i++) {
			ret = mt76s_tx_run_queue(dev, dev->q_tx[i].q);
			if (ret < 0) {
				nframes = 0;
				break;
			}
			nframes += ret;
		}

out:
		if (!nframes || !test_bit(MT76_STATE_RUNNING, &mphy->state)) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
		}
	}

	return 0;
}

static int
mt76s_tx_queue_skb(struct mt76_dev *dev, enum mt76_txq_id qid,
		   struct sk_buff *skb, struct mt76_wcid *wcid,
		   struct ieee80211_sta *sta)
{
	struct mt76_queue *q = dev->q_tx[qid].q;
	struct mt76_tx_info tx_info = {
		.skb = skb,
	};
	int err, len = skb->len;
	u16 idx = q->tail;

	if (q->queued == q->ndesc)
		return -ENOSPC;

	skb->prev = skb->next = NULL;
	err = dev->drv->tx_prepare_skb(dev, NULL, qid, wcid, sta, &tx_info);
	if (err < 0)
		return err;

	q->entry[q->tail].skb = tx_info.skb;
	q->entry[q->tail].buf_sz = len;
	q->tail = (q->tail + 1) % q->ndesc;

	return idx;
}

static int
mt76s_tx_queue_skb_raw(struct mt76_dev *dev, enum mt76_txq_id qid,
		       struct sk_buff *skb, u32 tx_info)
{
	struct mt76_queue *q = dev->q_tx[qid].q;
	int ret = -ENOSPC, len = skb->len;

	spin_lock_bh(&q->lock);
	if (q->queued == q->ndesc)
		goto out;

	ret = mt76_skb_adjust_pad(skb);
	if (ret)
		goto out;

	q->entry[q->tail].skb = skb;
	q->entry[q->tail].buf_sz = len;
	q->tail = (q->tail + 1) % q->ndesc;

out:
	spin_unlock_bh(&q->lock);

	return ret;
}

static void mt76s_tx_kick(struct mt76_dev *dev, struct mt76_queue *q)
{
	struct mt76_sdio *sdio = &dev->sdio;

	wake_up_process(sdio->kthread);
}

static const struct mt76_queue_ops sdio_queue_ops = {
	.tx_queue_skb = mt76s_tx_queue_skb,
	.kick = mt76s_tx_kick,
	.tx_queue_skb_raw = mt76s_tx_queue_skb_raw,
};

void mt76s_deinit(struct mt76_dev *dev)
{
	struct mt76_sdio *sdio = &dev->sdio;
	int i;

	kthread_stop(sdio->kthread);
	mt76s_stop_txrx(dev);

	mt76_for_each_q_rx(dev, i)
		mt76s_free_rx_queue(dev, &dev->q_rx[i]);

	sdio_claim_host(sdio->func);
	sdio_release_irq(sdio->func);
	sdio_release_host(sdio->func);
}
EXPORT_SYMBOL_GPL(mt76s_deinit);

int mt76s_init(struct mt76_dev *dev, struct sdio_func *func)
{
	static const struct mt76_bus_ops mt76s_ops = {
		.rr = mt76s_rr,
		.rmw = mt76s_rmw,
		.wr = mt76s_wr,
		.write_copy = mt76s_write_copy,
		.read_copy = mt76s_read_copy,
		.wr_rp = mt76s_wr_rp,
		.rd_rp = mt76s_rd_rp,
		.type = MT76_BUS_SDIO,
	};
	struct mt76_sdio *sdio = &dev->sdio;

	sdio->kthread = kthread_create(mt76s_kthread_run, dev, "mt76s");
	if (IS_ERR(sdio->kthread))
		return PTR_ERR(sdio->kthread);

	tasklet_init(&sdio->rx_tasklet, mt76s_rx_tasklet, (unsigned long)dev);
	tasklet_init(&dev->tx_tasklet, mt76s_tx_tasklet, (unsigned long)dev);

	INIT_WORK(&sdio->stat_work, mt76s_tx_status_data);

	mutex_init(&sdio->sched.lock);
	dev->queue_ops = &sdio_queue_ops;
	dev->bus = &mt76s_ops;
	dev->sdio.func = func;

	return 0;
}
EXPORT_SYMBOL_GPL(mt76s_init);

MODULE_AUTHOR("Sean Wang <sean.wang@mediatek.com>");
MODULE_AUTHOR("Lorenzo Bianconi <lorenzo@kernel.org>");
MODULE_LICENSE("Dual BSD/GPL");
