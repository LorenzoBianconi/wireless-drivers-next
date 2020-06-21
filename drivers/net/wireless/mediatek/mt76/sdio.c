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

#include <linux/module.h>
#include "mt76.h"
#include "mt76s.h"

static u32 mt76s_read_whisr(struct mt76_dev *dev)
{
	struct sdio_func *func = dev->sdio.func;
	u32 status;

	status = sdio_readl(func, MCR_WHISR, NULL);

	return status;
}

static u32 __mt76s_rr_mailbox(struct mt76_dev *dev, u32 offset)
{
	struct sdio_func *func = dev->sdio.func;
	u32 val, status;
	int err;

	sdio_claim_host(func);

	sdio_writel(func, offset, MCR_H2DSM0R, &err);
	if (err < 0)
		goto err;

	sdio_writel(func, H2D_SW_INT_READ, MCR_WSICR, &err);
	if (err < 0)
		goto err;

	err = readx_poll_timeout(mt76s_read_whisr, dev, status,
			status & H2D_SW_INT_READ, 0, 1000000);
	if (err < 0) {
		dev_err(dev->dev, "%s: query whisr timeout\n", __func__);
		goto err;
	}

	sdio_writel(func, H2D_SW_INT_READ, MCR_WHISR, &err);
	if (err < 0)
		goto err;

	val = sdio_readl(func, MCR_H2DSM0R, &err);
	if (err < 0)
		goto err;

	if (val != offset) {
		dev_err(dev->dev, "register is mismatch\n");
		goto err;
	}

	val = sdio_readl(func, MCR_D2HRM1R, &err);
	if (err < 0)
		goto err;

	sdio_release_host(func);

	return val;
err:
	dev_err(dev->dev, "%s: err = %d\n", __func__, err);
	sdio_release_host(func);

	return err;
}

static void __mt76s_wr_mailbox(struct mt76_dev *dev, u32 offset, u32 val)
{
	struct sdio_func *func = dev->sdio.func;
	u32 status;
	int err;

	sdio_claim_host(func);

	sdio_writel(func, offset, MCR_H2DSM0R, &err);
	if (err < 0)
		goto err;

	sdio_writel(func, val, MCR_H2DSM1R, &err);
	if (err < 0)
		goto err;

	sdio_writel(func, H2D_SW_INT_WRITE, MCR_WSICR, &err);
	if (err < 0)
		goto err;

	err = readx_poll_timeout(mt76s_read_whisr, dev, status,
			status & H2D_SW_INT_WRITE, 0, 1000000);
	if (err < 0) {
		dev_err(dev->dev, "%s: query whisr timeout\n", __func__);
		goto err;
	}

	sdio_writel(func, H2D_SW_INT_WRITE, MCR_WHISR, &err);
	if (err < 0)
		goto err;

	val = sdio_readl(func, MCR_H2DSM0R, &err);
	if (err < 0)
		goto err;

	if (val != offset) {
		dev_err(dev->dev, "register is mismatch\n");
		goto err;
	}

	sdio_release_host(func);

	return;
err:
	dev_err(dev->dev, "%s: err = %d\n", __func__, err);
	sdio_release_host(func);
}

static u32 mt76s_rr(struct mt76_dev *dev, u32 offset)
{
	if (test_bit(MT76_STATE_MCU_RUNNING, &dev->phy.state))
		return dev->mcu_ops->mcu_rr(dev, offset);
	else
		return __mt76s_rr_mailbox(dev, offset);
}

static void mt76s_wr(struct mt76_dev *dev, u32 offset, u32 val)
{
	if (test_bit(MT76_STATE_MCU_RUNNING, &dev->phy.state))
		dev->mcu_ops->mcu_wr(dev, offset, val);
	else
		__mt76s_wr_mailbox(dev, offset, val);
}

static u32 mt76s_rmw(struct mt76_dev *dev, u32 offset, u32 mask, u32 val)
{
	val |= mt76s_rr(dev, offset) & ~mask;
	mt76s_wr(dev, offset, val);

	return val;
}

static void mt76s_write_copy(struct mt76_dev *dev, u32 offset, const void *data,
		int len)
{
	while (len) {
		mt76s_wr(dev, offset, *(u32 *)data);

		offset += sizeof(u32);
		data += sizeof(u32);
		len -= sizeof(u32);
	}
}

static void mt76s_read_copy(struct mt76_dev *dev, u32 offset, void *data,
		int len)
{
	while (len) {
		*(u32 *)data = mt76s_rr(dev, offset);

		offset += sizeof(u32);
		data += sizeof(u32);
		len -= sizeof(u32);
	}
}

static int mt76s_wr_rp(struct mt76_dev *dev, u32 base,
		const struct mt76_reg_pair *data, int len)
{
	while (len > 0) {
		mt76s_wr(dev, data->reg, data->value);
		data++;
		len--;
	}

	return 0;
}

static int mt76s_rd_rp(struct mt76_dev *dev, u32 base,
		struct mt76_reg_pair *data, int len)
{
	while (len > 0) {
		data->value = mt76s_rr(dev, data->reg);
		data++;
		len--;
	}

	return 0;
}

static int
mt76s_rx_buf_alloc(struct mt76_dev *dev, struct mt76_queue *q,
		   struct mt76_queue_entry *e, gfp_t gfp)
{
	e->buf = page_frag_alloc(&q->rx_page, q->buf_size, gfp);

	return e->buf ? 0 : -ENOMEM;
}

static void
mt76s_free_rx_queue(struct mt76_dev *dev, struct mt76_queue *q)
{
	struct page *page;
	int i;

	for (i = 0; i < q->ndesc; i++) {
		if (q->entry[i].buf) {
			skb_free_frag(q->entry[i].buf);
			q->entry[i].buf = NULL;
		}
	}

	if (!q->rx_page.va)
		return;

	page = virt_to_page(q->rx_page.va);
	__page_frag_cache_drain(page, q->rx_page.pagecnt_bias);
	memset(&q->rx_page, 0, sizeof(q->rx_page));
}

static void mt76s_free_rx(struct mt76_dev *dev)
{
	int i;

	mt76_for_each_q_rx(dev, i)
		mt76s_free_rx_queue(dev, &dev->q_rx[i]);
}

void mt76s_stop_rx(struct mt76_dev *dev)
{
	tasklet_kill(&dev->sdio.rx_tasklet);
}
EXPORT_SYMBOL_GPL(mt76s_stop_rx);

static int
mt76s_alloc_rx_queue(struct mt76_dev *dev, enum mt76_rxq_id qid)
{
	struct mt76_queue *q = &dev->q_rx[qid];
	int i, err;

	spin_lock_init(&q->lock);
	q->entry = devm_kcalloc(dev->dev,
				MT_NUM_RX_ENTRIES, sizeof(*q->entry),
				GFP_KERNEL);
	if (!q->entry)
		return -ENOMEM;

	q->ndesc = MT_NUM_RX_ENTRIES;
	q->buf_size = PAGE_SIZE;

	for (i = 0; i < q->ndesc; i++) {
		err = mt76s_rx_buf_alloc(dev, q, &q->entry[i], GFP_KERNEL);
		if (err < 0)
			goto free_rx_queue;
	}

	q->head = q->tail = 0;
	q->queued = 0;

	return 0;

free_rx_queue:
	mt76s_free_rx_queue(dev, q);

	return err;
}

int mt76s_alloc_mcu_queue(struct mt76_dev *dev)
{
	return mt76s_alloc_rx_queue(dev, MT_RXQ_MCU);
}
EXPORT_SYMBOL_GPL(mt76s_alloc_mcu_queue);

static int mt76s_alloc_tx(struct mt76_dev *dev)
{
	struct mt76_queue *q;
	int i;

	for (i = 0; i <= MT_TXQ_PSD; i++) {
		INIT_LIST_HEAD(&dev->q_tx[i].swq);

		if (i >= IEEE80211_NUM_ACS) {
			dev->q_tx[i].q = dev->q_tx[0].q;
			continue;
		}

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

static void mt76s_free_tx(struct mt76_dev *dev)
{

}

void mt76s_stop_tx(struct mt76_dev *dev)
{
	struct mt76_queue_entry entry;
	struct mt76_queue *q;
	int i, ret;

	ret = wait_event_timeout(dev->tx_wait, !mt76_has_tx_pending(&dev->phy),
				 HZ / 5);
	if (!ret) {
		dev_err(dev->dev, "timed out waiting for pending tx\n");

		tasklet_kill(&dev->tx_tasklet);

		for (i = 0; i < IEEE80211_NUM_ACS; i++) {
			q = dev->q_tx[i].q;
			if (!q)
				continue;

			spin_lock_bh(&q->lock);
			while (q->queued) {
				entry = q->entry[q->head];
				q->head = (q->head + 1) % q->ndesc;
				q->queued--;

				dev->drv->tx_complete_skb(dev, i, &entry);
			}
			spin_unlock_bh(&q->lock);
		}
	}
	cancel_work_sync(&dev->sdio.tx_work);

	cancel_work_sync(&dev->sdio.stat_work);
	clear_bit(MT76_READING_STATS, &dev->phy.state);

	mt76_tx_status_check(dev, NULL, true);
}
EXPORT_SYMBOL_GPL(mt76s_stop_tx);

static void mt76s_queues_deinit(struct mt76_dev *dev)
{
	mt76s_stop_rx(dev);
	mt76s_stop_tx(dev);

	mt76s_free_rx(dev);
	mt76s_free_tx(dev);
}

void mt76s_deinit(struct mt76_dev *dev)
{
	mt76s_queues_deinit(dev);
	sdio_release_irq(dev->sdio.func);
}
EXPORT_SYMBOL_GPL(mt76s_deinit);

int mt76s_alloc_queues(struct mt76_dev *dev)
{
	int err;

	err = mt76s_alloc_rx_queue(dev, MT_RXQ_MAIN);
	if (err < 0)
		return err;

	return mt76s_alloc_tx(dev);
}
EXPORT_SYMBOL_GPL(mt76s_alloc_queues);

int mt76s_skb_dma_info(struct sk_buff *skb, u32 info)
{
	struct sk_buff *last = skb;
	u32 pad;

	/* Add zero pad of 4 - 7 bytes */
	pad = round_up(skb->len, 4) + 4 - skb->len;

	if (skb_pad(last, pad))
		return -ENOMEM;
	__skb_put(last, pad);

	return 0;
}
EXPORT_SYMBOL_GPL(mt76s_skb_dma_info);

static struct mt76_queue_entry *
mt76s_get_next_rx_entry(struct mt76_queue *q)
{
	struct mt76_queue_entry *e = NULL;

	spin_lock(&q->lock);
	if (q->queued > 0) {
		e = &q->entry[q->head];
		q->head = (q->head + 1) % q->ndesc;
		q->queued--;
	}
	spin_unlock(&q->lock);

	return e;
}

static struct sk_buff *
mt76s_build_rx_skb(struct mt76_dev *dev, void *data,
		   int len, int buf_size)
{
	int head_room = 0;
	struct sk_buff *skb;

	if (SKB_WITH_OVERHEAD(buf_size) < head_room + len) {
		struct page *page;

		/* slow path, not enough space for data and
		 * skb_shared_info
		 */
		skb = alloc_skb(MT_SKB_HEAD_LEN, GFP_ATOMIC);
		if (!skb)
			return NULL;

		skb_put_data(skb, data + head_room, MT_SKB_HEAD_LEN);
		data += head_room + MT_SKB_HEAD_LEN;
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

	skb_reserve(skb, head_room);
	__skb_put(skb, len);

	return skb;
}

static int
mt76s_process_rx_entry(struct mt76_dev *dev, struct mt76_queue_entry *e,
		       int buf_size)
{
	struct sk_buff *skb;
	int nsgs = 1;

	if (!test_bit(MT76_STATE_INITIALIZED, &dev->phy.state))
		return 0;

	skb = mt76s_build_rx_skb(dev, e->buf, e->buf_sz, buf_size);
	if (!skb)
		return 0;

	dev->drv->rx_skb(dev, MT_RXQ_MAIN, skb);

	return nsgs;
}

static void
mt76s_process_rx_queue(struct mt76_dev *dev, struct mt76_queue *q)
{
	int qid = q - &dev->q_rx[MT_RXQ_MAIN];
	struct mt76_queue_entry *e;
	int err, count;

	while (true) {
		e = mt76s_get_next_rx_entry(q);
		if (!e)
			break;

		count = mt76s_process_rx_entry(dev, e, q->buf_size);
		if (count > 0) {
			err = mt76s_rx_buf_alloc(dev, q, e, GFP_ATOMIC);
			if (err < 0)
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

static void mt76s_rx_work(struct mt76_dev *dev, int num)
{
	struct mt76_sdio *sdio = &dev->sdio;
	struct mt76_queue_entry *e;
	struct mt76_queue *q;
	int len, qid, n, err;
	u32 val;

	qid = MT_RXQ_MAIN;
	q = &dev->q_rx[qid];

	for (n = 0; n < num; n++) {
		val = sdio_readl(sdio->func, MCR_WRPLR, &err);
		if (err < 0)
			dev_err(dev->dev, "sdio read len failed:%d\n", err);
		len = FIELD_GET(RX0_PACKET_LENGTH, val);
		if (!len)
			break;

		e = &q->entry[q->tail];

		/* Assume that an entry can hold a complete packet from SDIO
		 * port.
		 */
		e->buf_sz = len;

		len = roundup(len + 4, 4);
		if (len > sdio->func->cur_blksize)
			len = roundup(len, sdio->func->cur_blksize);

		if (len > q->buf_size) {
			dev_warn(dev->dev, "sdio data over holding buffer\n");
			len = rounddown(q->buf_size, sdio->func->cur_blksize);
		}

		err = sdio_readsb(sdio->func, e->buf, MCR_WRDR(0), len);
		if (err < 0)
			dev_err(dev->dev, "sdio read data failed:%d\n", err);

		spin_lock_bh(&q->lock);
		q->tail = (q->tail + 1) % q->ndesc;
		q->queued++;
		spin_unlock_bh(&q->lock);
	}
}

static void mt76s_tx_tasklet(unsigned long data)
{
	struct mt76_dev *dev = (struct mt76_dev *)data;
	struct mt76_queue_entry entry;
	struct mt76_sw_queue *sq;
	struct mt76_queue *q;
	bool wake;
	int i;

	for (i = 0; i < IEEE80211_NUM_ACS; i++) {
		u32 n_dequeued = 0, n_sw_dequeued = 0;

		sq = &dev->q_tx[i];
		q = sq->q;

		while (q->queued > n_dequeued) {
			if (!q->entry[q->head].done)
				break;

			if (q->entry[q->head].schedule) {
				q->entry[q->head].schedule = false;
				n_sw_dequeued++;
			}

			entry = q->entry[q->head];
			q->entry[q->head].done = false;
			q->head = (q->head + 1) % q->ndesc;
			n_dequeued++;

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

		mt76_txq_schedule(&dev->phy, i);

		if (dev->drv->tx_status_data &&
		    !test_and_set_bit(MT76_READING_STATS, &dev->phy.state))
			queue_work(dev->wq, &dev->sdio.stat_work);
		if (wake)
			ieee80211_wake_queue(dev->hw, i);
	}
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

static void mt76s_tx_work(struct work_struct *work)
{
	struct mt76_sdio *sdio = container_of(work, struct mt76_sdio, tx_work);
	struct mt76_dev *dev = container_of(sdio, struct mt76_dev, sdio);
	int i;

	for (i = 0; i < IEEE80211_NUM_ACS; i++) {
		struct mt76_queue *q = dev->q_tx[i].q;

		while (q->first != q->tail) {
			u16 idx = q->first;
			int err;

			err = mt76s_tx_add_buff(sdio, q->entry[q->first].skb);
			if (err) {
				dev_err(dev->dev, "sdio write failed: %d\n", err);
				return;
			}

			q->first = (q->first + 1) % q->ndesc;
			q->entry[idx].done = true;
		}
	}
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
	u16 idx = q->tail;
	int err;

	if (q->queued == q->ndesc)
		return -ENOSPC;

	skb->prev = skb->next = NULL;
	err = dev->drv->tx_prepare_skb(dev, NULL, qid, wcid, sta, &tx_info);
	if (err < 0)
		return err;

	q->tail = (q->tail + 1) % q->ndesc;
	q->entry[idx].skb = tx_info.skb;
	q->queued++;

	return idx;
}

static void mt76s_tx_kick(struct mt76_dev *dev, struct mt76_queue *q)
{
	struct mt76_sdio *sdio = &dev->sdio;

	queue_work(dev->wq, &sdio->tx_work);
}

static void mt76s_sdio_irq(struct sdio_func *func)
{
	struct mt76_dev *dev = sdio_get_drvdata(func);
	u32 intr;

	/* disable interrupt */
	sdio_writel(func, WHLPCR_INT_EN_CLR, MCR_WHLPCR, 0);

	intr = sdio_readl(func, MCR_WHISR, 0);

	/* Don't ACK read/wirte software interrupt otherwise it probably breaks
	 * mt76s_wr or mt76s_rr.
	 */
	intr &= ~(H2D_SW_INT_READ | H2D_SW_INT_WRITE);
	sdio_writel(func, intr, MCR_WHISR, 0);

	if (!test_bit(MT76_STATE_INITIALIZED, &dev->phy.state))
		goto out;

	if (intr & WHIER_RX0_DONE_INT_EN) {
		mt76s_rx_work(dev, 64);
		tasklet_schedule(&dev->sdio.rx_tasklet);
	}

	if (intr & WHIER_TX_DONE_INT_EN)
		tasklet_schedule(&dev->tx_tasklet);
out:
	/* enable interrupt */
	sdio_writel(func, WHLPCR_INT_EN_SET, MCR_WHLPCR, 0);
}

static u32 mt76s_sdio_read_pcr(struct mt76_dev *dev)
{
	struct sdio_func *func = dev->sdio.func;
	u32 status;

	status = sdio_readl(func, MCR_WHLPCR, NULL);

	return status;
}

int mt76s_driver_own(struct mt76_dev *dev)
{
	struct sdio_func *func = dev->sdio.func;
	u32 status;
	int ret;

	sdio_claim_host(func);

	sdio_writel(func, WHLPCR_FW_OWN_REQ_CLR, MCR_WHLPCR, 0);

	ret = readx_poll_timeout(mt76s_sdio_read_pcr, dev, status,
				 status & WHLPCR_IS_DRIVER_OWN, 2000, 1000000);
	if (ret < 0)
		dev_err(dev->dev, "Cannot get ownership from device");

	sdio_release_host(func);

	return ret;
}
EXPORT_SYMBOL_GPL(mt76s_driver_own);

int mt76s_firmware_own(struct mt76_dev *dev)
{
	struct sdio_func *func = dev->sdio.func;
	u32 status;
	int ret;

	sdio_claim_host(func);

	sdio_writel(func, WHLPCR_FW_OWN_REQ_SET, MCR_WHLPCR, 0);

	ret = readx_poll_timeout(mt76s_sdio_read_pcr, dev, status,
				 !(status & WHLPCR_IS_DRIVER_OWN), 2000, 1000000);
	if (ret < 0)
		dev_err(dev->dev, "Cannot set ownership to device");

	sdio_release_host(func);

	return ret;
}
EXPORT_SYMBOL_GPL(mt76s_firmware_own);

static int mt76s_hw_init(struct mt76_dev *dev, struct sdio_func *func)
{
	u32 status, ctrl;
	int ret;

	sdio_claim_host(func);

	ret = sdio_enable_func(func);
	if (ret < 0)
		goto release;

	/* Get ownership from the device */
	sdio_writel(func, WHLPCR_INT_EN_CLR | WHLPCR_FW_OWN_REQ_CLR,
		    MCR_WHLPCR, &ret);
	if (ret < 0)
		goto disable_func;

	ret = readx_poll_timeout(mt76s_sdio_read_pcr, dev, status,
				 status & WHLPCR_IS_DRIVER_OWN, 2000, 1000000);
	if (ret < 0) {
		dev_err(dev->dev, "Cannot get ownership from device");
		goto disable_func;
	}

	ret = sdio_set_block_size(func, 512);
	if (ret < 0)
		goto disable_func;

	/* Enable interrupt */
	sdio_writel(func, WHLPCR_INT_EN_SET, MCR_WHLPCR, &ret);
	if (ret < 0)
		goto disable_func;

	ctrl = WHIER_RX0_DONE_INT_EN | WHIER_TX_DONE_INT_EN;
	sdio_writel(func, ctrl, MCR_WHIER, &ret);
	if (ret < 0)
		goto disable_func;

	/* set WHISR as write clear and Rx aggregation number as 1 */
	ctrl = W_INT_CLR_CTRL | FIELD_PREP(MAX_HIF_RX_LEN_NUM, 1);
	sdio_writel(func, ctrl, MCR_WHCR, &ret);
	if (ret < 0)
		goto disable_func;

	ret = sdio_claim_irq(func, mt76s_sdio_irq);
	if (ret < 0)
		goto disable_func;

	sdio_release_host(func);

	return 0;
disable_func:
	sdio_disable_func(func);
release:
	sdio_release_host(func);

	return ret;
}

static const struct mt76_queue_ops sdio_queue_ops = {
	.tx_queue_skb = mt76s_tx_queue_skb,
	.kick = mt76s_tx_kick,
};

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

	tasklet_init(&sdio->rx_tasklet, mt76s_rx_tasklet, (unsigned long)dev);
	tasklet_init(&dev->tx_tasklet, mt76s_tx_tasklet, (unsigned long)dev);

	INIT_WORK(&sdio->stat_work, mt76s_tx_status_data);
	INIT_WORK(&sdio->tx_work, mt76s_tx_work);

	dev->bus = &mt76s_ops;
	dev->sdio.func = func;
	dev->queue_ops = &sdio_queue_ops;

	return mt76s_hw_init(dev, func);
}
EXPORT_SYMBOL_GPL(mt76s_init);

MODULE_AUTHOR("Sean Wang <sean.wang@mediatek.com>");
MODULE_AUTHOR("Lorenzo Bianconi <lorenzo@kernel.org>");
MODULE_LICENSE("Dual BSD/GPL");
