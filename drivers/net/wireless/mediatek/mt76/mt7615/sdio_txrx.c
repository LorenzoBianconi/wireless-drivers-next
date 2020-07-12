// SPDX-License-Identifier: ISC
/* Copyright (C) 2020 MediaTek Inc.
 *
 * Author: Felix Fietkau <nbd@nbd.name>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include <linux/kernel.h>
#include <linux/iopoll.h>
#include <linux/module.h>

#include <linux/mmc/host.h>
#include <linux/mmc/sdio_ids.h>
#include <linux/mmc/sdio_func.h>

#include "../trace.h"
#include "mt7615.h"
#include "sdio.h"
#include "mac.h"

void mt7663s_sdio_irq(struct sdio_func *func)
{
	struct mt76_dev *dev = sdio_get_drvdata(func);
	struct mt76_sdio *sdio = &dev->sdio;
	u32 intr;

	/* disable interrupt */
	sdio_writel(func, WHLPCR_INT_EN_CLR, MCR_WHLPCR, 0);

	intr = sdio_readl(func, MCR_WHISR, 0);
	trace_dev_irq(dev, intr, 0);

	if (!test_bit(MT76_STATE_INITIALIZED, &dev->phy.state))
		goto out;

	if (intr & (WHIER_RX0_DONE_INT_EN | WHIER_RX1_DONE_INT_EN |
		    WHIER_TX_DONE_INT_EN))
		wake_up_process(sdio->txrx_kthread);

	if (intr & WHIER_TX_DONE_INT_EN)
		wake_up_process(sdio->kthread);
out:
	/* enable interrupt */
	sdio_writel(func, WHLPCR_INT_EN_SET, MCR_WHLPCR, 0);
}

static void mt7663s_refill_sched_quota(struct mt7615_dev *dev)
{
	struct mt76_sdio *sdio = &dev->mt76.sdio;
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

static int mt7663s_rx_run_queue(struct mt7615_dev *dev, enum mt76_rxq_id qid)
{
	struct mt76_queue *q = &dev->mt76.q_rx[qid];
	int i;

	sdio_claim_host(dev->mt76.sdio.func);

	for (i = 0; i < MT76_SDIO_RX_QUOTA; i++) {
		struct mt76_queue_entry *e = &q->entry[q->tail];
		struct mt76_sdio *sdio = &dev->mt76.sdio;
		int len, err, size;
		u32 val;

		val = sdio_readl(sdio->func, MCR_WRPLR, &err);
		if (err < 0) {
			dev_err(dev->mt76.dev, "sdio read len failed:%d\n", err);
			i = err;
			break;
		}

		len = FIELD_GET(RX0_PACKET_LENGTH, val);
		if (!len)
			break;

		/* Assume that an entry can hold a complete packet from SDIO
		 * port.
		 */
		e->b_info.data_len = len;

		len = roundup(len + 4, 4);
		if (len > sdio->func->cur_blksize)
			len = roundup(len, sdio->func->cur_blksize);

		if (WARN_ON_ONCE(len > q->buf_size)) {
			i = -ENOMEM;
			break;
		}

		size = len + SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
		size = min_t(int, size, q->buf_size);

		e->buf = page_frag_alloc(&q->rx_page, size, GFP_KERNEL);
		if (!e->buf) {
			i = -ENOMEM;
			break;
		}
		e->b_info.len = size;

		err = sdio_readsb(sdio->func, e->buf, MCR_WRDR(qid), len);
		if (err < 0) {
			dev_err(dev->mt76.dev, "sdio read data failed:%d\n", err);
			i = err;
			break;
		}

		spin_lock_bh(&q->lock);
		q->tail = (q->tail + 1) % q->ndesc;
		q->queued++;
		spin_unlock_bh(&q->lock);
	}

	sdio_release_host(dev->mt76.sdio.func);

	return i;
}

static int mt7663s_tx_add_buff(struct mt7615_dev *dev, struct sk_buff *skb)
{
	struct mt76_sdio *sdio = &dev->mt76.sdio;
	int err, len = skb->len;

	if (len > sdio->func->cur_blksize)
		len = roundup(len, sdio->func->cur_blksize);

	sdio_claim_host(sdio->func);

	/* TODO: skb_walk_frags and then write to SDIO port */
	err = sdio_writesb(sdio->func, MCR_WTDR1, skb->data, len);

	sdio_release_host(sdio->func);

	return err;
}

static int mt7663s_tx_update_sched(struct mt7615_dev *dev,
				   struct mt76_queue_entry *e,
				   bool mcu)
{
	struct mt76_sdio *sdio = &dev->mt76.sdio;
	struct mt76_phy *mphy = &dev->mt76.phy;
	struct ieee80211_hdr *hdr;
	int size, ret = -EBUSY;

	size = DIV_ROUND_UP(e->b_info.len + sdio->sched.deficit,
			    MT_PSE_PAGE_SZ);

	if (mcu) {
		if (!test_bit(MT76_STATE_MCU_RUNNING, &mphy->state))
			return 0;

		mutex_lock(&sdio->sched.lock);
		if (sdio->sched.pse_mcu_quota > size) {
			sdio->sched.pse_mcu_quota -= size;
			ret = 0;
		}
		mutex_unlock(&sdio->sched.lock);

		return ret;
	}

	hdr = (struct ieee80211_hdr *)(e->skb->data + MT_USB_TXD_SIZE);
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

static int mt7663s_tx_run_queue(struct mt7615_dev *dev, struct mt76_queue *q)
{
	bool mcu = q == dev->mt76.q_tx[MT_TXQ_MCU].q;
	int nframes = 0;

	while (q->first != q->tail) {
		struct mt76_queue_entry *e = &q->entry[q->first];
		int err;

		if (mt7663s_tx_update_sched(dev, e, mcu))
			break;

		err = mt7663s_tx_add_buff(dev, e->skb);
		if (err) {
			dev_err(dev->mt76.dev, "sdio write failed: %d\n", err);
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

int mt7663s_kthread_run(void *data)
{
	struct mt7615_dev *dev = data;
	struct mt76_phy *mphy = &dev->mt76.phy;

	while (!kthread_should_stop()) {
		int i, ret, nframes = 0;

		cond_resched();

		mt76_for_each_q_rx(&dev->mt76, i) {
			ret = mt7663s_rx_run_queue(dev, i);
			if (ret < 0) {
				nframes = 0;
				goto out;
			}
			if (ret)
				wake_up_process(dev->mt76.sdio.kthread);
			nframes += ret;
		}

		mt7663s_refill_sched_quota(dev);
		for (i = 0; i < MT_TXQ_MCU_WA; i++) {
			ret = mt7663s_tx_run_queue(dev, dev->mt76.q_tx[i].q);
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
