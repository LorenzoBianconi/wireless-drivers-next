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

static void mt7663s_refill_sched_quota(struct mt7615_dev *dev, u32 *data);

static int mt7663s_rx_run_queue(struct mt7615_dev *dev, enum mt76_rxq_id qid,
				int pkt_cnt, u16 *pkt_len);

void mt7663s_sdio_irq(struct sdio_func *func)
{
	struct mt7615_dev *dev = sdio_get_drvdata(func);
	struct mt76_dev *mdev = &dev->mt76;
	struct mt76_sdio *sdio = &dev->mt76.sdio;
	struct mt76s_intr __intr;
	u32 intr;

	/* disable interrupt */
	sdio_writel(func, WHLPCR_INT_EN_CLR, MCR_WHLPCR, 0);

	do {
		sdio_readsb(func, &__intr, MCR_WHISR,
			    sizeof(struct mt76s_intr));

		intr = __intr.whisr;
		trace_dev_irq(mdev, intr, 0);

		if (!test_bit(MT76_STATE_INITIALIZED, &mdev->phy.state))
			goto out;

		if (intr & WHIER_RX0_DONE_INT_EN) {
			mt7663s_rx_run_queue(dev, 0,
					     __intr.pkt_num[0],
					     __intr.pkt_len[0]);
			wake_up_process(sdio->kthread);
		}

		if (intr & WHIER_RX1_DONE_INT_EN) {
			mt7663s_rx_run_queue(dev, 1,
					     __intr.pkt_num[1],
					     __intr.pkt_len[1]);
			wake_up_process(sdio->kthread);
		}

		if (intr & WHIER_TX_DONE_INT_EN) {
			mt7663s_refill_sched_quota(dev, __intr.wtqcr);
			wake_up_process(sdio->kthread);
			wake_up_process(sdio->txrx_kthread);
		}
	} while (intr);
out:
	/* enable interrupt */
	sdio_writel(func, WHLPCR_INT_EN_SET, MCR_WHLPCR, 0);
}

static void mt7663s_refill_sched_quota(struct mt7615_dev *dev, u32 *data)
{
	struct mt76_sdio *sdio = &dev->mt76.sdio;

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

static int mt7663s_rx_run_queue(struct mt7615_dev *dev, enum mt76_rxq_id qid,
				int pkt_cnt, u16 *pkt_len)
{
	struct mt76_queue *q = &dev->mt76.q_rx[qid];
	struct mt76_dev *mdev = &dev->mt76;
	struct mt76_sdio *sdio = &dev->mt76.sdio;
	struct mt76_queue_entry *e;
	int len = 0, err, size, i;
	u8 *pabuf;

	for (i = 0; i < pkt_cnt; i++)
		len += round_up(pkt_len[i] + 4, 4);

	if (!len)
		return 0;

	if (len > sdio->func->cur_blksize)
		len = roundup(len, sdio->func->cur_blksize);

	err = sdio_readsb(sdio->func, mdev->sdio.abuf, MCR_WRDR(qid), len);
	if (err < 0) {
		dev_err(mdev->dev, "sdio read data failed:%d\n", err);
		return err;
	}

	pabuf = mdev->sdio.abuf;

	for (i = 0; i < pkt_cnt; i++) {
		e = &q->entry[q->tail];

		/* Assume that an entry can hold a complete packet from SDIO
		 * port.
		 */
		e->b_info.data_len = pkt_len[i];

		if (WARN_ON_ONCE(pkt_len[i] > q->buf_size)) {
			i = -ENOMEM;
			break;
		}

		size = pkt_len[i] + SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
		size = round_up(size, 4); /* Avoid alignment trap */
		size = min_t(int, size, q->buf_size);

		e->buf = page_frag_alloc(&q->rx_page, size, GFP_KERNEL);
		if (!e->buf) {
			i = -ENOMEM;
			break;
		}
		e->b_info.len = size;

		/* TODO: Turning to zero copying */
		memcpy(e->buf, pabuf, pkt_len[i]);
		pabuf += round_up(pkt_len[i] + 4, 4);

		spin_lock_bh(&q->lock);
		q->tail = (q->tail + 1) % q->ndesc;
		q->queued++;
		spin_unlock_bh(&q->lock);
	}

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
#if 0
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
#endif
		for (i = 0; i < MT_TXQ_MCU_WA; i++) {
			ret = mt7663s_tx_run_queue(dev, dev->mt76.q_tx[i].q);
			if (ret < 0) {
				nframes = 0;
				break;
			}
			nframes += ret;
		}

		if (!nframes || !test_bit(MT76_STATE_RUNNING, &mphy->state)) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
		}
	}

	return 0;
}
