// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 *         Felix Fietkau <nbd@nbd.name>
 *	   Sean Wang <sean.wang@mediatek.com>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pci.h>

#include "mt7663.h"
#include "mac.h"
#include "regs.h"
#include "../dma.h"

void connac_irq_enable(struct connac_dev *dev, u32 mask)
{
	mt76_set_irq_mask(&dev->mt76, MT_INT_MASK_CSR, 0, mask);
}

void connac_irq_disable(struct connac_dev *dev, u32 mask)
{
	mt76_set_irq_mask(&dev->mt76, MT_INT_MASK_CSR, mask, 0);
}

int connac_poll_tx(struct napi_struct *napi, int budget)
{
	struct connac_dev *dev;
	int i;

	dev = container_of(napi, struct connac_dev, mt76.tx_napi);

	for (i = MT_TXQ_MCU; i >= 0; i--)
		mt76_queue_tx_cleanup(dev, i, false);

	if (napi_complete_done(napi, 0))
		connac_irq_enable(dev, MT_INT_TX_DONE_ALL);

	for (i = MT_TXQ_MCU; i >= 0; i--)
		mt76_queue_tx_cleanup(dev, i, false);

	tasklet_schedule(&dev->mt76.tx_tasklet);

	return 0;
}

static int connac_mmio_start(struct ieee80211_hw *hw)
{
	struct connac_dev *dev = hw->priv;

	dev->mphy.survey_time = ktime_get_boottime();
	set_bit(MT76_STATE_RUNNING, &dev->mphy.state);
	ieee80211_queue_delayed_work(mt76_hw(dev), &dev->mt76.mac_work,
				     CONNAC_WATCHDOG_TIME);

	return 0;
}

static void connac_mmio_stop(struct ieee80211_hw *hw)
{
	struct connac_dev *dev = hw->priv;

	clear_bit(MT76_STATE_RUNNING, &dev->mphy.state);
	cancel_delayed_work_sync(&dev->mt76.mac_work);
}

static void
connac_mmio_sta_rate_tbl_update(struct ieee80211_hw *hw,
				struct ieee80211_vif *vif,
				struct ieee80211_sta *sta)
{
	struct connac_dev *dev = hw->priv;
	struct connac_sta *msta = (struct connac_sta *)sta->drv_priv;
	struct ieee80211_sta_rates *sta_rates = rcu_dereference(sta->rates);
	int i;

	spin_lock_bh(&dev->mt76.lock);
	for (i = 0; i < ARRAY_SIZE(msta->rates); i++) {
		msta->rates[i].idx = sta_rates->rate[i].idx;
		msta->rates[i].count = sta_rates->rate[i].count;
		msta->rates[i].flags = sta_rates->rate[i].flags;

		if (msta->rates[i].idx < 0 || !msta->rates[i].count)
			break;
	}
	msta->n_rates = i;
	connac_mac_set_rates(dev, msta, NULL, msta->rates);
	msta->rate_probe = false;
	spin_unlock_bh(&dev->mt76.lock);
}

irqreturn_t connac_irq_handler(int irq, void *dev_instance)
{
	struct connac_dev *dev = dev_instance;
	u32 intr;

	intr = mt76_rr(dev, MT_INT_SOURCE_CSR);
	mt76_wr(dev, MT_INT_SOURCE_CSR, intr);

	if (!test_bit(MT76_STATE_INITIALIZED, &dev->mphy.state))
		return IRQ_NONE;

	intr &= dev->mt76.mmio.irqmask;

	if (intr & MT_INT_TX_DONE_ALL) {
		connac_irq_disable(dev, MT_INT_TX_DONE_ALL);
		napi_schedule(&dev->mt76.tx_napi);
	}

	if (intr & MT_INT_RX_DONE(0)) {
		connac_irq_disable(dev, MT_INT_RX_DONE(0));
		napi_schedule(&dev->mt76.napi[0]);
	}

	if (intr & MT_INT_RX_DONE(1)) {
		connac_irq_disable(dev, MT_INT_RX_DONE(1));
		napi_schedule(&dev->mt76.napi[1]);
	}

	return IRQ_HANDLED;
}

void connac_mmio_rx_poll_complete(struct mt76_dev *mdev,
				  enum mt76_rxq_id q)
{
	struct connac_dev *dev = container_of(mdev, struct connac_dev, mt76);

	connac_irq_enable(dev, MT_INT_RX_DONE(q));
}

static int
connac_set_key(struct ieee80211_hw *hw, enum set_key_cmd cmd,
	       struct ieee80211_vif *vif, struct ieee80211_sta *sta,
	       struct ieee80211_key_conf *key)
{
	struct connac_vif *mvif = (struct connac_vif *)vif->drv_priv;
	struct connac_dev *dev = hw->priv;
	struct connac_sta *msta;
	int err;

	msta = sta ? (struct connac_sta *)sta->drv_priv : &mvif->sta;
	err = connac_check_key(dev, cmd, vif, &msta->wcid, key);
	if (err < 0)
		return err;

	return connac_mac_wtbl_set_key(dev, &msta->wcid, key, cmd);
}

const struct ieee80211_ops connac_mmio_ops = {
	.tx = connac_tx,
	.start = connac_mmio_start,
	.stop = connac_mmio_stop,
	.add_interface = connac_add_interface,
	.remove_interface = connac_remove_interface,
	.config = connac_config,
	.conf_tx = connac_conf_tx,
	.configure_filter = connac_configure_filter,
	.bss_info_changed = connac_bss_info_changed,
	.sta_state = mt76_sta_state,
	.set_key = connac_set_key,
	.ampdu_action = connac_ampdu_action,
	.set_rts_threshold = connac_set_rts_threshold,
	.wake_tx_queue = mt76_wake_tx_queue,
	.sta_rate_tbl_update = connac_mmio_sta_rate_tbl_update,
	.sw_scan_start = mt76_sw_scan,
	.sw_scan_complete = mt76_sw_scan_complete,
	.release_buffered_frames = mt76_release_buffered_frames,
	.get_txpower = mt76_get_txpower,
	.get_survey = mt76_get_survey,
};
