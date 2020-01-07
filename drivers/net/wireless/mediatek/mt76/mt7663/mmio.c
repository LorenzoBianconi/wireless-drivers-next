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

void mt7663_irq_enable(struct mt7663_dev *dev, u32 mask)
{
	mt76_set_irq_mask(&dev->mt76, MT_INT_MASK_CSR, 0, mask);
}

void mt7663_irq_disable(struct mt7663_dev *dev, u32 mask)
{
	mt76_set_irq_mask(&dev->mt76, MT_INT_MASK_CSR, mask, 0);
}

int mt7663_poll_tx(struct napi_struct *napi, int budget)
{
	struct mt7663_dev *dev;
	int i;

	dev = container_of(napi, struct mt7663_dev, mt76.tx_napi);

	for (i = MT_TXQ_MCU; i >= 0; i--)
		mt76_queue_tx_cleanup(dev, i, false);

	if (napi_complete_done(napi, 0))
		mt7663_irq_enable(dev, MT_INT_TX_DONE_ALL);

	for (i = MT_TXQ_MCU; i >= 0; i--)
		mt76_queue_tx_cleanup(dev, i, false);

	tasklet_schedule(&dev->mt76.tx_tasklet);

	return 0;
}

static int mt7663_start(struct ieee80211_hw *hw)
{
	struct mt7663_dev *dev = hw->priv;

	dev->mphy.survey_time = ktime_get_boottime();
	set_bit(MT76_STATE_RUNNING, &dev->mphy.state);
	ieee80211_queue_delayed_work(mt76_hw(dev), &dev->mt76.mac_work,
				     MT7663_WATCHDOG_TIME);

	return 0;
}

static void mt7663_stop(struct ieee80211_hw *hw)
{
	struct mt7663_dev *dev = hw->priv;

	clear_bit(MT76_STATE_RUNNING, &dev->mphy.state);
	cancel_delayed_work_sync(&dev->mt76.mac_work);
}

static void
mt7663_sta_rate_tbl_update(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			   struct ieee80211_sta *sta)
{
	struct mt7663_dev *dev = hw->priv;
	struct mt7663_sta *msta = (struct mt7663_sta *)sta->drv_priv;
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
	mt7663_mac_set_rates(dev, msta, NULL, msta->rates);
	msta->rate_probe = false;
	spin_unlock_bh(&dev->mt76.lock);
}

irqreturn_t mt7663_irq_handler(int irq, void *dev_instance)
{
	struct mt7663_dev *dev = dev_instance;
	u32 intr;

	intr = mt76_rr(dev, MT_INT_SOURCE_CSR);
	mt76_wr(dev, MT_INT_SOURCE_CSR, intr);

	if (!test_bit(MT76_STATE_INITIALIZED, &dev->mphy.state))
		return IRQ_NONE;

	intr &= dev->mt76.mmio.irqmask;

	if (intr & MT_INT_TX_DONE_ALL) {
		mt7663_irq_disable(dev, MT_INT_TX_DONE_ALL);
		napi_schedule(&dev->mt76.tx_napi);
	}

	if (intr & MT_INT_RX_DONE(0)) {
		mt7663_irq_disable(dev, MT_INT_RX_DONE(0));
		napi_schedule(&dev->mt76.napi[0]);
	}

	if (intr & MT_INT_RX_DONE(1)) {
		mt7663_irq_disable(dev, MT_INT_RX_DONE(1));
		napi_schedule(&dev->mt76.napi[1]);
	}

	return IRQ_HANDLED;
}

void mt7663_rx_poll_complete(struct mt76_dev *mdev, enum mt76_rxq_id q)
{
	struct mt7663_dev *dev = container_of(mdev, struct mt7663_dev, mt76);

	mt7663_irq_enable(dev, MT_INT_RX_DONE(q));
}

static int
mt7663_set_key(struct ieee80211_hw *hw, enum set_key_cmd cmd,
	       struct ieee80211_vif *vif, struct ieee80211_sta *sta,
	       struct ieee80211_key_conf *key)
{
	struct mt7663_vif *mvif = (struct mt7663_vif *)vif->drv_priv;
	struct mt7663_dev *dev = hw->priv;
	struct mt7663_sta *msta;
	int err;

	msta = sta ? (struct mt7663_sta *)sta->drv_priv : &mvif->sta;
	err = mt7663_check_key(dev, cmd, vif, &msta->wcid, key);
	if (err < 0)
		return err;

	return mt7663_mac_wtbl_set_key(dev, &msta->wcid, key, cmd);
}

static void
mt7663_configure_filter(struct ieee80211_hw *hw,
			unsigned int changed_flags,
			unsigned int *total_flags,
			u64 multicast)
{
	struct mt7663_dev *dev = hw->priv;
	u32 flags = 0;

#define MT76_FILTER(_flag, _hw) do { \
		flags |= *total_flags & FIF_##_flag;			\
		dev->mt76.rxfilter &= ~(_hw);				\
		dev->mt76.rxfilter |= !(flags & FIF_##_flag) * (_hw);	\
	} while (0)

	dev->mt76.rxfilter &= ~(MT_WF_RFCR_DROP_OTHER_BSS |
				MT_WF_RFCR_DROP_OTHER_BEACON |
				MT_WF_RFCR_DROP_FRAME_REPORT |
				MT_WF_RFCR_DROP_PROBEREQ |
				MT_WF_RFCR_DROP_MCAST_FILTERED |
				MT_WF_RFCR_DROP_MCAST |
				MT_WF_RFCR_DROP_BCAST |
				MT_WF_RFCR_DROP_DUPLICATE |
				MT_WF_RFCR_DROP_A2_BSSID |
				MT_WF_RFCR_DROP_UNWANTED_CTL |
				MT_WF_RFCR_DROP_STBC_MULTI);

	MT76_FILTER(OTHER_BSS, MT_WF_RFCR_DROP_OTHER_TIM |
			       MT_WF_RFCR_DROP_A3_MAC |
			       MT_WF_RFCR_DROP_A3_BSSID);

	MT76_FILTER(FCSFAIL, MT_WF_RFCR_DROP_FCSFAIL);

	MT76_FILTER(CONTROL, MT_WF_RFCR_DROP_CTS |
			     MT_WF_RFCR_DROP_RTS |
			     MT_WF_RFCR_DROP_CTL_RSV |
			     MT_WF_RFCR_DROP_NDPA);

	*total_flags = flags;
	mt76_wr(dev, MT_WF_RFCR, dev->mt76.rxfilter);
}

static int mt7663_set_channel(struct mt7663_dev *dev)
{
	int ret;

	cancel_delayed_work_sync(&dev->mt76.mac_work);

	mutex_lock(&dev->mt76.mutex);
	set_bit(MT76_RESET, &dev->mphy.state);

	mt7663_dfs_check_channel(dev);

	mt76_set_channel(&dev->mphy);

	ret = mt7663_mcu_set_channel(dev);
	if (ret)
		goto out;

	ret = mt7663_dfs_init_radar_detector(dev);
	mt7663_mac_cca_stats_reset(dev);
	dev->mphy.survey_time = ktime_get_boottime();
	mt76_rr(dev, MT_MIB_SDR16(0));

out:
	clear_bit(MT76_RESET, &dev->mphy.state);
	mutex_unlock(&dev->mt76.mutex);

	mt76_txq_schedule_all(&dev->mphy);
	ieee80211_queue_delayed_work(mt76_hw(dev), &dev->mt76.mac_work,
				     MT7663_WATCHDOG_TIME);
	return ret;
}

static int
mt7663_config(struct ieee80211_hw *hw, u32 changed)
{
	struct mt7663_dev *dev = hw->priv;
	int ret = 0;

	if (changed & IEEE80211_CONF_CHANGE_CHANNEL) {
		ieee80211_stop_queues(hw);
		ret = mt7663_set_channel(dev);
		ieee80211_wake_queues(hw);
	}

	mutex_lock(&dev->mt76.mutex);
#if 0 /* MT7663 : TBD */
	if (changed & IEEE80211_CONF_CHANGE_POWER)
		ret = mt7663_mcu_set_tx_power(dev);
#endif

	if (changed & IEEE80211_CONF_CHANGE_MONITOR) {
		if (!(hw->conf.flags & IEEE80211_CONF_MONITOR))
			dev->mt76.rxfilter |= MT_WF_RFCR_DROP_OTHER_UC;
		else
			dev->mt76.rxfilter &= ~MT_WF_RFCR_DROP_OTHER_UC;

		mt76_wr(dev, MT_WF_RFCR, dev->mt76.rxfilter);
	}

	mutex_unlock(&dev->mt76.mutex);

	return ret;
}

const struct ieee80211_ops mt7663_mmio_ops = {
	.tx = mt7663_tx,
	.start = mt7663_start,
	.stop = mt7663_stop,
	.add_interface = mt7663_add_interface,
	.remove_interface = mt7663_remove_interface,
	.config = mt7663_config,
	.conf_tx = mt7663_conf_tx,
	.configure_filter = mt7663_configure_filter,
	.bss_info_changed = mt7663_bss_info_changed,
	.sta_state = mt76_sta_state,
	.set_key = mt7663_set_key,
	.ampdu_action = mt7663_ampdu_action,
	.set_rts_threshold = mt7663_set_rts_threshold,
	.wake_tx_queue = mt76_wake_tx_queue,
	.sta_rate_tbl_update = mt7663_sta_rate_tbl_update,
	.sw_scan_start = mt76_sw_scan,
	.sw_scan_complete = mt76_sw_scan_complete,
	.release_buffered_frames = mt76_release_buffered_frames,
	.get_txpower = mt76_get_txpower,
	.get_survey = mt76_get_survey,
};
