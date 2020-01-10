// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Felix Fietkau <nbd@nbd.name>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "mt7663.h"
#include "mt7615.h"
#include "usb_sdio_regs.h"

static int mt7663u_start(struct ieee80211_hw *hw)
{
	struct mt7615_dev *dev = hw->priv;

	dev->mphy.survey_time = ktime_get_boottime();
	set_bit(MT76_STATE_RUNNING, &dev->mphy.state);
	ieee80211_queue_delayed_work(mt76_hw(dev), &dev->mt76.mac_work,
				     MT7663_WATCHDOG_TIME);

	return 0;
}

static void mt7663u_stop(struct ieee80211_hw *hw)
{
	struct mt7615_dev *dev = hw->priv;

	clear_bit(MT76_STATE_RUNNING, &dev->mphy.state);
	mt76u_stop_tx(&dev->mt76);
	cancel_delayed_work_sync(&dev->mt76.mac_work);
}

static void
mt7663u_sta_rate_tbl_update(struct ieee80211_hw *hw,
			    struct ieee80211_vif *vif,
			    struct ieee80211_sta *sta)
{
	struct mt7615_dev *dev = hw->priv;
	struct mt7615_sta *msta = (struct mt7615_sta *)sta->drv_priv;
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
	mt7663u_mac_set_rates(dev, msta, NULL, msta->rates);
	msta->rate_probe = false;
	spin_unlock_bh(&dev->mt76.lock);
}

void mt7663u_rc_work(struct work_struct *work)
{
	struct mt7615_dev *dev;
	struct mt7663_rate_desc *rc, *tmp_rc;
	int err;

	dev = (struct mt7615_dev *)container_of(work, struct mt7615_dev,
						rate_work);

	list_for_each_entry_safe(rc, tmp_rc, &dev->rd_head, node) {
		spin_lock_bh(&dev->mt76.lock);
		list_del(&rc->node);
		spin_unlock_bh(&dev->mt76.lock);

		err = __mt7663u_mac_set_rates(dev, rc);
		if (err)
			dev_err(dev->mt76.dev, "something wrong in setting rate\n");

		kfree(rc);
	}
}

static int mt7663u_set_channel(struct mt7615_dev *dev)
{
	int ret;

	cancel_delayed_work_sync(&dev->mt76.mac_work);

	mutex_lock(&dev->mt76.mutex);
	set_bit(MT76_RESET, &dev->mphy.state);

	mt76_set_channel(&dev->mphy);

	ret = mt7663_mcu_set_channel(dev);
	if (ret)
		goto out;

	ret = mt7663_dfs_init_radar_detector(dev);

	mt7663u_mac_cca_stats_reset(dev);
	dev->mphy.survey_time = ktime_get_boottime();
	/* TODO: add DBDC support */
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
mt7663u_config(struct ieee80211_hw *hw, u32 changed)
{
	struct mt7615_dev *dev = hw->priv;
	int ret = 0;

	if (changed & IEEE80211_CONF_CHANGE_CHANNEL) {
		ieee80211_stop_queues(hw);
		ret = mt7663u_set_channel(dev);
		ieee80211_wake_queues(hw);
	}

	mutex_lock(&dev->mt76.mutex);

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

static void
mt7663u_configure_filter(struct ieee80211_hw *hw,
			 unsigned int changed_flags,
			 unsigned int *total_flags, u64 multicast)
{
	struct mt7615_dev *dev = hw->priv;
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

static int
mt7663u_set_key(struct ieee80211_hw *hw, enum set_key_cmd cmd,
		struct ieee80211_vif *vif, struct ieee80211_sta *sta,
		struct ieee80211_key_conf *key)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct mt7615_dev *dev = hw->priv;
	struct mt7615_sta *msta;
	int err;

	msta = sta ? (struct mt7615_sta *)sta->drv_priv : &mvif->sta;
	err = mt7663_check_key(dev, cmd, vif, &msta->wcid, key);
	if (err < 0)
		return err;

	return mt7663u_mac_wtbl_set_key(dev, &msta->wcid, key, cmd);
}

const struct ieee80211_ops mt7663_usb_ops = {
	.tx = mt7663_tx,
	.start = mt7663u_start,
	.stop = mt7663u_stop,
	.add_interface = mt7663_add_interface,
	.remove_interface = mt7663_remove_interface,
	.config = mt7663u_config,
	.conf_tx = mt7663_conf_tx,
	.configure_filter = mt7663u_configure_filter,
	.bss_info_changed = mt7663_bss_info_changed,
	.sta_state = mt76_sta_state,
	.set_key = mt7663u_set_key,
	.ampdu_action = mt7663_ampdu_action,
	.set_rts_threshold = mt7663_set_rts_threshold,
	.wake_tx_queue = mt76_wake_tx_queue,
	.sta_rate_tbl_update = mt7663u_sta_rate_tbl_update,
	.sw_scan_start = mt76_sw_scan,
	.sw_scan_complete = mt76_sw_scan_complete,
	.release_buffered_frames = mt76_release_buffered_frames,
	.get_txpower = mt76_get_txpower,
	.get_survey = mt76_get_survey,
};
