// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Felix Fietkau <nbd@nbd.name>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "mt7615.h"
#include "usb_sdio_regs.h"

static int mt7663u_start(struct ieee80211_hw *hw)
{
	struct mt7615_dev *dev = hw->priv;

	dev->mphy.survey_time = ktime_get_boottime();
	set_bit(MT76_STATE_RUNNING, &dev->mphy.state);
	ieee80211_queue_delayed_work(mt76_hw(dev), &dev->mt76.mac_work,
				     MT7615_WATCHDOG_TIME);

	return 0;
}

static void mt7663u_stop(struct ieee80211_hw *hw)
{
	struct mt7615_dev *dev = hw->priv;

	clear_bit(MT76_STATE_RUNNING, &dev->mphy.state);
	mt76u_stop_tx(&dev->mt76);
	cancel_delayed_work_sync(&dev->mt76.mac_work);
}

static int
mt7663u_add_interface(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct mt7615_dev *dev = mt7615_hw_dev(hw);
	int idx;

	mutex_lock(&dev->mt76.mutex);

	idx = mt7615_setup_interface(hw, vif);
	if (idx < 0)
		goto out;

	mt7615_mac_wtbl_update(dev, idx,
			       MT_WTBL_UPDATE_ADM_COUNT_CLEAR);
out:
	mutex_unlock(&dev->mt76.mutex);

	return 0;
}

int mt7663u_sta_add(struct mt76_dev *mdev, struct ieee80211_vif *vif,
		    struct ieee80211_sta *sta)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	struct mt7615_sta *msta = (struct mt7615_sta *)sta->drv_priv;
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	int idx;

	idx = mt76_wcid_alloc(dev->mt76.wcid_mask, MT7615_WTBL_STA - 1);
	if (idx < 0)
		return -ENOSPC;

	INIT_LIST_HEAD(&msta->poll_list);
	msta->vif = mvif;
	msta->wcid.sta = 1;
	msta->wcid.idx = idx;
	mt7615_mac_wtbl_update(dev, idx,
			       MT_WTBL_UPDATE_ADM_COUNT_CLEAR);

	mt7663_mcu_set_sta_rec(dev, vif, sta, 1);

	return 0;
}

void mt7663u_sta_remove(struct mt76_dev *mdev, struct ieee80211_vif *vif,
			struct ieee80211_sta *sta)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	struct mt7615_sta *msta = (struct mt7615_sta *)sta->drv_priv;

	mt7663_mcu_set_sta_rec(dev, vif, sta, 0);

	mt7615_mac_wtbl_update(dev, msta->wcid.idx,
			       MT_WTBL_UPDATE_ADM_COUNT_CLEAR);

	spin_lock_bh(&dev->sta_poll_lock);
	if (!list_empty(&msta->poll_list))
		list_del_init(&msta->poll_list);
	spin_unlock_bh(&dev->sta_poll_lock);
}

void mt7663u_sta_assoc(struct mt76_dev *mdev, struct ieee80211_vif *vif,
		       struct ieee80211_sta *sta)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);

	mt7663_mcu_set_sta_rec(dev, vif, sta, 1);
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
	mt7615_mac_set_rates(&dev->phy, msta, NULL, msta->rates);
	msta->rate_probe = false;
	spin_unlock_bh(&dev->mt76.lock);
}

void mt7663u_rate_work(struct work_struct *work)
{
	struct mt7615_rate_desc *rd, *rd_next;
	struct mt7615_dev *dev;

	dev = (struct mt7615_dev *)container_of(work, struct mt7615_dev,
						rate_work);

	list_for_each_entry_safe(rd, rd_next, &dev->rd_head, node) {
		spin_lock_bh(&dev->mt76.lock);
		list_del(&rd->node);
		spin_unlock_bh(&dev->mt76.lock);

		__mt7663u_mac_set_rates(dev, rd);
		kfree(rd);
	}
}

static int mt7663u_set_channel(struct mt7615_dev *dev)
{
	struct mt7615_phy *phy = &dev->phy;
	int ret;

	cancel_delayed_work_sync(&dev->mt76.mac_work);

	mutex_lock(&dev->mt76.mutex);
	set_bit(MT76_RESET, &dev->mphy.state);

	phy->chfreq_seq = (phy->chfreq_seq + 1) & MT_CHFREQ_SEQ;
	phy->dfs_state = -1;
	mt76_set_channel(&dev->mphy);

	ret = mt7663_mcu_set_channel(dev);
	if (ret)
		goto out;

	mt76_wr(dev, MT_CHFREQ(0), MT_CHFREQ_VALID | phy->chfreq_seq);
	ret = mt7615_dfs_init_radar_detector(&dev->phy);

	mt7663u_mac_cca_stats_reset(dev);
	dev->mphy.survey_time = ktime_get_boottime();
	/* TODO: add DBDC support */
	mt76_rr(dev, MT_MIB_SDR16(0));

out:
	clear_bit(MT76_RESET, &dev->mphy.state);
	mutex_unlock(&dev->mt76.mutex);

	mt76_txq_schedule_all(&dev->mphy);
	ieee80211_queue_delayed_work(mt76_hw(dev), &dev->mt76.mac_work,
				     MT7615_WATCHDOG_TIME);
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
	struct mt76_wcid *wcid;
	int idx = key->keyidx;

	msta = sta ? (struct mt7615_sta *)sta->drv_priv : &mvif->sta;
	wcid = &msta->wcid;

	/* The hardware does not support per-STA RX GTK, fallback
	 * to software mode for these.
	 */
	if ((vif->type == NL80211_IFTYPE_ADHOC ||
	     vif->type == NL80211_IFTYPE_MESH_POINT) &&
	    (key->cipher == WLAN_CIPHER_SUITE_TKIP ||
	     key->cipher == WLAN_CIPHER_SUITE_CCMP) &&
	    !(key->flags & IEEE80211_KEY_FLAG_PAIRWISE))
		return -EOPNOTSUPP;

	/* fall back to sw encryption for unsupported ciphers */
	switch (key->cipher) {
	case WLAN_CIPHER_SUITE_AES_CMAC:
		key->flags |= IEEE80211_KEY_FLAG_GENERATE_MMIE;
		break;
	case WLAN_CIPHER_SUITE_WEP40:
	case WLAN_CIPHER_SUITE_WEP104:
	case WLAN_CIPHER_SUITE_TKIP:
	case WLAN_CIPHER_SUITE_CCMP:
	case WLAN_CIPHER_SUITE_CCMP_256:
	case WLAN_CIPHER_SUITE_GCMP:
	case WLAN_CIPHER_SUITE_GCMP_256:
	case WLAN_CIPHER_SUITE_SMS4:
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (cmd == SET_KEY) {
		key->hw_key_idx = wcid->idx;
		wcid->hw_key_idx = idx;
	} else if (idx == wcid->hw_key_idx) {
		wcid->hw_key_idx = -1;
	}
	mt76_wcid_key_setup(&dev->mt76, wcid,
			    cmd == SET_KEY ? key : NULL);

	return mt7663u_mac_wtbl_set_key(dev, &msta->wcid, key, cmd);
}

static void
mt7663u_bss_info_changed(struct ieee80211_hw *hw,
			 struct ieee80211_vif *vif,
			 struct ieee80211_bss_conf *info,
			 u32 changed)
{
	struct mt7615_dev *dev = hw->priv;

	mutex_lock(&dev->mt76.mutex);

	if (changed & BSS_CHANGED_ASSOC)
		mt7615_mcu_set_bss_info(dev, vif, info->assoc);

	/* TODO: update beacon content
	 * BSS_CHANGED_BEACON
	 */

	if (changed & BSS_CHANGED_BEACON_ENABLED) {
		mt7615_mcu_set_bss_info(dev, vif, info->enable_beacon);
		mt7615_mcu_wtbl_bmc(dev, vif, info->enable_beacon);
		mt7663_mcu_set_sta_rec_bmc(dev, vif, info->enable_beacon);
	}

	mutex_unlock(&dev->mt76.mutex);
}

const struct ieee80211_ops mt7663_usb_ops = {
	.tx = mt7615_tx,
	.start = mt7663u_start,
	.stop = mt7663u_stop,
	.add_interface = mt7663u_add_interface,
	.remove_interface = mt7615_remove_interface,
	.config = mt7663u_config,
	.conf_tx = mt7615_conf_tx,
	.configure_filter = mt7663u_configure_filter,
	.bss_info_changed = mt7663u_bss_info_changed,
	.sta_state = mt76_sta_state,
	.set_key = mt7663u_set_key,
	.ampdu_action = mt7615_ampdu_action,
	.set_rts_threshold = mt7615_set_rts_threshold,
	.wake_tx_queue = mt76_wake_tx_queue,
	.sta_rate_tbl_update = mt7663u_sta_rate_tbl_update,
	.sw_scan_start = mt76_sw_scan,
	.sw_scan_complete = mt76_sw_scan_complete,
	.release_buffered_frames = mt76_release_buffered_frames,
	.get_txpower = mt76_get_txpower,
	.get_survey = mt76_get_survey,
};
