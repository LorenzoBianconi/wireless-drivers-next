// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Roy Luo <royluo@google.com>
 *         Ryder Lee <ryder.lee@mediatek.com>
 *         Felix Fietkau <nbd@nbd.name>
 *	   Chih-Min Chen <chih-min.chen@mediatek.com>
 *	   Sean Wang <sean.wang@mediatek.com> 
 */

#include <linux/etherdevice.h>
#include <linux/platform_device.h>
#include <linux/pci.h>
#include <linux/module.h>
#include "connac.h"

static int connac_start(struct ieee80211_hw *hw)
{
	struct connac_dev *dev = hw->priv;

	dev->mphy.survey_time = ktime_get_boottime();
	set_bit(MT76_STATE_RUNNING, &dev->mphy.state);
	ieee80211_queue_delayed_work(mt76_hw(dev), &dev->mt76.mac_work,
				     CONNAC_WATCHDOG_TIME);

	return 0;
}

static void connac_stop(struct ieee80211_hw *hw)
{
	struct connac_dev *dev = hw->priv;

	clear_bit(MT76_STATE_RUNNING, &dev->mphy.state);
	cancel_delayed_work_sync(&dev->mt76.mac_work);
}

static int get_omac_idx(enum nl80211_iftype type, u32 mask)
{
	int i;

	switch (type) {
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_MESH_POINT:
		/* ap use hw bssid 0 and ext bssid */
		if (~mask & BIT(HW_BSSID_0))
			return HW_BSSID_0;

		for (i = EXT_BSSID_1; i < EXT_BSSID_END; i++)
			if (~mask & BIT(i))
				return i;

		break;
	case NL80211_IFTYPE_STATION:
		/* sta use hw bssid other than 0 */
		for (i = HW_BSSID_1; i < HW_BSSID_MAX; i++)
			if (~mask & BIT(i))
				return i;

		break;
	default:
		WARN_ON(1);
		break;
	};

	return -1;
}

static int connac_add_interface(struct ieee80211_hw *hw,
				struct ieee80211_vif *vif)
{
	struct connac_vif *mvif = (struct connac_vif *)vif->drv_priv;
	struct connac_dev *dev = hw->priv;
	struct mt76_txq *mtxq;
	int idx, ret = 0;

	mutex_lock(&dev->mt76.mutex);

	mvif->idx = ffs(~dev->vif_mask) - 1;
	if (mvif->idx >= CONNAC_MAX_INTERFACES) {
		ret = -ENOSPC;
		goto out;
	}

	idx = get_omac_idx(vif->type, dev->omac_mask);
	if (idx < 0) {
		ret = -ENOSPC;
		goto out;
	}
	mvif->omac_idx = idx;

	/* TODO: DBDC support. Use band 0 for now */
	mvif->band_idx = 0;
	mvif->wmm_idx = mvif->idx % CONNAC_MAX_WMM_SETS;

	ret = connac_mcu_set_dev_info(dev, vif, 1);
	if (ret)
		goto out;

	dev->vif_mask |= BIT(mvif->idx);
	dev->omac_mask |= BIT(mvif->omac_idx);
	idx = CONNAC_WTBL_RESERVED - mvif->idx;
	mvif->sta.wcid.idx = idx;
	mvif->sta.wcid.hw_key_idx = -1;

	rcu_assign_pointer(dev->mt76.wcid[idx], &mvif->sta.wcid);
	mtxq = (struct mt76_txq *)vif->txq->drv_priv;
	mtxq->wcid = &mvif->sta.wcid;
	mt76_txq_init(&dev->mt76, vif->txq);

out:
	mutex_unlock(&dev->mt76.mutex);

	return ret;
}

static void connac_remove_interface(struct ieee80211_hw *hw,
				    struct ieee80211_vif *vif)
{
	struct connac_vif *mvif = (struct connac_vif *)vif->drv_priv;
	struct connac_dev *dev = hw->priv;
	int idx = mvif->sta.wcid.idx;

	/* TODO: disable beacon for the bss */

	connac_mcu_set_dev_info(dev, vif, 0);

	rcu_assign_pointer(dev->mt76.wcid[idx], NULL);
	mt76_txq_remove(&dev->mt76, vif->txq);

	mutex_lock(&dev->mt76.mutex);
	dev->vif_mask &= ~BIT(mvif->idx);
	dev->omac_mask &= ~BIT(mvif->omac_idx);
	mutex_unlock(&dev->mt76.mutex);
}

static int connac_set_channel(struct connac_dev *dev)
{
	int ret;

	cancel_delayed_work_sync(&dev->mt76.mac_work);

	mutex_lock(&dev->mt76.mutex);
	set_bit(MT76_RESET, &dev->mphy.state);

	connac_dfs_check_channel(dev);

	mt76_set_channel(&dev->mphy);

	ret = connac_mcu_set_channel(dev);
	if (ret)
		goto out;

	ret = connac_dfs_init_radar_detector(dev);
	connac_mac_cca_stats_reset(dev);
	dev->mphy.survey_time = ktime_get_boottime();
	/* TODO: add DBDC support */
	mt76_rr(dev, MT_MIB_SDR16(dev, 0));

out:
	clear_bit(MT76_RESET, &dev->mphy.state);
	mutex_unlock(&dev->mt76.mutex);

	mt76_txq_schedule_all(&dev->mphy);
	ieee80211_queue_delayed_work(mt76_hw(dev), &dev->mt76.mac_work,
				     CONNAC_WATCHDOG_TIME);
	return ret;
}

static int connac_set_key(struct ieee80211_hw *hw, enum set_key_cmd cmd,
			  struct ieee80211_vif *vif, struct ieee80211_sta *sta,
			  struct ieee80211_key_conf *key)
{
	struct connac_dev *dev = hw->priv;
	struct connac_vif *mvif = (struct connac_vif *)vif->drv_priv;
	struct connac_sta *msta = sta ? (struct connac_sta *)sta->drv_priv :
				  &mvif->sta;
	struct mt76_wcid *wcid = &msta->wcid;
	int idx = key->keyidx;

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

	return connac_mac_wtbl_set_key(dev, wcid, key, cmd);
}

static int connac_config(struct ieee80211_hw *hw, u32 changed)
{
	struct connac_dev *dev = hw->priv;
	int ret = 0;

	if (changed & IEEE80211_CONF_CHANGE_CHANNEL) {
		ieee80211_stop_queues(hw);
		ret = connac_set_channel(dev);
		ieee80211_wake_queues(hw);
	}

	mutex_lock(&dev->mt76.mutex);
#if 0 /* CONNAC : TBD */
	if (changed & IEEE80211_CONF_CHANGE_POWER)
		ret = connac_mcu_set_tx_power(dev);
#endif

	if (changed & IEEE80211_CONF_CHANGE_MONITOR) {
		if (!(hw->conf.flags & IEEE80211_CONF_MONITOR))
			dev->mt76.rxfilter |= MT_WF_RFCR_DROP_OTHER_UC;
		else
			dev->mt76.rxfilter &= ~MT_WF_RFCR_DROP_OTHER_UC;

		mt76_wr(dev, MT_WF_RFCR(dev), dev->mt76.rxfilter);
	}

	mutex_unlock(&dev->mt76.mutex);

	return ret;
}

static int
connac_conf_tx(struct ieee80211_hw *hw, struct ieee80211_vif *vif, u16 queue,
	       const struct ieee80211_tx_queue_params *params)
{
	static const u8 wmm_queue_map[] = {
		[IEEE80211_AC_BK]/*3*/ = 0,
		[IEEE80211_AC_BE]/*2*/ = 1,
		[IEEE80211_AC_VI]/*1*/ = 2,
		[IEEE80211_AC_VO]/*0*/ = 4,
	};
	struct connac_vif *mvif = (struct connac_vif *)vif->drv_priv;
	struct connac_dev *dev = hw->priv;
	u16 wmm_mapping = mvif->wmm_idx * CONNAC_MAX_WMM_SETS;

	wmm_mapping += wmm_queue_map[queue];
	/* TODO: hw wmm_set 1~3 */
	return connac_mcu_set_wmm(dev, wmm_mapping, params);
}

static void connac_configure_filter(struct ieee80211_hw *hw,
				    unsigned int changed_flags,
				    unsigned int *total_flags,
				    u64 multicast)
{
	struct connac_dev *dev = hw->priv;
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
	mt76_wr(dev, MT_WF_RFCR(dev), dev->mt76.rxfilter);
}

static void connac_bss_info_changed(struct ieee80211_hw *hw,
				    struct ieee80211_vif *vif,
				    struct ieee80211_bss_conf *info,
				    u32 changed)
{
	struct connac_dev *dev = hw->priv;

	mutex_lock(&dev->mt76.mutex);

	if (changed & BSS_CHANGED_ASSOC)
		connac_mcu_set_bss_info(dev, vif, info->assoc);

	/* TODO: update beacon content
	 * BSS_CHANGED_BEACON
	 */

	if (changed & BSS_CHANGED_BEACON_ENABLED) {
		connac_mcu_set_bss_info(dev, vif, info->enable_beacon);
		connac_mcu_wtbl_bmc(dev, vif, info->enable_beacon);
		connac_mcu_set_sta_rec_bmc(dev, vif, info->enable_beacon);
		connac_mcu_set_bcn(dev, vif, info->enable_beacon);
	}

	mutex_unlock(&dev->mt76.mutex);
}

static void
connac_channel_switch_beacon(struct ieee80211_hw *hw,
			     struct ieee80211_vif *vif,
			     struct cfg80211_chan_def *chandef)
{
	struct connac_dev *dev = hw->priv;

	mutex_lock(&dev->mt76.mutex);
	connac_mcu_set_bcn(dev, vif, true);
	mutex_unlock(&dev->mt76.mutex);
}

int connac_sta_add(struct mt76_dev *mdev, struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta)
{
	struct connac_dev *dev = container_of(mdev, struct connac_dev, mt76);
	struct connac_sta *msta = (struct connac_sta *)sta->drv_priv;
	struct connac_vif *mvif = (struct connac_vif *)vif->drv_priv;
	int idx;

	idx = mt76_wcid_alloc(dev->mt76.wcid_mask, CONNAC_WTBL_STA - 1);
	if (idx < 0)
		return -ENOSPC;

	msta->vif = mvif;
	msta->wcid.sta = 1;
	msta->wcid.idx = idx;

	connac_mcu_set_sta_rec(dev, vif, sta, 1);

	return 0;
}

void connac_sta_assoc(struct mt76_dev *mdev, struct ieee80211_vif *vif,
		      struct ieee80211_sta *sta)
{
	struct connac_dev *dev = container_of(mdev, struct connac_dev, mt76);

	connac_mcu_set_sta_rec(dev, vif, sta, 1);
}

void connac_sta_remove(struct mt76_dev *mdev, struct ieee80211_vif *vif,
		       struct ieee80211_sta *sta)
{
	struct connac_dev *dev = container_of(mdev, struct connac_dev, mt76);

	connac_mcu_set_sta_rec(dev, vif, sta, 0);
}

static void connac_sta_rate_tbl_update(struct ieee80211_hw *hw,
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
	if (dev->flag & CONNAC_USB)
		connac_usb_mac_set_rates(dev, msta, NULL, msta->rates);
	else
		connac_mac_set_rates(dev, msta, NULL, msta->rates);
	msta->rate_probe = false;
	spin_unlock_bh(&dev->mt76.lock);
}

static void
connac_altx(struct mt76_dev *dev, struct ieee80211_sta *sta,
	    struct mt76_wcid *wcid, struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct mt76_queue *q;

	if (!(wcid->tx_info & MT_WCID_TX_INFO_SET))
		ieee80211_get_tx_rates(info->control.vif, sta, skb,
				       info->control.rates, 1);

	q = dev->q_tx[MT_TXQ_PSD].q;

	spin_lock_bh(&q->lock);
	dev->queue_ops->tx_queue_skb(dev, MT_TXQ_PSD, skb, wcid, sta);
	dev->queue_ops->kick(dev, q);

	if (q->queued > q->ndesc - 8 && !q->stopped) {
		ieee80211_stop_queue(dev->hw, skb_get_queue_mapping(skb));
		q->stopped = true;
	}

	spin_unlock_bh(&q->lock);
}

static void connac_tx(struct ieee80211_hw *hw,
		      struct ieee80211_tx_control *control,
		      struct sk_buff *skb)
{
	struct connac_dev *dev = hw->priv;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_vif *vif = info->control.vif;
	struct mt76_wcid *wcid = &dev->mt76.global_wcid;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;

	if (control->sta) {
		struct connac_sta *sta;

		sta = (struct connac_sta *)control->sta->drv_priv;
		wcid = &sta->wcid;
	}

	if (vif && !control->sta && ieee80211_is_data_qos(hdr->frame_control)) {
		struct connac_vif *mvif;

		mvif = (struct connac_vif *)vif->drv_priv;
		wcid = &mvif->sta.wcid;
	}

	if (wcid->idx != dev->mt76.global_wcid.idx)
		mt76_tx(&dev->mphy, control->sta, wcid, skb);
	else
		connac_altx(&dev->mt76, control->sta, wcid, skb);
}

static int connac_set_rts_threshold(struct ieee80211_hw *hw, u32 val)
{
	struct connac_dev *dev = hw->priv;

	mutex_lock(&dev->mt76.mutex);
	connac_mcu_set_rts_thresh(dev, val);
	mutex_unlock(&dev->mt76.mutex);

	return 0;
}

static int
connac_ampdu_action(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		    struct ieee80211_ampdu_params *params)
{
	enum ieee80211_ampdu_mlme_action action = params->action;
	struct connac_dev *dev = hw->priv;
	struct ieee80211_sta *sta = params->sta;
	struct ieee80211_txq *txq = sta->txq[params->tid];
	struct connac_sta *msta = (struct connac_sta *)sta->drv_priv;
	u16 tid = params->tid;
	u16 ssn = params->ssn;
	struct mt76_txq *mtxq;

	if (!txq)
		return -EINVAL;

	mtxq = (struct mt76_txq *)txq->drv_priv;

	switch (action) {
	case IEEE80211_AMPDU_RX_START:
		mt76_rx_aggr_start(&dev->mt76, &msta->wcid, tid, ssn,
				   params->buf_size);
		connac_mcu_set_rx_ba(dev, params, 1);
		break;
	case IEEE80211_AMPDU_RX_STOP:
		mt76_rx_aggr_stop(&dev->mt76, &msta->wcid, tid);
		connac_mcu_set_rx_ba(dev, params, 0);
		break;
	case IEEE80211_AMPDU_TX_OPERATIONAL:
		mtxq->aggr = true;
		mtxq->send_bar = false;
		connac_mcu_set_tx_ba(dev, params, 1);
		break;
	case IEEE80211_AMPDU_TX_STOP_FLUSH:
	case IEEE80211_AMPDU_TX_STOP_FLUSH_CONT:
		mtxq->aggr = false;
		connac_mcu_set_tx_ba(dev, params, 0);
		break;
	case IEEE80211_AMPDU_TX_START:
		mtxq->agg_ssn = IEEE80211_SN_TO_SEQ(ssn);
		ieee80211_start_tx_ba_cb_irqsafe(vif, sta->addr, tid);
		break;
	case IEEE80211_AMPDU_TX_STOP_CONT:
		mtxq->aggr = false;
		connac_mcu_set_tx_ba(dev, params, 0);
		ieee80211_stop_tx_ba_cb_irqsafe(vif, sta->addr, tid);
		break;
	}

	return 0;
}

const struct ieee80211_ops connac_ops = {
	.tx = connac_tx,
	.start = connac_start,
	.stop = connac_stop,
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
	.sta_rate_tbl_update = connac_sta_rate_tbl_update,
	.sw_scan_start = mt76_sw_scan,
	.sw_scan_complete = mt76_sw_scan_complete,
	.release_buffered_frames = mt76_release_buffered_frames,
	.get_txpower = mt76_get_txpower,
	.channel_switch_beacon = connac_channel_switch_beacon,
	.get_survey = mt76_get_survey,
};
