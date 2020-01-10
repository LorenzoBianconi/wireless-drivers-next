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

#include "mt7663.h"
#include "mt7615.h"
#include "regs.h"

int mt7663_check_key(struct mt7615_dev *dev, enum set_key_cmd cmd,
		     struct ieee80211_vif *vif, struct mt76_wcid *wcid,
		     struct ieee80211_key_conf *key)
{
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

	return 0;
}
EXPORT_SYMBOL_GPL(mt7663_check_key);

int mt7663_conf_tx(struct ieee80211_hw *hw,
		   struct ieee80211_vif *vif, u16 queue,
		   const struct ieee80211_tx_queue_params *params)
{
	static const u8 wmm_queue_map[] = {
		[IEEE80211_AC_BK]/*3*/ = 0,
		[IEEE80211_AC_BE]/*2*/ = 1,
		[IEEE80211_AC_VI]/*1*/ = 2,
		[IEEE80211_AC_VO]/*0*/ = 4,
	};
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct mt7615_dev *dev = hw->priv;
	u16 wmm_mapping = mvif->wmm_idx * MT7663_MAX_WMM_SETS;

	wmm_mapping += wmm_queue_map[queue];
	/* TODO: hw wmm_set 1~3 */
	return mt7663_mcu_set_wmm(dev, wmm_mapping, params);
}
EXPORT_SYMBOL_GPL(mt7663_conf_tx);

void mt7663_bss_info_changed(struct ieee80211_hw *hw,
			     struct ieee80211_vif *vif,
			     struct ieee80211_bss_conf *info,
			     u32 changed)
{
	struct mt7615_dev *dev = hw->priv;

	mutex_lock(&dev->mt76.mutex);

	if (changed & BSS_CHANGED_ASSOC)
		mt7663_mcu_set_bss_info(dev, vif, info->assoc);

	/* TODO: update beacon content
	 * BSS_CHANGED_BEACON
	 */

	if (changed & BSS_CHANGED_BEACON_ENABLED) {
		mt7663_mcu_set_bss_info(dev, vif, info->enable_beacon);
		mt7663_mcu_wtbl_bmc(dev, vif, info->enable_beacon);
		mt7663_mcu_set_sta_rec_bmc(dev, vif, info->enable_beacon);
		mt7663_mcu_set_bcn(dev, vif, info->enable_beacon);
	}

	mutex_unlock(&dev->mt76.mutex);
}
EXPORT_SYMBOL_GPL(mt7663_bss_info_changed);

int mt7615_sta_add(struct mt76_dev *mdev, struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	struct mt7615_sta *msta = (struct mt7615_sta *)sta->drv_priv;
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	int idx;

	idx = mt76_wcid_alloc(dev->mt76.wcid_mask, MT7663_WTBL_STA - 1);
	if (idx < 0)
		return -ENOSPC;

	msta->vif = mvif;
	msta->wcid.sta = 1;
	msta->wcid.idx = idx;

	mt7663_mcu_set_sta_rec(dev, vif, sta, 1);

	return 0;
}
EXPORT_SYMBOL_GPL(mt7615_sta_add);

void mt7615_sta_assoc(struct mt76_dev *mdev, struct ieee80211_vif *vif,
		      struct ieee80211_sta *sta)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);

	mt7663_mcu_set_sta_rec(dev, vif, sta, 1);
}
EXPORT_SYMBOL_GPL(mt7615_sta_assoc);

void mt7615_sta_remove(struct mt76_dev *mdev, struct ieee80211_vif *vif,
		       struct ieee80211_sta *sta)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);

	mt7663_mcu_set_sta_rec(dev, vif, sta, 0);
}
EXPORT_SYMBOL_GPL(mt7615_sta_remove);

void mt7663_tx(struct ieee80211_hw *hw,
	       struct ieee80211_tx_control *control,
	       struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_vif *vif = info->control.vif;
	struct mt76_phy *mphy = hw->priv;
	struct mt76_wcid *wcid;
	struct mt7615_dev *dev;

	dev = container_of(mphy->dev, struct mt7615_dev, mt76);
	wcid = &dev->mt76.global_wcid;

	if (control->sta) {
		struct mt7615_sta *sta;

		sta = (struct mt7615_sta *)control->sta->drv_priv;
		wcid = &sta->wcid;
	}

	if (vif && !control->sta) {
		struct mt7615_vif *mvif;

		mvif = (struct mt7615_vif *)vif->drv_priv;
		wcid = &mvif->sta.wcid;
	}

	mt76_tx(mphy, control->sta, wcid, skb);
}
EXPORT_SYMBOL_GPL(mt7663_tx);

int mt7663_set_rts_threshold(struct ieee80211_hw *hw, u32 val)
{
	struct mt7615_dev *dev = hw->priv;

	mutex_lock(&dev->mt76.mutex);
	mt7663_mcu_set_rts_thresh(dev, val);
	mutex_unlock(&dev->mt76.mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(mt7663_set_rts_threshold);

int mt7663_ampdu_action(struct ieee80211_hw *hw,
			struct ieee80211_vif *vif,
			struct ieee80211_ampdu_params *params)
{
	enum ieee80211_ampdu_mlme_action action = params->action;
	struct mt7615_dev *dev = hw->priv;
	struct ieee80211_sta *sta = params->sta;
	struct ieee80211_txq *txq = sta->txq[params->tid];
	struct mt7615_sta *msta = (struct mt7615_sta *)sta->drv_priv;
	u16 tid = params->tid;
	u16 ssn = params->ssn;
	struct mt76_txq *mtxq;

	if (!txq)
		return -EINVAL;

	mtxq = (struct mt76_txq *)txq->drv_priv;

	mutex_lock(&dev->mt76.mutex);
	switch (action) {
	case IEEE80211_AMPDU_RX_START:
		mt76_rx_aggr_start(&dev->mt76, &msta->wcid, tid, ssn,
				   params->buf_size);
		mt7663_mcu_set_rx_ba(dev, params, 1);
		break;
	case IEEE80211_AMPDU_RX_STOP:
		mt76_rx_aggr_stop(&dev->mt76, &msta->wcid, tid);
		mt7663_mcu_set_rx_ba(dev, params, 0);
		break;
	case IEEE80211_AMPDU_TX_OPERATIONAL:
		mtxq->aggr = true;
		mtxq->send_bar = false;
		mt7663_mcu_set_tx_ba(dev, params, 1);
		break;
	case IEEE80211_AMPDU_TX_STOP_FLUSH:
	case IEEE80211_AMPDU_TX_STOP_FLUSH_CONT:
		mtxq->aggr = false;
		mt7663_mcu_set_tx_ba(dev, params, 0);
		break;
	case IEEE80211_AMPDU_TX_START:
		mtxq->agg_ssn = IEEE80211_SN_TO_SEQ(ssn);
		ieee80211_start_tx_ba_cb_irqsafe(vif, sta->addr, tid);
		break;
	case IEEE80211_AMPDU_TX_STOP_CONT:
		mtxq->aggr = false;
		mt7663_mcu_set_tx_ba(dev, params, 0);
		ieee80211_stop_tx_ba_cb_irqsafe(vif, sta->addr, tid);
		break;
	}
	mutex_unlock(&dev->mt76.mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(mt7663_ampdu_action);
