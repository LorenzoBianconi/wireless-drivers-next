
// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Roy Luo <royluo@google.com>
 *         Ryder Lee <ryder.lee@mediatek.com>
 *         Felix Fietkau <nbd@nbd.name>
 *         Lorenzo Bianconi <lorenzo@kernel.org>
 */

#include <linux/etherdevice.h>
#include <linux/platform_device.h>
#include <linux/pci.h>
#include <linux/module.h>

#include "mt7615.h"
#include "regs.h"

static int
mt7615_get_omac_idx(enum nl80211_iftype type, u32 mask)
{
	int i;

	switch (type) {
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_MESH_POINT:
	case NL80211_IFTYPE_ADHOC:
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
	}

	return -1;
}

int mt7615_setup_interface(struct ieee80211_hw *hw,
			   struct ieee80211_vif *vif)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct mt7615_dev *dev = mt7615_hw_dev(hw);
	struct mt7615_phy *phy = mt7615_hw_phy(hw);
	struct mt76_txq *mtxq;
	bool ext_phy = phy != &dev->phy;
	int idx, ret = 0;

	mvif->idx = ffs(~dev->vif_mask) - 1;
	if (mvif->idx >= MT7615_MAX_INTERFACES)
		return -ENOSPC;

	idx = mt7615_get_omac_idx(vif->type, dev->omac_mask);
	if (idx < 0)
		return -ENOSPC;

	mvif->omac_idx = idx;

	mvif->band_idx = ext_phy;
	if (mt7615_ext_phy(dev))
		mvif->wmm_idx = ext_phy * (MT7615_MAX_WMM_SETS / 2) +
				mvif->idx % (MT7615_MAX_WMM_SETS / 2);
	else
		mvif->wmm_idx = mvif->idx % MT7615_MAX_WMM_SETS;

	ret = mt7615_mcu_set_dev_info(dev, vif, 1);
	if (ret)
		return ret;

	dev->vif_mask |= BIT(mvif->idx);
	dev->omac_mask |= BIT(mvif->omac_idx);
	phy->omac_mask |= BIT(mvif->omac_idx);

	mt7615_mcu_set_dbdc(dev);

	idx = MT7615_WTBL_RESERVED - mvif->idx;

	INIT_LIST_HEAD(&mvif->sta.poll_list);
	mvif->sta.wcid.idx = idx;
	mvif->sta.wcid.ext_phy = mvif->band_idx;
	mvif->sta.wcid.hw_key_idx = -1;

	rcu_assign_pointer(dev->mt76.wcid[idx], &mvif->sta.wcid);
	mtxq = (struct mt76_txq *)vif->txq->drv_priv;
	mtxq->wcid = &mvif->sta.wcid;
	mt76_txq_init(&dev->mt76, vif->txq);

	return idx;
}
EXPORT_SYMBOL_GPL(mt7615_setup_interface);

void mt7615_remove_interface(struct ieee80211_hw *hw,
			     struct ieee80211_vif *vif)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct mt7615_sta *msta = &mvif->sta;
	struct mt7615_dev *dev = mt7615_hw_dev(hw);
	struct mt7615_phy *phy = mt7615_hw_phy(hw);
	int idx = msta->wcid.idx;

	/* TODO: disable beacon for the bss */

	mt7615_mcu_set_dev_info(dev, vif, 0);

	rcu_assign_pointer(dev->mt76.wcid[idx], NULL);
	mt76_txq_remove(&dev->mt76, vif->txq);

	mutex_lock(&dev->mt76.mutex);
	dev->vif_mask &= ~BIT(mvif->idx);
	dev->omac_mask &= ~BIT(mvif->omac_idx);
	phy->omac_mask &= ~BIT(mvif->omac_idx);
	mutex_unlock(&dev->mt76.mutex);

	spin_lock_bh(&dev->sta_poll_lock);
	if (!list_empty(&msta->poll_list))
		list_del_init(&msta->poll_list);
	spin_unlock_bh(&dev->sta_poll_lock);
}
EXPORT_SYMBOL_GPL(mt7615_remove_interface);

int mt7615_conf_tx(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		   u16 queue, const struct ieee80211_tx_queue_params *params)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct mt7615_dev *dev = mt7615_hw_dev(hw);
	u16 wmm_q;

	wmm_q = mt7615_wmm_queue_map(dev, queue);
	wmm_q += mvif->wmm_idx * MT7615_MAX_WMM_SETS;

	return mt7615_mcu_set_wmm(dev, wmm_q, params);
}
EXPORT_SYMBOL_GPL(mt7615_conf_tx);

u32 mt7615_reg_map(struct mt7615_dev *dev, u32 addr)
{
	u32 base = addr & MT_MCU_PCIE_REMAP_2_BASE;
	u32 offset = addr & MT_MCU_PCIE_REMAP_2_OFFSET;

	mt76_wr(dev, MT_MCU_PCIE_REMAP_2, base);

	return MT_PCIE_REMAP_BASE_2 + offset;
}
EXPORT_SYMBOL_GPL(mt7615_reg_map);

void mt7615_tx(struct ieee80211_hw *hw, struct ieee80211_tx_control *control,
	       struct sk_buff *skb)
{
	struct mt7615_dev *dev = mt7615_hw_dev(hw);
	struct mt76_phy *mphy = hw->priv;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_vif *vif = info->control.vif;
	struct mt76_wcid *wcid = &dev->mt76.global_wcid;

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
EXPORT_SYMBOL_GPL(mt7615_tx);

int mt7615_set_rts_threshold(struct ieee80211_hw *hw, u32 val)
{
	struct mt7615_dev *dev = mt7615_hw_dev(hw);
	struct mt7615_phy *phy = mt7615_hw_phy(hw);

	mutex_lock(&dev->mt76.mutex);
	mt7615_mcu_set_rts_thresh(phy, val);
	mutex_unlock(&dev->mt76.mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(mt7615_set_rts_threshold);

void mt7615_sta_rate_tbl_update(struct ieee80211_hw *hw,
				struct ieee80211_vif *vif,
				struct ieee80211_sta *sta)
{
	struct mt7615_dev *dev = mt7615_hw_dev(hw);
	struct mt7615_phy *phy = mt7615_hw_phy(hw);
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
	mt7615_mac_set_rates(phy, msta, NULL, msta->rates);
	msta->rate_probe = false;
	spin_unlock_bh(&dev->mt76.lock);
}
EXPORT_SYMBOL_GPL(mt7615_sta_rate_tbl_update);

int mt7615_ampdu_action(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			struct ieee80211_ampdu_params *params)
{
	enum ieee80211_ampdu_mlme_action action = params->action;
	struct mt7615_dev *dev = mt7615_hw_dev(hw);
	struct ieee80211_sta *sta = params->sta;
	struct ieee80211_txq *txq = sta->txq[params->tid];
	struct mt7615_sta *msta = (struct mt7615_sta *)sta->drv_priv;
	u16 tid = params->tid;
	u16 ssn = params->ssn;
	struct mt76_txq *mtxq;
	int ret = 0;

	if (!txq)
		return -EINVAL;

	mtxq = (struct mt76_txq *)txq->drv_priv;

	mutex_lock(&dev->mt76.mutex);
	switch (action) {
	case IEEE80211_AMPDU_RX_START:
		mt76_rx_aggr_start(&dev->mt76, &msta->wcid, tid, ssn,
				   params->buf_size);
		mt7615_mcu_set_rx_ba(dev, params, 1);
		break;
	case IEEE80211_AMPDU_RX_STOP:
		mt76_rx_aggr_stop(&dev->mt76, &msta->wcid, tid);
		mt7615_mcu_set_rx_ba(dev, params, 0);
		break;
	case IEEE80211_AMPDU_TX_OPERATIONAL:
		mtxq->aggr = true;
		mtxq->send_bar = false;
		mt7615_mcu_set_tx_ba(dev, params, 1);
		break;
	case IEEE80211_AMPDU_TX_STOP_FLUSH:
	case IEEE80211_AMPDU_TX_STOP_FLUSH_CONT:
		mtxq->aggr = false;
		mt7615_mcu_set_tx_ba(dev, params, 0);
		break;
	case IEEE80211_AMPDU_TX_START:
		mtxq->agg_ssn = IEEE80211_SN_TO_SEQ(ssn);
		ret = IEEE80211_AMPDU_TX_START_IMMEDIATE;
		break;
	case IEEE80211_AMPDU_TX_STOP_CONT:
		mtxq->aggr = false;
		mt7615_mcu_set_tx_ba(dev, params, 0);
		ieee80211_stop_tx_ba_cb_irqsafe(vif, sta->addr, tid);
		break;
	}
	mutex_unlock(&dev->mt76.mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(mt7615_ampdu_action);
