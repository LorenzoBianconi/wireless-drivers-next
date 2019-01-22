// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Roy Luo <roychl666@gmail.com>
 *         Ryder Lee <ryder.lee@mediatek.com>
 */

#include <linux/etherdevice.h>
#include <linux/platform_device.h>
#include <linux/pci.h>
#include <linux/module.h>
#include "mt7615.h"

static int mt7615_start(struct ieee80211_hw *hw)
{
	struct mt7615_dev *dev = hw->priv;

	set_bit(MT76_STATE_RUNNING, &dev->mt76.state);

	return 0;
}

static void mt7615_stop(struct ieee80211_hw *hw)
{
	struct mt7615_dev *dev = hw->priv;

	clear_bit(MT76_STATE_RUNNING, &dev->mt76.state);
}

static void mt7615_txq_init(struct mt7615_dev *dev, struct ieee80211_txq *txq)
{
	struct mt76_txq *mtxq;

	if (!txq)
		return;

	mtxq = (struct mt76_txq *)txq->drv_priv;
	if (txq->sta) {
		struct mt7615_sta *sta;

		sta = (struct mt7615_sta *)txq->sta->drv_priv;
		mtxq->wcid = &sta->wcid;
	} else {
		struct mt7615_vif *mvif;

		mvif = (struct mt7615_vif *)txq->vif->drv_priv;
		mtxq->wcid = &mvif->sta.wcid;
	}

	mt76_txq_init(&dev->mt76, txq);
}

static int get_omac_idx(enum nl80211_iftype type, u32 mask)
{
	int i;

	switch (type) {
	case NL80211_IFTYPE_AP:
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

static int mt7615_add_interface(struct ieee80211_hw *hw,
				struct ieee80211_vif *vif)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct mt7615_dev *dev = hw->priv;
	int idx, ret = 0;

	mutex_lock(&dev->mt76.mutex);

	mvif->idx = ffs(~dev->vif_mask) - 1;
	if (mvif->idx >= MT7615_MAX_INTERFACES) {
		ret = -ENOSPC;
		goto out;
	}

	mvif->omac_idx = get_omac_idx(vif->type, dev->omac_mask);
	if (mvif->omac_idx < 0) {
		ret = -ENOSPC;
		goto out;
	}

	/* TODO: DBDC support. Use band 0 and wmm 0 for now */
	mvif->band_idx = 0;
	mvif->wmm_idx = 0;

	ret = mt7615_mcu_set_dev_info(dev, vif, 1);
	if (ret)
		goto out;

	dev->vif_mask |= BIT(mvif->idx);
	dev->omac_mask |= BIT(mvif->omac_idx);
	idx = MT7615_WTBL_RESERVED - 1 - mvif->idx;
	mvif->sta.wcid.idx = idx;
	mvif->sta.wcid.hw_key_idx = -1;
	rcu_assign_pointer(dev->mt76.wcid[idx], &mvif->sta.wcid);
	mt7615_txq_init(dev, vif->txq);

out:
	mutex_unlock(&dev->mt76.mutex);

	return ret;
}

static void mt7615_remove_interface(struct ieee80211_hw *hw,
				    struct ieee80211_vif *vif)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct mt7615_dev *dev = hw->priv;
	int idx = mvif->sta.wcid.idx;

	/* TODO: disable beacon for the bss */

	mt7615_mcu_set_dev_info(dev, vif, 0);

	rcu_assign_pointer(dev->mt76.wcid[idx], NULL);
	mt76_txq_remove(&dev->mt76, vif->txq);

	mutex_lock(&dev->mt76.mutex);
	dev->vif_mask &= ~BIT(mvif->idx);
	dev->omac_mask &= ~BIT(mvif->omac_idx);
	mutex_unlock(&dev->mt76.mutex);
}

static int mt7615_set_channel(struct mt7615_dev *dev,
			      struct cfg80211_chan_def *def)
{
	struct mt76_queue *q;
	int ret;

	set_bit(MT76_RESET, &dev->mt76.state);

	mt76_set_channel(&dev->mt76);

	ret = mt7615_mcu_set_channel(dev);
	if (ret)
		return ret;

	clear_bit(MT76_RESET, &dev->mt76.state);

	q = &dev->mt76.q_tx[MT7615_TXQ_MAIN];
	spin_lock_bh(&q->lock);
	mt76_txq_schedule(&dev->mt76, q);
	spin_unlock_bh(&q->lock);

	return 0;
}

static int mt7615_config(struct ieee80211_hw *hw, u32 changed)
{
	struct mt7615_dev *dev = hw->priv;
	int ret = 0;

	mutex_lock(&dev->mt76.mutex);

	if (changed & IEEE80211_CONF_CHANGE_CHANNEL) {
		ieee80211_stop_queues(hw);
		ret = mt7615_set_channel(dev, &hw->conf.chandef);
		ieee80211_wake_queues(hw);
	}

	mutex_unlock(&dev->mt76.mutex);

	return ret;
}

static void mt7615_configure_filter(struct ieee80211_hw *hw,
				    unsigned int changed_flags,
				    unsigned int *total_flags,
				    u64 multicast)
{
	u32 flags = 0;

	*total_flags = flags;
}

static void mt7615_bss_info_changed(struct ieee80211_hw *hw,
				    struct ieee80211_vif *vif,
				    struct ieee80211_bss_conf *info,
				    u32 changed)
{
	struct mt7615_dev *dev = hw->priv;

	mutex_lock(&dev->mt76.mutex);

	/* TODO: sta mode connect/disconnect
	 * BSS_CHANGED_ASSOC | BSS_CHANGED_BSSID
	 */

	/* TODO: update beacon content
	 * BSS_CHANGED_BEACON
	 */

	if (changed & BSS_CHANGED_BEACON_ENABLED) {
		if (info->enable_beacon) {
			mt7615_mcu_set_bss_info(dev, vif, 1);
			mt7615_mcu_add_wtbl_bmc(dev, vif);
			mt7615_mcu_add_sta_rec_bmc(dev, vif);
			mt7615_mcu_set_bcn(dev, vif, 1);
		} else {
			mt7615_mcu_del_sta_rec_bmc(dev, vif);
			mt7615_mcu_del_wtbl_bmc(dev, vif);
			mt7615_mcu_set_bss_info(dev, vif, 0);
			mt7615_mcu_set_bcn(dev, vif, 0);
		}
	}

	mutex_unlock(&dev->mt76.mutex);
}

static int mt7615_sta_add(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			  struct ieee80211_sta *sta)
{
	return 0;
}

static int mt7615_sta_remove(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			     struct ieee80211_sta *sta)
{
	return 0;
}

static void mt7615_tx(struct ieee80211_hw *hw,
		      struct ieee80211_tx_control *control,
		      struct sk_buff *skb)
{
	struct mt7615_dev *dev = hw->priv;
	struct mt76_dev *mdev = &dev->mt76;
	struct mt76_queue *q = &mdev->q_tx[MT7615_TXQ_MAIN];
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

	if (!wcid->tx_rate_set)
		ieee80211_get_tx_rates(info->control.vif, control->sta, skb,
				       info->control.rates, 1);

	spin_lock_bh(&q->lock);

	mdev->queue_ops->tx_queue_skb(mdev, q, skb, wcid, control->sta);
	mdev->queue_ops->kick(mdev, q);

	if (q->queued > q->ndesc - 8)
		ieee80211_stop_queue(mdev->hw, MT7615_TXQ_MAIN);

	spin_unlock_bh(&q->lock);
}

const struct ieee80211_ops mt7615_ops = {
	.tx = mt7615_tx,
	.start = mt7615_start,
	.stop = mt7615_stop,
	.add_interface = mt7615_add_interface,
	.remove_interface = mt7615_remove_interface,
	.config = mt7615_config,
	.configure_filter = mt7615_configure_filter,
	.bss_info_changed = mt7615_bss_info_changed,
	.sta_add = mt7615_sta_add,
	.sta_remove = mt7615_sta_remove,
};
