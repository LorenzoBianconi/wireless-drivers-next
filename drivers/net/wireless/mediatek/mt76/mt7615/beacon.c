// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Lorenzo Bianconi <lorenzo@kernel.org>
 *         Felix Fietkau <nbd@nbd.name>
 */

#include <linux/etherdevice.h>
#include "mt7615.h"
#include "mac.h"

static void
mt7615_beacon_enable(struct mt7615_dev *dev,
		     struct mt7615_vif *mvif, bool enable)
{
	bool hidx = mvif->omac_idx > HW_BSSID_MAX;
	u32 addr, val;

	if (enable)
		addr = hidx ? MT_ARB_TQSE(mvif->band_idx)
			    : MT_ARB_TQSM(mvif->band_idx);
	else
		addr = hidx ? MT_ARB_TQFE(mvif->band_idx)
			    : MT_ARB_TQFM(mvif->band_idx);

	val = 1 << ((!hidx << 4) + mvif->omac_idx);
	mt76_set(dev, addr, val);
}

static void
mt7615_update_beacon_iter(void *priv, u8 *mac,
			  struct ieee80211_vif *vif)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct mt7615_dev *dev = (struct mt7615_dev *)priv;
	struct sk_buff *skb;

	if (!(dev->mt76.beacon_mask & BIT(mvif->idx)))
		return;

	skb = ieee80211_beacon_get(mt76_hw(dev), vif);
	if (!skb)
		return;

	mt7615_beacon_enable(dev, mvif, false);
	mt76_tx_queue_skb(dev, MT_TXQ_BEACON, skb, &mvif->sta.wcid, NULL);
	mt7615_beacon_enable(dev, mvif, true);
}

void mt7615_pre_tbtt_tasklet(unsigned long arg)
{
	struct mt7615_dev *dev = (struct mt7615_dev *)arg;
	struct mt76_queue *q = dev->mt76.q_tx[MT_TXQ_BEACON].q;
	struct ieee80211_hw *hw = mt76_hw(dev);

	if (hw->conf.flags & IEEE80211_CONF_OFFCHANNEL)
		return;

	spin_lock_bh(&q->lock);
	ieee80211_iterate_active_interfaces_atomic(hw,
			IEEE80211_IFACE_ITER_RESUME_ALL,
			mt7615_update_beacon_iter, dev);
	mt76_queue_kick(dev, q);
	spin_unlock_bh(&q->lock);
}

int mt7615_beacon_set_timer(struct mt7615_dev *dev, int idx,
			    int intval)
{
	u32 opmode = 1; /* XXX: support mesh/ad-hoc */

	if (idx >= 0) {
		if (intval)
			dev->mt76.beacon_mask |= BIT(idx);
		else
			dev->mt76.beacon_mask &= ~BIT(idx);
	}

	if (!dev->mt76.beacon_mask || (!intval && idx < 0)) {
		mt7615_irq_disable(dev, MT_INT_MAC_IRQ3);
		mt76_clear(dev, MT_HW_INT_MASK(3),
			   MT_HW_INT3_TBTT0 | MT_HW_INT3_PRE_TBTT0);
		return 0;
	}

	dev->mt76.beacon_int = intval;

	/* set ARB opmode */
	mt76_set(dev, MT_ARB_SCR,
		 MT_ARB_SCR_BM_CTRL | MT_ARB_SCR_BCN_CTRL |
		 MT_ARB_SCR_BCN_EMPTY | opmode);

	mt76_set(dev, MT_LPON_TCR(0), MT_TSF_TIMER_HW_MODE_TICK_ONLY);

	/* pre-tbtt 5ms */
	mt76_set(dev, MT_LPON_PISR, 0x50);

	/* MPTCR */
	mt76_set(dev, MT_LPON_MPTCR(0),
		 MT_TBTT_TIMEUP_EN | MT_TBTT_PERIOD_TIMER_EN |
		 MT_PRETBTT_TIMEUP_EN | MT_PRETBTT_TIMEUP_EN);

	/* beacon period */
	mt76_wr(dev, MT_LPON_TTPCR(0),
		FIELD_PREP(MT_TBTT_PERIOD, intval) | MT_TBTT_CAL_ENABLE);

	/* host irq pin */
	mt76_set(dev, MT_HW_INT_MASK(3),
		 MT_HW_INT3_TBTT0 | MT_HW_INT3_PRE_TBTT0);
	mt7615_irq_enable(dev, MT_INT_MAC_IRQ3);

	return 0;
}
