/*
 * Copyright (C) 2014 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2015 Jakub Kicinski <kubakici@wp.pl>
 * Copyright (C) 2018 Stanislaw Gruszka <stf_xl@wp.pl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "mt76x0.h"
#include "trace.h"
#include <linux/etherdevice.h>

void mt76x0_mac_set_protection(struct mt76x0_dev *dev, bool legacy_prot,
				int ht_mode)
{
	int mode = ht_mode & IEEE80211_HT_OP_MODE_PROTECTION;
	bool non_gf = !!(ht_mode & IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT);
	u32 prot[6];
	bool ht_rts[4] = {};
	int i;

	prot[0] = MT_PROT_NAV_SHORT |
		  MT_PROT_TXOP_ALLOW_ALL |
		  MT_PROT_RTS_THR_EN;
	prot[1] = prot[0];
	if (legacy_prot)
		prot[1] |= MT_PROT_CTRL_CTS2SELF;

	prot[2] = prot[4] = MT_PROT_NAV_SHORT | MT_PROT_TXOP_ALLOW_BW20;
	prot[3] = prot[5] = MT_PROT_NAV_SHORT | MT_PROT_TXOP_ALLOW_ALL;

	if (legacy_prot) {
		prot[2] |= MT_PROT_RATE_CCK_11;
		prot[3] |= MT_PROT_RATE_CCK_11;
		prot[4] |= MT_PROT_RATE_CCK_11;
		prot[5] |= MT_PROT_RATE_CCK_11;
	} else {
		prot[2] |= MT_PROT_RATE_OFDM_24;
		prot[3] |= MT_PROT_RATE_DUP_OFDM_24;
		prot[4] |= MT_PROT_RATE_OFDM_24;
		prot[5] |= MT_PROT_RATE_DUP_OFDM_24;
	}

	switch (mode) {
	case IEEE80211_HT_OP_MODE_PROTECTION_NONE:
		break;

	case IEEE80211_HT_OP_MODE_PROTECTION_NONMEMBER:
		ht_rts[0] = ht_rts[1] = ht_rts[2] = ht_rts[3] = true;
		break;

	case IEEE80211_HT_OP_MODE_PROTECTION_20MHZ:
		ht_rts[1] = ht_rts[3] = true;
		break;

	case IEEE80211_HT_OP_MODE_PROTECTION_NONHT_MIXED:
		ht_rts[0] = ht_rts[1] = ht_rts[2] = ht_rts[3] = true;
		break;
	}

	if (non_gf)
		ht_rts[2] = ht_rts[3] = true;

	for (i = 0; i < 4; i++)
		if (ht_rts[i])
			prot[i + 2] |= MT_PROT_CTRL_RTS_CTS;

	for (i = 0; i < 6; i++)
		mt76_wr(dev, MT_CCK_PROT_CFG + i * 4, prot[i]);
}

void mt76x0_mac_set_short_preamble(struct mt76x0_dev *dev, bool short_preamb)
{
	if (short_preamb)
		mt76_set(dev, MT_AUTO_RSP_CFG, MT_AUTO_RSP_PREAMB_SHORT);
	else
		mt76_clear(dev, MT_AUTO_RSP_CFG, MT_AUTO_RSP_PREAMB_SHORT);
}

void mt76x0_mac_config_tsf(struct mt76x0_dev *dev, bool enable, int interval)
{
	u32 val = mt76_rr(dev, MT_BEACON_TIME_CFG);

	val &= ~(MT_BEACON_TIME_CFG_TIMER_EN |
		 MT_BEACON_TIME_CFG_SYNC_MODE |
		 MT_BEACON_TIME_CFG_TBTT_EN);

	if (!enable) {
		mt76_wr(dev, MT_BEACON_TIME_CFG, val);
		return;
	}

	val &= ~MT_BEACON_TIME_CFG_INTVAL;
	val |= FIELD_PREP(MT_BEACON_TIME_CFG_INTVAL, interval << 4) |
		MT_BEACON_TIME_CFG_TIMER_EN |
		MT_BEACON_TIME_CFG_SYNC_MODE |
		MT_BEACON_TIME_CFG_TBTT_EN;
}

static void mt76x0_check_mac_err(struct mt76x0_dev *dev)
{
	u32 val = mt76_rr(dev, 0x10f4);

	if (!(val & BIT(29)) || !(val & (BIT(7) | BIT(5))))
		return;

	dev_err(dev->mt76.dev, "Error: MAC specific condition occurred\n");

	mt76_set(dev, MT_MAC_SYS_CTRL, MT_MAC_SYS_CTRL_RESET_CSR);
	udelay(10);
	mt76_clear(dev, MT_MAC_SYS_CTRL, MT_MAC_SYS_CTRL_RESET_CSR);
}
void mt76x0_mac_work(struct work_struct *work)
{
	struct mt76x0_dev *dev = container_of(work, struct mt76x0_dev,
					       mac_work.work);
	struct {
		u32 addr_base;
		u32 span;
		u64 *stat_base;
	} spans[] = {
		{ MT_RX_STAT_0,	3,	dev->stats.rx_stat },
		{ MT_TX_STA_0,	3,	dev->stats.tx_stat },
		{ MT_TX_AGG_STAT,	1,	dev->stats.aggr_stat },
		{ MT_MPDU_DENSITY_CNT,	1,	dev->stats.zero_len_del },
		{ MT_TX_AGG_CNT_BASE0,	8,	&dev->stats.aggr_n[0] },
		{ MT_TX_AGG_CNT_BASE1,	8,	&dev->stats.aggr_n[16] },
	};
	u32 sum, n;
	int i, j, k;

	/* Note: using MCU_RANDOM_READ is actually slower then reading all the
	 *	 registers by hand.  MCU takes ca. 20ms to complete read of 24
	 *	 registers while reading them one by one will takes roughly
	 *	 24*200us =~ 5ms.
	 */

	k = 0;
	n = 0;
	sum = 0;
	for (i = 0; i < ARRAY_SIZE(spans); i++)
		for (j = 0; j < spans[i].span; j++) {
			u32 val = mt76_rr(dev, spans[i].addr_base + j * 4);

			spans[i].stat_base[j * 2] += val & 0xffff;
			spans[i].stat_base[j * 2 + 1] += val >> 16;

			/* Calculate average AMPDU length */
			if (spans[i].addr_base != MT_TX_AGG_CNT_BASE0 &&
			    spans[i].addr_base != MT_TX_AGG_CNT_BASE1)
				continue;

			n += (val >> 16) + (val & 0xffff);
			sum += (val & 0xffff) * (1 + k * 2) +
				(val >> 16) * (2 + k * 2);
			k++;
		}

	atomic_set(&dev->avg_ampdu_len, n ? DIV_ROUND_CLOSEST(sum, n) : 1);

	mt76x0_check_mac_err(dev);

	ieee80211_queue_delayed_work(dev->mt76.hw, &dev->mac_work, 10 * HZ);
}

void mt76x0_mac_set_ampdu_factor(struct mt76x0_dev *dev)
{
	struct ieee80211_sta *sta;
	struct mt76_wcid *wcid;
	void *msta;
	u8 min_factor = 3;
	int i;

	rcu_read_lock();
	for (i = 0; i < ARRAY_SIZE(dev->mt76.wcid); i++) {
		wcid = rcu_dereference(dev->mt76.wcid[i]);
		if (!wcid)
			continue;

		msta = container_of(wcid, struct mt76x02_sta, wcid);
		sta = container_of(msta, struct ieee80211_sta, drv_priv);

		min_factor = min(min_factor, sta->ht_cap.ampdu_factor);
	}
	rcu_read_unlock();

	mt76_wr(dev, MT_MAX_LEN_CFG, 0xa0fff |
		   FIELD_PREP(MT_MAX_LEN_CFG_AMPDU, min_factor));
}

static void
mt76_mac_process_rate(struct ieee80211_rx_status *status, u16 rate)
{
	u8 idx = FIELD_GET(MT_RXWI_RATE_INDEX, rate);

	switch (FIELD_GET(MT_RXWI_RATE_PHY, rate)) {
	case MT_PHY_TYPE_OFDM:
		if (idx >= 8)
			idx = 0;

		if (status->band == NL80211_BAND_2GHZ)
			idx += 4;

		status->rate_idx = idx;
		return;
	case MT_PHY_TYPE_CCK:
		if (idx >= 8) {
			idx -= 8;
			status->enc_flags |= RX_ENC_FLAG_SHORTPRE;
		}

		if (idx >= 4)
			idx = 0;

		status->rate_idx = idx;
		return;
	case MT_PHY_TYPE_HT_GF:
		status->enc_flags |= RX_ENC_FLAG_HT_GF;
		/* fall through */
	case MT_PHY_TYPE_HT:
		status->encoding = RX_ENC_HT;
		status->rate_idx = idx;
		break;
	case MT_PHY_TYPE_VHT:
		status->encoding = RX_ENC_VHT;
		status->rate_idx = FIELD_GET(MT_RATE_INDEX_VHT_IDX, idx);
		status->nss = FIELD_GET(MT_RATE_INDEX_VHT_NSS, idx) + 1;
		break;
	default:
		WARN_ON(1);
		return;
	}

	if (rate & MT_RXWI_RATE_LDPC)
		status->enc_flags |= RX_ENC_FLAG_LDPC;

	if (rate & MT_RXWI_RATE_SGI)
		status->enc_flags |= RX_ENC_FLAG_SHORT_GI;

	if (rate & MT_RXWI_RATE_STBC)
		status->enc_flags |= 1 << RX_ENC_FLAG_STBC_SHIFT;

	switch (FIELD_GET(MT_RXWI_RATE_BW, rate)) {
	case MT_PHY_BW_20:
		break;
	case MT_PHY_BW_40:
		status->bw = RATE_INFO_BW_40;
		break;
	case MT_PHY_BW_80:
		status->bw = RATE_INFO_BW_80;
		break;
	default:
		WARN_ON(1);
		break;
	}
}

static void
mt76x0_rx_monitor_beacon(struct mt76x0_dev *dev, struct mt76x02_rxwi *rxwi,
			  u16 rate, int rssi)
{
	dev->bcn_phy_mode = FIELD_GET(MT_RXWI_RATE_PHY, rate);
	dev->avg_rssi = ((dev->avg_rssi * 15) / 16 + (rssi << 8)) / 256;
}

static int
mt76x0_rx_is_our_beacon(struct mt76x0_dev *dev, u8 *data)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)data;

	return ieee80211_is_beacon(hdr->frame_control) &&
		ether_addr_equal(hdr->addr2, dev->ap_bssid);
}

u32 mt76x0_mac_process_rx(struct mt76x0_dev *dev, struct sk_buff *skb,
			u8 *data, void *rxi)
{
	struct ieee80211_rx_status *status = IEEE80211_SKB_RXCB(skb);
	struct mt76x02_rxwi *rxwi = rxi;
	u32 len, ctl = le32_to_cpu(rxwi->ctl);
	u16 rate = le16_to_cpu(rxwi->rate);
	int rssi;

	len = FIELD_GET(MT_RXWI_CTL_MPDU_LEN, ctl);
	if (WARN_ON(len < 10))
		return 0;

	if (rxwi->rxinfo & cpu_to_le32(MT_RXINFO_DECRYPT)) {
		status->flag |= RX_FLAG_DECRYPTED;
		status->flag |= RX_FLAG_IV_STRIPPED | RX_FLAG_MMIC_STRIPPED;
	}

	status->chains = BIT(0);
	rssi = mt76x0_phy_get_rssi(dev, rxwi);
	status->chain_signal[0] = status->signal = rssi;
	status->freq = dev->mt76.chandef.chan->center_freq;
	status->band = dev->mt76.chandef.chan->band;

	mt76_mac_process_rate(status, rate);

	spin_lock_bh(&dev->con_mon_lock);
	if (mt76x0_rx_is_our_beacon(dev, data)) {
		mt76x0_rx_monitor_beacon(dev, rxwi, rate, rssi);
	} else if (rxwi->rxinfo & cpu_to_le32(MT_RXINFO_UNICAST)) {
		if (dev->avg_rssi == 0)
			dev->avg_rssi = rssi;
		else
			dev->avg_rssi = (dev->avg_rssi * 15) / 16 + rssi / 16;

	}
	spin_unlock_bh(&dev->con_mon_lock);

	return len;
}
