// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 *         Roy Luo <royluo@google.com>
 *         Felix Fietkau <nbd@nbd.name>
 *         Lorenzo Bianconi <lorenzo@kernel.org>
 */

#include <linux/etherdevice.h>
#include <linux/timekeeping.h>
#include "mt7615.h"
#include "../dma.h"
#include "regs.h"
#include "mac.h"

#define to_rssi(field, rxv)		((FIELD_GET(field, rxv) - 220) / 2)

static struct mt76_wcid *mt7615_rx_get_wcid(struct mt7615_dev *dev,
					    u8 idx, bool unicast)
{
	struct mt7615_sta *sta;
	struct mt76_wcid *wcid;

	if (idx >= ARRAY_SIZE(dev->mt76.wcid))
		return NULL;

	wcid = rcu_dereference(dev->mt76.wcid[idx]);
	if (unicast || !wcid)
		return wcid;

	if (!wcid->sta)
		return NULL;

	sta = container_of(wcid, struct mt7615_sta, wcid);
	if (!sta->vif)
		return NULL;

	return &sta->vif->sta.wcid;
}

static int
mt7615_mac_fill_rx(struct mt7615_dev *dev, struct sk_buff *skb)
{
	struct mt76_rx_status *status = (struct mt76_rx_status *)skb->cb;
	struct mt76_phy *mphy = &dev->mt76.phy;
	struct mt7615_phy *phy = &dev->phy;
	struct ieee80211_supported_band *sband;
	struct ieee80211_hdr *hdr;
	__le32 *rxd = (__le32 *)skb->data;
	u32 rxd0 = le32_to_cpu(rxd[0]);
	u32 rxd1 = le32_to_cpu(rxd[1]);
	u32 rxd2 = le32_to_cpu(rxd[2]);
	bool unicast, remove_pad, insert_ccmp_hdr = false;
	int i, idx;
	u8 chfreq;

	memset(status, 0, sizeof(*status));

	chfreq = FIELD_GET(MT_RXD1_NORMAL_CH_FREQ, rxd1);
	if (!(chfreq & MT_CHFREQ_VALID))
		return -EINVAL;

	if (chfreq & MT_CHFREQ_DBDC_IDX) {
		mphy = dev->mt76.phy2;
		if (!mphy)
			return -EINVAL;

		phy = mphy->priv;
		status->ext_phy = true;
	}

	if ((chfreq & MT_CHFREQ_SEQ) != phy->chfreq_seq)
		return -EINVAL;

	if (!test_bit(MT76_STATE_RUNNING, &mphy->state))
		return -EINVAL;

	unicast = (rxd1 & MT_RXD1_NORMAL_ADDR_TYPE) == MT_RXD1_NORMAL_U2M;
	idx = FIELD_GET(MT_RXD2_NORMAL_WLAN_IDX, rxd2);
	status->wcid = mt7615_rx_get_wcid(dev, idx, unicast);

	if (status->wcid) {
		struct mt7615_sta *msta;

		msta = container_of(status->wcid, struct mt7615_sta, wcid);
		spin_lock_bh(&dev->sta_poll_lock);
		if (list_empty(&msta->poll_list))
			list_add_tail(&msta->poll_list, &dev->sta_poll_list);
		spin_unlock_bh(&dev->sta_poll_lock);
	}

	status->freq = mphy->chandef.chan->center_freq;
	status->band = mphy->chandef.chan->band;
	if (status->band == NL80211_BAND_5GHZ)
		sband = &mphy->sband_5g.sband;
	else
		sband = &mphy->sband_2g.sband;

	if (rxd2 & MT_RXD2_NORMAL_FCS_ERR)
		status->flag |= RX_FLAG_FAILED_FCS_CRC;

	if (rxd2 & MT_RXD2_NORMAL_TKIP_MIC_ERR)
		status->flag |= RX_FLAG_MMIC_ERROR;

	if (FIELD_GET(MT_RXD2_NORMAL_SEC_MODE, rxd2) != 0 &&
	    !(rxd2 & (MT_RXD2_NORMAL_CLM | MT_RXD2_NORMAL_CM))) {
		status->flag |= RX_FLAG_DECRYPTED;
		status->flag |= RX_FLAG_IV_STRIPPED;
		status->flag |= RX_FLAG_MMIC_STRIPPED | RX_FLAG_MIC_STRIPPED;
	}

	if (!(rxd2 & (MT_RXD2_NORMAL_NON_AMPDU_SUB |
		      MT_RXD2_NORMAL_NON_AMPDU))) {
		status->flag |= RX_FLAG_AMPDU_DETAILS;

		/* all subframes of an A-MPDU have the same timestamp */
		if (phy->rx_ampdu_ts != rxd[12]) {
			if (!++phy->ampdu_ref)
				phy->ampdu_ref++;
		}
		phy->rx_ampdu_ts = rxd[12];

		status->ampdu_ref = phy->ampdu_ref;
	}

	remove_pad = rxd1 & MT_RXD1_NORMAL_HDR_OFFSET;

	if (rxd2 & MT_RXD2_NORMAL_MAX_LEN_ERROR)
		return -EINVAL;

	if (!sband->channels)
		return -EINVAL;

	rxd += 4;
	if (rxd0 & MT_RXD0_NORMAL_GROUP_4) {
		rxd += 4;
		if ((u8 *)rxd - skb->data >= skb->len)
			return -EINVAL;
	}

	if (rxd0 & MT_RXD0_NORMAL_GROUP_1) {
		u8 *data = (u8 *)rxd;

		if (status->flag & RX_FLAG_DECRYPTED) {
			status->iv[0] = data[5];
			status->iv[1] = data[4];
			status->iv[2] = data[3];
			status->iv[3] = data[2];
			status->iv[4] = data[1];
			status->iv[5] = data[0];

			insert_ccmp_hdr = FIELD_GET(MT_RXD2_NORMAL_FRAG, rxd2);
		}
		rxd += 4;
		if ((u8 *)rxd - skb->data >= skb->len)
			return -EINVAL;
	}

	if (rxd0 & MT_RXD0_NORMAL_GROUP_2) {
		rxd += 2;
		if ((u8 *)rxd - skb->data >= skb->len)
			return -EINVAL;
	}

	if (rxd0 & MT_RXD0_NORMAL_GROUP_3) {
		u32 rxdg0 = le32_to_cpu(rxd[0]);
		u32 rxdg1 = le32_to_cpu(rxd[1]);
		u32 rxdg3 = le32_to_cpu(rxd[3]);
		u8 stbc = FIELD_GET(MT_RXV1_HT_STBC, rxdg0);
		bool cck = false;

		i = FIELD_GET(MT_RXV1_TX_RATE, rxdg0);
		switch (FIELD_GET(MT_RXV1_TX_MODE, rxdg0)) {
		case MT_PHY_TYPE_CCK:
			cck = true;
			/* fall through */
		case MT_PHY_TYPE_OFDM:
			i = mt76_get_rate(&dev->mt76, sband, i, cck);
			break;
		case MT_PHY_TYPE_HT_GF:
		case MT_PHY_TYPE_HT:
			status->encoding = RX_ENC_HT;
			if (i > 31)
				return -EINVAL;
			break;
		case MT_PHY_TYPE_VHT:
			status->nss = FIELD_GET(MT_RXV2_NSTS, rxdg1) + 1;
			status->encoding = RX_ENC_VHT;
			break;
		default:
			return -EINVAL;
		}
		status->rate_idx = i;

		switch (FIELD_GET(MT_RXV1_FRAME_MODE, rxdg0)) {
		case MT_PHY_BW_20:
			break;
		case MT_PHY_BW_40:
			status->bw = RATE_INFO_BW_40;
			break;
		case MT_PHY_BW_80:
			status->bw = RATE_INFO_BW_80;
			break;
		case MT_PHY_BW_160:
			status->bw = RATE_INFO_BW_160;
			break;
		default:
			return -EINVAL;
		}

		if (rxdg0 & MT_RXV1_HT_SHORT_GI)
			status->enc_flags |= RX_ENC_FLAG_SHORT_GI;
		if (rxdg0 & MT_RXV1_HT_AD_CODE)
			status->enc_flags |= RX_ENC_FLAG_LDPC;

		status->enc_flags |= RX_ENC_FLAG_STBC_MASK * stbc;

		status->chains = dev->mphy.antenna_mask;
		status->chain_signal[0] = to_rssi(MT_RXV4_RCPI0, rxdg3);
		status->chain_signal[1] = to_rssi(MT_RXV4_RCPI1, rxdg3);
		status->chain_signal[2] = to_rssi(MT_RXV4_RCPI2, rxdg3);
		status->chain_signal[3] = to_rssi(MT_RXV4_RCPI3, rxdg3);
		status->signal = status->chain_signal[0];

		for (i = 1; i < hweight8(dev->mphy.antenna_mask); i++) {
			if (!(status->chains & BIT(i)))
				continue;

			status->signal = max(status->signal,
					     status->chain_signal[i]);
		}

		rxd += 6;
		if ((u8 *)rxd - skb->data >= skb->len)
			return -EINVAL;
	}

	skb_pull(skb, (u8 *)rxd - skb->data + 2 * remove_pad);

	if (insert_ccmp_hdr) {
		u8 key_id = FIELD_GET(MT_RXD1_NORMAL_KEY_ID, rxd1);

		mt76_insert_ccmp_hdr(skb, key_id);
	}

	hdr = (struct ieee80211_hdr *)skb->data;
	if (!status->wcid || !ieee80211_is_data_qos(hdr->frame_control))
		return 0;

	status->aggr = unicast &&
		       !ieee80211_is_qos_nullfunc(hdr->frame_control);
	status->tid = *ieee80211_get_qos_ctl(hdr) & IEEE80211_QOS_CTL_TID_MASK;
	status->seqno = IEEE80211_SEQ_TO_SN(le16_to_cpu(hdr->seq_ctrl));

	return 0;
}

void mt7615_sta_ps(struct mt76_dev *mdev, struct ieee80211_sta *sta, bool ps)
{
}
EXPORT_SYMBOL_GPL(mt7615_sta_ps);

u16
mt7615_mac_tx_rate_val(struct mt7615_dev *dev,
		       struct mt76_phy *mphy,
		       const struct ieee80211_tx_rate *rate,
		       bool stbc, u8 *bw)
{
	u8 phy, nss, rate_idx;
	u16 rateval = 0;

	*bw = 0;

	if (rate->flags & IEEE80211_TX_RC_VHT_MCS) {
		rate_idx = ieee80211_rate_get_vht_mcs(rate);
		nss = ieee80211_rate_get_vht_nss(rate);
		phy = MT_PHY_TYPE_VHT;
		if (rate->flags & IEEE80211_TX_RC_40_MHZ_WIDTH)
			*bw = 1;
		else if (rate->flags & IEEE80211_TX_RC_80_MHZ_WIDTH)
			*bw = 2;
		else if (rate->flags & IEEE80211_TX_RC_160_MHZ_WIDTH)
			*bw = 3;
	} else if (rate->flags & IEEE80211_TX_RC_MCS) {
		rate_idx = rate->idx;
		nss = 1 + (rate->idx >> 3);
		phy = MT_PHY_TYPE_HT;
		if (rate->flags & IEEE80211_TX_RC_GREEN_FIELD)
			phy = MT_PHY_TYPE_HT_GF;
		if (rate->flags & IEEE80211_TX_RC_40_MHZ_WIDTH)
			*bw = 1;
	} else {
		const struct ieee80211_rate *r;
		int band = mphy->chandef.chan->band;
		u16 val;

		nss = 1;
		r = &mphy->hw->wiphy->bands[band]->bitrates[rate->idx];
		if (rate->flags & IEEE80211_TX_RC_USE_SHORT_PREAMBLE)
			val = r->hw_value_short;
		else
			val = r->hw_value;

		phy = val >> 8;
		rate_idx = val & 0xff;
	}

	if (stbc && nss == 1) {
		nss++;
		rateval |= MT_TX_RATE_STBC;
	}

	rateval |= (FIELD_PREP(MT_TX_RATE_IDX, rate_idx) |
		    FIELD_PREP(MT_TX_RATE_MODE, phy) |
		    FIELD_PREP(MT_TX_RATE_NSS, nss - 1));

	return rateval;
}

int mt7615_mac_write_txwi(struct mt7615_dev *dev, __le32 *txwi,
			  struct sk_buff *skb, struct mt76_wcid *wcid,
			  struct ieee80211_sta *sta, int pid,
			  struct ieee80211_key_conf *key)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_tx_rate *rate = &info->control.rates[0];
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	bool multicast = is_multicast_ether_addr(hdr->addr1);
	struct ieee80211_vif *vif = info->control.vif;
	struct mt76_phy *mphy = &dev->mphy;
	bool ext_phy = info->hw_queue & MT_TX_HW_QUEUE_EXT_PHY;
	bool is_usb = mt76_is_usb(&dev->mt76);
	int tx_count = 8;
	u8 fc_type, fc_stype, p_fmt, q_idx, omac_idx = 0, wmm_idx = 0;
	__le16 fc = hdr->frame_control;
	u32 val, sz_txd = is_usb ? MT7663_USB_TXD_SIZE : MT_TXD_SIZE;
	u16 seqno = 0;

	if (vif) {
		struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;

		omac_idx = mvif->omac_idx;
		wmm_idx = mvif->wmm_idx;
	}

	if (sta) {
		struct mt7615_sta *msta = (struct mt7615_sta *)sta->drv_priv;

		tx_count = msta->rate_count;
	}

	if (ext_phy && dev->mt76.phy2)
		mphy = dev->mt76.phy2;

	fc_type = (le16_to_cpu(fc) & IEEE80211_FCTL_FTYPE) >> 2;
	fc_stype = (le16_to_cpu(fc) & IEEE80211_FCTL_STYPE) >> 4;

	if (ieee80211_is_data(fc) || ieee80211_is_bufferable_mmpdu(fc)) {
		q_idx = wmm_idx * MT7615_MAX_WMM_SETS +
			mt7615_wmm_queue_map(dev, skb_get_queue_mapping(skb));
		p_fmt = is_usb ? MT_TX_TYPE_SF : MT_TX_TYPE_CT;
	} else if (ieee80211_is_beacon(fc)) {
		if (ext_phy)
			q_idx = MT_LMAC_BCN1;
		else
			q_idx = MT_LMAC_BCN0;
		p_fmt = MT_TX_TYPE_FW;
	} else {
		if (ext_phy)
			q_idx = MT_LMAC_ALTX1;
		else
			q_idx = MT_LMAC_ALTX0;
		p_fmt = is_usb ? MT_TX_TYPE_SF : MT_TX_TYPE_CT;
	}

	val = FIELD_PREP(MT_TXD0_TX_BYTES, skb->len + sz_txd) |
	      FIELD_PREP(MT_TXD0_P_IDX, MT_TX_PORT_IDX_LMAC) |
	      FIELD_PREP(MT_TXD0_Q_IDX, q_idx);
	txwi[0] = cpu_to_le32(val);

	val = MT_TXD1_LONG_FORMAT |
	      FIELD_PREP(MT_TXD1_WLAN_IDX, wcid->idx) |
	      FIELD_PREP(MT_TXD1_HDR_FORMAT, MT_HDR_FORMAT_802_11) |
	      FIELD_PREP(MT_TXD1_HDR_INFO,
			 ieee80211_get_hdrlen_from_skb(skb) / 2) |
	      FIELD_PREP(MT_TXD1_TID,
			 skb->priority & IEEE80211_QOS_CTL_TID_MASK) |
	      FIELD_PREP(MT_TXD1_PKT_FMT, p_fmt) |
	      FIELD_PREP(MT_TXD1_OWN_MAC, omac_idx);
	txwi[1] = cpu_to_le32(val);

	val = FIELD_PREP(MT_TXD2_FRAME_TYPE, fc_type) |
	      FIELD_PREP(MT_TXD2_SUB_TYPE, fc_stype) |
	      FIELD_PREP(MT_TXD2_MULTICAST, multicast);
	if (key) {
		if (multicast && ieee80211_is_robust_mgmt_frame(skb) &&
		    key->cipher == WLAN_CIPHER_SUITE_AES_CMAC) {
			val |= MT_TXD2_BIP;
			txwi[3] = 0;
		} else {
			txwi[3] = cpu_to_le32(MT_TXD3_PROTECT_FRAME);
		}
	} else {
		txwi[3] = 0;
	}
	txwi[2] = cpu_to_le32(val);

	if (!(info->flags & IEEE80211_TX_CTL_AMPDU))
		txwi[2] |= cpu_to_le32(MT_TXD2_BA_DISABLE);

	txwi[4] = 0;
	txwi[6] = 0;

	if (rate->idx >= 0 && rate->count &&
	    !(info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE)) {
		bool stbc = info->flags & IEEE80211_TX_CTL_STBC;
		u8 bw;
		u16 rateval = mt7615_mac_tx_rate_val(dev, mphy, rate, stbc,
						     &bw);

		txwi[2] |= cpu_to_le32(MT_TXD2_FIX_RATE);

		val = MT_TXD6_FIXED_BW |
		      FIELD_PREP(MT_TXD6_BW, bw) |
		      FIELD_PREP(MT_TXD6_TX_RATE, rateval);
		txwi[6] |= cpu_to_le32(val);

		if (rate->flags & IEEE80211_TX_RC_SHORT_GI)
			txwi[6] |= cpu_to_le32(MT_TXD6_SGI);

		if (info->flags & IEEE80211_TX_CTL_LDPC)
			txwi[6] |= cpu_to_le32(MT_TXD6_LDPC);

		if (!(rate->flags & (IEEE80211_TX_RC_MCS |
				     IEEE80211_TX_RC_VHT_MCS)))
			txwi[2] |= cpu_to_le32(MT_TXD2_BA_DISABLE);

		tx_count = rate->count;
	}

	if (!ieee80211_is_beacon(fc)) {
		val = MT_TXD5_TX_STATUS_HOST | MT_TXD5_SW_POWER_MGMT |
		      FIELD_PREP(MT_TXD5_PID, pid);
		txwi[5] = cpu_to_le32(val);
	} else {
		txwi[5] = 0;
		/* use maximum tx count for beacons */
		tx_count = 0x1f;
	}

	val = FIELD_PREP(MT_TXD3_REM_TX_COUNT, tx_count);
	if (ieee80211_is_data_qos(hdr->frame_control)) {
		seqno = IEEE80211_SEQ_TO_SN(le16_to_cpu(hdr->seq_ctrl));
		val |= MT_TXD3_SN_VALID;
	} else if (ieee80211_is_back_req(hdr->frame_control)) {
		struct ieee80211_bar *bar = (struct ieee80211_bar *)skb->data;

		seqno = IEEE80211_SEQ_TO_SN(le16_to_cpu(bar->start_seq_num));
		val |= MT_TXD3_SN_VALID;
	}
	val |= FIELD_PREP(MT_TXD3_SEQ, seqno);

	txwi[3] |= cpu_to_le32(val);

	if (info->flags & IEEE80211_TX_CTL_NO_ACK)
		txwi[3] |= cpu_to_le32(MT_TXD3_NO_ACK);

	txwi[7] = FIELD_PREP(MT_TXD7_TYPE, fc_type) |
		  FIELD_PREP(MT_TXD7_SUB_TYPE, fc_stype);
	if (is_usb)
		txwi[8] = FIELD_PREP(MT_TXD8_L_TYPE, fc_type) |
			  FIELD_PREP(MT_TXD8_L_SUB_TYPE, fc_stype);

	return 0;
}
EXPORT_SYMBOL_GPL(mt7615_mac_write_txwi);

static void
mt7615_mac_update_rate_desc(struct mt7615_phy *phy, struct mt7615_sta *sta,
			    struct ieee80211_tx_rate *probe_rate,
			    struct ieee80211_tx_rate *rates,
			    struct mt7615_rate_desc *rd)
{
	struct mt7615_dev *dev = phy->dev;
	struct mt76_phy *mphy = phy->mt76;
	struct ieee80211_tx_rate *ref;
	int wcid = sta->wcid.idx;
	bool rateset, stbc = false;
	int n_rates = sta->n_rates;
	u8 bw, bw_prev;
	int i, j;

	for (i = n_rates; i < 4; i++)
		rates[i] = rates[n_rates - 1];

	rateset = !(sta->rate_set_tsf & BIT(0));
	memcpy(sta->rateset[rateset].rates, rates,
	       sizeof(sta->rateset[rateset].rates));
	if (probe_rate) {
		sta->rateset[rateset].probe_rate = *probe_rate;
		ref = &sta->rateset[rateset].probe_rate;
	} else {
		sta->rateset[rateset].probe_rate.idx = -1;
		ref = &sta->rateset[rateset].rates[0];
	}

	rates = sta->rateset[rateset].rates;
	for (i = 0; i < ARRAY_SIZE(sta->rateset[rateset].rates); i++) {
		/*
		 * We don't support switching between short and long GI
		 * within the rate set. For accurate tx status reporting, we
		 * need to make sure that flags match.
		 * For improved performance, avoid duplicate entries by
		 * decrementing the MCS index if necessary
		 */
		if ((ref->flags ^ rates[i].flags) & IEEE80211_TX_RC_SHORT_GI)
			rates[i].flags ^= IEEE80211_TX_RC_SHORT_GI;

		for (j = 0; j < i; j++) {
			if (rates[i].idx != rates[j].idx)
				continue;
			if ((rates[i].flags ^ rates[j].flags) &
			    (IEEE80211_TX_RC_40_MHZ_WIDTH |
			     IEEE80211_TX_RC_80_MHZ_WIDTH |
			     IEEE80211_TX_RC_160_MHZ_WIDTH))
				continue;

			if (!rates[i].idx)
				continue;

			rates[i].idx--;
		}
	}

	rd->val[0] = mt7615_mac_tx_rate_val(dev, mphy, &rates[0], stbc, &bw);
	bw_prev = bw;

	if (probe_rate) {
		rd->probe_val = mt7615_mac_tx_rate_val(dev, mphy, probe_rate,
						       stbc, &bw);
		if (bw)
			rd->bw_idx = 1;
		else
			bw_prev = 0;
	} else {
		rd->probe_val = rd->val[0];
	}

	rd->val[1] = mt7615_mac_tx_rate_val(dev, mphy, &rates[1], stbc, &bw);
	if (bw_prev) {
		rd->bw_idx = 3;
		bw_prev = bw;
	}

	rd->val[2] = mt7615_mac_tx_rate_val(dev, mphy, &rates[2], stbc, &bw);
	if (bw_prev) {
		rd->bw_idx = 5;
		bw_prev = bw;
	}

	rd->val[3] = mt7615_mac_tx_rate_val(dev, mphy, &rates[3], stbc, &bw);
	if (bw_prev)
		rd->bw_idx = 7;

	rd->wcid = wcid;
	rd->bw = bw;
	rd->sta = sta;
	rd->rateset = rateset;
}

u32 mt7615_mac_wtbl_addr(int wcid)
{
	return MT_WTBL_BASE + wcid * MT_WTBL_ENTRY_SIZE;
}
EXPORT_SYMBOL_GPL(mt7615_mac_wtbl_addr);

static void
mt7615_mac_queue_rate_update(struct mt7615_phy *phy, struct mt7615_sta *sta,
			     struct ieee80211_tx_rate *probe_rate,
			     struct ieee80211_tx_rate *rates)
{
	struct mt7615_dev *dev = phy->dev;
	struct mt7615_rate_desc *rd;

	rd = kzalloc(sizeof(*rd), GFP_ATOMIC);
	if (!rd)
		return;

	mt7615_mac_update_rate_desc(phy, sta, probe_rate, rates, rd);
	list_add_tail(&rd->node, &dev->rd_head);
	queue_work(dev->mt76.usb.wq, &dev->rate_work);
}

void mt7615_mac_set_rates(struct mt7615_phy *phy, struct mt7615_sta *sta,
			  struct ieee80211_tx_rate *probe_rate,
			  struct ieee80211_tx_rate *rates)
{
	int wcid = sta->wcid.idx, n_rates = sta->n_rates;
	struct mt7615_dev *dev = phy->dev;
	struct mt7615_rate_desc rd;
	u32 w5, w27, addr;

	if (mt76_is_usb(&dev->mt76)) {
		mt7615_mac_queue_rate_update(phy, sta, probe_rate, rates);
		return;
	}

	if (!mt76_poll(dev, MT_WTBL_UPDATE, MT_WTBL_UPDATE_BUSY, 0, 5000))
		return;

	memset(&rd, 0, sizeof(struct mt7615_rate_desc));
	mt7615_mac_update_rate_desc(phy, sta, probe_rate, rates, &rd);

	addr = mt7615_mac_wtbl_addr(wcid);
	w27 = mt76_rr(dev, addr + 27 * 4);
	w27 &= ~MT_WTBL_W27_CC_BW_SEL;
	w27 |= FIELD_PREP(MT_WTBL_W27_CC_BW_SEL, rd.bw);

	w5 = mt76_rr(dev, addr + 5 * 4);
	w5 &= ~(MT_WTBL_W5_BW_CAP | MT_WTBL_W5_CHANGE_BW_RATE |
		MT_WTBL_W5_MPDU_OK_COUNT |
		MT_WTBL_W5_MPDU_FAIL_COUNT |
		MT_WTBL_W5_RATE_IDX);
	w5 |= FIELD_PREP(MT_WTBL_W5_BW_CAP, rd.bw) |
	      FIELD_PREP(MT_WTBL_W5_CHANGE_BW_RATE,
			 rd.bw_idx ? rd.bw_idx - 1 : 7);

	mt76_wr(dev, MT_WTBL_RIUCR0, w5);

	mt76_wr(dev, MT_WTBL_RIUCR1,
		FIELD_PREP(MT_WTBL_RIUCR1_RATE0, rd.probe_val) |
		FIELD_PREP(MT_WTBL_RIUCR1_RATE1, rd.val[0]) |
		FIELD_PREP(MT_WTBL_RIUCR1_RATE2_LO, rd.val[1]));

	mt76_wr(dev, MT_WTBL_RIUCR2,
		FIELD_PREP(MT_WTBL_RIUCR2_RATE2_HI, rd.val[1] >> 8) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE3, rd.val[1]) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE4, rd.val[2]) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE5_LO, rd.val[2]));

	mt76_wr(dev, MT_WTBL_RIUCR3,
		FIELD_PREP(MT_WTBL_RIUCR3_RATE5_HI, rd.val[2] >> 4) |
		FIELD_PREP(MT_WTBL_RIUCR3_RATE6, rd.val[3]) |
		FIELD_PREP(MT_WTBL_RIUCR3_RATE7, rd.val[3]));

	mt76_wr(dev, MT_WTBL_UPDATE,
		FIELD_PREP(MT_WTBL_UPDATE_WLAN_IDX, wcid) |
		MT_WTBL_UPDATE_RATE_UPDATE |
		MT_WTBL_UPDATE_TX_COUNT_CLEAR);

	mt76_wr(dev, addr + 27 * 4, w27);

	mt76_set(dev, MT_LPON_T0CR, MT_LPON_T0CR_MODE); /* TSF read */
	sta->rate_set_tsf = (mt76_rr(dev, MT_LPON_UTTR0) & ~BIT(0)) | rd.rateset;

	if (!(sta->wcid.tx_info & MT_WCID_TX_INFO_SET))
		mt76_poll(dev, MT_WTBL_UPDATE, MT_WTBL_UPDATE_BUSY, 0, 5000);

	sta->rate_count = 2 * MT7615_RATE_RETRY * n_rates;
	sta->wcid.tx_info |= MT_WCID_TX_INFO_SET;
}
EXPORT_SYMBOL_GPL(mt7615_mac_set_rates);

int mt7615_mac_wtbl_update_key(struct mt7615_dev *dev, struct mt76_wcid *wcid,
			       u32 base_addr, struct ieee80211_key_conf *key,
			       enum mt7615_cipher_type cipher,
			       enum set_key_cmd cmd)
{
	u32 addr = base_addr + 30 * 4;
	u8 data[32] = {};

	if (key->keylen > sizeof(data))
		return -EINVAL;

	mt76_rr_copy(dev, addr, data, sizeof(data));
	if (cmd == SET_KEY) {
		if (cipher == MT_CIPHER_TKIP) {
			/* Rx/Tx MIC keys are swapped */
			memcpy(data + 16, key->key + 24, 8);
			memcpy(data + 24, key->key + 16, 8);
		}
		if (cipher != MT_CIPHER_BIP_CMAC_128 && wcid->cipher)
			memmove(data + 16, data, 16);
		if (cipher != MT_CIPHER_BIP_CMAC_128 || !wcid->cipher)
			memcpy(data, key->key, key->keylen);
		else if (cipher == MT_CIPHER_BIP_CMAC_128)
			memcpy(data + 16, key->key, 16);
	} else {
		if (wcid->cipher & ~BIT(cipher)) {
			if (cipher != MT_CIPHER_BIP_CMAC_128)
				memmove(data, data + 16, 16);
			memset(data + 16, 0, 16);
		} else {
			memset(data, 0, sizeof(data));
		}
	}
	mt76_wr_copy(dev, addr, data, sizeof(data));

	return 0;
}
EXPORT_SYMBOL_GPL(mt7615_mac_wtbl_update_key);

void mt7615_mac_wtbl_update_cipher(struct mt7615_dev *dev,
				   struct mt76_wcid *wcid, u32 addr,
				   enum mt7615_cipher_type cipher,
				   enum set_key_cmd cmd)
{
	if (cmd == SET_KEY) {
		if (cipher != MT_CIPHER_BIP_CMAC_128 || !wcid->cipher)
			mt76_rmw(dev, addr + 2 * 4, MT_WTBL_W2_KEY_TYPE,
				 FIELD_PREP(MT_WTBL_W2_KEY_TYPE, cipher));
	} else {
		if (cipher != MT_CIPHER_BIP_CMAC_128 &&
		    wcid->cipher & BIT(MT_CIPHER_BIP_CMAC_128))
			mt76_rmw(dev, addr + 2 * 4, MT_WTBL_W2_KEY_TYPE,
				 FIELD_PREP(MT_WTBL_W2_KEY_TYPE,
					    MT_CIPHER_BIP_CMAC_128));
		else if (!(wcid->cipher & ~BIT(cipher)))
			mt76_clear(dev, addr + 2 * 4, MT_WTBL_W2_KEY_TYPE);
	}
}
EXPORT_SYMBOL_GPL(mt7615_mac_wtbl_update_cipher);

static bool mt7615_fill_txs(struct mt7615_dev *dev, struct mt7615_sta *sta,
			    struct ieee80211_tx_info *info, __le32 *txs_data)
{
	struct ieee80211_supported_band *sband;
	struct mt7615_rate_set *rs;
	struct mt76_phy *mphy;
	int first_idx = 0, last_idx;
	int i, idx, count;
	bool fixed_rate, ack_timeout;
	bool probe, ampdu, cck = false;
	bool rs_idx;
	u32 rate_set_tsf;
	u32 final_rate, final_rate_flags, final_nss, txs;

	fixed_rate = info->status.rates[0].count;
	probe = !!(info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE);

	txs = le32_to_cpu(txs_data[1]);
	ampdu = !fixed_rate && (txs & MT_TXS1_AMPDU);

	txs = le32_to_cpu(txs_data[3]);
	count = FIELD_GET(MT_TXS3_TX_COUNT, txs);
	last_idx = FIELD_GET(MT_TXS3_LAST_TX_RATE, txs);

	txs = le32_to_cpu(txs_data[0]);
	final_rate = FIELD_GET(MT_TXS0_TX_RATE, txs);
	ack_timeout = txs & MT_TXS0_ACK_TIMEOUT;

	if (!ampdu && (txs & MT_TXS0_RTS_TIMEOUT))
		return false;

	if (txs & MT_TXS0_QUEUE_TIMEOUT)
		return false;

	if (!ack_timeout)
		info->flags |= IEEE80211_TX_STAT_ACK;

	info->status.ampdu_len = 1;
	info->status.ampdu_ack_len = !!(info->flags &
					IEEE80211_TX_STAT_ACK);

	if (ampdu || (info->flags & IEEE80211_TX_CTL_AMPDU))
		info->flags |= IEEE80211_TX_STAT_AMPDU | IEEE80211_TX_CTL_AMPDU;

	first_idx = max_t(int, 0, last_idx - (count + 1) / MT7615_RATE_RETRY);

	if (fixed_rate && !probe) {
		info->status.rates[0].count = count;
		i = 0;
		goto out;
	}

	rate_set_tsf = READ_ONCE(sta->rate_set_tsf);
	rs_idx = !((u32)(FIELD_GET(MT_TXS4_F0_TIMESTAMP, le32_to_cpu(txs_data[4])) -
			 rate_set_tsf) < 1000000);
	rs_idx ^= rate_set_tsf & BIT(0);
	rs = &sta->rateset[rs_idx];

	if (!first_idx && rs->probe_rate.idx >= 0) {
		info->status.rates[0] = rs->probe_rate;

		spin_lock_bh(&dev->mt76.lock);
		if (sta->rate_probe) {
			struct mt7615_phy *phy = &dev->phy;

			if (sta->wcid.ext_phy && dev->mt76.phy2)
				phy = dev->mt76.phy2->priv;

			mt7615_mac_set_rates(phy, sta, NULL, sta->rates);
			sta->rate_probe = false;
		}
		spin_unlock_bh(&dev->mt76.lock);
	} else {
		info->status.rates[0] = rs->rates[first_idx / 2];
	}
	info->status.rates[0].count = 0;

	for (i = 0, idx = first_idx; count && idx <= last_idx; idx++) {
		struct ieee80211_tx_rate *cur_rate;
		int cur_count;

		cur_rate = &rs->rates[idx / 2];
		cur_count = min_t(int, MT7615_RATE_RETRY, count);
		count -= cur_count;

		if (idx && (cur_rate->idx != info->status.rates[i].idx ||
			    cur_rate->flags != info->status.rates[i].flags)) {
			i++;
			if (i == ARRAY_SIZE(info->status.rates)) {
				i--;
				break;
			}

			info->status.rates[i] = *cur_rate;
			info->status.rates[i].count = 0;
		}

		info->status.rates[i].count += cur_count;
	}

out:
	final_rate_flags = info->status.rates[i].flags;

	switch (FIELD_GET(MT_TX_RATE_MODE, final_rate)) {
	case MT_PHY_TYPE_CCK:
		cck = true;
		/* fall through */
	case MT_PHY_TYPE_OFDM:
		mphy = &dev->mphy;
		if (sta->wcid.ext_phy && dev->mt76.phy2)
			mphy = dev->mt76.phy2;

		if (mphy->chandef.chan->band == NL80211_BAND_5GHZ)
			sband = &mphy->sband_5g.sband;
		else
			sband = &mphy->sband_2g.sband;
		final_rate &= MT_TX_RATE_IDX;
		final_rate = mt76_get_rate(&dev->mt76, sband, final_rate,
					   cck);
		final_rate_flags = 0;
		break;
	case MT_PHY_TYPE_HT_GF:
	case MT_PHY_TYPE_HT:
		final_rate_flags |= IEEE80211_TX_RC_MCS;
		final_rate &= MT_TX_RATE_IDX;
		if (final_rate > 31)
			return false;
		break;
	case MT_PHY_TYPE_VHT:
		final_nss = FIELD_GET(MT_TX_RATE_NSS, final_rate);

		if ((final_rate & MT_TX_RATE_STBC) && final_nss)
			final_nss--;

		final_rate_flags |= IEEE80211_TX_RC_VHT_MCS;
		final_rate = (final_rate & MT_TX_RATE_IDX) | (final_nss << 4);
		break;
	default:
		return false;
	}

	info->status.rates[i].idx = final_rate;
	info->status.rates[i].flags = final_rate_flags;

	return true;
}

static bool mt7615_mac_add_txs_skb(struct mt7615_dev *dev,
				   struct mt7615_sta *sta, int pid,
				   __le32 *txs_data)
{
	struct mt76_dev *mdev = &dev->mt76;
	struct sk_buff_head list;
	struct sk_buff *skb;

	if (pid < MT_PACKET_ID_FIRST)
		return false;

	mt76_tx_status_lock(mdev, &list);
	skb = mt76_tx_status_skb_get(mdev, &sta->wcid, pid, &list);
	if (skb) {
		struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

		if (!mt7615_fill_txs(dev, sta, info, txs_data)) {
			ieee80211_tx_info_clear_status(info);
			info->status.rates[0].idx = -1;
		}

		mt76_tx_status_skb_done(mdev, skb, &list);
	}
	mt76_tx_status_unlock(mdev, &list);

	return !!skb;
}

static void
mt7615_mac_add_txs(struct mt7615_dev *dev, void *data)
{
	struct ieee80211_tx_info info = {};
	struct ieee80211_sta *sta = NULL;
	struct mt7615_sta *msta = NULL;
	struct mt76_wcid *wcid;
	struct mt76_phy *mphy = &dev->mt76.phy;
	__le32 *txs_data = data;
	u32 txs;
	u8 wcidx;
	u8 pid;

	txs = le32_to_cpu(txs_data[0]);
	pid = FIELD_GET(MT_TXS0_PID, txs);
	txs = le32_to_cpu(txs_data[2]);
	wcidx = FIELD_GET(MT_TXS2_WCID, txs);

	if (pid == MT_PACKET_ID_NO_ACK)
		return;

	if (wcidx >= ARRAY_SIZE(dev->mt76.wcid))
		return;

	rcu_read_lock();

	wcid = rcu_dereference(dev->mt76.wcid[wcidx]);
	if (!wcid)
		goto out;

	msta = container_of(wcid, struct mt7615_sta, wcid);
	sta = wcid_to_sta(wcid);

	spin_lock_bh(&dev->sta_poll_lock);
	if (list_empty(&msta->poll_list))
		list_add_tail(&msta->poll_list, &dev->sta_poll_list);
	spin_unlock_bh(&dev->sta_poll_lock);

	if (mt7615_mac_add_txs_skb(dev, msta, pid, txs_data))
		goto out;

	if (wcidx >= MT7615_WTBL_STA || !sta)
		goto out;

	if (wcid->ext_phy && dev->mt76.phy2)
		mphy = dev->mt76.phy2;

	if (mt7615_fill_txs(dev, msta, &info, txs_data))
		ieee80211_tx_status_noskb(mphy->hw, sta, &info);

out:
	rcu_read_unlock();
}

void mt7615_txp_skb_unmap(struct mt76_dev *dev,
			  struct mt76_txwi_cache *t)
{
	struct mt7615_txp *txp;
	int i;

	txp = mt7615_txwi_to_txp(dev, t);
	for (i = 1; i < txp->nbuf; i++)
		dma_unmap_single(dev->dev, le32_to_cpu(txp->buf[i]),
				 le16_to_cpu(txp->len[i]), DMA_TO_DEVICE);
}
EXPORT_SYMBOL_GPL(mt7615_txp_skb_unmap);

static void
mt7615_mac_tx_free(struct mt7615_dev *dev, struct sk_buff *skb)
{
	struct mt7615_tx_free *free = (struct mt7615_tx_free *)skb->data;
	struct mt76_dev *mdev = &dev->mt76;
	struct mt76_txwi_cache *txwi;
	u8 i, count;

	count = FIELD_GET(MT_TX_FREE_MSDU_ID_CNT, le16_to_cpu(free->ctrl));
	for (i = 0; i < count; i++) {
		spin_lock_bh(&dev->token_lock);
		txwi = idr_remove(&dev->token, le16_to_cpu(free->token[i]));
		spin_unlock_bh(&dev->token_lock);

		if (!txwi)
			continue;

		mt7615_txp_skb_unmap(mdev, txwi);
		if (txwi->skb) {
			mt76_tx_complete_skb(mdev, txwi->skb);
			txwi->skb = NULL;
		}

		mt76_put_txwi(mdev, txwi);
	}
	dev_kfree_skb(skb);
}

void mt7615_queue_rx_skb(struct mt76_dev *mdev, enum mt76_rxq_id q,
			 struct sk_buff *skb)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	__le32 *rxd = (__le32 *)skb->data;
	__le32 *end = (__le32 *)&skb->data[skb->len];
	enum rx_pkt_type type;

	type = FIELD_GET(MT_RXD0_PKT_TYPE, le32_to_cpu(rxd[0]));

	switch (type) {
	case PKT_TYPE_TXS:
		for (rxd++; rxd + 7 <= end; rxd += 7)
			mt7615_mac_add_txs(dev, rxd);
		dev_kfree_skb(skb);
		break;
	case PKT_TYPE_TXRX_NOTIFY:
		mt7615_mac_tx_free(dev, skb);
		break;
	case PKT_TYPE_RX_EVENT:
		mt7615_mcu_rx_event(dev, skb);
		break;
	case PKT_TYPE_NORMAL:
		if (!mt7615_mac_fill_rx(dev, skb)) {
			mt76_rx(&dev->mt76, q, skb);
			return;
		}
		/* fall through */
	default:
		dev_kfree_skb(skb);
		break;
	}
}
EXPORT_SYMBOL_GPL(mt7615_queue_rx_skb);

static void mt7615_dfs_stop_radar_detector(struct mt7615_phy *phy)
{
	struct mt7615_dev *dev = phy->dev;

	if (phy->rdd_state & BIT(0))
		mt7615_mcu_rdd_cmd(dev, RDD_STOP, 0, MT_RX_SEL0, 0);
	if (phy->rdd_state & BIT(1))
		mt7615_mcu_rdd_cmd(dev, RDD_STOP, 1, MT_RX_SEL0, 0);
}

static int mt7615_dfs_start_rdd(struct mt7615_dev *dev, int chain)
{
	int err;

	err = mt7615_mcu_rdd_cmd(dev, RDD_START, chain, MT_RX_SEL0, 0);
	if (err < 0)
		return err;

	return mt7615_mcu_rdd_cmd(dev, RDD_DET_MODE, chain,
				  MT_RX_SEL0, 1);
}

static int mt7615_dfs_start_radar_detector(struct mt7615_phy *phy)
{
	struct cfg80211_chan_def *chandef = &phy->mt76->chandef;
	struct mt7615_dev *dev = phy->dev;
	bool ext_phy = phy != &dev->phy;
	int err;

	/* start CAC */
	err = mt7615_mcu_rdd_cmd(dev, RDD_CAC_START, ext_phy, MT_RX_SEL0, 0);
	if (err < 0)
		return err;

	err = mt7615_dfs_start_rdd(dev, ext_phy);
	if (err < 0)
		return err;

	phy->rdd_state |= BIT(ext_phy);

	if (chandef->width == NL80211_CHAN_WIDTH_160 ||
	    chandef->width == NL80211_CHAN_WIDTH_80P80) {
		err = mt7615_dfs_start_rdd(dev, 1);
		if (err < 0)
			return err;

		phy->rdd_state |= BIT(1);
	}

	return 0;
}

int mt7615_dfs_init_radar_detector(struct mt7615_phy *phy)
{
	struct cfg80211_chan_def *chandef = &phy->mt76->chandef;
	struct mt7615_dev *dev = phy->dev;
	bool ext_phy = phy != &dev->phy;
	int err;

	if (dev->mt76.region == NL80211_DFS_UNSET) {
		phy->dfs_state = -1;
		if (phy->rdd_state)
			goto stop;

		return 0;
	}

	if (test_bit(MT76_SCANNING, &phy->mt76->state))
		return 0;

	if (phy->dfs_state == chandef->chan->dfs_state)
		return 0;

	phy->dfs_state = chandef->chan->dfs_state;

	if (chandef->chan->flags & IEEE80211_CHAN_RADAR) {
		if (chandef->chan->dfs_state != NL80211_DFS_AVAILABLE)
			return mt7615_dfs_start_radar_detector(phy);

		return mt7615_mcu_rdd_cmd(dev, RDD_CAC_END, ext_phy,
					  MT_RX_SEL0, 0);
	}

stop:
	err = mt7615_mcu_rdd_cmd(dev, RDD_NORMAL_START, ext_phy, MT_RX_SEL0, 0);
	if (err < 0)
		return err;

	mt7615_dfs_stop_radar_detector(phy);
	return 0;
}
EXPORT_SYMBOL_GPL(mt7615_dfs_init_radar_detector);
