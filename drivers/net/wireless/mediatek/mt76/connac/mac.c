// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 *         Roy Luo <royluo@google.com>
 *         Felix Fietkau <nbd@nbd.name>
 *         Lorenzo Bianconi <lorenzo@kernel.org>
 *	   Chih-Min Chen <chih-min.chen@mediatek.com>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include <linux/etherdevice.h>
#include <linux/timekeeping.h>
#include "connac.h"
#include "../dma.h"
#include "mac.h"

static inline s8 to_rssi(u32 field, u32 rxv)
{
	return (FIELD_GET(field, rxv) - 220) / 2;
}

static struct mt76_wcid *connac_rx_get_wcid(struct connac_dev *dev,
					    u8 idx, bool unicast)
{
	struct connac_sta *sta;
	struct mt76_wcid *wcid;

	if (idx >= ARRAY_SIZE(dev->mt76.wcid))
		return NULL;

	wcid = rcu_dereference(dev->mt76.wcid[idx]);
	if (unicast || !wcid)
		return wcid;

	if (!wcid->sta)
		return NULL;

	sta = container_of(wcid, struct connac_sta, wcid);
	if (!sta->vif)
		return NULL;

	return &sta->vif->sta.wcid;
}

int connac_mac_fill_rx(struct connac_dev *dev, struct sk_buff *skb)
{
	struct mt76_rx_status *status = (struct mt76_rx_status *)skb->cb;
	struct ieee80211_supported_band *sband;
	struct ieee80211_hdr *hdr;
	__le32 *rxd = (__le32 *)skb->data;
	u32 rxd0 = le32_to_cpu(rxd[0]);
	u32 rxd1 = le32_to_cpu(rxd[1]);
	u32 rxd2 = le32_to_cpu(rxd[2]);
	bool unicast, remove_pad, insert_ccmp_hdr = false;
	int i, idx;

	if (!test_bit(MT76_STATE_RUNNING, &dev->mphy.state))
		return -EINVAL;

	memset(status, 0, sizeof(*status));

	unicast = (rxd1 & MT_RXD1_NORMAL_ADDR_TYPE) == MT_RXD1_NORMAL_U2M;
	idx = FIELD_GET(MT_RXD2_NORMAL_WLAN_IDX, rxd2);
	status->wcid = connac_rx_get_wcid(dev, idx, unicast);

	/* TODO: properly support DBDC */
	status->freq = dev->mphy.chandef.chan->center_freq;
	status->band = dev->mphy.chandef.chan->band;
	if (status->band == NL80211_BAND_5GHZ)
		sband = &dev->mphy.sband_5g.sband;
	else
		sband = &dev->mphy.sband_2g.sband;

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

void connac_sta_ps(struct mt76_dev *mdev, struct ieee80211_sta *sta, bool ps)
{
}

void connac_tx_complete_skb(struct mt76_dev *mdev, enum mt76_txq_id qid,
			    struct mt76_queue_entry *e)
{
	if (!e->txwi) {
		dev_kfree_skb_any(e->skb);
		return;
	}

	/* error path */
	if (e->skb == DMA_DUMMY_DATA) {
		struct mt76_txwi_cache *t = NULL;

		t = e->txwi;
		e->skb = t ? t->skb : NULL;
	}

	if (e->skb)
		mt76_tx_complete_skb(mdev, e->skb);
}

static void connac_usb_remove_dma_hdr(struct sk_buff *skb)
{
	skb_pull(skb, CONNAC_USB_TXD_SIZE);
}

void connac_usb_tx_complete_skb(struct mt76_dev *mdev, enum mt76_txq_id qid,
				struct mt76_queue_entry *e)
{
	connac_usb_remove_dma_hdr(e->skb);
	mt76_tx_complete_skb(mdev, e->skb);
}

static u16
connac_mac_tx_rate_val(struct connac_dev *dev,
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
		int band = dev->mphy.chandef.chan->band;
		u16 val;

		nss = 1;
		r = &mt76_hw(dev)->wiphy->bands[band]->bitrates[rate->idx];
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

int connac_mac_write_txwi(struct connac_dev *dev, __le32 *txwi,
			  struct sk_buff *skb, enum mt76_txq_id qid,
			  struct mt76_wcid *wcid,
			  struct ieee80211_sta *sta, int pid,
			  struct ieee80211_key_conf *key)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_tx_rate *rate = &info->control.rates[0];
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	bool multicast = is_multicast_ether_addr(hdr->addr1);
	struct ieee80211_vif *vif = info->control.vif;
	int tx_count = 8;
	u8 fc_type, fc_stype, p_fmt, q_idx, omac_idx = 0, wmm_idx = 0;
	__le16 fc = hdr->frame_control;
	u16 seqno = 0;
	u32 val, sz_txd;
	int i;

	static const u8 wmm_queue_map[] = {
		[MT_TXQ_VO] /* 0 */ = MT_LMAC_AC03,
		[MT_TXQ_VI] /* 1 */ = MT_LMAC_AC02,
		[MT_TXQ_BE] /* 2 */ = MT_LMAC_AC01,
		[MT_TXQ_BK] /* 3 */ = MT_LMAC_AC00,
		[MT_TXQ_PSD] /* 4 */ = MT_LMAC_ALTX0,
		[MT_TXQ_BEACON] /* 6 */ = MT_LMAC_BCN0,
	};

	if (vif) {
		struct connac_vif *mvif = (struct connac_vif *)vif->drv_priv;

		omac_idx = mvif->omac_idx;
		wmm_idx = mvif->wmm_idx;
	}

	if (sta) {
		struct connac_sta *msta = (struct connac_sta *)sta->drv_priv;

		tx_count = msta->rate_count;
	}

	fc_type = (le16_to_cpu(fc) & IEEE80211_FCTL_FTYPE) >> 2;
	fc_stype = (le16_to_cpu(fc) & IEEE80211_FCTL_STYPE) >> 4;

	if (ieee80211_is_beacon(fc)) {
		p_fmt = MT_TX_TYPE_FW;
	} else {
		if (dev->flag & CONNAC_USB)
			p_fmt = MT_TX_TYPE_SF;
		else
			p_fmt = MT_TX_TYPE_CT;
	}

	if (qid <= MT_TXQ_BK)
		q_idx = (wmm_idx * CONNAC_MAX_WMM_SETS) + wmm_queue_map[qid];
	else
		q_idx = wmm_queue_map[qid];

	if (dev->flag & CONNAC_USB)
		sz_txd = CONNAC_USB_TXD_SIZE;
	else
		sz_txd = MT_TXD_SIZE;

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
		u16 rateval = connac_mac_tx_rate_val(dev, rate, stbc, &bw);

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
		  FIELD_PREP(MT_TXD7_SUB_TYPE, fc_stype) |
		  FIELD_PREP(MT_TXD7_HW_AMSDU_CAP, 1);

	if (dev->flag & CONNAC_USB) {
		for (i = 8 ; i <= 15 ; i++)
			txwi[i] = 0;
	}

	return 0;
}

void connac_txp_skb_unmap(struct mt76_dev *dev,
			  struct mt76_txwi_cache *t)
{
	struct connac_txp *txp;
	u8 *txwi;
	int i, nbuf = 0;

	txwi = mt76_get_txwi_ptr(dev, t);
	txp = (struct connac_txp *)(txwi + MT_TXD_SIZE);

	// calculate nbuf by MSDU VLD bit
	for (i = 0; i < MT_TXP_MAX_BUF_NUM; i++) {
		if (txp->buf[i] & cpu_to_le16(TXD_MSDU_ID_VLD))
			nbuf++;
	}

	/* HW-AMSDU didn't support >= 2 */
	WARN_ON(nbuf >= 2);

	for (i = 0; i < nbuf; i++) {
		dma_unmap_single(dev->dev, le32_to_cpu(txp->buf[i]),
				 le16_to_cpu((i & 1) ? txp->ptr_len[i].u2len1 :
				 txp->ptr_len[i].u2len0), DMA_TO_DEVICE);
	}
}

static u32 connac_mac_wtbl_addr(struct connac_dev *dev, int wcid)
{
	return MT_WTBL(dev, 0) + wcid * MT_WTBL_ENTRY_SIZE;
}

void connac_mac_set_rates(struct connac_dev *dev, struct connac_sta *sta,
			  struct ieee80211_tx_rate *probe_rate,
			  struct ieee80211_tx_rate *rates)
{
	struct ieee80211_tx_rate *ref;
	int wcid = sta->wcid.idx;
	u32 addr = connac_mac_wtbl_addr(dev, wcid);
	bool stbc = false;
	int n_rates = sta->n_rates;
	u8 bw, bw_prev, bw_idx = 0;
	u16 val[4];
	u16 probe_val;
	u32 w5, w27;
	bool rateset;
	int i, k;

	if (!mt76_poll(dev, MT_WTBL_UPDATE(dev), MT_WTBL_UPDATE_BUSY, 0, 5000))
		return;

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
		/* We don't support switching between short and long GI
		 * within the rate set. For accurate tx status reporting, we
		 * need to make sure that flags match.
		 * For improved performance, avoid duplicate entries by
		 * decrementing the MCS index if necessary
		 */
		if ((ref->flags ^ rates[i].flags) & IEEE80211_TX_RC_SHORT_GI)
			rates[i].flags ^= IEEE80211_TX_RC_SHORT_GI;

		for (k = 0; k < i; k++) {
			if (rates[i].idx != rates[k].idx)
				continue;
			if ((rates[i].flags ^ rates[k].flags) &
			    (IEEE80211_TX_RC_40_MHZ_WIDTH |
			     IEEE80211_TX_RC_80_MHZ_WIDTH |
			     IEEE80211_TX_RC_160_MHZ_WIDTH))
				continue;

			if (!rates[i].idx)
				continue;

			rates[i].idx--;
		}
	}

	val[0] = connac_mac_tx_rate_val(dev, &rates[0], stbc, &bw);
	bw_prev = bw;

	if (probe_rate) {
		probe_val = connac_mac_tx_rate_val(dev, probe_rate, stbc, &bw);
		if (bw)
			bw_idx = 1;
		else
			bw_prev = 0;
	} else {
		probe_val = val[0];
	}

	val[1] = connac_mac_tx_rate_val(dev, &rates[1], stbc, &bw);
	if (bw_prev) {
		bw_idx = 3;
		bw_prev = bw;
	}

	val[2] = connac_mac_tx_rate_val(dev, &rates[2], stbc, &bw);
	if (bw_prev) {
		bw_idx = 5;
		bw_prev = bw;
	}

	val[3] = connac_mac_tx_rate_val(dev, &rates[3], stbc, &bw);
	if (bw_prev)
		bw_idx = 7;

	w27 = mt76_rr(dev, addr + 27 * 4);
	w27 &= ~MT_WTBL_W27_CC_BW_SEL;
	w27 |= FIELD_PREP(MT_WTBL_W27_CC_BW_SEL, bw);

	w5 = mt76_rr(dev, addr + 5 * 4);
	w5 &= ~(MT_WTBL_W5_BW_CAP | MT_WTBL_W5_CHANGE_BW_RATE |
		MT_WTBL_W5_MPDU_OK_COUNT |
		MT_WTBL_W5_MPDU_FAIL_COUNT |
		MT_WTBL_W5_RATE_IDX);
	w5 |= FIELD_PREP(MT_WTBL_W5_BW_CAP, bw) |
	      FIELD_PREP(MT_WTBL_W5_CHANGE_BW_RATE, bw_idx ? bw_idx - 1 : 7);

	mt76_wr(dev, MT_WTBL_RIUCR0(dev), w5);

	mt76_wr(dev, MT_WTBL_RIUCR1(dev),
		FIELD_PREP(MT_WTBL_RIUCR1_RATE0, probe_val) |
		FIELD_PREP(MT_WTBL_RIUCR1_RATE1, val[0]) |
		FIELD_PREP(MT_WTBL_RIUCR1_RATE2_LO, val[1]));

	mt76_wr(dev, MT_WTBL_RIUCR2(dev),
		FIELD_PREP(MT_WTBL_RIUCR2_RATE2_HI, val[1] >> 8) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE3, val[1]) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE4, val[2]) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE5_LO, val[2]));

	mt76_wr(dev, MT_WTBL_RIUCR3(dev),
		FIELD_PREP(MT_WTBL_RIUCR3_RATE5_HI, val[2] >> 4) |
		FIELD_PREP(MT_WTBL_RIUCR3_RATE6, val[3]) |
		FIELD_PREP(MT_WTBL_RIUCR3_RATE7, val[3]));

	mt76_wr(dev, MT_WTBL_UPDATE(dev),
		FIELD_PREP(MT_WTBL_UPDATE_WLAN_IDX, wcid) |
		MT_WTBL_UPDATE_RATE_UPDATE |
		MT_WTBL_UPDATE_TX_COUNT_CLEAR);

	mt76_wr(dev, addr + 27 * 4, w27);

	mt76_set(dev, MT_LPON_T0CR(dev), MT_LPON_T0CR_MODE); /* TSF read */
	sta->rate_set_tsf = (mt76_rr(dev, MT_LPON_UTTR0(dev)) & ~BIT(0)) | rateset;

	if (!(sta->wcid.tx_info & MT_WCID_TX_INFO_SET))
		mt76_poll(dev, MT_WTBL_UPDATE(dev), MT_WTBL_UPDATE_BUSY, 0,
			  5000);

	sta->rate_count = 2 * CONNAC_RATE_RETRY * n_rates;
	sta->wcid.tx_info |= MT_WCID_TX_INFO_SET;
}

static int
__connac_mac_set_rates(struct connac_dev *dev, struct connac_rate_desc *rc)
{
	u32 addr = MT_WTBL(dev, 0) + rc->wcid * MT_WTBL_ENTRY_SIZE;
	u32 w5, w27;

	if (!mt76_poll(dev, MT_WTBL_UPDATE(dev), MT_WTBL_UPDATE_BUSY, 0, 5000))
		return -ETIMEDOUT;

	w27 = mt76_rr(dev, addr + 27 * 4);
	w27 &= ~MT_WTBL_W27_CC_BW_SEL;
	w27 |= FIELD_PREP(MT_WTBL_W27_CC_BW_SEL, rc->bw);

	w5 = mt76_rr(dev, addr + 5 * 4);
	w5 &= ~(MT_WTBL_W5_BW_CAP | MT_WTBL_W5_CHANGE_BW_RATE |
		MT_WTBL_W5_MPDU_OK_COUNT |
		MT_WTBL_W5_MPDU_FAIL_COUNT |
		MT_WTBL_W5_RATE_IDX);
	w5 |= FIELD_PREP(MT_WTBL_W5_BW_CAP, rc->bw) |
	      FIELD_PREP(MT_WTBL_W5_CHANGE_BW_RATE,
			 rc->bw_idx ? rc->bw_idx - 1 : 7);

	mt76_wr(dev, MT_WTBL_RIUCR0(dev), w5);

	mt76_wr(dev, MT_WTBL_RIUCR1(dev),
		FIELD_PREP(MT_WTBL_RIUCR1_RATE0, rc->probe_val) |
		FIELD_PREP(MT_WTBL_RIUCR1_RATE1, rc->val[0]) |
		FIELD_PREP(MT_WTBL_RIUCR1_RATE2_LO, rc->val[1]));

	mt76_wr(dev, MT_WTBL_RIUCR2(dev),
		FIELD_PREP(MT_WTBL_RIUCR2_RATE2_HI, rc->val[1] >> 8) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE3, rc->val[1]) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE4, rc->val[2]) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE5_LO, rc->val[2]));

	mt76_wr(dev, MT_WTBL_RIUCR3(dev),
		FIELD_PREP(MT_WTBL_RIUCR3_RATE5_HI, rc->val[2] >> 4) |
		FIELD_PREP(MT_WTBL_RIUCR3_RATE6, rc->val[3]) |
		FIELD_PREP(MT_WTBL_RIUCR3_RATE7, rc->val[3]));

	mt76_wr(dev, MT_WTBL_UPDATE(dev),
		FIELD_PREP(MT_WTBL_UPDATE_WLAN_IDX, rc->wcid) |
		MT_WTBL_UPDATE_RATE_UPDATE |
		MT_WTBL_UPDATE_TX_COUNT_CLEAR);

	mt76_wr(dev, addr + 27 * 4, w27);

	mt76_set(dev, MT_LPON_T0CR(dev), MT_LPON_T0CR_MODE); /* TSF read */
	rc->sta->rate_set_tsf = (mt76_rr(dev, MT_LPON_UTTR0(dev)) & ~BIT(0)) | rc->rateset;

	if (!(rc->sta->wcid.tx_info & MT_WCID_TX_INFO_SET))
		mt76_poll(dev, MT_WTBL_UPDATE(dev), MT_WTBL_UPDATE_BUSY, 0,
			  5000);

	rc->sta->rate_count = 2 * CONNAC_RATE_RETRY * rc->sta->n_rates;
	rc->sta->wcid.tx_info |= MT_WCID_TX_INFO_SET;

	return 0;
}

void connac_usb_rc_work(struct work_struct *work)
{
	struct connac_dev *dev;
	struct connac_rate_desc *rc, *tmp_rc;
	int err;

	dev = (struct connac_dev *)container_of(work, struct connac_dev,
						rc_work);

	list_for_each_entry_safe(rc, tmp_rc, &dev->rc_processing, node) {
		spin_lock_bh(&dev->mt76.lock);
		list_del(&rc->node);
		spin_unlock_bh(&dev->mt76.lock);

		err = __connac_mac_set_rates(dev, rc);
		if (err)
			dev_err(dev->mt76.dev, "something wrong in setting rate\n");

		kfree(rc);
	}
}

void connac_usb_mac_set_rates(struct connac_dev *dev, struct connac_sta *sta,
			      struct ieee80211_tx_rate *probe_rate,
			      struct ieee80211_tx_rate *rates)
{
	struct connac_rate_desc *rc_desc;
	struct ieee80211_tx_rate *ref;
	int wcid = sta->wcid.idx;
	bool stbc = false;
	int n_rates = sta->n_rates;
	u8 bw, bw_prev, bw_idx = 0;
	u16 val[4];
	u16 probe_val;
	bool rateset;
	int i, k;

	rc_desc = kzalloc(sizeof(*rc_desc), GFP_ATOMIC);
	if (!rc_desc)
		return;

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
		/* We don't support switching between short and long GI
		 * within the rate set. For accurate tx status reporting, we
		 * need to make sure that flags match.
		 * For improved performance, avoid duplicate entries by
		 * decrementing the MCS index if necessary
		 */
		if ((ref->flags ^ rates[i].flags) & IEEE80211_TX_RC_SHORT_GI)
			rates[i].flags ^= IEEE80211_TX_RC_SHORT_GI;

		for (k = 0; k < i; k++) {
			if (rates[i].idx != rates[k].idx)
				continue;
			if ((rates[i].flags ^ rates[k].flags) &
			    (IEEE80211_TX_RC_40_MHZ_WIDTH |
			     IEEE80211_TX_RC_80_MHZ_WIDTH |
			     IEEE80211_TX_RC_160_MHZ_WIDTH))
				continue;

			if (!rates[i].idx)
				continue;

			rates[i].idx--;
		}
	}

	val[0] = connac_mac_tx_rate_val(dev, &rates[0], stbc, &bw);
	bw_prev = bw;

	if (probe_rate) {
		probe_val = connac_mac_tx_rate_val(dev, probe_rate, stbc, &bw);
		if (bw)
			bw_idx = 1;
		else
			bw_prev = 0;
	} else {
		probe_val = val[0];
	}

	val[1] = connac_mac_tx_rate_val(dev, &rates[1], stbc, &bw);
	if (bw_prev) {
		bw_idx = 3;
		bw_prev = bw;
	}

	val[2] = connac_mac_tx_rate_val(dev, &rates[2], stbc, &bw);
	if (bw_prev) {
		bw_idx = 5;
		bw_prev = bw;
	}

	val[3] = connac_mac_tx_rate_val(dev, &rates[3], stbc, &bw);
	if (bw_prev)
		bw_idx = 7;

	rc_desc->wcid = wcid;
	rc_desc->bw = bw;
	rc_desc->bw_idx = bw_idx;
	rc_desc->probe_val = probe_val;
	rc_desc->sta = sta;
	rc_desc->rateset = rateset;

	for (i = 0 ; i < 4 ; i++)
		rc_desc->val[i] = val[i];

	list_add_tail(&rc_desc->node, &dev->rc_processing);

	ieee80211_queue_work(mt76_hw(dev), &dev->rc_work);
}

static enum connac_cipher_type
connac_mac_get_cipher(int cipher)
{
	switch (cipher) {
	case WLAN_CIPHER_SUITE_WEP40:
		return MT_CIPHER_WEP40;
	case WLAN_CIPHER_SUITE_WEP104:
		return MT_CIPHER_WEP104;
	case WLAN_CIPHER_SUITE_TKIP:
		return MT_CIPHER_TKIP;
	case WLAN_CIPHER_SUITE_AES_CMAC:
		return MT_CIPHER_BIP_CMAC_128;
	case WLAN_CIPHER_SUITE_CCMP:
		return MT_CIPHER_AES_CCMP;
	case WLAN_CIPHER_SUITE_CCMP_256:
		return MT_CIPHER_CCMP_256;
	case WLAN_CIPHER_SUITE_GCMP:
		return MT_CIPHER_GCMP;
	case WLAN_CIPHER_SUITE_GCMP_256:
		return MT_CIPHER_GCMP_256;
	case WLAN_CIPHER_SUITE_SMS4:
		return MT_CIPHER_WAPI;
	default:
		return MT_CIPHER_NONE;
	}
}

static int
connac_mac_wtbl_update_key(struct connac_dev *dev, struct mt76_wcid *wcid,
			   struct ieee80211_key_conf *key,
			   enum connac_cipher_type cipher,
			   enum set_key_cmd cmd)
{
	u32 addr = connac_mac_wtbl_addr(dev, wcid->idx) + 30 * 4;
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

static int
connac_mac_wtbl_update_pk(struct connac_dev *dev, struct mt76_wcid *wcid,
			  enum connac_cipher_type cipher, int keyidx,
			  enum set_key_cmd cmd)
{
	u32 addr = connac_mac_wtbl_addr(dev, wcid->idx), w0, w1;

	if (!mt76_poll(dev, MT_WTBL_UPDATE(dev), MT_WTBL_UPDATE_BUSY, 0, 5000))
		return -ETIMEDOUT;

	w0 = mt76_rr(dev, addr);
	w1 = mt76_rr(dev, addr + 4);
	if (cmd == SET_KEY) {
		w0 |= MT_WTBL_W0_RX_KEY_VALID |
		      FIELD_PREP(MT_WTBL_W0_RX_IK_VALID,
				 cipher == MT_CIPHER_BIP_CMAC_128);
		if (cipher != MT_CIPHER_BIP_CMAC_128 ||
		    !wcid->cipher)
			w0 |= FIELD_PREP(MT_WTBL_W0_KEY_IDX, keyidx);
	}  else {
		if (!(wcid->cipher & ~BIT(cipher)))
			w0 &= ~(MT_WTBL_W0_RX_KEY_VALID |
				MT_WTBL_W0_KEY_IDX);
		if (cipher == MT_CIPHER_BIP_CMAC_128)
			w0 &= ~MT_WTBL_W0_RX_IK_VALID;
	}
	mt76_wr(dev, MT_WTBL_RICR0(dev), w0);
	mt76_wr(dev, MT_WTBL_RICR1(dev), w1);

	mt76_wr(dev, MT_WTBL_UPDATE(dev),
		FIELD_PREP(MT_WTBL_UPDATE_WLAN_IDX, wcid->idx) |
		MT_WTBL_UPDATE_RXINFO_UPDATE);

	if (!mt76_poll(dev, MT_WTBL_UPDATE(dev), MT_WTBL_UPDATE_BUSY, 0, 5000))
		return -ETIMEDOUT;

	return 0;
}

static void
connac_mac_wtbl_update_cipher(struct connac_dev *dev, struct mt76_wcid *wcid,
			      enum connac_cipher_type cipher,
			      enum set_key_cmd cmd)
{
	u32 addr = connac_mac_wtbl_addr(dev, wcid->idx);

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

int connac_mac_wtbl_set_key(struct connac_dev *dev,
			    struct mt76_wcid *wcid,
			    struct ieee80211_key_conf *key,
			    enum set_key_cmd cmd)
{
	enum connac_cipher_type cipher;
	int err;

	cipher = connac_mac_get_cipher(key->cipher);
	if (cipher == MT_CIPHER_NONE)
		return -EOPNOTSUPP;

	mutex_lock(&dev->mt76.mutex);

	connac_mac_wtbl_update_cipher(dev, wcid, cipher, cmd);
	err = connac_mac_wtbl_update_key(dev, wcid, key, cipher, cmd);
	if (err < 0)
		goto out;

	err = connac_mac_wtbl_update_pk(dev, wcid, cipher, key->keyidx,
					cmd);
	if (err < 0)
		goto out;

	if (cmd == SET_KEY)
		wcid->cipher |= BIT(cipher);
	else
		wcid->cipher &= ~BIT(cipher);

out:
	mutex_unlock(&dev->mt76.mutex);

	return err;
}

int connac_tx_prepare_skb(struct mt76_dev *mdev, void *txwi_ptr,
			  enum mt76_txq_id qid, struct mt76_wcid *wcid,
			  struct ieee80211_sta *sta,
			  struct mt76_tx_info *tx_info)
{
	struct connac_dev *dev = container_of(mdev, struct connac_dev, mt76);
	struct connac_sta *msta = container_of(wcid, struct connac_sta, wcid);
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx_info->skb);
	struct ieee80211_key_conf *key = info->control.hw_key;
	int i, pid, id, nbuf = tx_info->nbuf - 1;
	u8 *txwi = (u8 *)txwi_ptr;
	struct mt76_txwi_cache *t;
	struct connac_txp *txp;
	struct txd_ptr_len *txp_ptr_len;

	if (!wcid)
		wcid = &dev->mt76.global_wcid;

	pid = mt76_tx_status_skb_add(mdev, wcid, tx_info->skb);

	if (info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE) {
		spin_lock_bh(&dev->mt76.lock);
		connac_mac_set_rates(dev, msta, &info->control.rates[0],
				     msta->rates);
		msta->rate_probe = true;
		spin_unlock_bh(&dev->mt76.lock);
	}

	connac_mac_write_txwi(dev, txwi_ptr, tx_info->skb, qid, wcid, sta,
			      pid, key);

	txp = (struct connac_txp *)(txwi + MT_TXD_SIZE);

	t = (struct mt76_txwi_cache *)(txwi + mdev->drv->txwi_size);
	t->skb = tx_info->skb;
	//t->nbuf = nbuf;

	/* Write back nbuf to minus 1, for dmad of connac only need one
	 * segment.
	 */
	tx_info->nbuf = nbuf;

	for (i = 0; i < nbuf; i++) {
		txp_ptr_len = &txp->ptr_len[i / 2];
		if ((i & 0x1) == 0x0) {
			txp_ptr_len->u4ptr0 = cpu_to_le32(tx_info->buf[i + 1].addr);
			txp_ptr_len->u2len0 = cpu_to_le16((tx_info->buf[i + 1].len & TXD_LEN_MASK_V2) | TXD_LEN_ML_V2);
		} else {
			txp_ptr_len->u4ptr1 = cpu_to_le32(tx_info->buf[i + 1].addr);
			txp_ptr_len->u2len1 = cpu_to_le16((tx_info->buf[i + 1].len & TXD_LEN_MASK_V2) | TXD_LEN_ML_V2);
		}

		spin_lock_bh(&dev->token_lock);
		id = idr_alloc(&dev->token, t, 0, CONNAC_TOKEN_SIZE,
			       GFP_ATOMIC);
		spin_unlock_bh(&dev->token_lock);
		if (id < 0)
			return id;

		txp->buf[i] = cpu_to_le16(id | TXD_MSDU_ID_VLD);
	}

	tx_info->skb = DMA_DUMMY_DATA;

	return 0;
}

int connac_usb_tx_prepare_skb(struct mt76_dev *mdev, void *txwi_ptr,
			      enum mt76_txq_id qid, struct mt76_wcid *wcid,
			      struct ieee80211_sta *sta,
			      struct mt76_tx_info *tx_info)
{
	struct connac_dev *dev = container_of(mdev, struct connac_dev, mt76);
	struct connac_sta *msta = container_of(wcid, struct connac_sta, wcid);
	int pid, err, nhead = CONNAC_USB_HDR_SIZE + CONNAC_USB_TXD_SIZE;
	struct sk_buff *skb = tx_info->skb;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_key_conf *key = info->control.hw_key;
	__le32 *usb_hdr;
	u32 pad;

	if (unlikely(skb_headroom(skb) < nhead)) {
		err = pskb_expand_head(skb, nhead, 0, GFP_ATOMIC);
		if (err < 0) {
			pr_err("err@%s %d\n", __func__, __LINE__);
			return err;
		}
	}

	txwi_ptr = (void *)(skb->data - CONNAC_USB_TXD_SIZE);

	if (!wcid)
		wcid = &dev->mt76.global_wcid;

	pid = mt76_tx_status_skb_add(mdev, wcid, skb);

	if (info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE) {
		spin_lock_bh(&dev->mt76.lock);
		connac_usb_mac_set_rates(dev, msta, &info->control.rates[0],
					 msta->rates);
		msta->rate_probe = true;
		spin_unlock_bh(&dev->mt76.lock);
	}

	connac_mac_write_txwi(dev, txwi_ptr, skb, qid, wcid, sta, pid, key);

	/* Add MAC TXD */
	skb_push(skb, CONNAC_USB_TXD_SIZE);

	/* Add USB header in the front */
	usb_hdr = (__le32 *)(skb->data - CONNAC_USB_HDR_SIZE);
	*usb_hdr = cpu_to_le32(skb->len);
	skb_push(skb, CONNAC_USB_HDR_SIZE);

	/* Add padding for 4-bytes alignment and USB trailer at the end */
	pad = (round_up(skb->len, 4) - skb->len) + CONNAC_USB_TAIL_SIZE;

	if (skb_pad(skb, pad))
		return -ENOMEM;
	__skb_put(skb, pad);

	return 0;
}

static bool connac_fill_txs(struct connac_dev *dev, struct connac_sta *sta,
			    struct ieee80211_tx_info *info, __le32 *txs_data)
{
	struct ieee80211_supported_band *sband;
	struct connac_rate_set *rs;
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

	first_idx = max_t(int, 0, last_idx - (count + 1) / CONNAC_RATE_RETRY);

	if (fixed_rate && !probe) {
		info->status.rates[0].count = count;
		i = 0;
		goto out;
	}

	rate_set_tsf = READ_ONCE(sta->rate_set_tsf);
	rs_idx = !((u32)(FIELD_GET(MT_TXS4_F0_TIMESTAMP,
			 le32_to_cpu(txs_data[4])) - rate_set_tsf) < 1000000);
	rs_idx ^= rate_set_tsf & BIT(0);
	rs = &sta->rateset[rs_idx];

	if (!first_idx && rs->probe_rate.idx >= 0) {
		info->status.rates[0] = rs->probe_rate;

		spin_lock_bh(&dev->mt76.lock);
		if (sta->rate_probe) {
			if (dev->flag & CONNAC_USB)
				connac_usb_mac_set_rates(dev, sta, NULL,
							 sta->rates);
			else
				connac_mac_set_rates(dev, sta, NULL,
						     sta->rates);
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
		cur_count = min_t(int, CONNAC_RATE_RETRY, count);
		count -= cur_count;

		if (idx && (cur_rate->idx != info->status.rates[i].idx ||
			    cur_rate->flags != info->status.rates[i].flags)) {
			i++;
			if (i == ARRAY_SIZE(info->status.rates))
				break;

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
		if (dev->mphy.chandef.chan->band == NL80211_BAND_5GHZ)
			sband = &dev->mphy.sband_5g.sband;
		else
			sband = &dev->mphy.sband_2g.sband;
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

static bool connac_mac_add_txs_skb(struct connac_dev *dev,
				   struct connac_sta *sta, int pid,
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

		if (!connac_fill_txs(dev, sta, info, txs_data)) {
			ieee80211_tx_info_clear_status(info);
			info->status.rates[0].idx = -1;
		}

		mt76_tx_status_skb_done(mdev, skb, &list);
	}
	mt76_tx_status_unlock(mdev, &list);

	return !!skb;
}

void connac_mac_add_txs(struct connac_dev *dev, void *data)
{
	struct ieee80211_tx_info info = {};
	struct ieee80211_sta *sta = NULL;
	struct connac_sta *msta = NULL;
	struct mt76_wcid *wcid;
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

	msta = container_of(wcid, struct connac_sta, wcid);
	sta = wcid_to_sta(wcid);

	if (connac_mac_add_txs_skb(dev, msta, pid, txs_data))
		goto out;

	if (wcidx >= CONNAC_WTBL_STA || !sta)
		goto out;

	if (connac_fill_txs(dev, msta, &info, txs_data))
		ieee80211_tx_status_noskb(mt76_hw(dev), sta, &info);

out:
	rcu_read_unlock();
}

void connac_mac_tx_free(struct connac_dev *dev, struct sk_buff *skb)
{
	struct connac_tx_free *free = (struct connac_tx_free *)skb->data;
	struct mt76_dev *mdev = &dev->mt76;
	struct mt76_txwi_cache *txwi;
	int token_id;
	u8 i, count;

	count = FIELD_GET(MT_TX_FREE_MSDU_ID_CNT, le16_to_cpu(free->ctrl));

	for (i = 0; i < count; i++) {
		spin_lock_bh(&dev->token_lock);
		token_id = (free->token[i] & 0xffff);
		txwi = idr_remove(&dev->token, token_id);
		spin_unlock_bh(&dev->token_lock);

		if (!txwi)
			continue;

		connac_txp_skb_unmap(mdev, txwi);
		if (txwi->skb) {
			mt76_tx_complete_skb(mdev, txwi->skb);
			txwi->skb = NULL;
		}

		mt76_put_txwi(mdev, txwi);
	}
	dev_kfree_skb(skb);
}

void connac_mac_cca_stats_reset(struct connac_dev *dev)
{
	mt76_clear(dev, MT_WF_PHY_R0_B0_PHYMUX_5(dev), GENMASK(22, 20));
	mt76_set(dev, MT_WF_PHY_R0_B0_PHYMUX_5(dev), BIT(22) | BIT(20));
}

void connac_update_channel(struct mt76_dev *mdev)
{
	struct connac_dev *dev = container_of(mdev, struct connac_dev, mt76);
	struct mt76_channel_state *state;
	u64 busy_time, tx_time, rx_time, obss_time;

	/* Todo for USB for fixing up scheduling while atomic */
	if (dev->flag & CONNAC_USB)
		return;

	/* TODO: add DBDC support */
	busy_time = mt76_get_field(dev, MT_MIB_SDR9(dev, 0),
				   MT_MIB_SDR9_BUSY_MASK);
	tx_time = mt76_get_field(dev, MT_MIB_SDR36(dev, 0),
				 MT_MIB_SDR36_TXTIME_MASK);
	rx_time = mt76_get_field(dev, MT_MIB_SDR37(dev, 0),
				 MT_MIB_SDR37_RXTIME_MASK);
	obss_time = mt76_get_field(dev, MT_WF_RMAC_MIB_TIME5(dev),
				   MT_MIB_OBSSTIME_MASK);

	state = mdev->phy.chan_state;
	state->cc_busy += busy_time;
	state->cc_tx += tx_time;
	state->cc_rx += rx_time + obss_time;
	state->cc_bss_rx += rx_time;

	/* reset obss airtime */
	mt76_set(dev, MT_WF_RMAC_MIB_TIME0(dev), MT_WF_RMAC_MIB_RXTIME_CLR);
}

void connac_mac_work(struct work_struct *work)
{
	struct connac_dev *dev;

	dev = (struct connac_dev *)container_of(work, struct mt76_dev,
						mac_work.work);

	mutex_lock(&dev->mt76.mutex);
	connac_update_channel(&dev->mt76);
	if (++dev->mac_work_count == 5) {
#if 0	/* connac TBD */
		connac_mac_scs_check(dev);
#endif
		dev->mac_work_count = 0;
	}
	mutex_unlock(&dev->mt76.mutex);

	mt76_tx_status_check(&dev->mt76, NULL, false);
	ieee80211_queue_delayed_work(mt76_hw(dev), &dev->mt76.mac_work,
				     CONNAC_WATCHDOG_TIME);
}

int connac_dfs_stop_radar_detector(struct connac_dev *dev)
{
	struct cfg80211_chan_def *chandef = &dev->mphy.chandef;
	int err;

	err = connac_mcu_rdd_cmd(dev, RDD_STOP, MT_HW_RDD0,
				 MT_RX_SEL0, 0);
	if (err < 0)
		return err;

	if (chandef->width == NL80211_CHAN_WIDTH_160 ||
	    chandef->width == NL80211_CHAN_WIDTH_80P80)
		err = connac_mcu_rdd_cmd(dev, RDD_STOP, MT_HW_RDD1,
					 MT_RX_SEL0, 0);
	return err;
}

static int connac_dfs_start_rdd(struct connac_dev *dev, int chain)
{
	int err;

	err = connac_mcu_rdd_cmd(dev, RDD_START, chain, MT_RX_SEL0, 0);
	if (err < 0)
		return err;

	return connac_mcu_rdd_cmd(dev, RDD_DET_MODE, chain,
				  MT_RX_SEL0, 1);
}

int connac_dfs_start_radar_detector(struct connac_dev *dev)
{
	struct cfg80211_chan_def *chandef = &dev->mphy.chandef;
	int err;

	/* start CAC */
	err = connac_mcu_rdd_cmd(dev, RDD_CAC_START, MT_HW_RDD0,
				 MT_RX_SEL0, 0);
	if (err < 0)
		return err;

	/* TODO: DBDC support */

	err = connac_dfs_start_rdd(dev, MT_HW_RDD0);
	if (err < 0)
		return err;

	if (chandef->width == NL80211_CHAN_WIDTH_160 ||
	    chandef->width == NL80211_CHAN_WIDTH_80P80) {
		err = connac_dfs_start_rdd(dev, MT_HW_RDD1);
		if (err < 0)
			return err;
	}

	return 0;
}

int connac_dfs_init_radar_detector(struct connac_dev *dev)
{
	struct cfg80211_chan_def *chandef = &dev->mphy.chandef;
	int err;

	if (dev->mt76.region == NL80211_DFS_UNSET)
		return 0;

	if (test_bit(MT76_SCANNING, &dev->mphy.state))
		return 0;

	if (dev->dfs_state == chandef->chan->dfs_state)
		return 0;

	dev->dfs_state = chandef->chan->dfs_state;

	if (chandef->chan->flags & IEEE80211_CHAN_RADAR) {
		if (chandef->chan->dfs_state != NL80211_DFS_AVAILABLE)
			return connac_dfs_start_radar_detector(dev);
		else
			return connac_mcu_rdd_cmd(dev, RDD_CAC_END, MT_HW_RDD0,
						  MT_RX_SEL0, 0);
	} else {
		err = connac_mcu_rdd_cmd(dev, RDD_NORMAL_START,
					 MT_HW_RDD0, MT_RX_SEL0, 0);
		if (err < 0)
			return err;

		return connac_dfs_stop_radar_detector(dev);
	}
}
