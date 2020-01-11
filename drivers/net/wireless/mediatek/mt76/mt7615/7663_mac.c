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

#include "mt7615.h"
#include "../dma.h"
#include "regs.h"
#include "mac.h"

static inline s8 to_rssi(u32 field, u32 rxv)
{
	return (FIELD_GET(field, rxv) - 220) / 2;
}

static struct mt76_wcid *
mt7663_rx_get_wcid(struct mt7615_dev *dev,
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

int mt7663_mac_fill_rx(struct mt7615_dev *dev, struct sk_buff *skb)
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
	status->wcid = mt7663_rx_get_wcid(dev, idx, unicast);

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

static bool mt7663_fill_txs(struct mt7615_dev *dev, struct mt7615_sta *sta,
			    struct ieee80211_tx_info *info, __le32 *txs_data)
{
	struct ieee80211_supported_band *sband;
	struct mt7615_rate_set *rs;
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
	rs_idx = !((u32)(FIELD_GET(MT_TXS4_F0_TIMESTAMP,
			 le32_to_cpu(txs_data[4])) - rate_set_tsf) < 1000000);
	rs_idx ^= rate_set_tsf & BIT(0);
	rs = &sta->rateset[rs_idx];

	if (!first_idx && rs->probe_rate.idx >= 0) {
		info->status.rates[0] = rs->probe_rate;

		spin_lock_bh(&dev->mt76.lock);
		if (sta->rate_probe) {
			mt7615_mac_set_rates(&dev->phy, sta, NULL, sta->rates);
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

static bool mt7663_mac_add_txs_skb(struct mt7615_dev *dev,
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

		if (!mt7663_fill_txs(dev, sta, info, txs_data)) {
			ieee80211_tx_info_clear_status(info);
			info->status.rates[0].idx = -1;
		}

		mt76_tx_status_skb_done(mdev, skb, &list);
	}
	mt76_tx_status_unlock(mdev, &list);

	return !!skb;
}

void mt7663_mac_add_txs(struct mt7615_dev *dev, void *data)
{
	struct ieee80211_tx_info info = {};
	struct ieee80211_sta *sta = NULL;
	struct mt7615_sta *msta = NULL;
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

	msta = container_of(wcid, struct mt7615_sta, wcid);
	sta = wcid_to_sta(wcid);

	if (mt7663_mac_add_txs_skb(dev, msta, pid, txs_data))
		goto out;

	if (wcidx >= MT7615_WTBL_STA || !sta)
		goto out;

	if (mt7663_fill_txs(dev, msta, &info, txs_data))
		ieee80211_tx_status_noskb(mt76_hw(dev), sta, &info);

out:
	rcu_read_unlock();
}
