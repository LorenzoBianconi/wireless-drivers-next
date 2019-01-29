// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 *         Roy Luo <roychl666@gmail.com>
 */

#include <linux/etherdevice.h>
#include <linux/timekeeping.h>
#include "mt7615.h"
#include "mac.h"

int mt7615_mac_fill_rx(struct mt7615_dev *dev, struct sk_buff *skb)
{
	__le32 *rxd = (__le32 *)skb->data;
	u32 rxd0 = le32_to_cpu(rxd[0]);
	u32 rxd1 = le32_to_cpu(rxd[1]);
	bool remove_pad;

	remove_pad = rxd1 & MT_RXD1_NORMAL_HDR_OFFSET;

	rxd += 4;
	if (rxd0 & MT_RXD0_NORMAL_GROUP_4) {
		rxd += 4;
		if ((u8 *)rxd - skb->data >= skb->len)
			return -EINVAL;
	}

	if (rxd0 & MT_RXD0_NORMAL_GROUP_1) {
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
		rxd += 6;
		if ((u8 *)rxd - skb->data >= skb->len)
			return -EINVAL;
	}

	skb_pull(skb, (u8 *)rxd - skb->data + 2 * remove_pad);

	return 0;
}

int mt7615_tx_prepare_skb(struct mt76_dev *mdev, void *txwi_ptr,
			  struct sk_buff *skb, struct mt76_queue *q,
			  struct mt76_wcid *wcid, struct ieee80211_sta *sta,
			  u32 *tx_info)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_key_conf *key = info->control.hw_key;

	/* TODO: complete tx path */
	mt7615_mac_write_txwi(dev, txwi_ptr, skb, wcid, sta, key);

	return 0;
}

void mt7615_sta_ps(struct mt76_dev *mdev, struct ieee80211_sta *sta, bool ps)
{
}

static u16 mt7615_mac_tx_rate_val(struct mt7615_dev *dev,
				  const struct ieee80211_tx_rate *rate,
				  bool stbc, u8 *bw)
{
	u8 phy, nss, rate_idx;
	u16 rateval;

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
		int band = dev->mt76.chandef.chan->band;
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

	rateval = (FIELD_PREP(MT_TX_RATE_IDX, rate_idx) |
		   FIELD_PREP(MT_TX_RATE_MODE, phy));

	if (stbc && nss == 1)
		rateval |= MT_TX_RATE_STBC;

	return rateval;
}

int mt7615_mac_write_txwi(struct mt7615_dev *dev, __le32 *txwi,
			  struct sk_buff *skb, struct mt76_wcid *wcid,
			  struct ieee80211_sta *sta,
			  struct ieee80211_key_conf *key)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_tx_rate *rate = &info->control.rates[0];
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct ieee80211_vif *vif = info->control.vif;
	int tx_count = 8;
	u8 fc_type, fc_stype, p_fmt, q_idx, omac_idx = 0;
	u16 fc = le16_to_cpu(hdr->frame_control);
	u32 val;

	if (vif) {
		struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;

		omac_idx = mvif->omac_idx;
	}

	fc_type = (fc & IEEE80211_FCTL_FTYPE) >> 2;
	fc_stype = (fc & IEEE80211_FCTL_STYPE) >> 4;

	if (ieee80211_is_data(fc)) {
		q_idx = skb_get_queue_mapping(skb);
		p_fmt = MT_TX_TYPE_CT;
	} else if (ieee80211_is_beacon(fc)) {
		q_idx = MT_LMAC_BCN0;
		p_fmt = MT_TX_TYPE_FW;
	} else {
		q_idx = MT_LMAC_ALTX0;
		p_fmt = MT_TX_TYPE_CT;
	}

	val = FIELD_PREP(MT_TXD0_TX_BYTES, skb->len + MT_TXD_SIZE) |
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

	val = MT_TXD2_FIX_RATE |
	      FIELD_PREP(MT_TXD2_FRAME_TYPE, fc_type) |
	      FIELD_PREP(MT_TXD2_SUB_TYPE, fc_stype) |
	      FIELD_PREP(MT_TXD2_MULTICAST,
			 is_multicast_ether_addr(hdr->addr1));
	txwi[2] = cpu_to_le32(val);

	if (!(info->flags & IEEE80211_TX_CTL_AMPDU))
		txwi[2] |= cpu_to_le32(MT_TXD2_BA_DISABLE);

	txwi[4] = 0;
	txwi[6] = 0;

	/* TODO: support non-fixed rate */
	if (rate->idx >= 0 && rate->count &&
	    !(info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE)) {
		bool stbc = info->flags & IEEE80211_TX_CTL_STBC;
		u8 bw;
		u16 rateval = mt7615_mac_tx_rate_val(dev, rate, stbc, &bw);

		val = MT_TXD6_FIXED_BW |
		      FIELD_PREP(MT_TXD6_BW, bw) |
		      FIELD_PREP(MT_TXD6_TX_RATE, rateval);
		txwi[6] |= cpu_to_le32(val);

		if (rate->flags & IEEE80211_TX_RC_SHORT_GI)
			txwi[6] |= cpu_to_le32(MT_TXD6_SGI);

		if (!(rate->flags & IEEE80211_TX_RC_MCS))
			txwi[2] |= cpu_to_le32(MT_TXD2_BA_DISABLE);

		tx_count = rate->count;
	}

	if (!ieee80211_is_beacon(fc)) {
		txwi[5] = cpu_to_le32(MT_TXD5_SW_POWER_MGMT);
	} else {
		txwi[5] = 0;
		/* use maximum tx count for beacons */
		tx_count = 0x1f;
	}

	txwi[3] = cpu_to_le32(FIELD_PREP(MT_TXD3_REM_TX_COUNT, tx_count));

	if (info->flags & IEEE80211_TX_CTL_NO_ACK)
		txwi[3] |= cpu_to_le32(MT_TXD3_NO_ACK);

	if (key)
		txwi[3] |= cpu_to_le32(MT_TXD3_PROTECT_FRAME);

	txwi[7] = 0;

	return 0;
}

static int mt7615_token_enqueue(struct mt7615_dev *dev, struct sk_buff *skb)
{
	struct mt7615_token_queue *q = &dev->tkq;
	u16 token;

	token = q->id[q->head];

	if (q->queued == q->ntoken || token == q->used)
		return -ENOSPC;

	q->id[q->head] = q->used;
	q->skb[token] = skb;

	q->head = (q->head + 1) % q->ntoken;
	q->queued++;

	return token;
}

static struct sk_buff *mt7615_token_dequeue(struct mt7615_dev *dev, u16 token)
{
	struct mt7615_token_queue *q = &dev->tkq;
	struct sk_buff *skb;

	if (!q->queued)
		return NULL;

	skb = q->skb[token];

	q->id[q->tail] = token;
	q->skb[token] = NULL;

	q->tail = (q->tail + 1) % q->ntoken;
	q->queued--;

	return skb;
}

int mt7615_tx_prepare_txp(struct mt76_dev *mdev, void *txwi_ptr,
			  struct sk_buff *skb, struct mt76_queue_buf *buf,
			  int nbufs)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_key_conf *key = info->control.hw_key;
	struct ieee80211_vif *vif = info->control.vif;
	struct mt7615_txp *txp = (struct mt7615_txp *)((__le32 *)txwi_ptr + 8);
	int i, token;

	/* first buffer is preserved for txd */
	if (nbufs - 1 > MT_TXP_MAX_BUF_NUM)
		return -ENOSPC;

	token = mt7615_token_enqueue(dev, skb);
	if (token < 0)
		return token;

	memset(txp, 0, sizeof(struct mt7615_txp));

	txp->flags = cpu_to_le16(MT_CT_INFO_APPLY_TXD);
	if (!key)
		txp->flags |= cpu_to_le16(MT_CT_INFO_NONE_CIPHER_FRAME);

	if (ieee80211_is_mgmt(hdr->frame_control) &&
	    !ieee80211_is_beacon(hdr->frame_control))
		txp->flags |= cpu_to_le16(MT_CT_INFO_MGMT_FRAME);

	if (vif) {
		struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;

		txp->bss_idx = mvif->idx;
	}

	txp->token = cpu_to_le16(token);
	txp->rept_wds_wcid = 0xff;
	txp->nbuf = nbufs - 1;

	for (i = 1; i < nbufs; i++) {
		txp->buf[i - 1] = cpu_to_le32(buf[i].addr);
		txp->len[i - 1] = cpu_to_le16(buf[i].len);
	}

	return 0;
}

static void mt7615_skb_done(struct mt7615_dev *dev, struct sk_buff *skb,
			    u8 flags)
{
	struct mt76_tx_cb *cb = mt76_tx_skb_cb(skb);
	u8 done = MT_TX_CB_DMA_DONE | MT_TX_CB_TX_FREE;

	flags |= cb->flags;
	cb->flags = flags;

	if ((flags & done) != done)
		return;

	ieee80211_tx_status(mt76_hw(dev), skb);
}

void mt7615_tx_complete_skb(struct mt76_dev *mdev, struct mt76_queue *q,
			    struct mt76_queue_entry *e, bool flush)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	struct sk_buff *skb = e->skb;
	bool free = true;

	if (!e->txwi) {
		dev_kfree_skb_any(skb);
		return;
	}

	if (!flush) {
		/* TODO: need a lock */
		mt7615_skb_done(dev, skb, MT_TX_CB_DMA_DONE);
		free = false;
	}

	if (free)
		ieee80211_free_txskb(mdev->hw, skb);
}

void mt7615_mac_tx_free(struct mt7615_dev *dev, struct sk_buff *skb)
{
	struct mt7615_tx_free *free;
	u8 i, cnt;

	free = (struct mt7615_tx_free *)skb->data;
	cnt = FIELD_GET(MT_TX_FREE_MSDU_ID_CNT, le16_to_cpu(free->ctrl));

	for (i = 0; i < cnt; i++) {
		struct sk_buff *skb;

		skb = mt7615_token_dequeue(dev, le16_to_cpu(free->token[i]));
		if (!skb)
			continue;

		spin_lock_bh(&dev->token_lock);
		mt7615_skb_done(dev, skb, MT_TX_CB_TX_FREE);
		spin_unlock_bh(&dev->token_lock);
	}

	dev_kfree_skb(skb);
}
