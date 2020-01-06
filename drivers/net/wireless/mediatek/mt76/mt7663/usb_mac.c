// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Felix Fietkau <nbd@nbd.name>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "mt7663.h"
#include "mac.h"
#include "usb_sdio_regs.h"

static u32 mt7663u_mac_wtbl_addr(struct mt7663_dev *dev, int wcid)
{
	return MT_WTBL(0) + wcid * MT_WTBL_ENTRY_SIZE;
}

int __mt7663u_mac_set_rates(struct mt7663_dev *dev,
			    struct mt7663_rate_desc *rc)
{
	u32 addr = mt7663u_mac_wtbl_addr(dev, rc->wcid);
	u32 w5, w27;

	if (!mt76_poll(dev, MT_WTBL_UPDATE, MT_WTBL_UPDATE_BUSY, 0, 5000))
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

	mt76_wr(dev, MT_WTBL_RIUCR0, w5);

	mt76_wr(dev, MT_WTBL_RIUCR1,
		FIELD_PREP(MT_WTBL_RIUCR1_RATE0, rc->probe_val) |
		FIELD_PREP(MT_WTBL_RIUCR1_RATE1, rc->val[0]) |
		FIELD_PREP(MT_WTBL_RIUCR1_RATE2_LO, rc->val[1]));

	mt76_wr(dev, MT_WTBL_RIUCR2,
		FIELD_PREP(MT_WTBL_RIUCR2_RATE2_HI, rc->val[1] >> 8) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE3, rc->val[1]) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE4, rc->val[2]) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE5_LO, rc->val[2]));

	mt76_wr(dev, MT_WTBL_RIUCR3,
		FIELD_PREP(MT_WTBL_RIUCR3_RATE5_HI, rc->val[2] >> 4) |
		FIELD_PREP(MT_WTBL_RIUCR3_RATE6, rc->val[3]) |
		FIELD_PREP(MT_WTBL_RIUCR3_RATE7, rc->val[3]));

	mt76_wr(dev, MT_WTBL_UPDATE,
		FIELD_PREP(MT_WTBL_UPDATE_WLAN_IDX, rc->wcid) |
		MT_WTBL_UPDATE_RATE_UPDATE |
		MT_WTBL_UPDATE_TX_COUNT_CLEAR);

	mt76_wr(dev, addr + 27 * 4, w27);

	mt76_set(dev, MT_LPON_T0CR, MT_LPON_T0CR_MODE); /* TSF read */
	rc->sta->rate_set_tsf = mt76_rr(dev, MT_LPON_UTTR0) & ~BIT(0);
	rc->sta->rate_set_tsf |= rc->rateset;

	if (!(rc->sta->wcid.tx_info & MT_WCID_TX_INFO_SET))
		mt76_poll(dev, MT_WTBL_UPDATE, MT_WTBL_UPDATE_BUSY, 0, 5000);

	rc->sta->rate_count = 2 * MT7663_RATE_RETRY * rc->sta->n_rates;
	rc->sta->wcid.tx_info |= MT_WCID_TX_INFO_SET;

	return 0;
}

void mt7663u_mac_cca_stats_reset(struct mt7663_dev *dev)
{
	mt76_clear(dev, MT_WF_PHY_R0_B0_PHYMUX_5, GENMASK(22, 20));
	mt76_set(dev, MT_WF_PHY_R0_B0_PHYMUX_5, BIT(22) | BIT(20));
}

void mt7663u_mac_write_txwi(struct mt7663_dev *dev, struct mt76_wcid *wcid,
			    enum mt76_txq_id qid, struct ieee80211_sta *sta,
			    struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	__le32 *txwi;
	int pid;

	if (!wcid)
		wcid = &dev->mt76.global_wcid;

	pid = mt76_tx_status_skb_add(&dev->mt76, wcid, skb);

	txwi = (__le32 *)(skb->data - MT7663_USB_TXD_SIZE);
	memset(txwi, 0, MT7663_USB_TXD_SIZE);
	mt7663_mac_write_txwi(dev, txwi, skb, qid, wcid, sta,
			      pid, info->control.hw_key);
	skb_push(skb, MT7663_USB_TXD_SIZE);
}

static int
mt7663u_mac_wtbl_update_pk(struct mt7663_dev *dev, struct mt76_wcid *wcid,
			   enum mt7663_cipher_type cipher, int keyidx,
			   enum set_key_cmd cmd)
{
	u32 addr = mt7663u_mac_wtbl_addr(dev, wcid->idx), w0, w1;

	if (!mt76_poll(dev, MT_WTBL_UPDATE, MT_WTBL_UPDATE_BUSY, 0, 5000))
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
	mt76_wr(dev, MT_WTBL_RICR0, w0);
	mt76_wr(dev, MT_WTBL_RICR1, w1);

	mt76_wr(dev, MT_WTBL_UPDATE,
		FIELD_PREP(MT_WTBL_UPDATE_WLAN_IDX, wcid->idx) |
		MT_WTBL_UPDATE_RXINFO_UPDATE);

	if (!mt76_poll(dev, MT_WTBL_UPDATE, MT_WTBL_UPDATE_BUSY, 0, 5000))
		return -ETIMEDOUT;

	return 0;
}

int mt7663u_mac_wtbl_set_key(struct mt7663_dev *dev,
			     struct mt76_wcid *wcid,
			     struct ieee80211_key_conf *key,
			     enum set_key_cmd cmd)
{
	u32 addr = mt7663u_mac_wtbl_addr(dev, wcid->idx);
	enum mt7663_cipher_type cipher;
	int err;

	cipher = mt7663_mac_get_cipher(key->cipher);
	if (cipher == MT_CIPHER_NONE)
		return -EOPNOTSUPP;

	mutex_lock(&dev->mt76.mutex);

	mt7663_mac_wtbl_update_cipher(dev, wcid, addr, cipher, cmd);
	err = mt7663_mac_wtbl_update_key(dev, wcid, addr, key, cipher, cmd);
	if (err < 0)
		goto out;

	err = mt7663u_mac_wtbl_update_pk(dev, wcid, cipher, key->keyidx, cmd);
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
