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
#include "mt7615.h"
#include "7663_mac.h"
#include "usb_sdio_regs.h"

static u32 mt7663u_mac_wtbl_addr(struct mt7615_dev *dev, int wcid)
{
	return MT_WTBL(0) + wcid * MT_WTBL_ENTRY_SIZE;
}

void mt7663u_update_channel(struct mt76_dev *mdev)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	u64 busy_time, tx_time, rx_time, obss_time;
	struct mt76_channel_state *state;

	busy_time = mt76_get_field(dev, MT_MIB_SDR9(0), MT_MIB_SDR9_BUSY_MASK);
	tx_time = mt76_get_field(dev, MT_MIB_SDR36(0),
				 MT_MIB_SDR36_TXTIME_MASK);
	rx_time = mt76_get_field(dev, MT_MIB_SDR37(0),
				 MT_MIB_SDR37_RXTIME_MASK);
	obss_time = mt76_get_field(dev, MT_WF_RMAC_MIB_TIME5,
				   MT_MIB_OBSSTIME_MASK);

	state = mdev->phy.chan_state;
	state->cc_busy += busy_time;
	state->cc_tx += tx_time;
	state->cc_rx += rx_time + obss_time;
	state->cc_bss_rx += rx_time;

	/* reset obss airtime */
	mt76_set(dev, MT_WF_RMAC_MIB_TIME0, MT_WF_RMAC_MIB_RXTIME_CLR);
}

void mt7663u_mac_work(struct work_struct *work)
{
	struct mt7615_dev *dev;

	dev = (struct mt7615_dev *)container_of(work, struct mt76_dev,
						mac_work.work);

	mutex_lock(&dev->mt76.mutex);
	mt7663u_update_channel(&dev->mt76);
	mutex_unlock(&dev->mt76.mutex);

	mt76_tx_status_check(&dev->mt76, NULL, false);
	ieee80211_queue_delayed_work(mt76_hw(dev), &dev->mt76.mac_work,
				     MT7663_WATCHDOG_TIME);
}

int __mt7663u_mac_set_rates(struct mt7615_dev *dev,
			    struct mt7615_rate_desc *rd)
{
	u32 addr = mt7663u_mac_wtbl_addr(dev, rd->wcid);
	u32 w5, w27;

	if (!mt76_poll(dev, MT_WTBL_UPDATE, MT_WTBL_UPDATE_BUSY, 0, 5000))
		return -ETIMEDOUT;

	w27 = mt76_rr(dev, addr + 27 * 4);
	w27 &= ~MT_WTBL_W27_CC_BW_SEL;
	w27 |= FIELD_PREP(MT_WTBL_W27_CC_BW_SEL, rd->bw);

	w5 = mt76_rr(dev, addr + 5 * 4);
	w5 &= ~(MT_WTBL_W5_BW_CAP | MT_WTBL_W5_CHANGE_BW_RATE |
		MT_WTBL_W5_MPDU_OK_COUNT |
		MT_WTBL_W5_MPDU_FAIL_COUNT |
		MT_WTBL_W5_RATE_IDX);
	w5 |= FIELD_PREP(MT_WTBL_W5_BW_CAP, rd->bw) |
	      FIELD_PREP(MT_WTBL_W5_CHANGE_BW_RATE,
			 rd->bw_idx ? rd->bw_idx - 1 : 7);

	mt76_wr(dev, MT_WTBL_RIUCR0, w5);

	mt76_wr(dev, MT_WTBL_RIUCR1,
		FIELD_PREP(MT_WTBL_RIUCR1_RATE0, rd->probe_val) |
		FIELD_PREP(MT_WTBL_RIUCR1_RATE1, rd->val[0]) |
		FIELD_PREP(MT_WTBL_RIUCR1_RATE2_LO, rd->val[1]));

	mt76_wr(dev, MT_WTBL_RIUCR2,
		FIELD_PREP(MT_WTBL_RIUCR2_RATE2_HI, rd->val[1] >> 8) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE3, rd->val[1]) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE4, rd->val[2]) |
		FIELD_PREP(MT_WTBL_RIUCR2_RATE5_LO, rd->val[2]));

	mt76_wr(dev, MT_WTBL_RIUCR3,
		FIELD_PREP(MT_WTBL_RIUCR3_RATE5_HI, rd->val[2] >> 4) |
		FIELD_PREP(MT_WTBL_RIUCR3_RATE6, rd->val[3]) |
		FIELD_PREP(MT_WTBL_RIUCR3_RATE7, rd->val[3]));

	mt76_wr(dev, MT_WTBL_UPDATE,
		FIELD_PREP(MT_WTBL_UPDATE_WLAN_IDX, rd->wcid) |
		MT_WTBL_UPDATE_RATE_UPDATE |
		MT_WTBL_UPDATE_TX_COUNT_CLEAR);

	mt76_wr(dev, addr + 27 * 4, w27);

	mt76_set(dev, MT_LPON_T0CR, MT_LPON_T0CR_MODE); /* TSF read */
	rd->sta->rate_set_tsf = mt76_rr(dev, MT_LPON_UTTR0) & ~BIT(0);
	rd->sta->rate_set_tsf |= rd->rateset;

	if (!(rd->sta->wcid.tx_info & MT_WCID_TX_INFO_SET))
		mt76_poll(dev, MT_WTBL_UPDATE, MT_WTBL_UPDATE_BUSY, 0, 5000);

	rd->sta->rate_count = 2 * MT7663_RATE_RETRY * rd->sta->n_rates;
	rd->sta->wcid.tx_info |= MT_WCID_TX_INFO_SET;

	return 0;
}

void mt7663u_mac_cca_stats_reset(struct mt7615_dev *dev)
{
	mt76_clear(dev, MT_WF_PHY_R0_B0_PHYMUX_5, GENMASK(22, 20));
	mt76_set(dev, MT_WF_PHY_R0_B0_PHYMUX_5, BIT(22) | BIT(20));
}

void mt7663u_mac_write_txwi(struct mt7615_dev *dev, struct mt76_wcid *wcid,
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
mt7663u_mac_wtbl_update_pk(struct mt7615_dev *dev, struct mt76_wcid *wcid,
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

int mt7663u_mac_wtbl_set_key(struct mt7615_dev *dev,
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
