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

void mt7615_mac_reset_counters(struct mt7615_dev *dev)
{
	int i;

	for (i = 0; i < 4; i++)
		mt76_rr(dev, MT_TX_AGG_CNT(i));

	memset(dev->mt76.aggr_stats, 0, sizeof(dev->mt76.aggr_stats));
	dev->mt76.phy.survey_time = ktime_get_boottime();
	if (dev->mt76.phy2)
		dev->mt76.phy2->survey_time = ktime_get_boottime();

	/* reset airtime counters */
	mt76_rr(dev, MT_MIB_SDR9(0));
	mt76_rr(dev, MT_MIB_SDR9(1));

	mt76_rr(dev, MT_MIB_SDR36(0));
	mt76_rr(dev, MT_MIB_SDR36(1));

	mt76_rr(dev, MT_MIB_SDR37(0));
	mt76_rr(dev, MT_MIB_SDR37(1));

	mt76_set(dev, MT_WF_RMAC_MIB_TIME0, MT_WF_RMAC_MIB_RXTIME_CLR);
	mt76_set(dev, MT_WF_RMAC_MIB_AIRTIME0, MT_WF_RMAC_MIB_RXTIME_CLR);
}

void mt7615_mac_set_timing(struct mt7615_phy *phy)
{
	s16 coverage_class = phy->coverage_class;
	struct mt7615_dev *dev = phy->dev;
	bool ext_phy = phy != &dev->phy;
	u32 val, reg_offset;
	u32 cck = FIELD_PREP(MT_TIMEOUT_VAL_PLCP, 231) |
		  FIELD_PREP(MT_TIMEOUT_VAL_CCA, 48);
	u32 ofdm = FIELD_PREP(MT_TIMEOUT_VAL_PLCP, 60) |
		   FIELD_PREP(MT_TIMEOUT_VAL_CCA, 24);
	int sifs, offset;

	if (phy->mt76->chandef.chan->band == NL80211_BAND_5GHZ)
		sifs = 16;
	else
		sifs = 10;

	if (ext_phy) {
		coverage_class = max_t(s16, dev->phy.coverage_class,
				       coverage_class);
		mt76_set(dev, MT_ARB_SCR,
			 MT_ARB_SCR_TX1_DISABLE | MT_ARB_SCR_RX1_DISABLE);
	} else {
		struct mt7615_phy *phy_ext = mt7615_ext_phy(dev);

		if (phy_ext)
			coverage_class = max_t(s16, phy_ext->coverage_class,
					       coverage_class);
		mt76_set(dev, MT_ARB_SCR,
			 MT_ARB_SCR_TX0_DISABLE | MT_ARB_SCR_RX0_DISABLE);
	}
	udelay(1);

	offset = 3 * coverage_class;
	reg_offset = FIELD_PREP(MT_TIMEOUT_VAL_PLCP, offset) |
		     FIELD_PREP(MT_TIMEOUT_VAL_CCA, offset);
	mt76_wr(dev, MT_TMAC_CDTR, cck + reg_offset);
	mt76_wr(dev, MT_TMAC_ODTR, ofdm + reg_offset);

	mt76_wr(dev, MT_TMAC_ICR(ext_phy),
		FIELD_PREP(MT_IFS_EIFS, 360) |
		FIELD_PREP(MT_IFS_RIFS, 2) |
		FIELD_PREP(MT_IFS_SIFS, sifs) |
		FIELD_PREP(MT_IFS_SLOT, phy->slottime));

	if (phy->slottime < 20)
		val = MT7615_CFEND_RATE_DEFAULT;
	else
		val = MT7615_CFEND_RATE_11B;

	mt76_rmw_field(dev, MT_AGG_ACR(ext_phy), MT_AGG_ACR_CFEND_RATE, val);
	if (ext_phy)
		mt76_clear(dev, MT_ARB_SCR,
			   MT_ARB_SCR_TX1_DISABLE | MT_ARB_SCR_RX1_DISABLE);
	else
		mt76_clear(dev, MT_ARB_SCR,
			   MT_ARB_SCR_TX0_DISABLE | MT_ARB_SCR_RX0_DISABLE);

}

void mt7615_tx_complete_skb(struct mt76_dev *mdev, enum mt76_txq_id qid,
			    struct mt76_queue_entry *e)
{
	if (!e->txwi) {
		dev_kfree_skb_any(e->skb);
		return;
	}

	/* error path */
	if (e->skb == DMA_DUMMY_DATA) {
		struct mt76_txwi_cache *t;
		struct mt7615_dev *dev;
		struct mt7615_txp *txp;

		dev = container_of(mdev, struct mt7615_dev, mt76);
		txp = mt7615_txwi_to_txp(mdev, e->txwi);

		spin_lock_bh(&dev->token_lock);
		t = idr_remove(&dev->token, le16_to_cpu(txp->token));
		spin_unlock_bh(&dev->token_lock);
		e->skb = t ? t->skb : NULL;
	}

	if (e->skb)
		mt76_tx_complete_skb(mdev, e->skb);
}

bool mt7615_mac_wtbl_update(struct mt7615_dev *dev, int idx, u32 mask)
{
	mt76_rmw(dev, MT_WTBL_UPDATE, MT_WTBL_UPDATE_WLAN_IDX,
		 FIELD_PREP(MT_WTBL_UPDATE_WLAN_IDX, idx) | mask);

	return mt76_poll(dev, MT_WTBL_UPDATE, MT_WTBL_UPDATE_BUSY,
			 0, 5000);
}

void mt7615_mac_sta_poll(struct mt7615_dev *dev)
{
	static const u8 ac_to_tid[4] = {
		[IEEE80211_AC_BE] = 0,
		[IEEE80211_AC_BK] = 1,
		[IEEE80211_AC_VI] = 4,
		[IEEE80211_AC_VO] = 6
	};
	static const u8 hw_queue_map[] = {
		[IEEE80211_AC_BK] = 0,
		[IEEE80211_AC_BE] = 1,
		[IEEE80211_AC_VI] = 2,
		[IEEE80211_AC_VO] = 3,
	};
	struct ieee80211_sta *sta;
	struct mt7615_sta *msta;
	u32 addr, tx_time[4], rx_time[4];
	int i;

	rcu_read_lock();

	while (true) {
		bool clear = false;

		spin_lock_bh(&dev->sta_poll_lock);
		if (list_empty(&dev->sta_poll_list)) {
			spin_unlock_bh(&dev->sta_poll_lock);
			break;
		}
		msta = list_first_entry(&dev->sta_poll_list,
					struct mt7615_sta, poll_list);
		list_del_init(&msta->poll_list);
		spin_unlock_bh(&dev->sta_poll_lock);

		addr = mt7615_mac_wtbl_addr(msta->wcid.idx) + 19 * 4;

		for (i = 0; i < 4; i++, addr += 8) {
			u32 tx_last = msta->airtime_ac[i];
			u32 rx_last = msta->airtime_ac[i + 4];

			msta->airtime_ac[i] = mt76_rr(dev, addr);
			msta->airtime_ac[i + 4] = mt76_rr(dev, addr + 4);
			tx_time[i] = msta->airtime_ac[i] - tx_last;
			rx_time[i] = msta->airtime_ac[i + 4] - rx_last;

			if ((tx_last | rx_last) & BIT(30))
				clear = true;
		}

		if (clear) {
			mt7615_mac_wtbl_update(dev, msta->wcid.idx,
					       MT_WTBL_UPDATE_ADM_COUNT_CLEAR);
			memset(msta->airtime_ac, 0, sizeof(msta->airtime_ac));
		}

		if (!msta->wcid.sta)
			continue;

		sta = container_of((void *)msta, struct ieee80211_sta,
				   drv_priv);
		for (i = 0; i < 4; i++) {
			u32 tx_cur = tx_time[i];
			u32 rx_cur = rx_time[hw_queue_map[i]];
			u8 tid = ac_to_tid[i];

			if (!tx_cur && !rx_cur)
				continue;

			ieee80211_sta_register_airtime(sta, tid, tx_cur,
						       rx_cur);
		}
	}

	rcu_read_unlock();
}

static int
mt7615_mac_wtbl_update_pk(struct mt7615_dev *dev, struct mt76_wcid *wcid,
			  enum mt7615_cipher_type cipher, int keyidx,
			  enum set_key_cmd cmd)
{
	u32 addr = mt7615_mac_wtbl_addr(wcid->idx), w0, w1;

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

	if (!mt7615_mac_wtbl_update(dev, wcid->idx,
				    MT_WTBL_UPDATE_RXINFO_UPDATE))
		return -ETIMEDOUT;

	return 0;
}

int mt7615_mac_wtbl_set_key(struct mt7615_dev *dev,
			    struct mt76_wcid *wcid,
			    struct ieee80211_key_conf *key,
			    enum set_key_cmd cmd)
{
	u32 addr = mt7615_mac_wtbl_addr(wcid->idx);
	enum mt7615_cipher_type cipher;
	int err;

	cipher = mt7615_mac_get_cipher(key->cipher);
	if (cipher == MT_CIPHER_NONE)
		return -EOPNOTSUPP;

	spin_lock_bh(&dev->mt76.lock);

	mt7615_mac_wtbl_update_cipher(dev, wcid, addr, cipher, cmd);
	err = mt7615_mac_wtbl_update_key(dev, wcid, addr, key, cipher, cmd);
	if (err < 0)
		goto out;

	err = mt7615_mac_wtbl_update_pk(dev, wcid, cipher, key->keyidx,
					cmd);
	if (err < 0)
		goto out;

	if (cmd == SET_KEY)
		wcid->cipher |= BIT(cipher);
	else
		wcid->cipher &= ~BIT(cipher);

out:
	spin_unlock_bh(&dev->mt76.lock);

	return err;
}

int mt7615_tx_prepare_skb(struct mt76_dev *mdev, void *txwi_ptr,
			  enum mt76_txq_id qid, struct mt76_wcid *wcid,
			  struct ieee80211_sta *sta,
			  struct mt76_tx_info *tx_info)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)tx_info->skb->data;
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	struct mt7615_sta *msta = container_of(wcid, struct mt7615_sta, wcid);
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx_info->skb);
	struct ieee80211_key_conf *key = info->control.hw_key;
	struct ieee80211_vif *vif = info->control.vif;
	int i, pid, id, nbuf = tx_info->nbuf - 1;
	u8 *txwi = (u8 *)txwi_ptr;
	struct mt76_txwi_cache *t;
	struct mt7615_txp *txp;

	if (!wcid)
		wcid = &dev->mt76.global_wcid;

	pid = mt76_tx_status_skb_add(mdev, wcid, tx_info->skb);

	if (info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE) {
		struct mt7615_phy *phy = &dev->phy;

		if ((info->hw_queue & MT_TX_HW_QUEUE_EXT_PHY) && mdev->phy2)
			phy = mdev->phy2->priv;

		spin_lock_bh(&dev->mt76.lock);
		mt7615_mac_set_rates(phy, msta, &info->control.rates[0],
				     msta->rates);
		msta->rate_probe = true;
		spin_unlock_bh(&dev->mt76.lock);
	}

	mt7615_mac_write_txwi(dev, txwi_ptr, tx_info->skb, wcid, sta,
			      pid, key);

	txp = (struct mt7615_txp *)(txwi + MT_TXD_SIZE);
	for (i = 0; i < nbuf; i++) {
		txp->buf[i] = cpu_to_le32(tx_info->buf[i + 1].addr);
		txp->len[i] = cpu_to_le16(tx_info->buf[i + 1].len);
	}
	txp->nbuf = nbuf;

	/* pass partial skb header to fw */
	tx_info->buf[1].len = MT_CT_PARSE_LEN;
	tx_info->nbuf = MT_CT_DMA_BUF_NUM;

	txp->flags = cpu_to_le16(MT_CT_INFO_APPLY_TXD);

	if (!key)
		txp->flags |= cpu_to_le16(MT_CT_INFO_NONE_CIPHER_FRAME);

	if (ieee80211_is_mgmt(hdr->frame_control))
		txp->flags |= cpu_to_le16(MT_CT_INFO_MGMT_FRAME);

	if (vif) {
		struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;

		txp->bss_idx = mvif->idx;
	}

	t = (struct mt76_txwi_cache *)(txwi + mdev->drv->txwi_size);
	t->skb = tx_info->skb;

	spin_lock_bh(&dev->token_lock);
	id = idr_alloc(&dev->token, t, 0, MT7615_TOKEN_SIZE, GFP_ATOMIC);
	spin_unlock_bh(&dev->token_lock);
	if (id < 0)
		return id;

	txp->token = cpu_to_le16(id);
	txp->rept_wds_wcid = 0xff;
	tx_info->skb = DMA_DUMMY_DATA;

	return 0;
}

static void
mt7615_mac_set_default_sensitivity(struct mt7615_phy *phy)
{
	struct mt7615_dev *dev = phy->dev;
	bool ext_phy = phy != &dev->phy;

	mt76_rmw(dev, MT_WF_PHY_MIN_PRI_PWR(ext_phy),
		 MT_WF_PHY_PD_OFDM_MASK(ext_phy),
		 MT_WF_PHY_PD_OFDM(ext_phy, 0x13c));
	mt76_rmw(dev, MT_WF_PHY_RXTD_CCK_PD(ext_phy),
		 MT_WF_PHY_PD_CCK_MASK(ext_phy),
		 MT_WF_PHY_PD_CCK(ext_phy, 0x92));

	phy->ofdm_sensitivity = -98;
	phy->cck_sensitivity = -110;
	phy->last_cca_adj = jiffies;
}

void mt7615_mac_set_scs(struct mt7615_dev *dev, bool enable)
{
	struct mt7615_phy *ext_phy;

	mutex_lock(&dev->mt76.mutex);

	if (dev->scs_en == enable)
		goto out;

	if (enable) {
		mt76_set(dev, MT_WF_PHY_MIN_PRI_PWR(0),
			 MT_WF_PHY_PD_BLK(0));
		mt76_set(dev, MT_WF_PHY_MIN_PRI_PWR(1),
			 MT_WF_PHY_PD_BLK(1));
		if (is_mt7622(&dev->mt76)) {
			mt76_set(dev, MT_MIB_M0_MISC_CR, 0x7 << 8);
			mt76_set(dev, MT_MIB_M0_MISC_CR, 0x7);
		}
	} else {
		mt76_clear(dev, MT_WF_PHY_MIN_PRI_PWR(0),
			   MT_WF_PHY_PD_BLK(0));
		mt76_clear(dev, MT_WF_PHY_MIN_PRI_PWR(1),
			   MT_WF_PHY_PD_BLK(1));
	}

	mt7615_mac_set_default_sensitivity(&dev->phy);
	ext_phy = mt7615_ext_phy(dev);
	if (ext_phy)
		mt7615_mac_set_default_sensitivity(ext_phy);

	dev->scs_en = enable;

out:
	mutex_unlock(&dev->mt76.mutex);
}

void mt7615_mac_enable_nf(struct mt7615_dev *dev, bool ext_phy)
{
	u32 rxtd;

	if (ext_phy)
		rxtd = MT_WF_PHY_RXTD2(10);
	else
		rxtd = MT_WF_PHY_RXTD(12);

	mt76_set(dev, rxtd, BIT(18) | BIT(29));
	mt76_set(dev, MT_WF_PHY_R0_PHYMUX_5(ext_phy), 0x5 << 12);
}

void mt7615_mac_cca_stats_reset(struct mt7615_phy *phy)
{
	struct mt7615_dev *dev = phy->dev;
	bool ext_phy = phy != &dev->phy;
	u32 reg = MT_WF_PHY_R0_PHYMUX_5(ext_phy);

	mt76_clear(dev, reg, GENMASK(22, 20));
	mt76_set(dev, reg, BIT(22) | BIT(20));
}

static void
mt7615_mac_adjust_sensitivity(struct mt7615_phy *phy,
			      u32 rts_err_rate, bool ofdm)
{
	struct mt7615_dev *dev = phy->dev;
	int false_cca = ofdm ? phy->false_cca_ofdm : phy->false_cca_cck;
	bool ext_phy = phy != &dev->phy;
	u16 def_th = ofdm ? -98 : -110;
	bool update = false;
	s8 *sensitivity;
	int signal;

	sensitivity = ofdm ? &phy->ofdm_sensitivity : &phy->cck_sensitivity;
	signal = mt76_get_min_avg_rssi(&dev->mt76, ext_phy);
	if (!signal) {
		mt7615_mac_set_default_sensitivity(phy);
		return;
	}

	signal = min(signal, -72);
	if (false_cca > 500) {
		if (rts_err_rate > MT_FRAC(40, 100))
			return;

		/* decrease coverage */
		if (*sensitivity == def_th && signal > -90) {
			*sensitivity = -90;
			update = true;
		} else if (*sensitivity + 2 < signal) {
			*sensitivity += 2;
			update = true;
		}
	} else if ((false_cca > 0 && false_cca < 50) ||
		   rts_err_rate > MT_FRAC(60, 100)) {
		/* increase coverage */
		if (*sensitivity - 2 >= def_th) {
			*sensitivity -= 2;
			update = true;
		}
	}

	if (*sensitivity > signal) {
		*sensitivity = signal;
		update = true;
	}

	if (update) {
		u16 val;

		if (ofdm) {
			val = *sensitivity * 2 + 512;
			mt76_rmw(dev, MT_WF_PHY_MIN_PRI_PWR(ext_phy),
				 MT_WF_PHY_PD_OFDM_MASK(ext_phy),
				 MT_WF_PHY_PD_OFDM(ext_phy, val));
		} else {
			val = *sensitivity + 256;
			if (!ext_phy)
			mt76_rmw(dev, MT_WF_PHY_RXTD_CCK_PD(ext_phy),
				 MT_WF_PHY_PD_CCK_MASK(ext_phy),
				 MT_WF_PHY_PD_CCK(ext_phy, val));
		}
		phy->last_cca_adj = jiffies;
	}
}

static void
mt7615_mac_scs_check(struct mt7615_phy *phy)
{
	struct mt7615_dev *dev = phy->dev;
	u32 val, rts_cnt = 0, rts_retries_cnt = 0, rts_err_rate = 0;
	u32 mdrdy_cck, mdrdy_ofdm, pd_cck, pd_ofdm;
	bool ext_phy = phy != &dev->phy;
	int i;

	if (!dev->scs_en)
		return;

	for (i = 0; i < 4; i++) {
		u32 data;

		val = mt76_rr(dev, MT_MIB_MB_SDR(ext_phy, i));
		data = FIELD_GET(MT_MIB_RTS_RETRIES_COUNT_MASK, val);
		if (data > rts_retries_cnt) {
			rts_cnt = FIELD_GET(MT_MIB_RTS_COUNT_MASK, val);
			rts_retries_cnt = data;
		}
	}

	val = mt76_rr(dev, MT_WF_PHY_R0_PHYCTRL_STS0(ext_phy));
	pd_cck = FIELD_GET(MT_WF_PHYCTRL_STAT_PD_CCK, val);
	pd_ofdm = FIELD_GET(MT_WF_PHYCTRL_STAT_PD_OFDM, val);

	val = mt76_rr(dev, MT_WF_PHY_R0_PHYCTRL_STS5(ext_phy));
	mdrdy_cck = FIELD_GET(MT_WF_PHYCTRL_STAT_MDRDY_CCK, val);
	mdrdy_ofdm = FIELD_GET(MT_WF_PHYCTRL_STAT_MDRDY_OFDM, val);

	phy->false_cca_ofdm = pd_ofdm - mdrdy_ofdm;
	phy->false_cca_cck = pd_cck - mdrdy_cck;
	mt7615_mac_cca_stats_reset(phy);

	if (rts_cnt + rts_retries_cnt)
		rts_err_rate = MT_FRAC(rts_retries_cnt,
				       rts_cnt + rts_retries_cnt);

	/* cck */
	mt7615_mac_adjust_sensitivity(phy, rts_err_rate, false);
	/* ofdm */
	mt7615_mac_adjust_sensitivity(phy, rts_err_rate, true);

	if (time_after(jiffies, phy->last_cca_adj + 10 * HZ))
		mt7615_mac_set_default_sensitivity(phy);
}

static u8
mt7615_phy_get_nf(struct mt7615_dev *dev, int idx)
{
	static const u8 nf_power[] = { 92, 89, 86, 83, 80, 75, 70, 65, 60, 55, 52 };
	u32 reg = idx ? MT_WF_PHY_RXTD2(17) : MT_WF_PHY_RXTD(20);
	u32 val, sum = 0, n = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(nf_power); i++, reg += 4) {
		val = mt76_rr(dev, reg);
		sum += val * nf_power[i];
		n += val;
	}

	if (!n)
		return 0;

	return sum / n;
}

static void
mt7615_phy_update_channel(struct mt76_phy *mphy, int idx)
{
	struct mt7615_dev *dev = container_of(mphy->dev, struct mt7615_dev, mt76);
	struct mt7615_phy *phy = mphy->priv;
	struct mt76_channel_state *state;
	u64 busy_time, tx_time, rx_time, obss_time;
	u32 obss_reg = idx ? MT_WF_RMAC_MIB_TIME6 : MT_WF_RMAC_MIB_TIME5;
	int nf;

	busy_time = mt76_get_field(dev, MT_MIB_SDR9(idx),
				   MT_MIB_SDR9_BUSY_MASK);
	tx_time = mt76_get_field(dev, MT_MIB_SDR36(idx),
				 MT_MIB_SDR36_TXTIME_MASK);
	rx_time = mt76_get_field(dev, MT_MIB_SDR37(idx),
				 MT_MIB_SDR37_RXTIME_MASK);
	obss_time = mt76_get_field(dev, obss_reg, MT_MIB_OBSSTIME_MASK);

	nf = mt7615_phy_get_nf(dev, idx);
	if (!phy->noise)
		phy->noise = nf << 4;
	else if (nf)
		phy->noise += nf - (phy->noise >> 4);

	state = mphy->chan_state;
	state->cc_busy += busy_time;
	state->cc_tx += tx_time;
	state->cc_rx += rx_time + obss_time;
	state->cc_bss_rx += rx_time;
	state->noise = -(phy->noise >> 4);
}

void mt7615_update_channel(struct mt76_dev *mdev)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);

	mt7615_phy_update_channel(&mdev->phy, 0);
	if (mdev->phy2)
		mt7615_phy_update_channel(mdev->phy2, 1);

	/* reset obss airtime */
	mt76_set(dev, MT_WF_RMAC_MIB_TIME0, MT_WF_RMAC_MIB_RXTIME_CLR);
}

void mt7615_mac_work(struct work_struct *work)
{
	struct mt7615_dev *dev;
	struct mt7615_phy *ext_phy;
	int i, idx;

	dev = (struct mt7615_dev *)container_of(work, struct mt76_dev,
						mac_work.work);

	mutex_lock(&dev->mt76.mutex);
	mt76_update_survey(&dev->mt76);
	if (++dev->mac_work_count == 5) {
		ext_phy = mt7615_ext_phy(dev);

		mt7615_mac_scs_check(&dev->phy);
		if (ext_phy)
			mt7615_mac_scs_check(ext_phy);

		dev->mac_work_count = 0;
	}

	for (i = 0, idx = 0; i < 4; i++) {
		u32 val = mt76_rr(dev, MT_TX_AGG_CNT(i));

		dev->mt76.aggr_stats[idx++] += val & 0xffff;
		dev->mt76.aggr_stats[idx++] += val >> 16;
	}
	mutex_unlock(&dev->mt76.mutex);

	mt76_tx_status_check(&dev->mt76, NULL, false);
	ieee80211_queue_delayed_work(mt76_hw(dev), &dev->mt76.mac_work,
				     MT7615_WATCHDOG_TIME);
}
