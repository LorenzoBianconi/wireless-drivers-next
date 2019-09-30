// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Roy Luo <royluo@google.com>
 *         Ryder Lee <ryder.lee@mediatek.com>
 *         Felix Fietkau <nbd@nbd.name>
 *	   Chih-Min Chen <chih-min.chen@mediatek.com>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include <linux/etherdevice.h>
#include "connac.h"
#include "mac.h"

static int
connac_dma_sched_init(struct connac_dev *dev)
{
	u32 val;

	val = mt76_rr(dev, MT_HIF_DMASHDL_PKT_MAX_SIZE(dev));
	val &= ~(PLE_PKT_MAX_SIZE_MASK | PSE_PKT_MAX_SIZE_MASK);
	val |= PLE_PKT_MAX_SIZE_NUM(0x1);
	val |= PSE_PKT_MAX_SIZE_NUM(0x8);
	mt76_wr(dev, MT_HIF_DMASHDL_PKT_MAX_SIZE(dev), val);

	/* Enable refill Control Group 0, 1, 2, 4, 5 */
	mt76_wr(dev, MT_HIF_DMASHDL_REFILL_CTRL(dev), 0xffc80000);
	/* Group 0, 1, 2, 4, 5, 15 joint the ask round robin */
	mt76_wr(dev, MT_HIF_DMASHDL_OPTION_CTRL(dev), 0x70068037);
	/*Each group min quota must larger then PLE_PKT_MAX_SIZE_NUM*/
	val = DMASHDL_MIN_QUOTA_NUM(0x40);
	val |= DMASHDL_MAX_QUOTA_NUM(0x800);

	mt76_wr(dev, MT_HIF_DMASHDL_GROUP0_CTRL(dev), val);
	mt76_wr(dev, MT_HIF_DMASHDL_GROUP1_CTRL(dev), val);
	mt76_wr(dev, MT_HIF_DMASHDL_GROUP2_CTRL(dev), val);
	mt76_wr(dev, MT_HIF_DMASHDL_GROUP4_CTRL(dev), val);
	val = DMASHDL_MIN_QUOTA_NUM(0x40);
	val |= DMASHDL_MAX_QUOTA_NUM(0x40);
	mt76_wr(dev, MT_HIF_DMASHDL_GROUP5_CTRL(dev), val);

	val = DMASHDL_MIN_QUOTA_NUM(0x20);
	val |= DMASHDL_MAX_QUOTA_NUM(0x20);
	mt76_wr(dev, MT_HIF_DMASHDL_GROUP15_CTRL(dev), val);

	mt76_wr(dev, MT_HIF_DMASHDL_Q_MAP0(dev), 0x42104210);
	mt76_wr(dev, MT_HIF_DMASHDL_Q_MAP1(dev), 0x42104210);
	/* ALTX0 and ALTX1 QID mapping to group 5 */
	mt76_wr(dev, MT_HIF_DMASHDL_Q_MAP2(dev), 0x00050005);
	mt76_wr(dev, MT_HIF_DMASHDL_Q_MAP3(dev), 0x0);
	mt76_wr(dev, MT_HIF_DMASHDL_SHDL_SET0(dev), 0x6012345f);
	mt76_wr(dev, MT_HIF_DMASHDL_SHDL_SET1(dev), 0xedcba987);

	return 0;
}

static int
connac_usb_dma_sched_init(struct connac_dev *dev)
{
	u32 val;

	val = mt76_rr(dev, DMASHDL_PKT_MAX_SIZE(dev));
	val &= ~(PLE_PACKET_MAX_SIZE | PSE_PACKET_MAX_SIZE);
	val |= FIELD_PREP(PLE_PACKET_MAX_SIZE, 0x1) |
	      FIELD_PREP(PSE_PACKET_MAX_SIZE, 0x8);
	mt76_wr(dev, DMASHDL_PKT_MAX_SIZE(dev), val);

	/* disable refill group 5 - group 15 and raise group 2
	 * and 3 as high priority.
	 */
	val = 0xffe00010;
	mt76_wr(dev, DMASHDL_REFILL_CONTROL(dev), val);

	val = mt76_rr(dev, DMASHDL_PAGE_SETTING(dev));
	val &= ~GROUP_SEQUENCE_ORDER_TYPE;
	mt76_wr(dev, DMASHDL_PAGE_SETTING(dev), val);

	val = FIELD_PREP(MIN_QUOTA, 0x3) |
	      FIELD_PREP(MAX_QUOTA, 0x1ff);
	mt76_wr(dev, DMASHDL_GROUP1_CONTROL(dev), val);
	mt76_wr(dev, DMASHDL_GROUP0_CONTROL(dev), val);
	mt76_wr(dev, DMASHDL_GROUP2_CONTROL(dev), val);
	mt76_wr(dev, DMASHDL_GROUP3_CONTROL(dev), val);
	mt76_wr(dev, DMASHDL_GROUP4_CONTROL(dev), val);

	val = FIELD_PREP(QUEUE0_MAP, 0x4) | /* ac0 group 0 */
	      FIELD_PREP(QUEUE1_MAP, 0x4) | /* ac1 group 1 */
	      FIELD_PREP(QUEUE2_MAP, 0x4) | /* ac2 group 2 */
	      FIELD_PREP(QUEUE3_MAP, 0x4) | /* ac3 group 3 */
	      FIELD_PREP(QUEUE4_MAP, 0x4) | /* ac10 group 4*/
	      FIELD_PREP(QUEUE5_MAP, 0x4) | /* ac11 */
	      FIELD_PREP(QUEUE6_MAP, 0x4) |
	      FIELD_PREP(QUEUE7_MAP, 0x4);
	mt76_wr(dev, DMASHDL_QUEUE_MAPPING0(dev), val);

	val = FIELD_PREP(QUEUE8_MAP, 0x4) | /* ac20 group 4*/
	      FIELD_PREP(QUEUE9_MAP, 0x4) |
	      FIELD_PREP(QUEUE10_MAP, 0x4) |
	      FIELD_PREP(QUEUE11_MAP, 0x4) |
	      FIELD_PREP(QUEUE12_MAP, 0x4) | /* ac30 group 4*/
	      FIELD_PREP(QUEUE13_MAP, 0x4) |
	      FIELD_PREP(QUEUE14_MAP, 0x4) |
	      FIELD_PREP(QUEUE15_MAP, 0x4);
	mt76_wr(dev, DMASHDL_QUEUE_MAPPING1(dev), val);

	val = FIELD_PREP(QUEUE16_MAP, 0x4) | /* altx group 4*/
	      FIELD_PREP(QUEUE17_MAP, 0x4) | /* bmc */
	      FIELD_PREP(QUEUE18_MAP, 0x4) | /* bcn */
	      FIELD_PREP(QUEUE19_MAP, 0x4);  /* psmp */
	mt76_wr(dev, DMASHDL_QUEUE_MAPPING2(dev), val);

	/* group pririority from high to low:
	 * 15 (cmd groups) > 4 > 3 > 2 > 1 > 0.
	 */
	mt76_wr(dev, DMASHDL_SCHED_SETTING0(dev), 0x6501234f);
	mt76_wr(dev, DMASHDL_SCHED_SETTING1(dev), 0xedcba987);
	mt76_wr(dev, DMASHDL_OPTIONAL_CONTROL(dev), 0x7004801c);

	/* setup UDMA Tx timeout */
	val = mt76_rr(dev, UDMA_WLCFG_1(dev));
	val &= ~WL_TX_TMOUT_LMT;
	val |= FIELD_PREP(WL_TX_TMOUT_LMT, 500);
	/* do we need to setup WL_RX_AGG_PKT_LMT? */
	mt76_wr(dev, UDMA_WLCFG_1(dev), val);

	val = mt76_rr(dev, UDMA_WLCFG_0(dev));
	val |= WL_TX_TMOUT_FUNC_EN;
	mt76_wr(dev, UDMA_WLCFG_0(dev), val);

	/* setup UDMA Rx Flush */
	val = mt76_rr(dev, UDMA_WLCFG_0(dev));
	val &= ~WL_RX_FLUSH;
	mt76_wr(dev, UDMA_WLCFG_0(dev), val);

	/* hif reset */
	val = mt76_rr(dev, PDMA_HIF_RST);
	val |= CONN_HIF_LOGIC_RST_N;
	mt76_wr(dev, PDMA_HIF_RST, val);

	return 0;
}

static void connac_phy_init(struct connac_dev *dev)
{
	/* CONNAC : no need */
}

static void connac_mac_init(struct connac_dev *dev)
{
	u32 val;
	bool init_mac1 = false;

	switch (dev->mt76.rev) {
	case 0x76630010:
		init_mac1 = true;
		break;
	}

	/* enable band 0 clk */
	mt76_rmw(dev, MT_CFG_CCR(dev),
		 MT_CFG_CCR_MAC_D0_1X_GC_EN | MT_CFG_CCR_MAC_D0_2X_GC_EN,
		 MT_CFG_CCR_MAC_D0_1X_GC_EN | MT_CFG_CCR_MAC_D0_2X_GC_EN);

	/* Hdr translation off*/
	mt76_wr(dev, MT_DMA_DCR0(dev), 0x471000);

	/* CCA Setting */
	val = mt76_rmw(dev, MT_TMAC_TRCR0(dev),
		       MT_TMAC_TRCR_CCA_SEL | MT_TMAC_TRCR_SEC_CCA_SEL,
		       FIELD_PREP(MT_TMAC_TRCR_CCA_SEL, 0x2) |
		       FIELD_PREP(MT_TMAC_TRCR_SEC_CCA_SEL, 0x0));

	mt76_rmw_field(dev, MT_TMAC_CTCR0(dev),
		       MT_TMAC_CTCR0_INS_DDLMT_REFTIME, 0x3f);
	mt76_rmw_field(dev, MT_TMAC_CTCR0(dev),
		       MT_TMAC_CTCR0_INS_DDLMT_DENSITY, 0x3);
	mt76_rmw(dev, MT_TMAC_CTCR0(dev),
		 MT_TMAC_CTCR0_INS_DDLMT_VHT_SMPDU_EN |
		 MT_TMAC_CTCR0_INS_DDLMT_EN,
		 MT_TMAC_CTCR0_INS_DDLMT_VHT_SMPDU_EN |
		 MT_TMAC_CTCR0_INS_DDLMT_EN);
	connac_mcu_set_rts_thresh(dev, 0x92b);

	mt76_rmw(dev, MT_AGG_SCR(dev), MT_AGG_SCR_NLNAV_MID_PTEC_DIS,
		 MT_AGG_SCR_NLNAV_MID_PTEC_DIS);

	connac_mcu_init_mac(dev, 0);

	if (init_mac1)
		connac_mcu_init_mac(dev, 1);

#define RF_LOW_BEACON_BAND0 0x11900
#define RF_LOW_BEACON_BAND1 0x11d00
	mt76_wr(dev, RF_LOW_BEACON_BAND0, 0x200);
	mt76_wr(dev, RF_LOW_BEACON_BAND1, 0x200);
	mt76_wr(dev, 0x7010, 0x8208);
	mt76_wr(dev, 0x44064, 0x2000000);
	mt76_wr(dev, MT_WF_AGG(dev, 0x160), 0x5c341c02);
	mt76_wr(dev, MT_WF_AGG(dev, 0x164), 0x70708040);
}

static int connac_init_hardware(struct connac_dev *dev)
{
	int ret, idx;
	bool init_dbdc = true;
	bool init_mac = false;

	switch (dev->mt76.rev) {
	case 0x76630010:
		init_dbdc = false;
		init_mac = true;
		break;
	}

	mt76_wr(dev, MT_INT_SOURCE_CSR(dev), ~0);

	spin_lock_init(&dev->token_lock);
	idr_init(&dev->token);

	ret = connac_eeprom_init(dev);
	if (ret < 0)
		return ret;

	ret = connac_dma_init(dev);
	if (ret)
		return ret;

	/* CONNAC : init before f/w download*/
	ret = connac_dma_sched_init(dev);
	if (ret)
		return ret;

	set_bit(MT76_STATE_INITIALIZED, &dev->mt76.state);

	ret = connac_mcu_init(dev);
	if (ret)
		return ret;

	connac_mcu_set_eeprom(dev);

	if (init_dbdc)
		connac_mcu_dbdc_ctrl(dev);

	connac_mac_init(dev);
	connac_phy_init(dev);

	connac_mcu_ctrl_pm_state(dev, 0);
	/* CONNAC : F/W halWtblClearAllWtbl() will do this in init. */
	/* connac_mcu_del_wtbl_all(dev); */

	/* Beacon and mgmt frames should occupy wcid 0 */
	idx = mt76_wcid_alloc(dev->mt76.wcid_mask, CONNAC_WTBL_STA - 1);
	if (idx)
		return -ENOSPC;

	dev->mt76.global_wcid.idx = idx;
	dev->mt76.global_wcid.hw_key_idx = -1;
	rcu_assign_pointer(dev->mt76.wcid[idx], &dev->mt76.global_wcid);

	if (init_mac) {
		//just for test
		//      eth_random_addr(dev->mt76.macaddr);
		dev->mt76.macaddr[0] = 0x1a;
		dev->mt76.macaddr[1] = 0xed;
		dev->mt76.macaddr[2] = 0x8f;
		dev->mt76.macaddr[3] = 0x7a;
		dev->mt76.macaddr[4] = 0x97;
		dev->mt76.macaddr[5] = 0x4e;

		dev_info(dev->mt76.dev,
			 "Force to use mac address %pM to test\n",
			 dev->mt76.macaddr);
	}

	return 0;
}

static int connac_usb_init_hardware(struct connac_dev *dev)
{
	int ret, idx;
	u32 val;

	ret = connac_eeprom_init(dev);
	if (ret < 0)
		return ret;

	ret = connac_usb_dma_sched_init(dev);
	if (ret)
		return ret;

	val = mt76_rr(dev, UDMA_WLCFG_0(dev));
	val &= ~(WL_RX_AGG_EN | WL_RX_AGG_LMT |  WL_RX_AGG_TO);
	val |=  WL_RX_AGG_EN | FIELD_PREP(WL_RX_AGG_LMT, 32) |
		FIELD_PREP(WL_RX_AGG_TO, 100);
	mt76_wr(dev, UDMA_WLCFG_0(dev), val);

	val = mt76_rr(dev, UDMA_WLCFG_0(dev));
	val |= WL_RX_EN | WL_TX_EN | WL_RX_MPSZ_PAD0 | TICK_1US_EN;
	mt76_wr(dev, UDMA_WLCFG_0(dev), val);

	val = mt76_rr(dev, UDMA_WLCFG_1(dev));
	val &= ~(WL_RX_AGG_PKT_LMT);
	val |= FIELD_PREP(WL_RX_AGG_PKT_LMT, 1);
	mt76_wr(dev, UDMA_WLCFG_1(dev), val);

	set_bit(MT76_STATE_INITIALIZED, &dev->mt76.state);

	ret = connac_usb_mcu_init(dev);
	if (ret)
		return ret;

	connac_mcu_set_eeprom(dev);
	connac_mac_init(dev);
	connac_phy_init(dev);
#if MTK_REBB
	connac_mcu_ctrl_pm_state(dev, 0);
#endif
	/* MT7663e : F/W halWtblClearAllWtbl() will do this in init. */
	/* mt7663u_mcu_del_wtbl_all(dev); */

	/* Beacon and mgmt frames should occupy wcid 0 */
	idx = mt76_wcid_alloc(dev->mt76.wcid_mask, CONNAC_WTBL_STA - 1);
	if (idx)
		return -ENOSPC;

	dev->mt76.global_wcid.idx = idx;
	dev->mt76.global_wcid.hw_key_idx = -1;
	rcu_assign_pointer(dev->mt76.wcid[idx], &dev->mt76.global_wcid);

/* sean test */
//      eth_random_addr(dev->mt76.macaddr);
	dev->mt76.macaddr[0] = 0x1a;
	dev->mt76.macaddr[1] = 0xed;
	dev->mt76.macaddr[2] = 0x8f;
	dev->mt76.macaddr[3] = 0x7a;
	dev->mt76.macaddr[4] = 0x97;
	dev->mt76.macaddr[5] = 0x9e;

	dev_info(dev->mt76.dev,
		 "Force to use mac address %pM to test\n",
		 dev->mt76.macaddr);

	return 0;
}

#define CCK_RATE(_idx, _rate) {						\
	.bitrate = _rate,						\
	.flags = IEEE80211_RATE_SHORT_PREAMBLE,				\
	.hw_value = (MT_PHY_TYPE_CCK << 8) | (_idx),			\
	.hw_value_short = (MT_PHY_TYPE_CCK << 8) | (4 + (_idx)),	\
}

#define OFDM_RATE(_idx, _rate) {					\
	.bitrate = _rate,						\
	.hw_value = (MT_PHY_TYPE_OFDM << 8) | (_idx),			\
	.hw_value_short = (MT_PHY_TYPE_OFDM << 8) | (_idx),		\
}

static struct ieee80211_rate connac_rates[] = {
	CCK_RATE(0, 10),
	CCK_RATE(1, 20),
	CCK_RATE(2, 55),
	CCK_RATE(3, 110),
	OFDM_RATE(11, 60),
	OFDM_RATE(15, 90),
	OFDM_RATE(10, 120),
	OFDM_RATE(14, 180),
	OFDM_RATE(9,  240),
	OFDM_RATE(13, 360),
	OFDM_RATE(8,  480),
	OFDM_RATE(12, 540),
};

static const struct ieee80211_iface_limit if_limits[] = {
	{
		.max = CONNAC_MAX_INTERFACES,
		.types = BIT(NL80211_IFTYPE_AP) |
#ifdef CONFIG_MAC80211_MESH
			 BIT(NL80211_IFTYPE_MESH_POINT) |
#endif
			 BIT(NL80211_IFTYPE_STATION)
	}
};

static const struct ieee80211_iface_combination if_comb[] = {
	{
		.limits = if_limits,
		.n_limits = ARRAY_SIZE(if_limits),
		.max_interfaces = 4,
		.num_different_channels = 1,
		.beacon_int_infra_match = true,
	}
};

static inline void _ieee80211_hw_clear(struct ieee80211_hw *hw,
				       enum ieee80211_hw_flags flg)
{
	return __clear_bit(flg, hw->flags);
}

#define ieee80211_hw_clear(hw, flg)	_ieee80211_hw_clear(hw, IEEE80211_HW_##flg)

int connac_register_device(struct connac_dev *dev)
{
	struct ieee80211_hw *hw = mt76_hw(dev);
	struct wiphy *wiphy = hw->wiphy;
	int ret;

	if (dev->flag & CONNAC_USB) {
		ret = connac_usb_init_hardware(dev);
		if (ret)
			return ret;

		INIT_WORK(&dev->rc_work, connac_usb_rc_work);
		INIT_LIST_HEAD(&dev->rc_processing);
	} else {
		ret = connac_init_hardware(dev);
		if (ret)
			return ret;
	}

	INIT_DELAYED_WORK(&dev->mt76.mac_work, connac_mac_work);

	hw->queues = 4;
	hw->max_rates = 3;
	hw->max_report_rates = 7;
	hw->max_rate_tries = 11;

	hw->sta_data_size = sizeof(struct connac_sta);
	hw->vif_data_size = sizeof(struct connac_vif);

	wiphy->iface_combinations = if_comb;
	wiphy->n_iface_combinations = ARRAY_SIZE(if_comb);

	dev->mt76.sband_2g.sband.ht_cap.cap |= IEEE80211_HT_CAP_LDPC_CODING;
	dev->mt76.sband_5g.sband.ht_cap.cap |= IEEE80211_HT_CAP_LDPC_CODING;
	dev->mt76.sband_5g.sband.vht_cap.cap |=
			IEEE80211_VHT_CAP_SHORT_GI_160 |
			IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454 |
			IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK |
			IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ;
	dev->mt76.chainmask = 0x03;
	dev->mt76.antenna_mask = 0x7;

	wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION) |
#ifdef CONFIG_MAC80211_MESH
				 BIT(NL80211_IFTYPE_MESH_POINT) |
#endif
				 BIT(NL80211_IFTYPE_AP);

	ret = mt76_register_device(&dev->mt76, true, connac_rates,
				   ARRAY_SIZE(connac_rates));

	ieee80211_hw_set(hw, SUPPORTS_REORDERING_BUFFER);
	ieee80211_hw_set(hw, TX_STATUS_NO_AMPDU_LEN);
	/* connac only support HW-AMSDU in this stage. */
	ieee80211_hw_clear(hw, TX_AMSDU);
	ieee80211_hw_clear(hw, TX_FRAG_LIST);

	if (ret)
		return ret;

	hw->max_tx_fragments = MT_TXP_MAX_BUF_NUM;

	return connac_init_debugfs(dev);
}

void connac_unregister_device(struct connac_dev *dev)
{
	struct mt76_txwi_cache *txwi;
	int id;

	mt76_unregister_device(&dev->mt76);
	connac_mcu_exit(dev);
	connac_dma_cleanup(dev);

	spin_lock_bh(&dev->token_lock);
	idr_for_each_entry(&dev->token, txwi, id) {
		connac_txp_skb_unmap(&dev->mt76, txwi);
		if (txwi->skb)
			dev_kfree_skb_any(txwi->skb);
		mt76_put_txwi(&dev->mt76, txwi);
	}
	spin_unlock_bh(&dev->token_lock);
	idr_destroy(&dev->token);

	mt76_free_device(&dev->mt76);
}
