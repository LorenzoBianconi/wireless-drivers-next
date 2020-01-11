// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Felix Fietkau <nbd@nbd.name>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "mt7615.h"
#include "eeprom.h"
#include "mac.h"
#include "usb_sdio_regs.h"

static int
mt7663u_init_debugfs(struct mt7615_dev *dev)
{
	struct dentry *dir;

	dir = mt76_register_debugfs(&dev->mt76);
	if (!dir)
		return -ENOMEM;

	return 0;
}

static int
mt7663u_dma_sched_init(struct mt7615_dev *dev)
{
	u32 val;

	val = mt76_rr(dev, MT_DMA_SHDL_PKT_MAX_SIZE);
	val &= ~(MT_PLE_PACKET_MAX_SIZE | MT_PSE_PACKET_MAX_SIZE);
	val |= FIELD_PREP(MT_PLE_PACKET_MAX_SIZE, 0x1) |
	       FIELD_PREP(MT_PSE_PACKET_MAX_SIZE, 0x8);
	mt76_wr(dev, MT_DMA_SHDL_PKT_MAX_SIZE, val);

	/* disable refill group 5 - group 15 and raise group 2
	 * and 3 as high priority.
	 */
	mt76_wr(dev, MT_DMA_SHDL_REFILL_CONTROL, 0xffe00006);

	mt76_clear(dev, MT_DMA_SHDL_PAGE_SETTING,
		   MT_GROUP_SEQUENCE_ORDER_TYPE);

	val = FIELD_PREP(MT_MIN_QUOTA, 0x3) |
	      FIELD_PREP(MT_MAX_QUOTA, 0x1ff);
	mt76_wr(dev, MT_DMA_SHDL_GROUP1_CONTROL, val);
	mt76_wr(dev, MT_DMA_SHDL_GROUP0_CONTROL, val);
	mt76_wr(dev, MT_DMA_SHDL_GROUP2_CONTROL, val);
	mt76_wr(dev, MT_DMA_SHDL_GROUP3_CONTROL, val);
	mt76_wr(dev, MT_DMA_SHDL_GROUP4_CONTROL, val);

	mt76_wr(dev, MT_DMA_SHDL_QUEUE_MAPPING0,
		FIELD_PREP(MT_QUEUE0_MAP, 0x0) | /* ac0 group 0 */
		FIELD_PREP(MT_QUEUE1_MAP, 0x1) | /* ac1 group 1 */
		FIELD_PREP(MT_QUEUE2_MAP, 0x2) | /* ac2 group 2 */
		FIELD_PREP(MT_QUEUE3_MAP, 0x3) | /* ac3 group 3 */
		FIELD_PREP(MT_QUEUE4_MAP, 0x0) | /* ac10 group 4*/
		FIELD_PREP(MT_QUEUE5_MAP, 0x1) | /* ac11 */
		FIELD_PREP(MT_QUEUE6_MAP, 0x2) |
		FIELD_PREP(MT_QUEUE7_MAP, 0x3));

	mt76_wr(dev, MT_DMA_SHDL_QUEUE_MAPPING1,
		FIELD_PREP(MT_QUEUE8_MAP, 0x0) | /* ac20 group 4*/
		FIELD_PREP(MT_QUEUE9_MAP, 0x1) |
		FIELD_PREP(MT_QUEUE10_MAP, 0x2) |
		FIELD_PREP(MT_QUEUE11_MAP, 0x3) |
		FIELD_PREP(MT_QUEUE12_MAP, 0x0) | /* ac30 group 4*/
		FIELD_PREP(MT_QUEUE13_MAP, 0x1) |
		FIELD_PREP(MT_QUEUE14_MAP, 0x2) |
		FIELD_PREP(MT_QUEUE15_MAP, 0x3));

	mt76_wr(dev, MT_DMA_SHDL_QUEUE_MAPPING2,
		FIELD_PREP(MT_QUEUE16_MAP, 0x4) | /* altx group 4*/
		FIELD_PREP(MT_QUEUE17_MAP, 0x4) | /* bmc */
		FIELD_PREP(MT_QUEUE18_MAP, 0x4) | /* bcn */
		FIELD_PREP(MT_QUEUE19_MAP, 0x4));  /* psmp */

	/* group pririority from high to low:
	 * 15 (cmd groups) > 4 > 3 > 2 > 1 > 0.
	 */
	mt76_wr(dev, MT_DMA_SHDL_SCHED_SETTING0, 0x6501234f);
	mt76_wr(dev, MT_DMA_SHDL_SCHED_SETTING1, 0xedcba987);
	mt76_wr(dev, MT_DMA_SHDL_OPTIONAL_CONTROL, 0x7004801c);

	/* setup UDMA Tx timeout */
	mt76_rmw_field(dev, MT_UDMA_WLCFG_1, MT_WL_TX_TMOUT_LMT, 80000);
	/* do we need to setup WL_RX_AGG_PKT_LMT? */
	mt76_wr(dev, MT_UDMA_WLCFG_1, val);

	mt76_set(dev, MT_UDMA_WLCFG_0, MT_WL_TX_TMOUT_FUNC_EN);

	/* setup UDMA Rx Flush */
	mt76_clear(dev, MT_UDMA_WLCFG_0, MT_WL_RX_FLUSH);

	/* hif reset */
	mt76_set(dev, MT_PDMA_HIF_RST, MT_HIF_LOGIC_RST_N);

	return 0;
}

static void
mt7663u_mac_init(struct mt7615_dev *dev)
{
	u32 val;

	/* enable band 0 clk */
	mt76_rmw(dev, MT_CFG_CCR,
		 MT_CFG_CCR_MAC_D0_1X_GC_EN | MT_CFG_CCR_MAC_D0_2X_GC_EN,
		 MT_CFG_CCR_MAC_D0_1X_GC_EN | MT_CFG_CCR_MAC_D0_2X_GC_EN);

	/* Hdr translation off*/
	mt76_wr(dev, MT_DMA_DCR0, 0x471000);

	/* CCA Setting */
	val = mt76_rmw(dev, MT_TMAC_TRCR0,
		       MT_TMAC_TRCR_CCA_SEL | MT_TMAC_TRCR_SEC_CCA_SEL,
		       FIELD_PREP(MT_TMAC_TRCR_CCA_SEL, 0x2) |
		       FIELD_PREP(MT_TMAC_TRCR_SEC_CCA_SEL, 0x0));

	mt76_rmw_field(dev, MT_TMAC_CTCR0,
		       MT_TMAC_CTCR0_INS_DDLMT_REFTIME, 0x3f);
	mt76_rmw_field(dev, MT_TMAC_CTCR0,
		       MT_TMAC_CTCR0_INS_DDLMT_DENSITY, 0x3);
	mt76_rmw(dev, MT_TMAC_CTCR0,
		 MT_TMAC_CTCR0_INS_DDLMT_VHT_SMPDU_EN |
		 MT_TMAC_CTCR0_INS_DDLMT_EN,
		 MT_TMAC_CTCR0_INS_DDLMT_VHT_SMPDU_EN |
		 MT_TMAC_CTCR0_INS_DDLMT_EN);
	mt7615_mcu_set_rts_thresh(&dev->phy, 0x92b);

	mt76_rmw(dev, MT_AGG_SCR, MT_AGG_SCR_NLNAV_MID_PTEC_DIS,
		 MT_AGG_SCR_NLNAV_MID_PTEC_DIS);

	mt7615_mcu_set_mac_enable(dev, 0, 0);
	if (dev->mt76.rev == 0x76630010)
		mt7615_mcu_set_mac_enable(dev, 0, 1);

#define RF_LOW_BEACON_BAND0 0x11900
#define RF_LOW_BEACON_BAND1 0x11d00
	mt76_wr(dev, RF_LOW_BEACON_BAND0, 0x200);
	mt76_wr(dev, RF_LOW_BEACON_BAND1, 0x200);
	mt76_wr(dev, 0x7010, 0x8208);
	mt76_wr(dev, 0x44064, 0x2000000);
	mt76_wr(dev, MT_WF_AGG(0x160), 0x5c341c02);
	mt76_wr(dev, MT_WF_AGG(0x164), 0x70708040);

	 /* Disable AMSDU de-aggregation */
	mt76_wr(dev, MT_WF_DMA(0x0), 0x0046f000);
}

static int
mt7663_init_eeprom(struct mt7615_dev *dev, u32 base)
{
	int ret;

	ret = mt7615_eeprom_load(dev, base);
	if (ret < 0)
		return ret;

	if (dev->mt76.otp.data)
		memcpy(dev->mt76.eeprom.data, dev->mt76.otp.data,
		       MT7615_EEPROM_SIZE);

	dev->mt76.cap.has_2ghz = true;
	dev->mt76.cap.has_5ghz = true;
	memcpy(dev->mt76.macaddr, dev->mt76.eeprom.data + MT_EE_MAC_ADDR,
	       ETH_ALEN);

	mt76_eeprom_override(&dev->mt76);

	return 0;
}

static int
mt7663u_init_hardware(struct mt7615_dev *dev)
{
	int ret, idx;
	u32 val;

	ret = mt7663_init_eeprom(dev, MT_EFUSE_BASE);
	if (ret < 0)
		return ret;

	ret = mt7663u_dma_sched_init(dev);
	if (ret)
		return ret;

	val = mt76_rr(dev, MT_UDMA_WLCFG_0);
	val &= ~(MT_WL_RX_AGG_EN | MT_WL_RX_AGG_LMT |  MT_WL_RX_AGG_TO);
	val |=  MT_WL_RX_AGG_EN | FIELD_PREP(MT_WL_RX_AGG_LMT, 32) |
		FIELD_PREP(MT_WL_RX_AGG_TO, 100);
	mt76_wr(dev, MT_UDMA_WLCFG_0, val);

	val = mt76_rr(dev, MT_UDMA_WLCFG_0);
	val |= MT_WL_RX_EN | MT_WL_TX_EN | MT_WL_RX_MPSZ_PAD0 |
	       MT_TICK_1US_EN;
	mt76_wr(dev, MT_UDMA_WLCFG_0, val);

	mt76_rmw_field(dev, MT_UDMA_WLCFG_1, MT_WL_RX_AGG_PKT_LMT, 1);
	set_bit(MT76_STATE_INITIALIZED, &dev->mphy.state);

	ret = mt7663u_mcu_init(dev);
	if (ret)
		return ret;

	mt7663_mcu_set_eeprom(dev);
	mt7663u_mac_init(dev);
	mt7663_mcu_ctrl_pm_state(dev, 0);
	/* MT7663e : F/W halWtblClearAllWtbl() will do this in init. */
	/* mt7663u_mcu_del_wtbl_all(dev); */

	/* Beacon and mgmt frames should occupy wcid 0 */
	idx = mt76_wcid_alloc(dev->mt76.wcid_mask, MT7615_WTBL_STA - 1);
	if (idx)
		return -ENOSPC;

	dev->mt76.global_wcid.idx = idx;
	dev->mt76.global_wcid.hw_key_idx = -1;
	rcu_assign_pointer(dev->mt76.wcid[idx], &dev->mt76.global_wcid);

	return 0;
}

int mt7663u_register_device(struct mt7615_dev *dev)
{
	struct ieee80211_hw *hw = mt76_hw(dev);
	int err;

	INIT_DELAYED_WORK(&dev->mt76.mac_work, mt7663u_mac_work);
	INIT_WORK(&dev->rate_work, mt7663u_rate_work);
	INIT_LIST_HEAD(&dev->rd_head);

	mt7615_init_device_cap(dev);
	err = mt7663u_init_hardware(dev);
	if (err)
		return err;

	hw->extra_tx_headroom += MT7663_USB_HDR_SIZE + MT7663_USB_TXD_SIZE;
	/* check hw sg support in order to enable AMSDU */
	hw->max_tx_fragments = dev->mt76.usb.sg_en ? MT_HW_TXP_MAX_BUF_NUM : 1;

	dev->mphy.antenna_mask = 0x7;
	dev->chainmask = 0x03;

	ieee80211_hw_set(hw, SUPPORTS_REORDERING_BUFFER);

	err = mt76_register_device(&dev->mt76, true, mt7615_rates,
				   ARRAY_SIZE(mt7615_rates));
	if (err)
		return err;

	err = mt7663u_init_debugfs(dev);
	if (err < 0)
		return err;

	if (!dev->mt76.usb.sg_en) {
		struct ieee80211_sta_vht_cap *vht_cap;

		/* decrease max A-MSDU size if SG is not supported */
		vht_cap = &dev->mphy.sband_5g.sband.vht_cap;
		vht_cap->cap &= ~IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454;
	}

	return 0;
}
