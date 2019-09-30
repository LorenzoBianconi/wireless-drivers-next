// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 *         Felix Fietkau <nbd@nbd.name>
 *	   Sean Wang <sean.wang@mediatek.com>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pci.h>

#include "mt7663.h"
#include "mac.h"
#include "regs.h"
#include "../dma.h"

static void mt7663_phy_init(struct mt7663_dev *dev)
{
	/* MT7663 : no need */
}

static int
mt7663_init_tx_queue(struct mt7663_dev *dev, struct mt76_sw_queue *q,
		     int idx, int n_desc)
{
	struct mt76_queue *hwq;
	int err;

	hwq = devm_kzalloc(dev->mt76.dev, sizeof(*hwq), GFP_KERNEL);
	if (!hwq)
		return -ENOMEM;

	err = mt76_queue_alloc(dev, hwq, idx, n_desc, 0, MT_TX_RING_BASE);
	if (err < 0)
		return err;

	INIT_LIST_HEAD(&q->swq);
	q->q = hwq;

	mt7663_irq_enable(dev, MT_INT_TX_DONE(idx));

	return 0;
}

static int
mt7663_dma_init(struct mt7663_dev *dev)
{
	int i, ret;
	static const u8 wmm_queue_map[] = {
		[IEEE80211_AC_BK] = 0,
		[IEEE80211_AC_BE] = 1,
		[IEEE80211_AC_VI] = 2,
		[IEEE80211_AC_VO] = 4,
	};

	mt76_dma_attach(&dev->mt76);

	mt76_wr(dev, MT_WPDMA_GLO_CFG,
		MT_WPDMA_GLO_CFG_TX_WRITEBACK_DONE |
		MT_WPDMA_GLO_CFG_FIFO_LITTLE_ENDIAN |
		MT_WPDMA_GLO_CFG_OMIT_TX_INFO);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG,
		       MT_WPDMA_GLO_CFG_FW_RING_BP_TX_SCH, 0x1);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG,
		       MT_WPDMA_GLO_CFG_TX_BT_SIZE_BIT21, 0x1);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG,
		       MT_WPDMA_GLO_CFG_DMA_BURST_SIZE, 0x3);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG,
		       MT_WPDMA_GLO_CFG_MULTI_DMA_EN, 0x3);

	mt76_wr(dev, MT_WPDMA_RST_IDX, ~0);

	for (i = 0; i < ARRAY_SIZE(wmm_queue_map); i++) {
		ret = mt7663_init_tx_queue(dev, &dev->mt76.q_tx[i],
					   wmm_queue_map[i],
					   MT7663_TX_RING_SIZE);
		if (ret)
			return ret;
	}

	ret = mt7663_init_tx_queue(dev, &dev->mt76.q_tx[MT_TXQ_PSD],
				   MT7663_TXQ_MGMT, MT7663_TX_RING_SIZE);
	if (ret)
		return ret;

	ret = mt7663_init_tx_queue(dev, &dev->mt76.q_tx[MT_TXQ_MCU],
				   MT7663_TXQ_MCU, MT7663_TX_MCU_RING_SIZE);
	if (ret)
		return ret;

	ret = mt7663_init_tx_queue(dev, &dev->mt76.q_tx[MT_TXQ_FWDL],
				   MT7663_TXQ_FWDL, MT7663_TX_FWDL_RING_SIZE);
	if (ret)
		return ret;

	/* bcn quueue init,only use for hw queue idx mapping */
	ret = mt7663_init_tx_queue(dev, &dev->mt76.q_tx[MT_TXQ_BEACON],
				   MT_LMAC_BCN0, MT7663_TX_RING_SIZE);

	/* init rx queues */
	ret = mt76_queue_alloc(dev, &dev->mt76.q_rx[MT_RXQ_MCU], 1,
			       MT7663_RX_MCU_RING_SIZE, MT_RX_BUF_SIZE,
			       MT_RX_RING_BASE);
	if (ret)
		return ret;

	ret = mt76_queue_alloc(dev, &dev->mt76.q_rx[MT_RXQ_MAIN], 0,
			       MT7663_RX_RING_SIZE, MT_RX_BUF_SIZE,
			       MT_RX_RING_BASE);
	if (ret)
		return ret;

	mt76_wr(dev, MT_DELAY_INT_CFG, 0);

	ret = mt76_init_queues(dev);
	if (ret < 0)
		return ret;

	netif_tx_napi_add(&dev->mt76.napi_dev, &dev->mt76.tx_napi,
			  mt7663_poll_tx, NAPI_POLL_WEIGHT);
	napi_enable(&dev->mt76.tx_napi);

	mt76_poll(dev, MT_WPDMA_GLO_CFG,
		  MT_WPDMA_GLO_CFG_TX_DMA_BUSY |
		  MT_WPDMA_GLO_CFG_RX_DMA_BUSY, 0, 1000);

	/* start dma engine */
	mt76_set(dev, MT_WPDMA_GLO_CFG,
		 MT_WPDMA_GLO_CFG_TX_DMA_EN |
		 MT_WPDMA_GLO_CFG_RX_DMA_EN);

	/* enable interrupts for TX/RX rings */
	mt7663_irq_enable(dev, MT_INT_RX_DONE_ALL | MT_INT_TX_DONE_ALL);

	return 0;
}

static int
mt7663_dma_sched_init(struct mt7663_dev *dev)
{
	u32 val;

	val = mt76_rr(dev, MT_HIF_DMA_SHDL_PKT_MAX_SIZE);
	val &= ~(MT_PLE_PKT_MAX_SIZE_MASK | MT_PSE_PKT_MAX_SIZE_MASK);
	val |= MT_PLE_PKT_MAX_SIZE_NUM(0x1);
	val |= MT_PSE_PKT_MAX_SIZE_NUM(0x8);
	mt76_wr(dev, MT_HIF_DMA_SHDL_PKT_MAX_SIZE, val);

	/* Enable refill Control Group 0, 1, 2, 4, 5 */
	mt76_wr(dev, MT_HIF_DMA_SHDL_REFILL_CTRL, 0xffc80000);
	/* Group 0, 1, 2, 4, 5, 15 joint the ask round robin */
	mt76_wr(dev, MT_HIF_DMA_SHDL_OPTION_CTRL, 0x70068037);
	/*Each group min quota must larger then PLE_PKT_MAX_SIZE_NUM*/
	val = MT_DMA_SHDL_MIN_QUOTA_NUM(0x40);
	val |= MT_DMA_SHDL_MAX_QUOTA_NUM(0x800);

	mt76_wr(dev, MT_HIF_DMA_SHDL_GROUP0_CTRL, val);
	mt76_wr(dev, MT_HIF_DMA_SHDL_GROUP1_CTRL, val);
	mt76_wr(dev, MT_HIF_DMA_SHDL_GROUP2_CTRL, val);
	mt76_wr(dev, MT_HIF_DMA_SHDL_GROUP4_CTRL, val);
	val = MT_DMA_SHDL_MIN_QUOTA_NUM(0x40);
	val |= MT_DMA_SHDL_MAX_QUOTA_NUM(0x40);
	mt76_wr(dev, MT_HIF_DMA_SHDL_GROUP5_CTRL, val);

	val = MT_DMA_SHDL_MIN_QUOTA_NUM(0x20);
	val |= MT_DMA_SHDL_MAX_QUOTA_NUM(0x20);
	mt76_wr(dev, MT_HIF_DMA_SHDL_GROUP15_CTRL, val);

	mt76_wr(dev, MT_HIF_DMA_SHDL_Q_MAP0, 0x42104210);
	mt76_wr(dev, MT_HIF_DMA_SHDL_Q_MAP1, 0x42104210);
	/* ALTX0 and ALTX1 QID mapping to group 5 */
	mt76_wr(dev, MT_HIF_DMA_SHDL_Q_MAP2, 0x00050005);
	mt76_wr(dev, MT_HIF_DMA_SHDL_Q_MAP3, 0x0);
	mt76_wr(dev, MT_HIF_DMA_SHDL_SHDL_SET0, 0x6012345f);
	mt76_wr(dev, MT_HIF_DMA_SHDL_SHDL_SET1, 0xedcba987);

	return 0;
}

static void mt7663_mac_init(struct mt7663_dev *dev)
{
	bool init_mac1 = dev->mt76.rev == 0x76630010;
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
	mt7663_mcu_set_rts_thresh(dev, 0x92b);

	mt76_rmw(dev, MT_AGG_SCR, MT_AGG_SCR_NLNAV_MID_PTEC_DIS,
		 MT_AGG_SCR_NLNAV_MID_PTEC_DIS);

	mt7663_mcu_init_mac(dev, 0);

	if (init_mac1)
		mt7663_mcu_init_mac(dev, 1);

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

static int mt7663_init_hardware(struct mt7663_dev *dev)
{
	u32 base = mt7663_reg_map(dev, MT_EFUSE_BASE);
	int ret, idx;

	mt76_wr(dev, MT_INT_SOURCE_CSR, ~0);

	spin_lock_init(&dev->token_lock);
	idr_init(&dev->token);

	ret = mt7663_eeprom_init(dev, base);
	if (ret < 0)
		return ret;

	ret = mt7663_dma_init(dev);
	if (ret)
		return ret;

	/* MT7663 : init before f/w download*/
	ret = mt7663_dma_sched_init(dev);
	if (ret)
		return ret;

	set_bit(MT76_STATE_INITIALIZED, &dev->mphy.state);

	ret = mt7663_mcu_init(dev);
	if (ret)
		return ret;

	mt7663_mcu_set_eeprom(dev);

	mt7663_mac_init(dev);
	mt7663_phy_init(dev);

	mt7663_mcu_ctrl_pm_state(dev, 0);
	/* MT7663 : F/W halWtblClearAllWtbl() will do this in init. */
	/* mt7663_mcu_del_wtbl_all(dev); */

	/* Beacon and mgmt frames should occupy wcid 0 */
	idx = mt76_wcid_alloc(dev->mt76.wcid_mask, MT7663_WTBL_STA - 1);
	if (idx)
		return -ENOSPC;

	dev->mt76.global_wcid.idx = idx;
	dev->mt76.global_wcid.hw_key_idx = -1;
	rcu_assign_pointer(dev->mt76.wcid[idx], &dev->mt76.global_wcid);

	return 0;
}

int mt7663_init_device(struct mt7663_dev *dev, int irq)
{
	struct ieee80211_hw *hw = mt76_hw(dev);
	int err;

	err = devm_request_irq(dev->mt76.dev, irq, mt7663_irq_handler,
			       IRQF_SHARED, KBUILD_MODNAME, dev);
	if (err)
		return err;

	err = mt7663_init_hardware(dev);
	if (err)
		return err;

	hw->max_tx_fragments = MT_TXP_MAX_BUF_NUM;

	return mt7663_register_device(dev);
}

static int __init mt7663_init(void)
{
	int ret;

	ret = pci_register_driver(&mt7663_pci_driver);
	if (ret)
		return ret;

	ret = platform_driver_register(&mt7629_wmac_driver);
	if (ret)
		pci_unregister_driver(&mt7663_pci_driver);

	return ret;
}

static void __exit mt7663_exit(void)
{
	platform_driver_unregister(&mt7629_wmac_driver);
	pci_unregister_driver(&mt7663_pci_driver);
}

module_init(mt7663_init);
module_exit(mt7663_exit);

MODULE_LICENSE("Dual BSD/GPL");
