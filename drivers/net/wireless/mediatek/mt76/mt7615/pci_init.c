// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Roy Luo <royluo@google.com>
 *         Ryder Lee <ryder.lee@mediatek.com>
 *         Felix Fietkau <nbd@nbd.name>
 *         Lorenzo Bianconi <lorenzo@kernel.org>
 */

#include <linux/etherdevice.h>
#include "mt7615.h"
#include "mac.h"
#include "eeprom.h"
#include "regs.h"

static void mt7615_phy_init(struct mt7615_dev *dev)
{
	/* disable rf low power beacon mode */
	mt76_set(dev, MT_WF_PHY_WF2_RFCTRL0(0), MT_WF_PHY_WF2_RFCTRL0_LPBCN_EN);
	mt76_set(dev, MT_WF_PHY_WF2_RFCTRL0(1), MT_WF_PHY_WF2_RFCTRL0_LPBCN_EN);
}

static void mt7615_mac_init(struct mt7615_dev *dev)
{
	u32 val, mask, set;
	int i;

	/* enable band 0/1 clk */
	mt76_set(dev, MT_CFG_CCR,
		 MT_CFG_CCR_MAC_D0_1X_GC_EN | MT_CFG_CCR_MAC_D0_2X_GC_EN |
		 MT_CFG_CCR_MAC_D1_1X_GC_EN | MT_CFG_CCR_MAC_D1_2X_GC_EN);

	val = mt76_rmw(dev, MT_TMAC_TRCR(0),
		       MT_TMAC_TRCR_CCA_SEL | MT_TMAC_TRCR_SEC_CCA_SEL,
		       FIELD_PREP(MT_TMAC_TRCR_CCA_SEL, 2) |
		       FIELD_PREP(MT_TMAC_TRCR_SEC_CCA_SEL, 0));
	mt76_wr(dev, MT_TMAC_TRCR(1), val);

	val = MT_AGG_ACR_PKT_TIME_EN | MT_AGG_ACR_NO_BA_AR_RULE |
	      FIELD_PREP(MT_AGG_ACR_CFEND_RATE, MT7615_CFEND_RATE_DEFAULT) |
	      FIELD_PREP(MT_AGG_ACR_BAR_RATE, MT7615_BAR_RATE_DEFAULT);
	mt76_wr(dev, MT_AGG_ACR(0), val);
	mt76_wr(dev, MT_AGG_ACR(1), val);

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
	mt7615_mac_set_scs(dev, true);

	mt76_rmw(dev, MT_AGG_SCR, MT_AGG_SCR_NLNAV_MID_PTEC_DIS,
		 MT_AGG_SCR_NLNAV_MID_PTEC_DIS);

	mt76_wr(dev, MT_DMA_DCR0, MT_DMA_DCR0_RX_VEC_DROP |
		FIELD_PREP(MT_DMA_DCR0_MAX_RX_LEN, 3072));

	val = FIELD_PREP(MT_AGG_ARxCR_LIMIT(0), 7) |
	      FIELD_PREP(MT_AGG_ARxCR_LIMIT(1), 2) |
	      FIELD_PREP(MT_AGG_ARxCR_LIMIT(2), 2) |
	      FIELD_PREP(MT_AGG_ARxCR_LIMIT(3), 2) |
	      FIELD_PREP(MT_AGG_ARxCR_LIMIT(4), 1) |
	      FIELD_PREP(MT_AGG_ARxCR_LIMIT(5), 1) |
	      FIELD_PREP(MT_AGG_ARxCR_LIMIT(6), 1) |
	      FIELD_PREP(MT_AGG_ARxCR_LIMIT(7), 1);
	mt76_wr(dev, MT_AGG_ARUCR(0), val);
	mt76_wr(dev, MT_AGG_ARUCR(1), val);

	val = FIELD_PREP(MT_AGG_ARxCR_LIMIT(0), MT7615_RATE_RETRY - 1) |
	      FIELD_PREP(MT_AGG_ARxCR_LIMIT(1), MT7615_RATE_RETRY - 1) |
	      FIELD_PREP(MT_AGG_ARxCR_LIMIT(2), MT7615_RATE_RETRY - 1) |
	      FIELD_PREP(MT_AGG_ARxCR_LIMIT(3), MT7615_RATE_RETRY - 1) |
	      FIELD_PREP(MT_AGG_ARxCR_LIMIT(4), MT7615_RATE_RETRY - 1) |
	      FIELD_PREP(MT_AGG_ARxCR_LIMIT(5), MT7615_RATE_RETRY - 1) |
	      FIELD_PREP(MT_AGG_ARxCR_LIMIT(6), MT7615_RATE_RETRY - 1) |
	      FIELD_PREP(MT_AGG_ARxCR_LIMIT(7), MT7615_RATE_RETRY - 1);
	mt76_wr(dev, MT_AGG_ARDCR(0), val);
	mt76_wr(dev, MT_AGG_ARDCR(1), val);

	mt76_wr(dev, MT_AGG_ARCR,
		(FIELD_PREP(MT_AGG_ARCR_RTS_RATE_THR, 2) |
		 MT_AGG_ARCR_RATE_DOWN_RATIO_EN |
		 FIELD_PREP(MT_AGG_ARCR_RATE_DOWN_RATIO, 1) |
		 FIELD_PREP(MT_AGG_ARCR_RATE_UP_EXTRA_TH, 4)));

	mask = MT_DMA_RCFR0_MCU_RX_MGMT |
	       MT_DMA_RCFR0_MCU_RX_CTL_NON_BAR |
	       MT_DMA_RCFR0_MCU_RX_CTL_BAR |
	       MT_DMA_RCFR0_MCU_RX_BYPASS |
	       MT_DMA_RCFR0_RX_DROPPED_UCAST |
	       MT_DMA_RCFR0_RX_DROPPED_MCAST;
	set = FIELD_PREP(MT_DMA_RCFR0_RX_DROPPED_UCAST, 2) |
	      FIELD_PREP(MT_DMA_RCFR0_RX_DROPPED_MCAST, 2);
	mt76_rmw(dev, MT_DMA_RCFR0(0), mask, set);
	mt76_rmw(dev, MT_DMA_RCFR0(1), mask, set);

	for (i = 0; i < MT7615_WTBL_SIZE; i++)
		mt7615_mac_wtbl_update(dev, i,
				       MT_WTBL_UPDATE_ADM_COUNT_CLEAR);

	mt76_set(dev, MT_WF_RMAC_MIB_TIME0, MT_WF_RMAC_MIB_RXTIME_EN);
	mt76_set(dev, MT_WF_RMAC_MIB_AIRTIME0, MT_WF_RMAC_MIB_RXTIME_EN);
}

bool mt7615_wait_for_mcu_init(struct mt7615_dev *dev)
{
	flush_work(&dev->mcu_work);

	return test_bit(MT76_STATE_MCU_RUNNING, &dev->mphy.state);
}

static void mt7615_init_work(struct work_struct *work)
{
	struct mt7615_dev *dev = container_of(work, struct mt7615_dev, mcu_work);

	if (mt7615_mcu_init(dev))
		return;

	mt7615_mcu_set_eeprom(dev);
	mt7615_mac_init(dev);
	mt7615_phy_init(dev);
	mt7615_mcu_del_wtbl_all(dev);
}

static int mt7615_init_hardware(struct mt7615_dev *dev)
{
	int ret, idx;

	mt76_wr(dev, MT_INT_SOURCE_CSR, ~0);

	INIT_WORK(&dev->mcu_work, mt7615_init_work);
	spin_lock_init(&dev->token_lock);
	idr_init(&dev->token);

	ret = mt7615_eeprom_init(dev);
	if (ret < 0)
		return ret;

	ret = mt7615_dma_init(dev);
	if (ret)
		return ret;

	set_bit(MT76_STATE_INITIALIZED, &dev->mphy.state);

	/* Beacon and mgmt frames should occupy wcid 0 */
	idx = mt76_wcid_alloc(dev->mt76.wcid_mask, MT7615_WTBL_STA - 1);
	if (idx)
		return -ENOSPC;

	dev->mt76.global_wcid.idx = idx;
	dev->mt76.global_wcid.hw_key_idx = -1;
	rcu_assign_pointer(dev->mt76.wcid[idx], &dev->mt76.global_wcid);

	return 0;
}

static void
mt7615_led_set_config(struct led_classdev *led_cdev,
		      u8 delay_on, u8 delay_off)
{
	struct mt7615_dev *dev;
	struct mt76_dev *mt76;
	u32 val, addr;

	mt76 = container_of(led_cdev, struct mt76_dev, led_cdev);
	dev = container_of(mt76, struct mt7615_dev, mt76);
	val = FIELD_PREP(MT_LED_STATUS_DURATION, 0xffff) |
	      FIELD_PREP(MT_LED_STATUS_OFF, delay_off) |
	      FIELD_PREP(MT_LED_STATUS_ON, delay_on);

	addr = mt7615_reg_map(dev, MT_LED_STATUS_0(mt76->led_pin));
	mt76_wr(dev, addr, val);
	addr = mt7615_reg_map(dev, MT_LED_STATUS_1(mt76->led_pin));
	mt76_wr(dev, addr, val);

	val = MT_LED_CTRL_REPLAY(mt76->led_pin) |
	      MT_LED_CTRL_KICK(mt76->led_pin);
	if (mt76->led_al)
		val |= MT_LED_CTRL_POLARITY(mt76->led_pin);
	addr = mt7615_reg_map(dev, MT_LED_CTRL);
	mt76_wr(dev, addr, val);
}

static int
mt7615_led_set_blink(struct led_classdev *led_cdev,
		     unsigned long *delay_on,
		     unsigned long *delay_off)
{
	u8 delta_on, delta_off;

	delta_off = max_t(u8, *delay_off / 10, 1);
	delta_on = max_t(u8, *delay_on / 10, 1);

	mt7615_led_set_config(led_cdev, delta_on, delta_off);

	return 0;
}

static void
mt7615_led_set_brightness(struct led_classdev *led_cdev,
			  enum led_brightness brightness)
{
	if (!brightness)
		mt7615_led_set_config(led_cdev, 0, 0xff);
	else
		mt7615_led_set_config(led_cdev, 0xff, 0);
}

static void
mt7615_cap_dbdc_enable(struct mt7615_dev *dev)
{
	dev->mphy.sband_5g.sband.vht_cap.cap &=
			~(IEEE80211_VHT_CAP_SHORT_GI_160 |
			  IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ);
	if (dev->chainmask == 0xf)
		dev->mphy.antenna_mask = dev->chainmask >> 2;
	else
		dev->mphy.antenna_mask = dev->chainmask >> 1;
	dev->phy.chainmask = dev->mphy.antenna_mask;
	mt76_set_stream_caps(&dev->mt76, true);
}

int mt7615_register_ext_phy(struct mt7615_dev *dev)
{
	struct mt7615_phy *phy = mt7615_ext_phy(dev);
	struct mt76_phy *mphy;
	int ret;

	if (test_bit(MT76_STATE_RUNNING, &dev->mphy.state))
		return -EINVAL;

	if (phy)
		return 0;

	mt7615_cap_dbdc_enable(dev);
	mphy = mt76_alloc_phy(&dev->mt76, sizeof(*phy), &mt7615_ops);
	if (!mphy)
		return -ENOMEM;

	phy = mphy->priv;
	phy->dev = dev;
	phy->mt76 = mphy;
	phy->chainmask = dev->chainmask & ~dev->phy.chainmask;
	mphy->antenna_mask = BIT(hweight8(phy->chainmask)) - 1;
	mt7615_init_wiphy(mphy->hw);

	/* second phy can only handle 5 GHz */
	mphy->sband_2g.sband.n_channels = 0;
	mphy->hw->wiphy->bands[NL80211_BAND_2GHZ] = NULL;

	ret = mt76_register_phy(mphy);
	if (ret)
		ieee80211_free_hw(mphy->hw);

	return ret;
}

void mt7615_unregister_ext_phy(struct mt7615_dev *dev)
{
	struct mt7615_phy *phy = mt7615_ext_phy(dev);
	struct mt76_phy *mphy = dev->mt76.phy2;

	if (!phy)
		return;

	mt7615_cap_dbdc_disable(dev);
	mt76_unregister_phy(mphy);
	ieee80211_free_hw(mphy->hw);
}

int mt7615_register_device(struct mt7615_dev *dev)
{
	int ret;

	INIT_DELAYED_WORK(&dev->mt76.mac_work, mt7615_mac_work);
	mt7615_init_device_cap(dev);

	ret = mt7615_init_hardware(dev);
	if (ret)
		return ret;

	ret = mt76_register_device(&dev->mt76, true, mt7615_rates,
				   ARRAY_SIZE(mt7615_rates));

	/* init led callbacks */
	if (IS_ENABLED(CONFIG_MT76_LEDS)) {
		dev->mt76.led_cdev.brightness_set = mt7615_led_set_brightness;
		dev->mt76.led_cdev.blink_set = mt7615_led_set_blink;
	}

	if (ret)
		return ret;

	ieee80211_queue_work(mt76_hw(dev), &dev->mcu_work);
	mt7615_init_txpower(dev, &dev->mphy.sband_2g.sband);
	mt7615_init_txpower(dev, &dev->mphy.sband_5g.sband);

	return mt7615_init_debugfs(dev);
}

void mt7615_unregister_device(struct mt7615_dev *dev)
{
	struct mt76_txwi_cache *txwi;
	bool mcu_running;
	int id;

	mcu_running = mt7615_wait_for_mcu_init(dev);

	mt7615_unregister_ext_phy(dev);
	mt76_unregister_device(&dev->mt76);
	if (mcu_running)
		mt7615_mcu_exit(dev);
	mt7615_dma_cleanup(dev);

	spin_lock_bh(&dev->token_lock);
	idr_for_each_entry(&dev->token, txwi, id) {
		mt7615_txp_skb_unmap(&dev->mt76, txwi);
		if (txwi->skb)
			dev_kfree_skb_any(txwi->skb);
		mt76_put_txwi(&dev->mt76, txwi);
	}
	spin_unlock_bh(&dev->token_lock);
	idr_destroy(&dev->token);

	mt76_free_device(&dev->mt76);
}
