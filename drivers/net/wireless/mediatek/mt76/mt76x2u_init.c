/*
 * Copyright (C) 2018 Lorenzo Bianconi <lorenzo.bianconi83@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/delay.h>

#include "mt76x2u.h"
#include "mt76x2_eeprom.h"

static void mt76x2u_power_on_rf_patch(struct mt76x2_dev *dev)
{
	mt76_set(dev, MT_VEND_ADDR(CFG, 0x130), BIT(0) | BIT(16));
	udelay(1);

	mt76_clear(dev, MT_VEND_ADDR(CFG, 0x1c), 0xff);
	mt76_set(dev, MT_VEND_ADDR(CFG, 0x1c), 0x30);

	mt76_wr(dev, MT_VEND_ADDR(CFG, 0x14), 0x484f);
	udelay(1);

	mt76_set(dev, MT_VEND_ADDR(CFG, 0x130), BIT(17));
	udelay(125);

	mt76_clear(dev, MT_VEND_ADDR(CFG, 0x130), BIT(16));
	udelay(50);

	mt76_set(dev, MT_VEND_ADDR(CFG, 0x14c), BIT(19) | BIT(20));
}

static void mt76x2u_power_on_rf(struct mt76x2_dev *dev, int unit)
{
	int shift = unit ? 8 : 0;
	u32 val = (BIT(1) | BIT(3) | BIT(4) | BIT(5)) << shift;

	/* Enable RF BG */
	mt76_set(dev, MT_VEND_ADDR(CFG, 0x130), BIT(0) << shift);
	udelay(10);

	/* Enable RFDIG LDO/AFE/ABB/ADDA */
	mt76_set(dev, MT_VEND_ADDR(CFG, 0x130), val);
	udelay(10);

	/* Switch RFDIG power to internal LDO */
	mt76_clear(dev, MT_VEND_ADDR(CFG, 0x130), BIT(2) << shift);
	udelay(10);

	mt76x2u_power_on_rf_patch(dev);

	mt76_set(dev, 0x530, 0xf);
}

static void mt76x2u_power_on(struct mt76x2_dev *dev)
{
	u32 val;

	/* Turn on WL MTCMOS */
	mt76_set(dev, MT_VEND_ADDR(CFG, 0x148),
		 MT_WLAN_MTC_CTRL_MTCMOS_PWR_UP);

	val = MT_WLAN_MTC_CTRL_STATE_UP |
	      MT_WLAN_MTC_CTRL_PWR_ACK |
	      MT_WLAN_MTC_CTRL_PWR_ACK_S;

	mt76_poll(dev, MT_VEND_ADDR(CFG, 0x148), val, val, 1000);

	mt76_clear(dev, MT_VEND_ADDR(CFG, 0x148), 0x7f << 16);
	udelay(10);

	mt76_clear(dev, MT_VEND_ADDR(CFG, 0x148), 0xf << 24);
	udelay(10);

	mt76_set(dev, MT_VEND_ADDR(CFG, 0x148), 0xf << 24);
	mt76_clear(dev, MT_VEND_ADDR(CFG, 0x148), 0xfff);

	/* Turn on AD/DA power down */
	mt76_clear(dev, MT_VEND_ADDR(CFG, 0x1204), BIT(3));

	/* WLAN function enable */
	mt76_set(dev, MT_VEND_ADDR(CFG, 0x80), BIT(0));

	/* Release BBP software reset */
	mt76_clear(dev, MT_VEND_ADDR(CFG, 0x64), BIT(18));

	mt76x2u_power_on_rf(dev, 0);
	mt76x2u_power_on_rf(dev, 1);
}

static int mt76x2u_init_eeprom(struct mt76x2_dev *dev)
{
	u32 val, i;

	dev->mt76.eeprom.data = devm_kzalloc(dev->mt76.dev,
					     MT7612U_EEPROM_SIZE,
					     GFP_KERNEL);
	dev->mt76.eeprom.size = MT7612U_EEPROM_SIZE;
	if (!dev->mt76.eeprom.data)
		return -ENOMEM;

	for (i = 0; i + 4 <= MT7612U_EEPROM_SIZE; i += 4) {
		val = mt76_rr(dev, MT_VEND_ADDR(EEPROM, i));
		put_unaligned_le32(val, dev->mt76.eeprom.data + i);
	}

	mt76x2_eeprom_parse_hw_cap(dev);
	return 0;
}

struct mt76x2_dev *mt76x2u_alloc_device(struct device *pdev)
{
	static const struct mt76_driver_ops drv_ops = {
		.tx_prepare_skb = mt76x2u_tx_prepare_skb,
		.tx_complete_skb = mt76x2u_tx_complete_skb,
		.rx_skb = mt76x2_queue_rx_skb,
	};
	struct ieee80211_hw *hw;
	struct mt76x2_dev *dev;

	hw = ieee80211_alloc_hw(sizeof(*dev), &mt76x2u_ops);
	if (!hw)
		return NULL;

	dev = hw->priv;
	dev->mt76.dev = pdev;
	dev->mt76.hw = hw;
	dev->mt76.drv = &drv_ops;
	mutex_init(&dev->mutex);

	return dev;
}

static void mt76x2u_init_beacon_offsets(struct mt76x2_dev *dev)
{
	mt76_wr(dev, MT_BCN_OFFSET(0), 0x18100800);
	mt76_wr(dev, MT_BCN_OFFSET(1), 0x38302820);
	mt76_wr(dev, MT_BCN_OFFSET(2), 0x58504840);
	mt76_wr(dev, MT_BCN_OFFSET(3), 0x78706860);
}

static int mt76x2u_init_hardware(struct mt76x2_dev *dev)
{
	static const u16 beacon_offsets[] = {
		/* 512 byte per beacon */
		0xc000, 0xc200, 0xc400, 0xc600,
		0xc800, 0xca00, 0xcc00, 0xce00,
		0xd000, 0xd200, 0xd400, 0xd600,
		0xd800, 0xda00, 0xdc00, 0xde00
	};
	const struct mt76_wcid_addr addr = {
		.macaddr = {0xff, 0xff, 0xff, 0xff,0xff, 0xff},
		.ba_mask = 0,
	};
	int i, err;

	dev->beacon_offsets = beacon_offsets;

	mt76x2_reset_wlan(dev, true);
	mt76x2u_power_on(dev);

	if (!mt76x2_wait_for_mac(dev))
		return -ETIMEDOUT;

	err = mt76x2u_mcu_fw_init(dev);
	if (err < 0)
		return err;

	if (!mt76_poll_msec(dev, MT_WPDMA_GLO_CFG,
			    MT_WPDMA_GLO_CFG_TX_DMA_BUSY |
			    MT_WPDMA_GLO_CFG_RX_DMA_BUSY, 0, 100))
		return -EIO;

	/* wait for asic ready after fw load. */
	if (!mt76x2_wait_for_mac(dev))
		return -ETIMEDOUT;

	mt76_wr(dev, MT_HEADER_TRANS_CTRL_REG, 0);
	mt76_wr(dev, MT_TSO_CTRL, 0);

	err = mt76x2u_dma_init(dev);
	if (err < 0)
		return err;

	err = mt76x2u_mcu_init(dev);
	if (err < 0)
		goto err_dma;

	err = mt76x2u_init_eeprom(dev);
	if (err < 0)
		goto err_mcu;

	mt76x2u_mac_setaddr(dev, dev->mt76.eeprom.data + MT_EE_MAC_ADDR);

	err = mt76x2u_mac_reset(dev);
	if (err < 0)
		goto err_mcu;

	dev->rxfilter = mt76_rr(dev, MT_RX_FILTR_CFG);

	mt76x2u_init_beacon_offsets(dev);

	if (!mt76x2_wait_for_bbp(dev)) {
		err = -ETIMEDOUT;
		goto err_mcu;
	}

	/* reset wcid table */
	for (i = 0; i < 254; i++)
		mt76_wr_copy(dev, MT_WCID_ADDR(i), &addr,
			     sizeof(struct mt76_wcid_addr));

	/* reset shared key table and pairwise key table */
	for (i = 0; i < 4; i++)
		mt76_wr(dev, MT_SKEY_MODE_BASE_0 + 4 * i, 0);
	for (i = 0; i < 256; i++)
		mt76_wr(dev, MT_WCID_ATTR(i), 1);

	mt76_clear(dev, MT_BEACON_TIME_CFG,
		   MT_BEACON_TIME_CFG_TIMER_EN |
		   MT_BEACON_TIME_CFG_SYNC_MODE |
		   MT_BEACON_TIME_CFG_TBTT_EN |
		   MT_BEACON_TIME_CFG_BEACON_TX);

	mt76_rmw(dev, MT_US_CYC_CFG, MT_US_CYC_CNT, 0x1e);
	mt76_wr(dev, MT_TXOP_CTRL_CFG, 0x583f);

	err = mt76x2u_mcu_load_cr(dev, MT_RF_BBP_CR, 0, 0);
	if (err < 0)
		goto err_mcu;

	mt76x2u_phy_set_rxpath(dev);
	mt76x2u_phy_set_txdac(dev);

	return mt76x2u_mac_stop(dev);

err_mcu:
	mt76x2u_mcu_deinit(dev);
err_dma:
	mt76x2u_dma_cleanup(dev);

	return err;
}

int mt76x2u_register_device(struct mt76x2_dev *dev)
{
	struct ieee80211_hw *hw = mt76_hw(dev);
	struct wiphy *wiphy = hw->wiphy;
	int err;

	INIT_DELAYED_WORK(&dev->cal_work, mt76x2u_phy_calibrate);
	INIT_DELAYED_WORK(&dev->stat_work, mt76x2u_tx_status_data);
	mt76x2_init_device(dev);

	err = mt76x2u_init_hardware(dev);
	if (err < 0)
		return err;

	wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);

	err = mt76_register_device(&dev->mt76, true, mt76x2_rates,
				   ARRAY_SIZE(mt76x2_rates));
	if (err)
		goto fail;

	set_bit(MT76_STATE_INITIALIZED, &dev->mt76.state);

	mt76x2_init_debugfs(dev);
	mt76x2_init_txpower(dev, &dev->mt76.sband_2g.sband);
	mt76x2_init_txpower(dev, &dev->mt76.sband_5g.sband);

	return 0;

fail:
	mt76x2u_cleanup(dev);
	return err;
}

void mt76x2u_stop_hw(struct mt76x2_dev *dev)
{
	cancel_delayed_work_sync(&dev->stat_work);
	cancel_delayed_work_sync(&dev->cal_work);
	mt76x2u_mac_stop(dev);
}

void mt76x2u_cleanup(struct mt76x2_dev *dev)
{
	mt76x2u_mcu_set_radio_state(dev, false);
	mt76x2u_dma_cleanup(dev);
	mt76x2u_stop_hw(dev);
	mt76x2u_mcu_deinit(dev);
}
