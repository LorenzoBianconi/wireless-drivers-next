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
#include <linux/kernel.h>
#include <linux/firmware.h>

#include "mt76x0.h"
#include "mcu.h"
#include "../mt76x02_dma.h"
#include "../mt76x02_mac.h"
#include "../mt76x02_util.h"

static void mt76x0u_stop(struct ieee80211_hw *hw)
{
	struct mt76x0_dev *dev = hw->priv;

	mutex_lock(&dev->mt76.mutex);
	clear_bit(MT76_STATE_RUNNING, &dev->mt76.state);
	mt76x0u_mac_stop(dev);
	mutex_unlock(&dev->mt76.mutex);
}

static void mt76x0_reset_csr_bbp(struct mt76x0_dev *dev)
{
	u32 val;

	val = mt76_rr(dev, MT_PBF_SYS_CTRL);
	val &= ~0x2000;
	mt76_wr(dev, MT_PBF_SYS_CTRL, val);

	mt76_wr(dev, MT_MAC_SYS_CTRL, MT_MAC_SYS_CTRL_RESET_CSR |
					 MT_MAC_SYS_CTRL_RESET_BBP);

	msleep(200);
}

static void mt76x0_init_usb_dma(struct mt76x0_dev *dev)
{
	u32 val;

	val = mt76_rr(dev, MT_USB_DMA_CFG);

	val |= MT_USB_DMA_CFG_RX_BULK_EN |
	       MT_USB_DMA_CFG_TX_BULK_EN;

	/* disable AGGR_BULK_RX in order to receive one
	 * frame in each rx urb and avoid copies
	 */
	val &= ~MT_USB_DMA_CFG_RX_BULK_AGG_EN;
	mt76_wr(dev, MT_USB_DMA_CFG, val);

	val = mt76_rr(dev, MT_COM_REG0);
	if (val & 1)
		dev_dbg(dev->mt76.dev, "MCU not ready\n");

	val = mt76_rr(dev, MT_USB_DMA_CFG);

	val |= MT_USB_DMA_CFG_RX_DROP_OR_PAD;
	mt76_wr(dev, MT_USB_DMA_CFG, val);
	val &= ~MT_USB_DMA_CFG_RX_DROP_OR_PAD;
	mt76_wr(dev, MT_USB_DMA_CFG, val);
}

int mt76x0u_init_hardware(struct mt76x0_dev *dev)
{
	int ret;

	if (!mt76_poll_msec(dev, MT_WPDMA_GLO_CFG,
			    MT_WPDMA_GLO_CFG_TX_DMA_BUSY |
			    MT_WPDMA_GLO_CFG_RX_DMA_BUSY, 0, 100))
		return -EIO;

	/* Wait for ASIC ready after FW load. */
	if (!mt76x02_wait_for_mac(&dev->mt76))
		return -ETIMEDOUT;

	mt76x0_reset_csr_bbp(dev);
	mt76x0_init_usb_dma(dev);

	mt76_wr(dev, MT_HEADER_TRANS_CTRL_REG, 0x0);
	mt76_wr(dev, MT_TSO_CTRL, 0x0);

	ret = mt76x02_mcu_function_select(&dev->mt76, Q_SELECT, 1, false);
	if (ret)
		return ret;

	mt76x0_init_mac_registers(dev);

	if (!mt76_poll_msec(dev, MT_MAC_STATUS,
			    MT_MAC_STATUS_TX | MT_MAC_STATUS_RX, 0, 1000))
		return -EIO;

	ret = mt76x0_init_bbp(dev);
	if (ret)
		return ret;

	ret = mt76x0_init_wcid_mem(dev);
	if (ret)
		return ret;

	mt76x0_init_key_mem(dev);

	ret = mt76x0_init_wcid_attr_mem(dev);
	if (ret)
		return ret;

	mt76_clear(dev, MT_BEACON_TIME_CFG,
		   (MT_BEACON_TIME_CFG_TIMER_EN |
		    MT_BEACON_TIME_CFG_SYNC_MODE |
		    MT_BEACON_TIME_CFG_TBTT_EN |
		    MT_BEACON_TIME_CFG_BEACON_TX));

	mt76x0_reset_counters(dev);

	mt76_rmw(dev, MT_US_CYC_CFG, MT_US_CYC_CNT, 0x1e);

	mt76_wr(dev, MT_TXOP_CTRL_CFG,
		FIELD_PREP(MT_TXOP_TRUN_EN, 0x3f) |
		FIELD_PREP(MT_TXOP_EXT_CCA_DLY, 0x58));

	ret = mt76x0_eeprom_init(dev);
	if (ret)
		return ret;

	mt76x0_phy_init(dev);

	return 0;
}

void mt76x0u_mac_stop(struct mt76x0_dev *dev)
{
	mt76u_stop_stat_wk(&dev->mt76);
	mt76x0_mac_stop(dev);
}

void mt76x0u_cleanup(struct mt76x0_dev *dev)
{
	clear_bit(MT76_STATE_INITIALIZED, &dev->mt76.state);
	mt76x0_chip_onoff(dev, false, false);
	mt76u_queues_deinit(&dev->mt76);
	mt76u_mcu_deinit(&dev->mt76);
}

int mt76x0u_register_device(struct mt76x0_dev *dev)
{
	struct ieee80211_hw *hw = dev->mt76.hw;
	int err;

	err = mt76u_mcu_init_rx(&dev->mt76);
	if (err < 0)
		return err;

	err = mt76u_alloc_queues(&dev->mt76);
	if (err < 0)
		return err;

	mt76x0_chip_onoff(dev, true, true);
	if (!mt76x02_wait_for_mac(&dev->mt76)) {
		err = -ETIMEDOUT;
		goto err;
	}

	err = mt76x0u_mcu_init(dev);
	if (err < 0)
		goto err;

	err = mt76x0u_init_hardware(dev);
	if (err < 0)
		goto err;

	err = mt76x0_register_device(dev);
	if (err < 0)
		goto err;

	/* check hw sg support in order to enable AMSDU */
	if (mt76u_check_sg(&dev->mt76))
		hw->max_tx_fragments = MT_SG_MAX_SIZE;
	else
		hw->max_tx_fragments = 1;

	set_bit(MT76_STATE_INITIALIZED, &dev->mt76.state);

	return 0;

err:
	mt76x0u_cleanup(dev);
	return err;
}

const struct ieee80211_ops mt76x0u_ops = {
	.tx = mt76x0_tx,
	.start = mt76x0_start,
	.stop = mt76x0u_stop,
	.add_interface = mt76x02_add_interface,
	.remove_interface = mt76x02_remove_interface,
	.config = mt76x0_config,
	.configure_filter = mt76x02_configure_filter,
	.bss_info_changed = mt76x0_bss_info_changed,
	.sta_add = mt76x02_sta_add,
	.sta_remove = mt76x02_sta_remove,
	.set_key = mt76x02_set_key,
	.conf_tx = mt76x02_conf_tx,
	.sw_scan_start = mt76x0_sw_scan,
	.sw_scan_complete = mt76x0_sw_scan_complete,
	.ampdu_action = mt76x02_ampdu_action,
	.sta_rate_tbl_update = mt76x02_sta_rate_tbl_update,
	.set_rts_threshold = mt76x0_set_rts_threshold,
	.wake_tx_queue = mt76_wake_tx_queue,
};
