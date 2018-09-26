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
#include "../mt76x02_util.h"

static int mt76x0e_start(struct ieee80211_hw *hw)
{
	struct mt76x0_dev *dev = hw->priv;

	mutex_lock(&dev->mt76.mutex);

	mt76x02_mac_start(&dev->mt76);
	mt76x0_start(dev);

	mutex_unlock(&dev->mt76.mutex);

	return 0;
}

static void mt76x0e_stop(struct ieee80211_hw *hw)
{
	struct mt76x0_dev *dev = hw->priv;

	mutex_lock(&dev->mt76.mutex);

	if (!mt76_poll(dev, MT_WPDMA_GLO_CFG, MT_WPDMA_GLO_CFG_TX_DMA_BUSY,
		       0, 1000))
		dev_warn(dev->mt76.dev, "TX DMA did not stop\n");
	mt76_clear(dev, MT_WPDMA_GLO_CFG, MT_WPDMA_GLO_CFG_TX_DMA_EN);

	mt76x0_stop(dev);

	if (!mt76_poll(dev, MT_WPDMA_GLO_CFG, MT_WPDMA_GLO_CFG_RX_DMA_BUSY,
		       0, 1000))
		dev_warn(dev->mt76.dev, "TX DMA did not stop\n");
	mt76_clear(dev, MT_WPDMA_GLO_CFG, MT_WPDMA_GLO_CFG_RX_DMA_EN);

	mutex_unlock(&dev->mt76.mutex);
}

const struct ieee80211_ops mt76x0e_ops = {
	.tx = mt76x0_tx,
	.start = mt76x0e_start,
	.stop = mt76x0e_stop,
	.config = mt76x0_config,
	.add_interface = mt76x02_add_interface,
	.remove_interface = mt76x02_remove_interface,
	.configure_filter = mt76x02_configure_filter,
};

int mt76x0e_register_device(struct mt76x0_dev *dev)
{
	int err;

	mt76x0_chip_onoff(dev, true, false);
	if (!mt76x02_wait_for_mac(&dev->mt76))
		return -ETIMEDOUT;

	mt76x02_dma_disable(&dev->mt76);
	err = mt76x0e_mcu_init(dev);
	if (err < 0)
		return err;

	err = mt76x02_dma_init(&dev->mt76);
	if (err < 0)
		return err;

	err = mt76x0_init_hardware(dev);
	if (err < 0)
		return err;

	if (mt76_chip(&dev->mt76) == 0x7610) {
		u16 val;

		mt76_clear(dev, MT_COEXCFG0, BIT(0));
		val = mt76x02_eeprom_get(&dev->mt76, MT_EE_NIC_CONF_0);
		if (val & MT_EE_NIC_CONF_0_PA_IO_CURRENT) {
			u32 data;

			/* set external external PA I/O
			 * current to 16mA
			 */
			data = mt76_rr(dev, 0x11c);
			val |= 0xc03;
			mt76_wr(dev, 0x11c, val);
		}
	}

	mt76_clear(dev, 0x110, BIT(9));
	mt76_set(dev, MT_MAX_LEN_CFG, BIT(13));

	return 0;
}
