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
#include "../mt76x02_dma.h"
#include "../mt76x02_mac.h"
#include "../mt76x02_util.h"

static int mt76x0e_init_hardware(struct mt76x0_dev *dev)
{
	int i, j, beacon_len, err;
	u32 val;

	mt76x0_chip_onoff(dev, true, false);
	if (!mt76x02_wait_for_mac(&dev->mt76))
		return -ETIMEDOUT;

	mt76x02_dma_disable(&dev->mt76);
	if (!mt76x02_wait_for_wpdma(&dev->mt76))
		return -ETIMEDOUT;

	err = mt76x0e_mcu_init(dev);
	if (err < 0)
		return err;

	mt76_wr(dev, MT_MAC_SYS_CTRL,
		MT_MAC_SYS_CTRL_RESET_CSR |
		MT_MAC_SYS_CTRL_RESET_BBP);

	mt76_clear(dev, MT_MAC_SYS_CTRL,
		   MT_MAC_SYS_CTRL_RESET_CSR |
		   MT_MAC_SYS_CTRL_RESET_BBP);

	mt76x0_init_mac_registers(dev);
	if (mt76_chip(&dev->mt76) == 0x7610)
		mt76_clear(dev, MT_COEXCFG0, BIT(0));

	mt76_clear(dev, 0x110, BIT(9));

	if (!mt76x02_wait_for_bbp(&dev->mt76))
		return  -ETIMEDOUT;

	usleep_range(1000, 2000);
	err = mt76x0_init_bbp(dev);
	if (err < 0)
		return err;

	val = mt76_rr(dev, MT_MAX_LEN_CFG);
	val &= 0xfff;
	val |= 0x2000;
	mt76_wr(dev, MT_MAX_LEN_CFG, val);

	mt76x0_reset_counters(dev);

	mt76x0_init_key_mem(dev);

	err = mt76x0_init_wcid_attr_mem(dev);
	if (err < 0)
		return err;

	beacon_len = mt76x02_beacon_offsets[1] - mt76x02_beacon_offsets[0];
	for (i = 0; i < 8; i++) {
		for (j = 0; j < beacon_len; j += 4)
			mt76_wr(dev, mt76x02_beacon_offsets[i] + j, 0);
	}

	return mt76x0_init_wcid_mem(dev);
}

int mt76x0e_register_device(struct mt76x0_dev *dev)
{
	int err;

	err = mt76x0e_init_hardware(dev);
	if (err < 0)
		return err;

	err = mt76x02_dma_init(&dev->mt76);
	if (err < 0)
		return err;

	return 0;
}
