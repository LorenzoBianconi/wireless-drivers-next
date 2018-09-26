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
