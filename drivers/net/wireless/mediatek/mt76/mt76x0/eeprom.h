/*
 * Copyright (C) 2014 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2015 Jakub Kicinski <kubakici@wp.pl>
 * Copyright (C) 2018 Stanislaw Gruszka <stf_xl@wp.pl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __MT76X0U_EEPROM_H
#define __MT76X0U_EEPROM_H

#include "../mt76x02_eeprom.h"

struct mt76x0_dev;

#define MT76X0U_EE_MAX_VER		0x0c
#define MT76X0_EEPROM_SIZE		512

struct reg_channel_bounds {
	u8 start;
	u8 num;
};

struct mt76x0_caldata {
	s8 rssi_offset[2];
	s8 lna_gain;

	s16 temp_offset;
	u8 freq_offset;
};

struct mt76x0_eeprom_params {

	u8 tx_pwr_per_chan[58];
};

int mt76x0_eeprom_init(struct mt76x0_dev *dev);
void mt76x0_read_rx_gain(struct mt76x0_dev *dev);
void mt76x0_get_tx_power_per_rate(struct mt76x0_dev *dev);

static inline s8 s6_to_s8(u32 val)
{
	s8 ret = val & GENMASK(5, 0);

	if (ret & BIT(5))
		ret -= BIT(6);
	return ret;
}

#endif
