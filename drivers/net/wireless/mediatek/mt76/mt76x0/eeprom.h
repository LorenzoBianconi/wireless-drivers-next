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

#define MT76X0_NUM_CHANS	58
struct mt76x0_caldata {
	s8 rssi_offset[2];
	s8 lna_gain;

	s16 temp_offset;
	u8 freq_offset;

	u8 tx_pwr_per_chan[MT76X0_NUM_CHANS];
	struct mt76_rate_power rate_power;
};

int mt76x0_eeprom_init(struct mt76x0_dev *dev);
void mt76x0_read_rx_gain(struct mt76x0_dev *dev);
void mt76x0_set_tx_power_per_rate(struct mt76x0_dev *dev,
				  struct cfg80211_chan_def *chandef);

static inline s8 s6_to_s8(u32 val)
{
	s8 ret = val & GENMASK(5, 0);

	if (ret & BIT(5))
		ret -= BIT(6);
	return ret;
}

static inline u32 int_to_s6(int val)
{
	if (val < -0x20)
		return 0x20;
	if (val > 0x1f)
		return 0x1f;

	return val & 0x3f;
}

#endif
