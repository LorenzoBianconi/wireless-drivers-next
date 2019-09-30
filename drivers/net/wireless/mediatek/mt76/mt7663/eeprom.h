/* SPDX-License-Identifier: ISC */
/* Copyright (C) 2019 MediaTek Inc. */

#ifndef __MT7663_EEPROM_H
#define __MT7663_EEPROM_H

#include "mt7663.h"

enum mt7663_eeprom_field {
	MT_EE_CHIP_ID =				0x000,
	MT_EE_VERSION =				0x002,
	MT_EE_MAC_ADDR =			0x004,
	MT_EE_NIC_CONF_0 =			0x034, /* MT7663 : useless */
	MT_EE_WIFI_CONF =			0x03e,
	/* MT7663 : assigin for f/w only */
	MT_EE_TX0_2G_TARGET_POWER =		0x123, /*~ 0x120~0x14f for 2G*/
	MT_EE_TX0_5G_G0_TARGET_POWER =		0x070,
	MT_EE_TX1_5G_G0_TARGET_POWER =		0x098,
	MT_EE_TX2_5G_G0_TARGET_POWER =		0x142,
	__MT_EE_MAX =				0x400
};

#define MT_EE_NIC_WIFI_CONF_BAND_SEL		GENMASK(5, 4)

enum mt7663_eeprom_band {
	MT_EE_DUAL_BAND,
	MT_EE_5GHZ,
	MT_EE_2GHZ,
};

enum mt7663_channel_group {
	MT_CH_5G_JAPAN,
	MT_CH_5G_UNII_1,
	MT_CH_5G_UNII_2A,
	MT_CH_5G_UNII_2B,
	MT_CH_5G_UNII_2E_1,
	MT_CH_5G_UNII_2E_2,
	MT_CH_5G_UNII_2E_3,
	MT_CH_5G_UNII_3,
	__MT_CH_MAX
};

static inline enum mt7663_channel_group
mt7663_get_channel_group(int channel)
{
	if (channel >= 184 && channel <= 196)
		return MT_CH_5G_JAPAN;
	if (channel <= 48)
		return MT_CH_5G_UNII_1;
	if (channel <= 64)
		return MT_CH_5G_UNII_2A;
	if (channel <= 114)
		return MT_CH_5G_UNII_2E_1;
	if (channel <= 144)
		return MT_CH_5G_UNII_2E_2;
	if (channel <= 161)
		return MT_CH_5G_UNII_2E_3;
	return MT_CH_5G_UNII_3;
}

#endif /* __MT7663_EEPROM_H */
