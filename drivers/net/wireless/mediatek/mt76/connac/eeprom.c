// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 *         Felix Fietkau <nbd@nbd.name>
 *	   Chih-Min Chen <chih-min.chen@mediatek.com>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include "connac.h"
#include "eeprom.h"

static int connac_efuse_init(struct connac_dev *dev)
{
	return 0;
}

static int connac_eeprom_load(struct connac_dev *dev)
{
	int ret;

	ret = mt76_eeprom_init(&dev->mt76, CONNAC_EEPROM_SIZE);
	if (ret < 0)
		return ret;

	return connac_efuse_init(dev);
}

int connac_eeprom_get_power_index(struct ieee80211_channel *chan,
				  u8 chain_idx)
{
	/* CONNAC : f/w handle */
	return 0;
}

static int connac_check_eeprom(struct mt76_dev *dev)
{
	u16 val = get_unaligned_le16(dev->eeprom.data);

	switch (val) {
	case 0x7629:
		return 0;
	default:
		return -EINVAL;
	}
}

static void connac_eeprom_parse_hw_cap(struct connac_dev *dev)
{
	u8 val, *eeprom = dev->mt76.eeprom.data;
	bool init_dbdc = true;

	switch (dev->mt76.rev) {
	case 0x76630010:
		init_dbdc = false;
		break;
	}

#if 1 /* CONNAC only support DBDC */
	val = FIELD_GET(MT_EE_NIC_WIFI_DBDC_ENABLE,
			eeprom[MT_EE_SYS_DBDC]);

#if 1 /* DBDC TODO */
	if (init_dbdc)
		val = MT_EE_2GHZ;
	else
		val = MT_EE_DUAL_BAND;
#else
	if (!val) /* CONNAC : TODO , default 2G */
		val = MT_EE_2GHZ;
#endif

#else
	val = FIELD_GET(MT_EE_NIC_WIFI_CONF_BAND_SEL,
			eeprom[MT_EE_WIFI_CONF]);

#endif
	switch (val) {
	case MT_EE_5GHZ:
		dev->mt76.cap.has_5ghz = true;
		break;
	case MT_EE_2GHZ:
		dev->mt76.cap.has_2ghz = true;
		break;
	default:
		dev->mt76.cap.has_2ghz = true;
		dev->mt76.cap.has_5ghz = true;
		break;
	}
}

int connac_eeprom_init(struct connac_dev *dev)
{
	int ret;

	ret = connac_eeprom_load(dev);
	if (ret < 0)
		return ret;

	ret = connac_check_eeprom(&dev->mt76);
	if (ret && dev->mt76.otp.data)
		memcpy(dev->mt76.eeprom.data, dev->mt76.otp.data,
		       CONNAC_EEPROM_SIZE);

	connac_eeprom_parse_hw_cap(dev);
	memcpy(dev->mt76.macaddr, dev->mt76.eeprom.data + MT_EE_MAC_ADDR,
	       ETH_ALEN);

	mt76_eeprom_override(&dev->mt76);

	return 0;
}
