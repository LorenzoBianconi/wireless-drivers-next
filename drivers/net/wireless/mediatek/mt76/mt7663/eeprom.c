// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 *         Felix Fietkau <nbd@nbd.name>
 *         Lorenzo Bianconi <lorenzo@kernel.org>
 *	   Chih-Min Chen <chih-min.chen@mediatek.com>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include "mt7663.h"
#include "eeprom.h"
#include "regs.h"

static int mt7663_efuse_read(struct mt7663_dev *dev, u32 base,
			     u16 addr, u8 *data)
{
	u32 val;
	int i;

	val = mt76_rr(dev, base + MT_EFUSE_CTRL);
	val &= ~(MT_EFUSE_CTRL_AIN | MT_EFUSE_CTRL_MODE);
	val |= FIELD_PREP(MT_EFUSE_CTRL_AIN, addr & ~0xf);
	val |= MT_EFUSE_CTRL_KICK;
	mt76_wr(dev, base + MT_EFUSE_CTRL, val);

	if (!mt76_poll(dev, base + MT_EFUSE_CTRL, MT_EFUSE_CTRL_KICK, 0, 1000))
		return -ETIMEDOUT;

	udelay(2);

	val = mt76_rr(dev, base + MT_EFUSE_CTRL);
	if ((val & MT_EFUSE_CTRL_AOUT) == MT_EFUSE_CTRL_AOUT ||
	    WARN_ON_ONCE(!(val & MT_EFUSE_CTRL_VALID))) {
		memset(data, 0x0, 16);
		return 0;
	}

	for (i = 0; i < 4; i++) {
		val = mt76_rr(dev, base + MT_EFUSE_RDATA(i));
		put_unaligned_le32(val, data + 4 * i);
	}

	return 0;
}

static int mt7663_efuse_init(struct mt7663_dev *dev, u32 base)
{
	int i, len = MT7663_EEPROM_SIZE;
	void *buf;
	u32 val;

	val = mt76_rr(dev, base + MT_EFUSE_BASE_CTRL);
	if (val & MT_EFUSE_BASE_CTRL_EMPTY)
		return 0;

	dev->mt76.otp.data = devm_kzalloc(dev->mt76.dev, len, GFP_KERNEL);
	dev->mt76.otp.size = len;
	if (!dev->mt76.otp.data)
		return -ENOMEM;

	buf = dev->mt76.otp.data;
	for (i = 0; i + 16 <= len; i += 16) {
		int ret;

		ret = mt7663_efuse_read(dev, base, i, buf + i);
		if (ret)
			return ret;
	}

	return 0;
}

static int mt7663_eeprom_load(struct mt7663_dev *dev, u32 base)
{
	int ret;

	ret = mt76_eeprom_init(&dev->mt76, MT7663_EEPROM_SIZE);
	if (ret < 0)
		return ret;

	return mt7663_efuse_init(dev, base);
}

int mt7663_eeprom_get_power_index(struct ieee80211_channel *chan,
				  u8 chain_idx)
{
	/* MT7663 : f/w handle */
	return 0;
}

static int mt7663_check_eeprom(struct mt76_dev *dev)
{
	u16 val = get_unaligned_le16(dev->eeprom.data);

	switch (val) {
	case 0x7629:
		return 0;
	default:
		return -EINVAL;
	}
}

static void mt7663_eeprom_parse_hw_cap(struct mt7663_dev *dev)
{
	u8 val, *eeprom = dev->mt76.eeprom.data;
	bool init_dbdc = true;

	switch (dev->mt76.rev) {
	case 0x76630010:
		init_dbdc = false;
		break;
	}

#if 1 /* MT7663 only support DBDC */
	val = FIELD_GET(MT_EE_NIC_WIFI_DBDC_ENABLE,
			eeprom[MT_EE_SYS_DBDC]);

#if 1 /* DBDC TODO */
	if (init_dbdc)
		val = MT_EE_2GHZ;
	else
		val = MT_EE_DUAL_BAND;
#else
	if (!val) /* MT7663 : TODO , default 2G */
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

int mt7663_eeprom_init(struct mt7663_dev *dev, u32 base)
{
	int ret;

	ret = mt7663_eeprom_load(dev, base);
	if (ret < 0)
		return ret;

	ret = mt7663_check_eeprom(&dev->mt76);
	if (ret && dev->mt76.otp.data)
		memcpy(dev->mt76.eeprom.data, dev->mt76.otp.data,
		       MT7663_EEPROM_SIZE);

	mt7663_eeprom_parse_hw_cap(dev);
	memcpy(dev->mt76.macaddr, dev->mt76.eeprom.data + MT_EE_MAC_ADDR,
	       ETH_ALEN);

	mt76_eeprom_override(&dev->mt76);

	return 0;
}
EXPORT_SYMBOL_GPL(mt7663_eeprom_init);
