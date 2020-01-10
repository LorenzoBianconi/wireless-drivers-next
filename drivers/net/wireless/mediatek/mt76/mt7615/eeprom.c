// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 *         Felix Fietkau <nbd@nbd.name>
 *         Lorenzo Bianconi <lorenzo@kernel.org>
 */

#include "mt7615.h"
#include "eeprom.h"
#include "regs.h"

static int mt7615_efuse_read(struct mt7615_dev *dev, u32 base,
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

static int mt7615_efuse_init(struct mt7615_dev *dev, u32 base)
{
	int i, len = MT7615_EEPROM_SIZE;
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

		ret = mt7615_efuse_read(dev, base, i, buf + i);
		if (ret)
			return ret;
	}

	return 0;
}

int mt7615_eeprom_get_power_index(struct mt7615_dev *dev,
				  struct ieee80211_channel *chan,
				  u8 chain_idx)
{
	int index;

	if (chain_idx > 3)
		return -EINVAL;

	/* TSSI disabled */
	if (mt7615_ext_pa_enabled(dev, chan->band)) {
		if (chan->band == NL80211_BAND_2GHZ)
			return MT_EE_EXT_PA_2G_TARGET_POWER;
		else
			return MT_EE_EXT_PA_5G_TARGET_POWER;
	}

	/* TSSI enabled */
	if (chan->band == NL80211_BAND_2GHZ) {
		index = MT_EE_TX0_2G_TARGET_POWER + chain_idx * 6;
	} else {
		int group = mt7615_get_channel_group(chan->hw_value);

		switch (chain_idx) {
		case 1:
			index = MT_EE_TX1_5G_G0_TARGET_POWER;
			break;
		case 2:
			index = MT_EE_TX2_5G_G0_TARGET_POWER;
			break;
		case 3:
			index = MT_EE_TX3_5G_G0_TARGET_POWER;
			break;
		case 0:
		default:
			index = MT_EE_TX0_5G_G0_TARGET_POWER;
			break;
		}
		index += 5 * group;
	}

	return index;
}
EXPORT_SYMBOL_GPL(mt7615_eeprom_get_power_index);

int mt7615_eeprom_load(struct mt7615_dev *dev, u32 base)
{
	int ret;

	ret = mt76_eeprom_init(&dev->mt76, MT7615_EEPROM_SIZE);
	if (ret < 0)
		return ret;

	return mt7615_efuse_init(dev, base);
}
EXPORT_SYMBOL_GPL(mt7615_eeprom_load);
