/*
 * Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
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

#include <asm/unaligned.h>

#include "mt76.h"
#include "mt76x02_eeprom.h"
#include "mt76x02_regs.h"

static int
mt76x02_efuse_read(struct mt76_dev *dev, u16 addr, u8 *data,
		   enum mt76x02_eeprom_modes mode)
{
	u32 val;
	int i;

	val = __mt76_rr(dev, MT_EFUSE_CTRL);
	val &= ~(MT_EFUSE_CTRL_AIN |
		 MT_EFUSE_CTRL_MODE);
	val |= FIELD_PREP(MT_EFUSE_CTRL_AIN, addr & ~0xf);
	val |= FIELD_PREP(MT_EFUSE_CTRL_MODE, mode);
	val |= MT_EFUSE_CTRL_KICK;
	__mt76_wr(dev, MT_EFUSE_CTRL, val);

	if (!__mt76_poll_msec(dev, MT_EFUSE_CTRL, MT_EFUSE_CTRL_KICK,
			      0, 1000))
		return -ETIMEDOUT;

	udelay(2);

	val = __mt76_rr(dev, MT_EFUSE_CTRL);
	if ((val & MT_EFUSE_CTRL_AOUT) == MT_EFUSE_CTRL_AOUT) {
		memset(data, 0xff, 16);
		return 0;
	}

	for (i = 0; i < 4; i++) {
		val = __mt76_rr(dev, MT_EFUSE_DATA(i));
		put_unaligned_le32(val, data + 4 * i);
	}

	return 0;
}

int mt76x02_get_efuse_data(struct mt76_dev *dev, u16 base, void *buf,
			   int len, enum mt76x02_eeprom_modes mode)
{
	int ret, i;

	for (i = 0; i + 16 <= len; i += 16) {
		ret = mt76x02_efuse_read(dev, base + i, buf + i, mode);
		if (ret)
			return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(mt76x02_get_efuse_data);

void mt76x02_eeprom_parse_hw_cap(struct mt76_dev *dev)
{
	u16 val = mt76x02_eeprom_get(dev, MT_EE_NIC_CONF_0);

	switch (FIELD_GET(MT_EE_NIC_CONF_0_BOARD_TYPE, val)) {
	case BOARD_TYPE_5GHZ:
		dev->cap.has_5ghz = true;
		break;
	case BOARD_TYPE_2GHZ:
		dev->cap.has_2ghz = true;
		break;
	default:
		dev->cap.has_2ghz = true;
		dev->cap.has_5ghz = true;
		break;
	}
}
EXPORT_SYMBOL_GPL(mt76x02_eeprom_parse_hw_cap);

bool mt76x02_ext_pa_enabled(struct mt76_dev *dev, enum nl80211_band band)
{
	u16 conf0 = mt76x02_eeprom_get(dev, MT_EE_NIC_CONF_0);

	if (band == NL80211_BAND_5GHZ)
		return !(conf0 & MT_EE_NIC_CONF_0_PA_INT_5G);
	else
		return !(conf0 & MT_EE_NIC_CONF_0_PA_INT_2G);
}
EXPORT_SYMBOL_GPL(mt76x02_ext_pa_enabled);

void mt76x02_get_rx_gain(struct mt76_dev *dev, enum nl80211_band band,
			 u16 *rssi_offset, s8 *lna_2g, s8 *lna_5g)
{
	u16 val;

	val = mt76x02_eeprom_get(dev, MT_EE_LNA_GAIN);
	*lna_2g = val & 0xff;
	lna_5g[0] = val >> 8;

	val = mt76x02_eeprom_get(dev, MT_EE_RSSI_OFFSET_2G_1);
	lna_5g[1] = val >> 8;

	val = mt76x02_eeprom_get(dev, MT_EE_RSSI_OFFSET_5G_1);
	lna_5g[2] = val >> 8;

	if (!mt76x02_field_valid(lna_5g[1]))
		lna_5g[1] = lna_5g[0];

	if (!mt76x02_field_valid(lna_5g[2]))
		lna_5g[2] = lna_5g[0];

	if (band == NL80211_BAND_2GHZ)
		*rssi_offset = mt76x02_eeprom_get(dev, MT_EE_RSSI_OFFSET_2G_0);
	else
		*rssi_offset = mt76x02_eeprom_get(dev, MT_EE_RSSI_OFFSET_5G_0);
}
EXPORT_SYMBOL_GPL(mt76x02_get_rx_gain);

u8 mt76x02_get_lna_gain(struct mt76_dev *dev,
			s8 *lna_2g, s8 *lna_5g,
			struct ieee80211_channel *chan)
{
	u16 val;
	u8 lna;

	val = mt76x02_eeprom_get(dev, MT_EE_NIC_CONF_1);
	if (val & MT_EE_NIC_CONF_1_LNA_EXT_2G)
		*lna_2g = 0;
	if (val & MT_EE_NIC_CONF_1_LNA_EXT_5G)
		memset(lna_5g, 0, sizeof(s8) * 3);

	if (chan->band == NL80211_BAND_2GHZ)
		lna = *lna_2g;
	else if (chan->hw_value <= 64)
		lna = lna_5g[0];
	else if (chan->hw_value <= 128)
		lna = lna_5g[1];
	else
		lna = lna_5g[2];

	return lna != 0xff ? lna : 0;
}
EXPORT_SYMBOL_GPL(mt76x02_get_lna_gain);

static bool mt76x02_has_cal_free_data(u8 *efuse)
{
	u16 *efuse_w = (u16 *) efuse;

	if (efuse_w[MT_EE_NIC_CONF_0] != 0)
		return false;

	if (efuse_w[MT_EE_XTAL_TRIM_1] == 0xffff)
		return false;

	if (efuse_w[MT_EE_TX_POWER_DELTA_BW40] != 0)
		return false;

	if (efuse_w[MT_EE_TX_POWER_0_START_2G] == 0xffff)
		return false;

	if (efuse_w[MT_EE_TX_POWER_0_GRP3_TX_POWER_DELTA] != 0)
		return false;

	if (efuse_w[MT_EE_TX_POWER_0_GRP4_TSSI_SLOPE] == 0xffff)
		return false;

	return true;
}

static void mt76x02_apply_cal_free_data(struct mt76_dev *dev, u8 *efuse)
{
#define GROUP_5G(_id)							   \
	MT_EE_TX_POWER_0_START_5G + MT_TX_POWER_GROUP_SIZE_5G * (_id),	   \
	MT_EE_TX_POWER_0_START_5G + MT_TX_POWER_GROUP_SIZE_5G * (_id) + 1, \
	MT_EE_TX_POWER_1_START_5G + MT_TX_POWER_GROUP_SIZE_5G * (_id),	   \
	MT_EE_TX_POWER_1_START_5G + MT_TX_POWER_GROUP_SIZE_5G * (_id) + 1

	static const u8 cal_free_bytes[] = {
		MT_EE_XTAL_TRIM_1,
		MT_EE_TX_POWER_EXT_PA_5G + 1,
		MT_EE_TX_POWER_0_START_2G,
		MT_EE_TX_POWER_0_START_2G + 1,
		MT_EE_TX_POWER_1_START_2G,
		MT_EE_TX_POWER_1_START_2G + 1,
		GROUP_5G(0),
		GROUP_5G(1),
		GROUP_5G(2),
		GROUP_5G(3),
		GROUP_5G(4),
		GROUP_5G(5),
		MT_EE_RF_2G_TSSI_OFF_TXPOWER,
		MT_EE_RF_2G_RX_HIGH_GAIN + 1,
		MT_EE_RF_5G_GRP0_1_RX_HIGH_GAIN,
		MT_EE_RF_5G_GRP0_1_RX_HIGH_GAIN + 1,
		MT_EE_RF_5G_GRP2_3_RX_HIGH_GAIN,
		MT_EE_RF_5G_GRP2_3_RX_HIGH_GAIN + 1,
		MT_EE_RF_5G_GRP4_5_RX_HIGH_GAIN,
		MT_EE_RF_5G_GRP4_5_RX_HIGH_GAIN + 1,
	};
	u8 *eeprom = dev->eeprom.data;
	u8 prev_grp0[4] = {
		eeprom[MT_EE_TX_POWER_0_START_5G],
		eeprom[MT_EE_TX_POWER_0_START_5G + 1],
		eeprom[MT_EE_TX_POWER_1_START_5G],
		eeprom[MT_EE_TX_POWER_1_START_5G + 1]
	};
	u16 val;
	int i;

	if (!mt76x02_has_cal_free_data(efuse))
		return;

	for (i = 0; i < ARRAY_SIZE(cal_free_bytes); i++) {
		int offset = cal_free_bytes[i];

		eeprom[offset] = efuse[offset];
	}

	if (!(efuse[MT_EE_TX_POWER_0_START_5G] |
	      efuse[MT_EE_TX_POWER_0_START_5G + 1]))
		memcpy(eeprom + MT_EE_TX_POWER_0_START_5G, prev_grp0, 2);
	if (!(efuse[MT_EE_TX_POWER_1_START_5G] |
	      efuse[MT_EE_TX_POWER_1_START_5G + 1]))
		memcpy(eeprom + MT_EE_TX_POWER_1_START_5G, prev_grp0 + 2, 2);

	val = get_unaligned_le16(efuse + MT_EE_BT_RCAL_RESULT);
	if (val != 0xffff)
		eeprom[MT_EE_BT_RCAL_RESULT] = val & 0xff;

	val = get_unaligned_le16(efuse + MT_EE_BT_VCDL_CALIBRATION);
	if (val != 0xffff)
		eeprom[MT_EE_BT_VCDL_CALIBRATION + 1] = val >> 8;

	val = get_unaligned_le16(efuse + MT_EE_BT_PMUCFG);
	if (val != 0xffff)
		eeprom[MT_EE_BT_PMUCFG] = val & 0xff;
}

static int mt76x02_check_eeprom(struct mt76_dev *dev)
{
	u16 val = get_unaligned_le16(dev->eeprom.data);

	if (!val)
		val = get_unaligned_le16(dev->eeprom.data + MT_EE_PCI_ID);

	switch (val) {
	case 0x7662:
	case 0x7612:
		return 0;
	default:
		dev_err(dev->dev, "EEPROM data check failed: %04x\n", val);
		return -EINVAL;
	}
}

int mt76x02_eeprom_load(struct mt76_dev *dev, int eeprom_size)
{
	void *efuse;
	bool found;
	int ret;

	ret = mt76_eeprom_init(dev, eeprom_size);
	if (ret < 0)
		return ret;

	found = ret;
	if (found)
		found = !mt76x02_check_eeprom(dev);

	dev->otp.data = devm_kzalloc(dev->dev, eeprom_size, GFP_KERNEL);
	dev->otp.size = eeprom_size;
	if (!dev->otp.data)
		return -ENOMEM;

	efuse = dev->otp.data;

	if (mt76x02_get_efuse_data(dev, 0, efuse, eeprom_size,
				   MT_EE_READ))
		goto out;

	if (found) {
		mt76x02_apply_cal_free_data(dev, efuse);
	} else {
		/* FIXME: check if efuse data is complete */
		found = true;
		memcpy(dev->eeprom.data, efuse, eeprom_size);
	}

out:
	if (!found)
		return -ENOENT;

	return 0;
}
EXPORT_SYMBOL_GPL(mt76x02_eeprom_load);
