// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 MediaTek Inc.
 *
 * Author: Felix Fietkau <nbd@nbd.name>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "mt7615.h"
#include "mac.h"
#include "regs.h"

static int mt7663s_init_hardware(struct mt7615_dev *dev)
{
	int ret, idx;

	ret = mt7615_eeprom_init(dev, MT_EFUSE_BASE);
	if (ret < 0)
		return ret;

	set_bit(MT76_STATE_INITIALIZED, &dev->mphy.state);

	/* Beacon and mgmt frames should occupy wcid 0 */
	idx = mt76_wcid_alloc(dev->mt76.wcid_mask, MT7615_WTBL_STA - 1);
	if (idx)
		return -ENOSPC;

	dev->mt76.global_wcid.idx = idx;
	dev->mt76.global_wcid.hw_key_idx = -1;
	rcu_assign_pointer(dev->mt76.wcid[idx], &dev->mt76.global_wcid);

	return 0;
}

static void mt7663s_init_work(struct work_struct *work)
{
	struct mt7615_dev *dev;

	dev = container_of(work, struct mt7615_dev, mcu_work);
	if (mt7663s_mcu_init(dev))
		return;

	mt7615_mcu_set_eeprom(dev);
	mt7615_mac_init(dev);
	mt7615_phy_init(dev);
	mt7615_mcu_del_wtbl_all(dev);
	mt7615_check_offload_capability(dev);
}

int mt7663s_register_device(struct mt7615_dev *dev)
{
	struct ieee80211_hw *hw = mt76_hw(dev);
	int err;

	INIT_WORK(&dev->wtbl_work, mt7663s_wtbl_work);
	INIT_WORK(&dev->mcu_work, mt7663s_init_work);
	INIT_LIST_HEAD(&dev->wd_head);
	mt7615_init_device(dev);

	err = mt7663s_init_hardware(dev);
	if (err)
		return err;

	hw->extra_tx_headroom += MT_SDIO_HDR_SIZE + MT_SDIO_TXD_SIZE;
	/* check hw sg support in order to enable AMSDU */
	hw->max_tx_fragments = MT_HW_TXP_MAX_BUF_NUM;

	err = mt76_register_device(&dev->mt76, true, mt7615_rates,
				   ARRAY_SIZE(mt7615_rates));
	if (err < 0)
		return err;

	ieee80211_queue_work(hw, &dev->mcu_work);
	mt7615_init_txpower(dev, &dev->mphy.sband_2g.sband);
	mt7615_init_txpower(dev, &dev->mphy.sband_5g.sband);

	return mt7615_init_debugfs(dev);
}
