// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include "mt7663.h"

int mt7663_init_debugfs(struct mt7663_dev *dev)
{
	struct dentry *dir;

	dir = mt76_register_debugfs(&dev->mt76);
	if (!dir)
		return -ENOMEM;

	return 0;
}
