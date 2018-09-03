/*
 * Copyright (C) 2014 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2015 Jakub Kicinski <kubakici@wp.pl>
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

#ifndef __MT76_MAC_H
#define __MT76_MAC_H

u32 mt76x0_mac_process_rx(struct mt76x0_dev *dev, struct sk_buff *skb,
			u8 *data, void *rxi);
struct mt76x02_tx_status
mt76x0_mac_fetch_tx_status(struct mt76x0_dev *dev);
void mt76x0_send_tx_status(struct mt76x0_dev *dev, struct mt76x02_tx_status *stat, u8 *update);

#endif
