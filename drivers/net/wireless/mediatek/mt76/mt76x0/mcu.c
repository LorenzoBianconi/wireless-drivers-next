/*
 * (c) Copyright 2002-2010, Ralink Technology, Inc.
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

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/usb.h>
#include <linux/skbuff.h>

#include "mt76x0.h"
#include "dma.h"
#include "mcu.h"
#include "usb.h"
#include "trace.h"

int mt76x0_mcu_function_select(struct mt76x0_dev *dev,
			       enum mcu_function func, u32 val)
{
	struct sk_buff *skb;
	struct {
		__le32 id;
		__le32 value;
	} __packed __aligned(4) msg = {
		.id = cpu_to_le32(func),
		.value = cpu_to_le32(val),
	};

	skb = mt76_mcu_msg_alloc(dev, &msg, sizeof(msg));
	return mt76_mcu_send_msg(dev, skb, CMD_FUN_SET_OP, func == 5);
}

int
mt76x0_mcu_calibrate(struct mt76x0_dev *dev, enum mcu_calibrate cal, u32 val)
{
	struct sk_buff *skb;
	struct {
		__le32 id;
		__le32 value;
	} __packed __aligned(4) msg = {
		.id = cpu_to_le32(cal),
		.value = cpu_to_le32(val),
	};

	skb = mt76_mcu_msg_alloc(dev, &msg, sizeof(msg));
	return mt76_mcu_send_msg(dev, skb, CMD_CALIBRATION_OP, true);
}

int mt76x0_mcu_cmd_init(struct mt76x0_dev *dev)
{
	return mt76x0_mcu_function_select(dev, Q_SELECT, 1);
}
