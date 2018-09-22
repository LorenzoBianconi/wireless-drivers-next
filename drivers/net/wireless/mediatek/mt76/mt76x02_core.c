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

#include <linux/kernel.h>

#include "mt76.h"
#include "mt76x02_dma.h"
#include "mt76x02_regs.h"

void mt76x02_set_irq_mask(struct mt76_dev *dev, u32 clear, u32 set)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->mmio.irq_lock, flags);
	dev->mmio.irqmask &= ~clear;
	dev->mmio.irqmask |= set;
	__mt76_wr(dev, MT_INT_MASK_CSR, dev->mmio.irqmask);
	spin_unlock_irqrestore(&dev->mmio.irq_lock, flags);
}
EXPORT_SYMBOL_GPL(mt76x02_set_irq_mask);

const u16 mt76x02_beacon_offsets[16] = {
	/* 1024 byte per beacon */
	0xc000,
	0xc400,
	0xc800,
	0xcc00,
	0xd000,
	0xd400,
	0xd800,
	0xdc00,
	/* BSS idx 8-15 not used for beacons */
	0xc000,
	0xc000,
	0xc000,
	0xc000,
	0xc000,
	0xc000,
	0xc000,
	0xc000,
};
EXPORT_SYMBOL_GPL(mt76x02_beacon_offsets);

void mt76x02_set_beacon_offsets(struct mt76_dev *dev)
{
	u16 val, base = MT_BEACON_BASE;
	u32 regs[4] = {};
	int i;

	for (i = 0; i < 16; i++) {
		val = mt76x02_beacon_offsets[i] - base;
		regs[i / 4] |= (val / 64) << (8 * (i % 4));
	}

	for (i = 0; i < 4; i++)
		__mt76_wr(dev, MT_BCN_OFFSET(i), regs[i]);
}
EXPORT_SYMBOL_GPL(mt76x02_set_beacon_offsets);
