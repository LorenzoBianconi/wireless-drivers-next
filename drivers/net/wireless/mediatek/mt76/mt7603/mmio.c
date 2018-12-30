/*
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

#include "mt7603.h"

static u32 __mt7603_reg_addr(struct mt7603_dev *dev, u32 addr)
{
	if (addr < 0x100000)
		return addr;

	return mt7603_reg_map(dev, addr);
}

static u32 mt7603_rr(struct mt76_dev *mdev, u32 offset)
{
	struct mt7603_dev *dev = container_of(mdev, struct mt7603_dev, mt76);
	u32 addr = __mt7603_reg_addr(dev, offset);

	return mt76_rr(dev, addr);
}

static void mt7603_wr(struct mt76_dev *mdev, u32 offset, u32 val)
{
	struct mt7603_dev *dev = container_of(mdev, struct mt7603_dev, mt76);
	u32 addr = __mt7603_reg_addr(dev, offset);

	mt76_wr(dev, addr, val);
}

static u32 mt7603_rmw(struct mt76_dev *mdev, u32 offset, u32 mask, u32 val)
{
	struct mt7603_dev *dev = container_of(mdev, struct mt7603_dev, mt76);
	u32 addr = __mt7603_reg_addr(dev, offset);

	return mt76_rmw(dev, addr, mask, val);
}

const struct mt76_bus_ops mt7603_mmio_ops = {
	.rr = mt7603_rr,
	.rmw = mt7603_rmw,
	.wr = mt7603_wr,
	.copy = mt76_mmio_copy,
	.wr_rp = mt76_mmio_wr_rp,
	.rd_rp = mt76_mmio_rd_rp,
	.type = MT76_BUS_MMIO,
};

