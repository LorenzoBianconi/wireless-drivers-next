/*
 * Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
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

#include "mt76.h"
#include "mmio_trace.h"

static u32 mt76_mmio_rr(struct mt76_dev *dev, u32 offset)
{
	struct mt76_mmio *mmio = &dev->mmio;
	u32 val;

	val = ioread32(mmio->regs + offset);
	trace_reg_rr(dev, offset, val);

	return val;
}

static void mt76_mmio_wr(struct mt76_dev *dev, u32 offset, u32 val)
{
	struct mt76_mmio *mmio = &dev->mmio;

	trace_reg_wr(dev, offset, val);
	iowrite32(val, mmio->regs + offset);
}

static u32 mt76_mmio_rmw(struct mt76_dev *dev, u32 offset, u32 mask, u32 val)
{
	val |= mt76_mmio_rr(dev, offset) & ~mask;
	mt76_mmio_wr(dev, offset, val);
	return val;
}

static void mt76_mmio_copy(struct mt76_dev *dev, u32 offset, const void *data,
			   int len)
{
	struct mt76_mmio *mmio = &dev->mmio;

	__iowrite32_copy(mmio->regs + offset, data, len >> 2);
}

void mt76e_set_irq_mask(struct mt76_dev *dev, u32 clear, u32 set)
{
	struct mt76_mmio *mmio = &dev->mmio;
	const int MT_INT_MASK_CSR = 0x0204;
	unsigned long flags;

	spin_lock_irqsave(&mmio->irq_lock, flags);
	mmio->irqmask &= ~clear;
	mmio->irqmask |= set;
	__mt76_wr(dev, MT_INT_MASK_CSR, mmio->irqmask);
	spin_unlock_irqrestore(&mmio->irq_lock, flags);
}
EXPORT_SYMBOL_GPL(mt76e_set_irq_mask);

void mt76_mmio_init(struct mt76_dev *dev, void __iomem *regs)
{
	static const struct mt76_bus_ops mt76_mmio_ops = {
		.rr = mt76_mmio_rr,
		.rmw = mt76_mmio_rmw,
		.wr = mt76_mmio_wr,
		.copy = mt76_mmio_copy,
	};

	dev->bus = &mt76_mmio_ops;
	dev->mmio.regs = regs;
	spin_lock_init(&dev->mmio.irq_lock);
}
EXPORT_SYMBOL_GPL(mt76_mmio_init);

MODULE_LICENSE("Dual BSD/GPL");
