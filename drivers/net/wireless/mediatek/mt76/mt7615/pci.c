// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "mt7615.h"

static const struct pci_device_id mt7615_pci_device_table[] = {
	{ PCI_DEVICE(0x14c3, 0x7615) },
	{ },
};

u32 mt7615_reg_map(struct mt7615_dev *dev, u32 addr)
{
	u32 base = addr & MT_MCU_PCIE_REMAP_2_BASE;
	u32 offset = addr & MT_MCU_PCIE_REMAP_2_OFFSET;

	mt76_wr(dev, MT_MCU_PCIE_REMAP_2, base);

	return MT_PCIE_REMAP_BASE_2 + offset;
}

void mt7615_rx_poll_complete(struct mt76_dev *mdev, enum mt76_rxq_id q)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);

	mt7615_irq_enable(dev, MT_INT_RX_DONE(q));
}

void mt7615_set_irq_mask(struct mt7615_dev *dev, u32 clear, u32 set)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->mt76.mmio.irq_lock, flags);
	dev->mt76.mmio.irqmask &= ~clear;
	dev->mt76.mmio.irqmask |= set;
	mt76_wr(dev, MT_INT_MASK_CSR, dev->mt76.mmio.irqmask);
	spin_unlock_irqrestore(&dev->mt76.mmio.irq_lock, flags);
}

irqreturn_t mt7615_irq_handler(int irq, void *dev_instance)
{
	struct mt7615_dev *dev = dev_instance;
	u32 intr;

	intr = mt76_rr(dev, MT_INT_SOURCE_CSR);
	mt76_wr(dev, MT_INT_SOURCE_CSR, intr);

	if (!test_bit(MT76_STATE_INITIALIZED, &dev->mt76.state))
		return IRQ_NONE;

	intr &= dev->mt76.mmio.irqmask;

	if (intr & MT_INT_TX_DONE_ALL) {
		mt7615_irq_disable(dev, MT_INT_TX_DONE_ALL);
		tasklet_schedule(&dev->tx_tasklet);
	}

	if (intr & MT_INT_RX_DONE(0)) {
		mt7615_irq_disable(dev, MT_INT_RX_DONE(0));
		napi_schedule(&dev->mt76.napi[0]);
	}

	if (intr & MT_INT_RX_DONE(1)) {
		mt7615_irq_disable(dev, MT_INT_RX_DONE(1));
		napi_schedule(&dev->mt76.napi[1]);
	}

	return IRQ_HANDLED;
}

static int mt7615_pci_probe(struct pci_dev *pdev,
			    const struct pci_device_id *id)
{
	struct mt7615_dev *dev;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;

	ret = pcim_iomap_regions(pdev, BIT(0), pci_name(pdev));
	if (ret)
		return ret;

	pci_set_master(pdev);

	ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
	if (ret)
		return ret;

	dev = mt7615_alloc_device(&pdev->dev);
	if (!dev)
		return -ENOMEM;

	mt76_mmio_init(&dev->mt76, pcim_iomap_table(pdev)[0]);

	dev->mt76.rev = (mt76_rr(dev, MT_HW_CHIPID) << 16) |
			(mt76_rr(dev, MT_HW_REV) & 0xff);
	dev_dbg(dev->mt76.dev, "ASIC revision: %04x\n", dev->mt76.rev);

	ret = devm_request_irq(dev->mt76.dev, pdev->irq, mt7615_irq_handler,
			       IRQF_SHARED, KBUILD_MODNAME, dev);
	if (ret)
		goto error;

	ret = mt7615_register_device(dev);
	if (ret)
		goto error;

	return 0;
error:
	ieee80211_free_hw(mt76_hw(dev));
	return ret;
}

static void mt7615_pci_remove(struct pci_dev *pdev)
{
	struct mt76_dev *mdev = pci_get_drvdata(pdev);
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);

	mt7615_unregister_device(dev);
	ieee80211_free_hw(mt76_hw(dev));
}

struct pci_driver mt7615_pci_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= mt7615_pci_device_table,
	.probe		= mt7615_pci_probe,
	.remove		= mt7615_pci_remove,
};

module_pci_driver(mt7615_pci_driver);

MODULE_DEVICE_TABLE(pci, mt7615_pci_device_table);
MODULE_FIRMWARE(MT7615_FIRMWARE_CR4);
MODULE_FIRMWARE(MT7615_FIRMWARE_N9);
MODULE_FIRMWARE(MT7615_ROM_PATCH);
