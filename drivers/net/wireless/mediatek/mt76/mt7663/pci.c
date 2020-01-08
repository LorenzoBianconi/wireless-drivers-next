// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 *         Felix Fietkau <nbd@nbd.name>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "connac.h"
#include "mac.h"
#include "regs.h"

static const struct pci_device_id connac_pci_device_table[] = {
	{ PCI_DEVICE(0x14c3, 0x7663) },
	{ },
};

static int connac_pci_probe(struct pci_dev *pdev,
			    const struct pci_device_id *id)
{
	static const struct mt76_driver_ops drv_ops = {
		/* txwi_size = txd size + txp size */
		.txwi_size = MT_TXD_SIZE + sizeof(struct connac_txp),
		.drv_flags = MT_DRV_TXWI_NO_FREE,
		.tx_prepare_skb = connac_tx_prepare_skb,
		.tx_complete_skb = connac_tx_complete_skb,
		.rx_skb = connac_queue_rx_skb,
		.rx_poll_complete = connac_mmio_rx_poll_complete,
		.sta_ps = connac_sta_ps,
		.sta_add = connac_sta_add,
		.sta_assoc = connac_sta_assoc,
		.sta_remove = connac_sta_remove,
		.update_survey = connac_update_channel,
	};
	struct connac_dev *dev;
	struct mt76_dev *mdev;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;

	ret = pcim_iomap_regions(pdev, BIT(0), pci_name(pdev));
	if (ret)
		return ret;

	pci_set_master(pdev);

	ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(36));
	if (ret)
		return ret;

	mdev = mt76_alloc_device(&pdev->dev, sizeof(*dev),
				 &connac_mmio_ops, &drv_ops);
	if (!mdev)
		return -ENOMEM;

	dev = container_of(mdev, struct connac_dev, mt76);
	mt76_mmio_init(&dev->mt76, pcim_iomap_table(pdev)[0]);

	mdev->rev = (mt76_rr(dev, MT_HW_CHIPID) << 16) |
		    (mt76_rr(dev, MT_HW_REV) & 0xff);
	dev_dbg(mdev->dev, "ASIC revision: %04x\n", mdev->rev);
	mt76_wr(dev, MT_PCIE_IRQ_ENABLE, 1);

	ret = connac_mmio_init_device(dev, pdev->irq);
	if (ret)
		goto error;

	return 0;

error:
	ieee80211_free_hw(mt76_hw(dev));
	return ret;
}

static void connac_pci_remove(struct pci_dev *pdev)
{
	struct mt76_dev *mdev = pci_get_drvdata(pdev);
	struct connac_dev *dev = container_of(mdev, struct connac_dev, mt76);

	connac_unregister_device(dev);
}

struct pci_driver connac_pci_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= connac_pci_device_table,
	.probe		= connac_pci_probe,
	.remove		= connac_pci_remove,
};

MODULE_DEVICE_TABLE(pci, connac_pci_device_table);
MODULE_FIRMWARE(MT7663_FIRMWARE_N9);
MODULE_FIRMWARE(MT7663_ROM_PATCH);
