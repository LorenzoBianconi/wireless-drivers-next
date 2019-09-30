// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Chih-Min Chen <chih-min.chen@mediatek.com>
 *         Yiwei Chung <yiwei.chung@mediatek.com>
 *         Ryder Lee <ryder.lee@mediatek.com>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#include "mt7663.h"
#include "mac.h"
#include "regs.h"

u32 mt7663_reg_map(struct mt7663_dev *dev, u32 addr)
{
	u32 base = addr & MT_MCU_PCIE_REMAP_2_BASE;
	u32 offset = addr & MT_MCU_PCIE_REMAP_2_OFFSET;

	mt76_wr(dev, MT_MCU_PCIE_REMAP_2, base);

	return MT_PCIE_REMAP_BASE_2 + offset;
}

static int mt76_wmac_probe(struct platform_device *pdev)
{
	static const struct mt76_driver_ops drv_ops = {
		/* txwi_size = txd size + txp size */
		.txwi_size = MT_TXD_SIZE + sizeof(struct mt7663_txp),
		.drv_flags = MT_DRV_TXWI_NO_FREE,
		.tx_prepare_skb = mt7663_tx_prepare_skb,
		.tx_complete_skb = mt7663_tx_complete_skb,
		.rx_skb = mt7663_queue_rx_skb,
		.rx_poll_complete = mt7663_rx_poll_complete,
		.sta_ps = mt7663_sta_ps,
		.sta_add = mt7663_sta_add,
		.sta_assoc = mt7663_sta_assoc,
		.sta_remove = mt7663_sta_remove,
		.update_survey = mt7663_update_channel,
	};
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	struct mt7663_dev *dev;
	void __iomem *mem_base;
	struct mt76_dev *mdev;
	unsigned int chipid, hwver, fwver;
	unsigned long reg_virt;
	int irq;
	int ret;

	dev_info(&pdev->dev, "%s\n", __func__);
	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(&pdev->dev, "Failed to get device IRQ\n");
		return irq;
	}

	mem_base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(mem_base)) {
		dev_err(&pdev->dev, "Failed to get memory resource\n");
		return PTR_ERR(mem_base);
	}

	mdev = mt76_alloc_device(&pdev->dev, sizeof(*dev),
				 &mt7663_mmio_ops, &drv_ops);
	if (!mdev)
		return -ENOMEM;

	dev = container_of(mdev, struct mt7663_dev, mt76);
	mt76_mmio_init(mdev, mem_base);

	/* CHIP ID*/
	reg_virt = (unsigned long)ioremap(0x8000000, 4);
	chipid = readl((void *)reg_virt);
	iounmap((void *)(reg_virt));

	/* HwVer */
	reg_virt = (unsigned long)ioremap(0x8000008, 4);
	hwver = readl((void *)reg_virt);
	iounmap((void *)(reg_virt));

	mdev->rev = ((chipid << 16) | (hwver & 0xff));

	/* FW Ver */
	reg_virt = (unsigned long)ioremap(0x800000c, 4);
	fwver = readl((void *)reg_virt);
	iounmap((void *)(reg_virt));
	dev_info(mdev->dev, "@@@ ASIC revision: %04x, fwver: %04x\n",
		 mdev->rev, fwver);

	ret = mt7663_init_device(dev, irq);
	if (ret)
		goto error;

	return 0;
error:
	ieee80211_free_hw(mt76_hw(dev));
	return ret;
}

static int mt76_wmac_remove(struct platform_device *pdev)
{
	struct mt76_dev *mdev = platform_get_drvdata(pdev);
	struct mt7663_dev *dev = container_of(mdev, struct mt7663_dev, mt76);

	mt7663_unregister_device(dev);

	return 0;
}

static const struct of_device_id of_wmac_match[] = {
	{ .compatible = "mediatek,mt7629-wmac" },
	{},
};
MODULE_DEVICE_TABLE(of, of_wmac_match);

MODULE_FIRMWARE(MT7629_EMI_IEMI);
MODULE_FIRMWARE(MT7629_EMI_DEMI);
MODULE_FIRMWARE(MT7629_FIRMWARE_N9);
MODULE_FIRMWARE(MT7629_ROM_PATCH);

struct platform_driver mt7629_wmac_driver = {
	.probe		= mt76_wmac_probe,
	.remove		= mt76_wmac_remove,
	.driver = {
		.name = "mt7663_wmac",
		.of_match_table = of_wmac_match,
	},
};
