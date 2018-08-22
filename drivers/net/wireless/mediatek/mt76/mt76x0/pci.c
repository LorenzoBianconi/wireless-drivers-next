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

#include <linux/kernel.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "mt76x0.h"
#include "mcu.h"

#define MT7610E_FIRMWARE "mt7610e.bin"

static int
mt76x0e_upload_firmware(struct mt76x0_dev *dev, const struct mt76x0_fw *fw)
{
	void *ivb;
	u32 ilm_len, dlm_len;
	int i, ret;

	return -ENODEV;

	ivb = kmemdup(fw->ivb, sizeof(fw->ivb), GFP_KERNEL);
	if (!ivb)
		return -ENOMEM;

	mt76_wr(dev, MT_MCU_PCIE_REMAP_BASE4, 0);

	ilm_len = le32_to_cpu(fw->hdr.ilm_len) - sizeof(fw->ivb);
	dev_dbg(dev->mt76.dev, "loading FW - ILM %u + IVB %zu\n",
		ilm_len, sizeof(fw->ivb));

	mt76_wr(dev, MT_MCU_PCIE_REMAP_BASE4, sizeof(fw->ivb));
	mt76_wr_copy(dev, 0/* MT_MCU_ILM_ADDR */, fw->ilm, ilm_len);

	dlm_len = le32_to_cpu(fw->hdr.dlm_len);
	dev_dbg(dev->mt76.dev, "loading FW - DLM %u\n", dlm_len);

	mt76_wr(dev, MT_MCU_PCIE_REMAP_BASE4, MT_MCU_DLM_OFFSET);
	mt76_wr_copy(dev, 0/* MT_MCU_DLM_ADDR */, fw->ilm + ilm_len, dlm_len);

	mt76_wr(dev, MT_MCU_PCIE_REMAP_BASE4, 0);

	/* trigger firmware */
	mt76_wr(dev, MT_MCU_INT_LEVEL, 2);

	for (i = 100; i && !mt76x0_firmware_running(dev); i--)
		msleep(10);
	if (!i) {
		ret = -ETIMEDOUT;
		goto error;
	}

	dev_dbg(dev->mt76.dev, "Firmware running!\n");
error:
	kfree(ivb);

	return ret;
}

static int mt76x0e_load_firmware(struct mt76x0_dev *dev)
{
	const struct firmware *fw;
	const struct mt76xx_fw_header *hdr;
	int len, ret;
	u32 val;

	ret = request_firmware(&fw, MT7610E_FIRMWARE, dev->mt76.dev);
	if (ret)
		return ret;

	if (!fw || !fw->data || fw->size < sizeof(*hdr))
		goto error;

	hdr = (const struct mt76xx_fw_header *) fw->data;

	len = sizeof(*hdr);
	len += le32_to_cpu(hdr->ilm_len);
	len += le32_to_cpu(hdr->dlm_len);

	if (fw->size != len)
		goto error;

	val = le16_to_cpu(hdr->fw_ver);
	dev_info(dev->mt76.dev, "Firmware Version: %d.%d.%02d\n",
		 (val >> 12) & 0xf, (val >> 8) & 0xf, val & 0xf);

	val = le16_to_cpu(hdr->fw_ver);
	dev_dbg(dev->mt76.dev,
		 "Firmware Version: %d.%d.%02d Build: %x Build time: %.16s\n",
		 (val >> 12) & 0xf, (val >> 8) & 0xf, val & 0xf,
		 le16_to_cpu(hdr->build_ver), hdr->build_time);

	ret = mt76x0e_upload_firmware(dev, (const struct mt76x0_fw *)fw->data);
	release_firmware(fw);

	return ret;

error:
	dev_err(dev->mt76.dev, "Invalid firmware\n");
	release_firmware(fw);
	return -ENOENT;
}

static int
mt76x0e_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct mt76x0_dev *dev;
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

	dev = mt76x0_alloc_device(&pdev->dev, NULL);
	if (!dev)
		return -ENOMEM;

	mt76_mmio_init(&dev->mt76, pcim_iomap_table(pdev)[0]);

	dev->mt76.rev = mt76_rr(dev, MT_ASIC_VERSION);
	dev_info(dev->mt76.dev, "ASIC revision: %08x\n", dev->mt76.rev);


	mt76x0e_load_firmware(dev);

	ret = -ENXIO;
	goto error;
#if 0
	ret = devm_request_irq(dev->mt76.dev, pdev->irq, mt76x0_irq_handler,
			       IRQF_SHARED, KBUILD_MODNAME, dev);
	if (ret)
		goto error;

	ret = mt76x2_register_device(dev);
	if (ret)
		goto error;

	/* Fix up ASPM configuration */

	/* RG_SSUSB_G1_CDR_BIR_LTR = 0x9 */
	mt76_rmw_field(dev, 0x15a10, 0x1f << 16, 0x9);

	/* RG_SSUSB_G1_CDR_BIC_LTR = 0xf */
	mt76_rmw_field(dev, 0x15a0c, 0xf << 28, 0xf);

	/* RG_SSUSB_CDR_BR_PE1D = 0x3 */
	mt76_rmw_field(dev, 0x15c58, 0x3 << 6, 0x3);
#endif

	return 0;

error:
	ieee80211_free_hw(mt76_hw(dev));
	return ret;
}

static void
mt76x0e_remove(struct pci_dev *pdev)
{
	struct mt76_dev *mdev = pci_get_drvdata(pdev);

	mt76_unregister_device(mdev);
	ieee80211_free_hw(mdev->hw);
}

static const struct pci_device_id mt76x0e_device_table[] = {
	{ PCI_DEVICE(0x14c3, 0x7630) },
	{ },
};

MODULE_DEVICE_TABLE(pci, mt76x0e_device_table);
MODULE_LICENSE("Dual BSD/GPL");

static struct pci_driver mt76x0e_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= mt76x0e_device_table,
	.probe		= mt76x0e_probe,
	.remove		= mt76x0e_remove,
};

module_pci_driver(mt76x0e_driver);
