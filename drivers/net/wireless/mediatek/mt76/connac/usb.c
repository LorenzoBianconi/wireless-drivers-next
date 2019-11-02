// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Felix Fietkau <nbd@nbd.name>
 *	   Lorenzo Bianconi <lorenzo.bianconi83@gmail.com>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/usb.h>

#include "connac.h"
#include "mac.h"
#include "mcu.h"
#include "../usb_trace.h"

static const struct usb_device_id connac_device_table[] = {
	{ USB_DEVICE_AND_INTERFACE_INFO(0x0e8d, 0x7663, 0xff, 0xff, 0xff)},
	{ },
};

static void connac_usb_cleanup(struct connac_dev *dev)
{
	clear_bit(MT76_STATE_INITIALIZED, &dev->mphy.state);
	mt76u_queues_deinit(&dev->mt76);
}

static int connac_usb_probe(struct usb_interface *usb_intf,
			    const struct usb_device_id *id)
{
	static const struct mt76_driver_ops drv_ops = {
		.txwi_size = CONNAC_USB_TXD_SIZE,
		.drv_flags = MT_DRV_RX_DMA_HDR,
		.tx_prepare_skb = connac_usb_tx_prepare_skb,
		.tx_complete_skb = connac_usb_tx_complete_skb,
		.rx_skb = connac_queue_rx_skb,
		.sta_ps = connac_sta_ps,
		.sta_add = connac_sta_add,
		.sta_assoc = connac_sta_assoc,
		.sta_remove = connac_sta_remove,
		.update_survey = connac_update_channel,
	};
	struct usb_device *udev = interface_to_usbdev(usb_intf);
	struct connac_dev *dev;
	struct mt76_dev *mdev;
	int ret;

	mdev = mt76_alloc_device(&usb_intf->dev, sizeof(*dev), &connac_ops,
				 &drv_ops);
	if (!mdev)
		return -ENOMEM;

	dev = container_of(mdev, struct connac_dev, mt76);
	udev = usb_get_dev(udev);
	usb_reset_device(udev);

	usb_set_intfdata(usb_intf, dev);

	dev->flag |= CONNAC_USB;
	dev->regs = connac_abs_regs_base;

	ret = mt76u_init(mdev, usb_intf, true);
	if (ret < 0)
		goto error;

	mdev->rev = (mt76_rr(dev, MT_HW_CHIPID(dev)) << 16) |
		    (mt76_rr(dev, MT_HW_REV(dev)) & 0xff);
	dev_dbg(mdev->dev, "ASIC revision: %04x\n", mdev->rev);

	if (mt76_poll_msec(dev, MT_CONN_ON_MISC(dev), MT_TOP_MISC2_FW_PWR_ON,
			   FW_STATE_PWR_ON << 1, 500)) {
		dev_dbg(dev->mt76.dev, "Dongle have been powered on\n");
		dev->required_poweroff = true;
		goto skip_poweron;
	}

	ret = mt76u_vendor_request(&dev->mt76, MT_VEND_POWER_ON,
			           USB_DIR_OUT | USB_TYPE_VENDOR,
				   0x0, 0x1, NULL, 0);
	if (ret)
		goto error;

	if (!mt76_poll_msec(dev, MT_CONN_ON_MISC(dev), MT_TOP_MISC2_FW_PWR_ON,
			    FW_STATE_PWR_ON << 1, 500)) {
		dev_err(dev->mt76.dev, "Timeout for power on\n");
		return -EIO;
	}

skip_poweron:
	ret = mt76u_alloc_mcu_queue(&dev->mt76);
	if (ret)
		goto error;

	ret = mt76u_alloc_queues(&dev->mt76);
	if (ret)
		goto error;

	ret = connac_register_device(dev);
	if (ret)
		goto error_freeq;

	return 0;
error_freeq:
	mt76u_queues_deinit(&dev->mt76);
error:
	usb_set_intfdata(usb_intf, NULL);
	usb_put_dev(interface_to_usbdev(usb_intf));

	ieee80211_free_hw(mdev->hw);

	return ret;
}

static void connac_usb_disconnect(struct usb_interface *usb_intf)
{
	struct connac_dev *dev = usb_get_intfdata(usb_intf);

	if (!test_bit(MT76_STATE_INITIALIZED, &dev->mphy.state))
		return;

	ieee80211_unregister_hw(dev->mt76.hw);
	connac_usb_cleanup(dev);

	usb_set_intfdata(usb_intf, NULL);
	usb_put_dev(interface_to_usbdev(usb_intf));

	ieee80211_free_hw(dev->mt76.hw);
}

static int __maybe_unused connac_usb_suspend(struct usb_interface *intf,
					     pm_message_t state)
{
	return 0;
}

static int __maybe_unused connac_usb_resume(struct usb_interface *intf)
{
	return 0;
}

MODULE_DEVICE_TABLE(usb, connac_device_table);
MODULE_FIRMWARE(MT7663_FIRMWARE_N9);
MODULE_FIRMWARE(MT7663_ROM_PATCH);

static struct usb_driver connac_usb_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= connac_device_table,
	.probe		= connac_usb_probe,
	.disconnect	= connac_usb_disconnect,
#ifdef CONFIG_PM
	.suspend	= connac_usb_suspend,
	.resume		= connac_usb_resume,
	.reset_resume	= connac_usb_resume,
#endif /* CONFIG_PM */
	.soft_unbind	= 1,
	.disable_hub_initiated_lpm = 1,
};
module_usb_driver(connac_usb_driver);

MODULE_AUTHOR("Sean Wang <sean.wang@mediatek.com>");
MODULE_LICENSE("Dual BSD/GPL");
