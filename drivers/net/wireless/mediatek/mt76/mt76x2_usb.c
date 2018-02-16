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

#include <linux/kernel.h>
#include <linux/module.h>

#include "mt76x2u.h"

static const struct usb_device_id mt76x2u_device_table[] = {
	{ USB_DEVICE(0x0846, 0x9053) },		/* Netgear A6210 */
	{ },
};

static int mt76x2u_probe(struct usb_interface *intf,
			 const struct usb_device_id *id)
{
	struct usb_device *udev = interface_to_usbdev(intf);
	struct mt76x2_dev *dev;
	int err;

	dev = mt76x2u_alloc_device(&intf->dev);
	if (!dev)
		return -ENOMEM;

	udev = usb_get_dev(udev);
	usb_reset_device(udev);

	err = mt76_usb_init(&dev->mt76, intf);
	if (err < 0)
		goto err;

	dev->mt76.rev = mt76_rr(dev, MT_ASIC_VERSION);
	dev_info(dev->mt76.dev, "ASIC revision: %08x\n", dev->mt76.rev);

	err = mt76x2u_register_device(dev);
	if (err < 0)
		goto err;

	return 0;

err:
	ieee80211_free_hw(mt76_hw(dev));
	usb_set_intfdata(intf, NULL);
	usb_put_dev(udev);

	return err;
}

static void mt76x2u_disconnect(struct usb_interface *intf)
{
	struct usb_device *udev = interface_to_usbdev(intf);
	struct mt76x2_dev *dev = usb_get_intfdata(intf);
	mt76x2u_cleanup(dev);

	ieee80211_free_hw(mt76_hw(dev));
	usb_set_intfdata(intf, NULL);
	usb_put_dev(udev);
}

MODULE_DEVICE_TABLE(usb, mt76x2u_device_table);
MODULE_FIRMWARE(MT7662U_FIRMWARE);
MODULE_FIRMWARE(MT7662U_ROM_PATCH);
MODULE_LICENSE("Dual BSD/GPL");

static struct usb_driver mt76x2u_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= mt76x2u_device_table,
	.probe		= mt76x2u_probe,
	.disconnect	= mt76x2u_disconnect,
};
module_usb_driver(mt76x2u_driver);
