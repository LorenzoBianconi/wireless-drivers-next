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

#define MT_VEND_REQ_MAX_RETRY	10
#define MT_VEND_REQ_TOUT_MS	300

static bool disable_usb_sg = true;
module_param_named(disable_usb_sg, disable_usb_sg, bool, 0644);
MODULE_PARM_DESC(disable_usb_sg, "Disable usb scatter-gather support");

static const struct usb_device_id connac_device_table[] = {
	{ USB_DEVICE_AND_INTERFACE_INFO(0x0e8d, 0x7663, 0xff, 0xff, 0xff)},
	{ },
};

/* should be called with usb_ctrl_mtx locked */
static int __connac_usb_vendor_request(struct mt76_dev *dev, u8 req,
				       u8 req_type, u16 val, u16 offset,
				       void *buf, size_t len)
{
	struct usb_device *udev = to_usb_device(dev->dev);
	unsigned int pipe;
	int i, ret;

	pipe = (req_type & USB_DIR_IN) ? usb_rcvctrlpipe(udev, 0)
				       : usb_sndctrlpipe(udev, 0);
	for (i = 0; i < MT_VEND_REQ_MAX_RETRY; i++) {
		if (test_bit(MT76_REMOVED, &dev->state))
			return -EIO;

		ret = usb_control_msg(udev, pipe, req, req_type, val,
				      offset, buf, len, MT_VEND_REQ_TOUT_MS);
		if (ret == -ENODEV)
			set_bit(MT76_REMOVED, &dev->state);
		if (ret >= 0 || ret == -ENODEV)
			return ret;
		usleep_range(5000, 10000);
	}

	dev_err(dev->dev, "vendor request req:%02x off:%04x failed:%d\n",
		req, offset, ret);
	return ret;
}

int connac_usb_vendor_request(struct mt76_dev *dev, u8 req,
			      u8 req_type, u16 val, u16 offset,
			      void *buf, size_t len)
{
	int ret;

	mutex_lock(&dev->usb.usb_ctrl_mtx);
	ret = __connac_usb_vendor_request(dev, req, req_type, val, offset, buf,
					  len);
	trace_usb_reg_wr(dev, offset, val);
	mutex_unlock(&dev->usb.usb_ctrl_mtx);

	return ret;
}

/* should be called with usb_ctrl_mtx locked */
static u32 __connac_usb_rr(struct mt76_dev *dev, u32 addr)
{
	struct mt76_usb *usb = &dev->usb;
	u32 data = ~0;
	u16 offset[2];
	int ret;
	u8 req;

	req = CONNAC_VEND_READ;
	offset[0] = (addr & 0xffff0000) >> 16;
	offset[1] = addr & 0xffff;

	ret = __connac_usb_vendor_request(dev, req,
					  USB_DIR_IN | USB_TYPE_VENDOR,
					  offset[0], offset[1], usb->data,
					  sizeof(__le32));
	if (ret == sizeof(__le32))
		data = get_unaligned_le32(usb->data);
	trace_usb_reg_rr(dev, addr, data);

	return data;
}

static u32 connac_usb_rr(struct mt76_dev *dev, u32 addr)
{
	u32 ret;

	mutex_lock(&dev->usb.usb_ctrl_mtx);
	ret = __connac_usb_rr(dev, addr);
	mutex_unlock(&dev->usb.usb_ctrl_mtx);

	return ret;
}

/* should be called with usb_ctrl_mtx locked */
static void __connac_usb_wr(struct mt76_dev *dev, u32 addr, u32 val)
{
	struct mt76_usb *usb = &dev->usb;
	u16 offset[2];
	u8 req;

	req = CONNAC_VEND_WRITE;
	offset[0] = (addr & 0xffff0000) >> 16;
	offset[1] = addr & 0xffff;

	put_unaligned_le32(val, usb->data);
	__connac_usb_vendor_request(dev, req,
				    USB_DIR_OUT | USB_TYPE_VENDOR, offset[0],
				    offset[1], usb->data, sizeof(__le32));
	trace_usb_reg_wr(dev, addr, val);
}

static void connac_usb_wr(struct mt76_dev *dev, u32 addr, u32 val)
{
	mutex_lock(&dev->usb.usb_ctrl_mtx);
	__connac_usb_wr(dev, addr, val);
	mutex_unlock(&dev->usb.usb_ctrl_mtx);
}

static u32 connac_usb_rmw(struct mt76_dev *dev, u32 addr,
			  u32 mask, u32 val)
{
	mutex_lock(&dev->usb.usb_ctrl_mtx);
	val |= __connac_usb_rr(dev, addr) & ~mask;
	__connac_usb_wr(dev, addr, val);
	mutex_unlock(&dev->usb.usb_ctrl_mtx);

	return val;
}


static void
connac_usb_write_copy(struct mt76_dev *dev, u32 offset, const void *data,
		      int len)
{
	mutex_lock(&dev->usb.usb_ctrl_mtx);

	while (len) {
		__connac_usb_wr(dev, offset, *(u32 *)data);

		offset += sizeof(u32);
		data += sizeof(u32);
		len -= sizeof(u32);
	}

	mutex_unlock(&dev->usb.usb_ctrl_mtx);
}

static void
connac_usb_read_copy(struct mt76_dev *dev, u32 offset, void *data, int len)
{
	mutex_lock(&dev->usb.usb_ctrl_mtx);

	while (len) {
		*(u32 *)data = __connac_usb_rr(dev, offset);

		offset += sizeof(u32);
		data += sizeof(u32);
		len -= sizeof(u32);
	}

	mutex_unlock(&dev->usb.usb_ctrl_mtx);
}

static void connac_usb_cleanup(struct connac_dev *dev)
{
	clear_bit(MT76_STATE_INITIALIZED, &dev->mt76.state);
	mt7663u_queues_deinit(&dev->mt76);
}

static int connac_usb_probe(struct usb_interface *usb_intf,
			    const struct usb_device_id *id)
{
	static const struct mt76_driver_ops drv_ops = {
		.txwi_size = CONNAC_USB_TXD_SIZE,
		.tx_prepare_skb = connac_usb_tx_prepare_skb,
		.tx_complete_skb = connac_usb_tx_complete_skb,
		.rx_skb = connac_queue_rx_skb,
		.sta_ps = connac_sta_ps,
		.sta_add = connac_sta_add,
		.sta_assoc = connac_sta_assoc,
		.sta_remove = connac_sta_remove,
		.update_survey = connac_update_channel,
	};

	static const struct mt76_bus_ops connac_usb_bus_ops = {
		.rr = connac_usb_rr,
		.wr = connac_usb_wr,
		.rmw = connac_usb_rmw,
		.read_copy = connac_usb_read_copy,
		.write_copy = connac_usb_write_copy,
		.type = MT76_BUS_USB,
	};

	struct usb_device *udev = interface_to_usbdev(usb_intf);
	struct connac_dev *dev;
	struct mt76_dev *mdev;
	int ret;

	mdev = mt76_alloc_device(&udev->dev, sizeof(*dev), &connac_ops,
				 &drv_ops);
	if (!mdev)
		return -ENOMEM;

	dev = container_of(mdev, struct connac_dev, mt76);
	udev = usb_get_dev(udev);
	usb_reset_device(udev);

	usb_set_intfdata(usb_intf, dev);

	dev->flag |= CONNAC_USB;
	dev->regs = connac_abs_regs_base;

	ret = mt7663u_init(mdev, usb_intf, &connac_usb_bus_ops);
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

	ret = connac_usb_vendor_request(&dev->mt76, CONNAC_VEND_POWERON,
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
	ret = mt7663u_alloc_queues(&dev->mt76);
	if (ret)
		goto error;

	ret = connac_register_device(dev);
	if (ret)
		goto error_freeq;

	return 0;
error_freeq:
	mt7663u_queues_deinit(&dev->mt76);
error:
	usb_set_intfdata(usb_intf, NULL);
	usb_put_dev(interface_to_usbdev(usb_intf));

	ieee80211_free_hw(mdev->hw);

	return ret;
}

static void connac_usb_disconnect(struct usb_interface *usb_intf)
{
	struct connac_dev *dev = usb_get_intfdata(usb_intf);
	bool initialized = test_bit(MT76_STATE_INITIALIZED, &dev->mt76.state);

	if (!initialized)
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
