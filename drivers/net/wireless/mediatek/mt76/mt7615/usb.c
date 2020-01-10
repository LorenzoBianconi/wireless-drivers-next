// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Felix Fietkau <nbd@nbd.name>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/usb.h>

#include "mt7663.h"
#include "mt7615.h"
#include "7663_mac.h"
#include "7663_mcu.h"
#include "usb_sdio_regs.h"

static const struct usb_device_id mt7615_device_table[] = {
	{ USB_DEVICE_AND_INTERFACE_INFO(0x0e8d, 0x7663, 0xff, 0xff, 0xff)},
	{ },
};

static void mt7663u_cleanup(struct mt7615_dev *dev)
{
	clear_bit(MT76_STATE_INITIALIZED, &dev->mphy.state);
	mt76u_queues_deinit(&dev->mt76);
}

static void
mt7663u_tx_complete_skb(struct mt76_dev *mdev, enum mt76_txq_id qid,
			struct mt76_queue_entry *e)
{
	skb_pull(e->skb, MT7663_USB_TXD_SIZE);
	mt76_tx_complete_skb(mdev, e->skb);
}

static int
mt7663u_tx_prepare_skb(struct mt76_dev *mdev, void *txwi_ptr,
		       enum mt76_txq_id qid, struct mt76_wcid *wcid,
		       struct ieee80211_sta *sta,
		       struct mt76_tx_info *tx_info)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx_info->skb);

	if (info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE) {
		struct mt7663_sta *msta;

		msta = container_of(wcid, struct mt7663_sta, wcid);
		spin_lock_bh(&dev->mt76.lock);
		mt7663u_mac_set_rates(dev, msta, &info->control.rates[0],
				      msta->rates);
		msta->rate_probe = true;
		spin_unlock_bh(&dev->mt76.lock);
	}
	mt7663u_mac_write_txwi(dev, wcid, qid, sta, tx_info->skb);

	return mt76u_skb_dma_info(tx_info->skb, tx_info->skb->len);
}

static int
mt7663u_probe(struct usb_interface *usb_intf,
	      const struct usb_device_id *id)
{
	static const struct mt76_driver_ops drv_ops = {
		.txwi_size = MT7663_USB_TXD_SIZE,
		.drv_flags = MT_DRV_RX_DMA_HDR,
		.tx_prepare_skb = mt7663u_tx_prepare_skb,
		.tx_complete_skb = mt7663u_tx_complete_skb,
		.rx_skb = mt7663_queue_rx_skb,
		.sta_ps = mt7663_sta_ps,
		.sta_add = mt7663_sta_add,
		.sta_assoc = mt7663_sta_assoc,
		.sta_remove = mt7663_sta_remove,
		.update_survey = mt7663_update_channel,
	};
	struct usb_device *udev = interface_to_usbdev(usb_intf);
	struct mt7615_dev *dev;
	struct mt76_dev *mdev;
	int ret;

	mdev = mt76_alloc_device(&usb_intf->dev, sizeof(*dev),
				 &mt7663_usb_ops, &drv_ops);
	if (!mdev)
		return -ENOMEM;

	dev = container_of(mdev, struct mt7615_dev, mt76);
	udev = usb_get_dev(udev);
	usb_reset_device(udev);

	usb_set_intfdata(usb_intf, dev);

	ret = mt76u_init(mdev, usb_intf, true);
	if (ret < 0)
		goto error;

	mdev->rev = (mt76_rr(dev, MT_HW_CHIPID) << 16) |
		    (mt76_rr(dev, MT_HW_REV) & 0xff);
	dev_dbg(mdev->dev, "ASIC revision: %04x\n", mdev->rev);

	if (mt76_poll_msec(dev, MT_CONN_ON_MISC, MT_TOP_MISC2_FW_PWR_ON,
			   FW_STATE_PWR_ON << 1, 500)) {
		dev_dbg(dev->mt76.dev, "Usb device already powered on\n");
		set_bit(MT76_STATE_POWER_OFF, &dev->mphy.state);
		goto alloc_queues;
	}

	ret = mt76u_vendor_request(&dev->mt76, MT_VEND_POWER_ON,
			           USB_DIR_OUT | USB_TYPE_VENDOR,
				   0x0, 0x1, NULL, 0);
	if (ret)
		goto error;

	if (!mt76_poll_msec(dev, MT_CONN_ON_MISC, MT_TOP_MISC2_FW_PWR_ON,
			    FW_STATE_PWR_ON << 1, 500)) {
		dev_err(dev->mt76.dev, "Timeout for power on\n");
		return -EIO;
	}

alloc_queues:
	ret = mt76u_alloc_mcu_queue(&dev->mt76);
	if (ret)
		goto error;

	ret = mt76u_alloc_queues(&dev->mt76);
	if (ret)
		goto error;

	ret = mt7663u_register_device(dev);
	if (ret)
		goto error_freeq;

	return 0;

error_freeq:
	mt76u_queues_deinit(&dev->mt76);
error:
	mt76u_deinit(&dev->mt76);
	usb_set_intfdata(usb_intf, NULL);
	usb_put_dev(interface_to_usbdev(usb_intf));

	ieee80211_free_hw(mdev->hw);

	return ret;
}

static void mt7663u_disconnect(struct usb_interface *usb_intf)
{
	struct mt7615_dev *dev = usb_get_intfdata(usb_intf);

	if (!test_bit(MT76_STATE_INITIALIZED, &dev->mphy.state))
		return;

	ieee80211_unregister_hw(dev->mt76.hw);
	mt7663u_cleanup(dev);

	usb_set_intfdata(usb_intf, NULL);
	usb_put_dev(interface_to_usbdev(usb_intf));

	mt76u_deinit(&dev->mt76);
	ieee80211_free_hw(dev->mt76.hw);
}

static int __maybe_unused
mt7663u_suspend(struct usb_interface *intf,
		pm_message_t state)
{
	return 0;
}

static int __maybe_unused
mt7663u_resume(struct usb_interface *intf)
{
	return 0;
}

MODULE_DEVICE_TABLE(usb, mt7615_device_table);
MODULE_FIRMWARE(MT7663_FIRMWARE_N9);
MODULE_FIRMWARE(MT7663_ROM_PATCH);

static struct usb_driver mt7663u_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= mt7615_device_table,
	.probe		= mt7663u_probe,
	.disconnect	= mt7663u_disconnect,
#ifdef CONFIG_PM
	.suspend	= mt7663u_suspend,
	.resume		= mt7663u_resume,
	.reset_resume	= mt7663u_resume,
#endif /* CONFIG_PM */
	.soft_unbind	= 1,
	.disable_hub_initiated_lpm = 1,
};
module_usb_driver(mt7663u_driver);

MODULE_AUTHOR("Sean Wang <sean.wang@mediatek.com>");
MODULE_AUTHOR("Lorenzo Bianconi <lorenzo@kernel.org>");
MODULE_LICENSE("Dual BSD/GPL");
