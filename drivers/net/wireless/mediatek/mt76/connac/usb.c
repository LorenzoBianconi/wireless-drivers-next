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

static void
connac_usb_tx_complete_skb(struct mt76_dev *mdev, enum mt76_txq_id qid,
				struct mt76_queue_entry *e)
{
	skb_pull(e->skb, CONNAC_USB_TXD_SIZE);
	mt76_tx_complete_skb(mdev, e->skb);
}

static int
connac_usb_tx_prepare_skb(struct mt76_dev *mdev, void *txwi_ptr,
			  enum mt76_txq_id qid, struct mt76_wcid *wcid,
			  struct ieee80211_sta *sta,
			  struct mt76_tx_info *tx_info)
{
	struct connac_dev *dev = container_of(mdev, struct connac_dev, mt76);
	struct connac_sta *msta = container_of(wcid, struct connac_sta, wcid);
	int pid, headroom = CONNAC_USB_HDR_SIZE + CONNAC_USB_TXD_SIZE;
	struct sk_buff *skb = tx_info->skb;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

	if (unlikely(skb_headroom(skb) < headroom)) {
		int err;

		err = pskb_expand_head(skb, headroom, 0, GFP_ATOMIC);
		if (err < 0)
			return err;
	}

	if (!wcid)
		wcid = &dev->mt76.global_wcid;
	pid = mt76_tx_status_skb_add(mdev, wcid, skb);

	if (info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE) {
		spin_lock_bh(&dev->mt76.lock);
		connac_usb_mac_set_rates(dev, msta, &info->control.rates[0],
					 msta->rates);
		msta->rate_probe = true;
		spin_unlock_bh(&dev->mt76.lock);
	}

	txwi_ptr = (void *)(skb->data - CONNAC_USB_TXD_SIZE);
	connac_mac_write_txwi(dev, txwi_ptr, skb, qid, wcid, sta, pid,
			      info->control.hw_key);
	/* Add MAC TXD */
	skb_push(skb, CONNAC_USB_TXD_SIZE);

	return mt76u_skb_dma_info(skb, cpu_to_le32(skb->len));
}

static int
connac_usb_dma_sched_init(struct connac_dev *dev)
{
	u32 val;

	val = mt76_rr(dev, DMASHDL_PKT_MAX_SIZE(dev));
	val &= ~(PLE_PACKET_MAX_SIZE | PSE_PACKET_MAX_SIZE);
	val |= FIELD_PREP(PLE_PACKET_MAX_SIZE, 0x1) |
	      FIELD_PREP(PSE_PACKET_MAX_SIZE, 0x8);
	mt76_wr(dev, DMASHDL_PKT_MAX_SIZE(dev), val);

	/* disable refill group 5 - group 15 and raise group 2
	 * and 3 as high priority.
	 */
	val = 0xffe00010;
	mt76_wr(dev, DMASHDL_REFILL_CONTROL(dev), val);

	val = mt76_rr(dev, DMASHDL_PAGE_SETTING(dev));
	val &= ~GROUP_SEQUENCE_ORDER_TYPE;
	mt76_wr(dev, DMASHDL_PAGE_SETTING(dev), val);

	val = FIELD_PREP(MIN_QUOTA, 0x3) |
	      FIELD_PREP(MAX_QUOTA, 0x1ff);
	mt76_wr(dev, DMASHDL_GROUP1_CONTROL(dev), val);
	mt76_wr(dev, DMASHDL_GROUP0_CONTROL(dev), val);
	mt76_wr(dev, DMASHDL_GROUP2_CONTROL(dev), val);
	mt76_wr(dev, DMASHDL_GROUP3_CONTROL(dev), val);
	mt76_wr(dev, DMASHDL_GROUP4_CONTROL(dev), val);

	val = FIELD_PREP(QUEUE0_MAP, 0x4) | /* ac0 group 0 */
	      FIELD_PREP(QUEUE1_MAP, 0x4) | /* ac1 group 1 */
	      FIELD_PREP(QUEUE2_MAP, 0x4) | /* ac2 group 2 */
	      FIELD_PREP(QUEUE3_MAP, 0x4) | /* ac3 group 3 */
	      FIELD_PREP(QUEUE4_MAP, 0x4) | /* ac10 group 4*/
	      FIELD_PREP(QUEUE5_MAP, 0x4) | /* ac11 */
	      FIELD_PREP(QUEUE6_MAP, 0x4) |
	      FIELD_PREP(QUEUE7_MAP, 0x4);
	mt76_wr(dev, DMASHDL_QUEUE_MAPPING0(dev), val);

	val = FIELD_PREP(QUEUE8_MAP, 0x4) | /* ac20 group 4*/
	      FIELD_PREP(QUEUE9_MAP, 0x4) |
	      FIELD_PREP(QUEUE10_MAP, 0x4) |
	      FIELD_PREP(QUEUE11_MAP, 0x4) |
	      FIELD_PREP(QUEUE12_MAP, 0x4) | /* ac30 group 4*/
	      FIELD_PREP(QUEUE13_MAP, 0x4) |
	      FIELD_PREP(QUEUE14_MAP, 0x4) |
	      FIELD_PREP(QUEUE15_MAP, 0x4);
	mt76_wr(dev, DMASHDL_QUEUE_MAPPING1(dev), val);

	val = FIELD_PREP(QUEUE16_MAP, 0x4) | /* altx group 4*/
	      FIELD_PREP(QUEUE17_MAP, 0x4) | /* bmc */
	      FIELD_PREP(QUEUE18_MAP, 0x4) | /* bcn */
	      FIELD_PREP(QUEUE19_MAP, 0x4);  /* psmp */
	mt76_wr(dev, DMASHDL_QUEUE_MAPPING2(dev), val);

	/* group pririority from high to low:
	 * 15 (cmd groups) > 4 > 3 > 2 > 1 > 0.
	 */
	mt76_wr(dev, DMASHDL_SCHED_SETTING0(dev), 0x6501234f);
	mt76_wr(dev, DMASHDL_SCHED_SETTING1(dev), 0xedcba987);
	mt76_wr(dev, DMASHDL_OPTIONAL_CONTROL(dev), 0x7004801c);

	/* setup UDMA Tx timeout */
	val = mt76_rr(dev, UDMA_WLCFG_1(dev));
	val &= ~WL_TX_TMOUT_LMT;
	val |= FIELD_PREP(WL_TX_TMOUT_LMT, 500);
	/* do we need to setup WL_RX_AGG_PKT_LMT? */
	mt76_wr(dev, UDMA_WLCFG_1(dev), val);

	val = mt76_rr(dev, UDMA_WLCFG_0(dev));
	val |= WL_TX_TMOUT_FUNC_EN;
	mt76_wr(dev, UDMA_WLCFG_0(dev), val);

	/* setup UDMA Rx Flush */
	val = mt76_rr(dev, UDMA_WLCFG_0(dev));
	val &= ~WL_RX_FLUSH;
	mt76_wr(dev, UDMA_WLCFG_0(dev), val);

	/* hif reset */
	val = mt76_rr(dev, PDMA_HIF_RST);
	val |= CONN_HIF_LOGIC_RST_N;
	mt76_wr(dev, PDMA_HIF_RST, val);

	return 0;
}

static int connac_usb_init_hardware(struct connac_dev *dev)
{
	int ret, idx;
	u32 val;

	ret = connac_eeprom_init(dev);
	if (ret < 0)
		return ret;

	ret = connac_usb_dma_sched_init(dev);
	if (ret)
		return ret;

	val = mt76_rr(dev, UDMA_WLCFG_0(dev));
	val &= ~(WL_RX_AGG_EN | WL_RX_AGG_LMT |  WL_RX_AGG_TO);
	val |=  WL_RX_AGG_EN | FIELD_PREP(WL_RX_AGG_LMT, 32) |
		FIELD_PREP(WL_RX_AGG_TO, 100);
	mt76_wr(dev, UDMA_WLCFG_0(dev), val);

	val = mt76_rr(dev, UDMA_WLCFG_0(dev));
	val |= WL_RX_EN | WL_TX_EN | WL_RX_MPSZ_PAD0 | TICK_1US_EN;
	mt76_wr(dev, UDMA_WLCFG_0(dev), val);

	val = mt76_rr(dev, UDMA_WLCFG_1(dev));
	val &= ~(WL_RX_AGG_PKT_LMT);
	val |= FIELD_PREP(WL_RX_AGG_PKT_LMT, 1);
	mt76_wr(dev, UDMA_WLCFG_1(dev), val);

	set_bit(MT76_STATE_INITIALIZED, &dev->mphy.state);

	ret = connac_usb_mcu_init(dev);
	if (ret)
		return ret;

	connac_mcu_set_eeprom(dev);
	connac_mac_init(dev);
#if MTK_REBB
	connac_mcu_ctrl_pm_state(dev, 0);
#endif
	/* MT7663e : F/W halWtblClearAllWtbl() will do this in init. */
	/* mt7663u_mcu_del_wtbl_all(dev); */

	/* Beacon and mgmt frames should occupy wcid 0 */
	idx = mt76_wcid_alloc(dev->mt76.wcid_mask, CONNAC_WTBL_STA - 1);
	if (idx)
		return -ENOSPC;

	dev->mt76.global_wcid.idx = idx;
	dev->mt76.global_wcid.hw_key_idx = -1;
	rcu_assign_pointer(dev->mt76.wcid[idx], &dev->mt76.global_wcid);

/* sean test */
//      eth_random_addr(dev->mt76.macaddr);
	dev->mt76.macaddr[0] = 0x1a;
	dev->mt76.macaddr[1] = 0xed;
	dev->mt76.macaddr[2] = 0x8f;
	dev->mt76.macaddr[3] = 0x7a;
	dev->mt76.macaddr[4] = 0x97;
	dev->mt76.macaddr[5] = 0x9e;

	dev_info(dev->mt76.dev,
		 "Force to use mac address %pM to test\n",
		 dev->mt76.macaddr);

	return 0;
}

static int
connac_usb_register_device(struct connac_dev *dev)
{
	int err;

	INIT_WORK(&dev->rc_work, connac_usb_rc_work);
	INIT_LIST_HEAD(&dev->rc_processing);

	err = connac_usb_init_hardware(dev);
	if (err)
		return err;

	return connac_register_device(dev);
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

	ret = connac_usb_register_device(dev);
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

static void connac_usb_disconnect(struct usb_interface *usb_intf)
{
	struct connac_dev *dev = usb_get_intfdata(usb_intf);

	if (!test_bit(MT76_STATE_INITIALIZED, &dev->mphy.state))
		return;

	ieee80211_unregister_hw(dev->mt76.hw);
	connac_usb_cleanup(dev);

	usb_set_intfdata(usb_intf, NULL);
	usb_put_dev(interface_to_usbdev(usb_intf));

	mt76u_deinit(&dev->mt76);
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
