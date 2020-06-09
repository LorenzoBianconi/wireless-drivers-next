// SPDX-License-Identifier: ISC
/* Copyright (C) 2020 MediaTek Inc.
 *
 * Author: Felix Fietkau <nbd@nbd.name>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include <linux/kernel.h>
#include <linux/iopoll.h>
#include <linux/module.h>

#include <linux/mmc/host.h>
#include <linux/mmc/sdio_ids.h>
#include <linux/mmc/sdio_func.h>

#include "mt7615.h"
#include "mac.h"
#include "mcu.h"
#include "regs.h"

static const struct sdio_device_id mt7663s_sdio_table[] = {
	{ SDIO_DEVICE(SDIO_VENDOR_ID_MEDIATEK, 0x7603) },
	{ }	/* Terminating entry */
};

static void mt7663s_stop(struct ieee80211_hw *hw)
{
	struct mt7615_phy *phy = mt7615_hw_phy(hw);
	struct mt7615_dev *dev = hw->priv;

	clear_bit(MT76_STATE_RUNNING, &dev->mphy.state);
	del_timer_sync(&phy->roc_timer);
	cancel_work_sync(&phy->roc_work);
	cancel_delayed_work_sync(&phy->scan_work);
	cancel_delayed_work_sync(&phy->mac_work);

	mt76s_stop_tx(&dev->mt76);
}

static void mt7663s_init_work(struct work_struct *work)
{
	struct mt7615_dev *dev;

	dev = container_of(work, struct mt7615_dev, mcu_work);
	if (mt7663s_mcu_init(dev))
		return;

	mt7615_mcu_set_eeprom(dev);
	mt7615_mac_init(dev);
	mt7615_phy_init(dev);
	mt7615_mcu_del_wtbl_all(dev);
	mt7615_check_offload_capability(dev);
}

static int mt7663s_sdio_probe(struct sdio_func *func,
			      const struct sdio_device_id *id)
{
	static const struct mt76_driver_ops drv_ops = {
		.txwi_size = MT_USB_TXD_SIZE,
		.drv_flags = MT_DRV_RX_DMA_HDR | MT_DRV_HW_MGMT_TXQ,
		.tx_prepare_skb = mt7663_usb_sdio_tx_prepare_skb,
		.tx_complete_skb = mt7663_usb_sdio_tx_complete_skb,
		.tx_status_data = mt7663_usb_sdio_tx_status_data,
		.rx_skb = mt7615_queue_rx_skb,
		.sta_ps = mt7615_sta_ps,
		.sta_add = mt7615_mac_sta_add,
		.sta_remove = mt7615_mac_sta_remove,
		.update_survey = mt7615_update_channel,
	};
	struct ieee80211_ops *ops;
	struct mt7615_dev *dev;
	struct mt76_dev *mdev;
	int ret;

	ops = devm_kmemdup(&func->dev, &mt7615_ops, sizeof(mt7615_ops),
			   GFP_KERNEL);
	if (!ops)
		return -ENOMEM;

	ops->stop = mt7663s_stop;

	mdev = mt76_alloc_device(&func->dev, sizeof(*dev), ops, &drv_ops);
	if (!mdev)
		return -ENOMEM;

	dev = container_of(mdev, struct mt7615_dev, mt76);

	INIT_WORK(&dev->mcu_work, mt7663s_init_work);
	dev->reg_map = mt7663_usb_sdio_reg_map;
	dev->ops = ops;
	sdio_set_drvdata(func, dev);

	ret = mt76s_init(mdev, func);
	if (ret < 0)
		goto err_free;

	mdev->rev = (mt76_rr(dev, MT_HW_CHIPID) << 16) |
		    (mt76_rr(dev, MT_HW_REV) & 0xff);
	dev_dbg(mdev->dev, "ASIC revision: %04x\n", mdev->rev);

	ret = mt76s_alloc_mcu_queue(&dev->mt76);
	if (ret)
		goto err_deinit;

	ret = mt76s_alloc_queues(&dev->mt76);
	if (ret)
		goto err_deinit;

	ret = mt7663_usb_sdio_register_device(dev);
	if (ret)
		goto err_deinit;

	return 0;

err_deinit:
	mt76s_deinit(&dev->mt76);
err_free:
	mt76_free_device(&dev->mt76);

	return ret;
}

static void mt7663s_sdio_remove(struct sdio_func *func)
{
	struct mt7615_dev *dev = sdio_get_drvdata(func);

	if (!test_and_clear_bit(MT76_STATE_INITIALIZED, &dev->mphy.state))
		return;

	ieee80211_unregister_hw(dev->mt76.hw);
	mt76s_deinit(&dev->mt76);
	mt76_free_device(&dev->mt76);
}

#ifdef CONFIG_PM
static int mt7663s_sdio_suspend(struct device *dev)
{
	struct sdio_func *func = dev_to_sdio_func(dev);
	struct mt7615_dev *mdev = sdio_get_drvdata(func);

	if (!test_bit(MT76_STATE_SUSPEND, &mdev->mphy.state) &&
	    mt7615_firmware_offload(mdev)) {
		int err;

		err = mt7615_mcu_set_hif_suspend(mdev, true);
		if (err < 0)
			return err;
	}

	mt76s_stop_rx(&mdev->mt76);

	mt76s_stop_tx(&mdev->mt76);
	tasklet_kill(&mdev->mt76.tx_tasklet);

	return mt7663s_firmware_own(mdev);
}

static int mt7663s_sdio_resume(struct device *dev)
{
	struct sdio_func *func = dev_to_sdio_func(dev);
	struct mt7615_dev *mdev = sdio_get_drvdata(func);
	int err;

	err = mt7663s_driver_own(mdev);
	if (err)
		return err;

	if (!test_bit(MT76_STATE_SUSPEND, &mdev->mphy.state) &&
	    mt7615_firmware_offload(mdev))
		err = mt7615_mcu_set_hif_suspend(mdev, false);

	return err;
}

static const struct dev_pm_ops mt7663s_pm_ops = {
	.suspend = mt7663s_sdio_suspend,
	.resume = mt7663s_sdio_resume,
};
#endif

MODULE_DEVICE_TABLE(sdio, mt7663s_sdio_table);
MODULE_FIRMWARE(MT7663_OFFLOAD_FIRMWARE_N9);
MODULE_FIRMWARE(MT7663_OFFLOAD_ROM_PATCH);
MODULE_FIRMWARE(MT7663_FIRMWARE_N9);
MODULE_FIRMWARE(MT7663_ROM_PATCH);

static struct sdio_driver mt7663s_sdio_driver = {
	.name		= "mt7663s_sdio",
	.probe		= mt7663s_sdio_probe,
	.remove		= mt7663s_sdio_remove,
	.id_table	= mt7663s_sdio_table,
#ifdef CONFIG_PM
	.drv = {
		.pm = &mt7663s_pm_ops,
	}
#endif
};
module_sdio_driver(mt7663s_sdio_driver);

MODULE_AUTHOR("Sean Wang <sean.wang@mediatek.com>");
MODULE_AUTHOR("Lorenzo Bianconi <lorenzo@kernel.org>");
MODULE_LICENSE("Dual BSD/GPL");
