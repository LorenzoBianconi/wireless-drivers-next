// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 *         Felix Fietkau <nbd@nbd.name>
 *	   Sean Wang <sean.wang@mediatek.com>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 */

#include <linux/of.h>
#include <linux/firmware.h>

#include "mt7663.h"
#include "mcu.h"
#include "mac.h"
#include "eeprom.h"
#include "regs.h"

static struct sk_buff *
mt7663_mcu_msg_alloc(const void *data, int len)
{
	return mt76_mcu_msg_alloc(data, sizeof(struct mt7663_mcu_txd),
				  len, 0);
}

static int
mt7663_mcu_msg_send(struct mt76_dev *mdev, int cmd, const void *data,
		    int len, bool wait_resp)
{
	struct mt7663_dev *dev = container_of(mdev, struct mt7663_dev, mt76);
	enum mt76_txq_id qid;
	struct sk_buff *skb;
	int ret, seq;

	skb = mt7663_mcu_msg_alloc(data, len);
	if (!skb)
		return -ENOMEM;

	mutex_lock(&mdev->mcu.mutex);

	mt7663_mcu_fill_msg(dev, skb, cmd, &seq);
	if (test_bit(MT76_STATE_MCU_RUNNING, &dev->mphy.state))
		qid = MT_TXQ_MCU;
	else
		qid = MT_TXQ_FWDL;

	ret = mt76_tx_queue_skb_raw(dev, qid, skb, 0);
	if (ret)
		goto out;

	if (wait_resp)
		ret = mt7663_mcu_wait_response(dev, cmd, seq);
out:
	mutex_unlock(&mdev->mcu.mutex);

	return ret;
}

static int mt7663_driver_own(struct mt7663_dev *dev)
{
	mt76_wr(dev, MT_CONN_HIF_ON_LPCTL, MT_CFG_LPCR_HOST_DRV_OWN);
	if (!mt76_poll_msec(dev, MT_CONN_HIF_ON_LPCTL,
			    MT_CFG_LPCR_HOST_FW_OWN, 0, 500)) {
		dev_err(dev->mt76.dev, "Timeout for driver own\n");
		return -EIO;
	}

	return 0;
}

static int mt7629_fw_ram_emi_setup(struct mt7663_dev *dev)
{
#define OF_EMI_RESERVED_MEMORY_STR "mediatek,leopard-N9-reserved"
	const struct firmware *fw_iemi, *fw_demi;
	const char *iemi_firmware = MT7629_EMI_IEMI;
	const char *demi_firmware = MT7629_EMI_DEMI;

	struct device_node *node = NULL;
	u32 emi_phyaddr_info[4] = {0, 0, 0, 0};
	u32 emi_phy_addr = MT7629_EMI_PHY_ADDR;
	u32 emi_phy_addr_size = MT7629_EMI_PHY_ADDR_SIZE;
	u32 ram_ilm_emi_addr_offset = MT7629_RAM_ILM_EMI_ADDR_OFFSET;
	u32 ram_dlm_emi_addr_offset = MT7629_RAM_DLM_EMI_ADDR_OFFSET;
	void __iomem *vir_addr = NULL, *target_vir_addr = NULL;
	int ret = 0;

	node = of_find_compatible_node(NULL, NULL, OF_EMI_RESERVED_MEMORY_STR);
	if (!node) {
		dev_err(dev->mt76.dev, "can't found node of %s from dts\n",
			OF_EMI_RESERVED_MEMORY_STR);
		return -EINVAL;
	}

	if (of_property_read_u32_array(node, "reg", emi_phyaddr_info,
				       ARRAY_SIZE(emi_phyaddr_info))) {
		dev_err(dev->mt76.dev,
			"can't get emi physical address from dts\n");
		return -EINVAL;
	}

	if (emi_phy_addr != emi_phyaddr_info[1]) {
		dev_err(dev->mt76.dev,
			"default emi physical address is different from dts\n");
		emi_phy_addr = emi_phyaddr_info[1];
	}

	if (emi_phy_addr_size != emi_phyaddr_info[3]) {
		dev_err(dev->mt76.dev,
			"default emi physical address size is different from dts\n");
		emi_phy_addr_size = emi_phyaddr_info[3];
	}

	dev_info(dev->mt76.dev,
		 "emi physical base: 0x%08x, size: 0x%08x\n", emi_phy_addr,
		 emi_phy_addr_size);

	/* load iemi */
	ret = request_firmware(&fw_iemi, iemi_firmware, dev->mt76.dev);
	if (ret)
		return ret;
	if (!fw_iemi || !fw_iemi->data) {
		dev_err(dev->mt76.dev, "Invalid firmware IEMI\n");
		ret = -EINVAL;
		goto out;
	}

	/* load demi */
	ret = request_firmware(&fw_demi, demi_firmware, dev->mt76.dev);
	if (ret)
		return ret;
	if (!fw_demi || !fw_demi->data) {
		dev_err(dev->mt76.dev, "Invalid firmware DEMI\n");
		ret = -EINVAL;
		goto out;
	}

	vir_addr = ioremap(emi_phy_addr, emi_phy_addr_size);
	if (vir_addr != 0) {
		/* wifi ram ilm emi download */
		target_vir_addr = vir_addr + ram_ilm_emi_addr_offset;
		memmove(target_vir_addr, fw_iemi->data, fw_iemi->size);

		/* wifi ram dlm emi download */
		target_vir_addr = vir_addr + ram_dlm_emi_addr_offset;
		memmove(target_vir_addr, fw_demi->data, fw_demi->size);

		iounmap(vir_addr);
		dev_info(dev->mt76.dev,
			 "wifi ram emi download successfully\n");
	} else {
		dev_err(dev->mt76.dev, "%s: ioremap fail!\n", __func__);
		return -EAGAIN;
	}

out:
	release_firmware(fw_demi);
	release_firmware(fw_iemi);

	return ret;
}

static void fwdl_datapath_setup(struct mt7663_dev *dev, bool init)
{
	u32 val;

	val = mt76_rr(dev, MT_WPDMA_GLO_CFG);
	if (init)
		val |= MT_WPDMA_GLO_CFG_FW_RING_BP_TX_SCH;
	else
		val &= ~MT_WPDMA_GLO_CFG_FW_RING_BP_TX_SCH;

	mt76_wr(dev, MT_WPDMA_GLO_CFG, val);
}

static int mt7663_load_firmware(struct mt7663_dev *dev)
{
	bool emi_load = false;
	int ret;
	u32 val;

	switch (dev->mt76.rev) {
	case 0x76290001:
		emi_load = true;
		break;
	}

	if (emi_load) {
		/* wifi_emi_loader use the other ko. */
		ret = mt7629_fw_ram_emi_setup(dev);
		if (ret)
			return ret;
	}

	fwdl_datapath_setup(dev, true);

	val = mt76_get_field(dev, MT_CONN_ON_MISC, MT_TOP_MISC2_FW_N9_RDY);
	if (val) {
		dev_dbg(dev->mt76.dev, "Firmware is already download\n");
		return -EIO;
	}

	ret = mt7663_mcu_load_patch(dev);
	if (ret)
		return ret;

	ret = mt7663_mcu_load_ram(dev);
	if (ret)
		return ret;

	if (!mt76_poll_msec(dev, MT_CONN_ON_MISC, MT_TOP_MISC2_FW_N9_RDY,
			    (FW_STATE_N9_RDY << 1), 1500)) {
		val = mt76_get_field(dev, MT_CONN_ON_MISC,
				     MT_TOP_MISC2_FW_STATE);
		dev_err(dev->mt76.dev, "Timeout for initializing firmware\n");
		return -EIO;
	}

	mt76_queue_tx_cleanup(dev, MT_TXQ_FWDL, false);
	dev_dbg(dev->mt76.dev, "Firmware init done\n");
	fwdl_datapath_setup(dev, false);

	return 0;
}

int mt7663_mcu_init(struct mt7663_dev *dev)
{
	static const struct mt76_mcu_ops mt7663_mcu_ops = {
		.mcu_send_msg = mt7663_mcu_msg_send,
		.mcu_restart = mt7663_mcu_restart,
	};
	int ret;

	dev->mt76.mcu_ops = &mt7663_mcu_ops,

	ret = mt7663_driver_own(dev);
	if (ret)
		return ret;

	ret = mt7663_load_firmware(dev);
	if (ret)
		return ret;

	set_bit(MT76_STATE_MCU_RUNNING, &dev->mphy.state);

	return 0;
}
