// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Roy Luo <roychl666@gmail.com>
	   Ryder Lee <ryder.lee@mediatek.com>
 */

#include <linux/firmware.h>
#include "mt7615.h"
#include "mcu.h"
#include "mac.h"
#include "eeprom.h"

struct mt7615_patch_hdr {
	char build_date[16];
	char platform[4];
	__be32 hw_sw_ver;
	__be32 patch_ver;
	__be16 checksum;
} __packed;

struct mt7615_fw_trailer {
	__le32 addr;
	u8 chip_id;
	u8 feature_set;
	u8 eco_code;
	char fw_ver[10];
	char build_date[15];
	__le32 len;
} __packed;

#define MCU_PATCH_ADDRESS		0x80000

#define N9_REGION_NUM			2
#define CR4_REGION_NUM			1

#define IMG_CRC_LEN			4

#define FW_FEATURE_SET_ENCRYPT		BIT(0)
#define FW_FEATURE_SET_KEY_IDX		GENMASK(2, 1)

#define DL_MODE_ENCRYPT			BIT(0)
#define DL_MODE_KEY_IDX			GENMASK(2, 1)
#define DL_MODE_RESET_SEC_IV		BIT(3)
#define DL_MODE_WORKING_PDA_CR4		BIT(4)
#define DL_MODE_NEED_RSP		BIT(31)

#define FW_START_OVERRIDE		BIT(0)
#define FW_START_WORKING_PDA_CR4	BIT(2)

static struct sk_buff *mt7615_mcu_msg_alloc(const void *data, int len)
{
	struct sk_buff *skb;

	skb = alloc_skb(len + sizeof(struct mt7615_mcu_txd),
			GFP_KERNEL);
	if (!skb)
		return NULL;

	skb_reserve(skb, sizeof(struct mt7615_mcu_txd));
	if (data && len)
		memcpy(skb_put(skb, len), data, len);

	return skb;
}

/* to support unsolicited event, need to do it here */
void mt7615_mcu_rx_event(struct mt7615_dev *dev, struct sk_buff *skb)
{
	skb_queue_tail(&dev->mt76.mmio.mcu.res_q, skb);
	wake_up(&dev->mt76.mmio.mcu.wait);
}

static struct sk_buff *mt7615_mcu_get_response(struct mt7615_dev *dev,
					       unsigned long expires)
{
	unsigned long timeout;

	if (!time_is_after_jiffies(expires))
		return NULL;

	timeout = expires - jiffies;
	wait_event_timeout(dev->mt76.mmio.mcu.wait,
			   !skb_queue_empty(&dev->mt76.mmio.mcu.res_q),
			   timeout);
	return skb_dequeue(&dev->mt76.mmio.mcu.res_q);
}

static int __mt7615_mcu_msg_send(struct mt7615_dev *dev, struct sk_buff *skb,
				 int cmd, int query, int dest, int *wait_seq)
{
	struct mt7615_mcu_txd *mcu_txd;
	u8 seq, q_idx, pkt_fmt;
	u32 val;
	__le32 *txd;

	if (!skb)
		return -EINVAL;

	seq = ++dev->mt76.mmio.mcu.msg_seq & 0xf;
	if (!seq)
		seq = ++dev->mt76.mmio.mcu.msg_seq & 0xf;

	mcu_txd = (struct mt7615_mcu_txd *)skb_push(skb,
		   sizeof(struct mt7615_mcu_txd));
	memset(mcu_txd, 0, sizeof(struct mt7615_mcu_txd));

	if (cmd != -MCU_CMD_FW_SCATTER) {
		q_idx = MT_TX_MCU_PORT_RX_Q0;
		pkt_fmt = MT_TX_TYPE_CMD;
	} else {
		q_idx = MT_TX_MCU_PORT_RX_FWDL;
		pkt_fmt = MT_TX_TYPE_FW;
	}

	txd = mcu_txd->txd;

	val = FIELD_PREP(MT_TXD0_TX_BYTES, cpu_to_le16(skb->len)) |
	      FIELD_PREP(MT_TXD0_P_IDX, MT_TX_PORT_IDX_MCU) |
	      FIELD_PREP(MT_TXD0_Q_IDX, q_idx);
	txd[0] = cpu_to_le32(val);

	val = MT_TXD1_LONG_FORMAT |
	      FIELD_PREP(MT_TXD1_HDR_FORMAT, MT_HDR_FORMAT_CMD) |
	      FIELD_PREP(MT_TXD1_PKT_FMT, pkt_fmt);
	txd[1] = cpu_to_le32(val);

	mcu_txd->len = cpu_to_le16(skb->len -
				   sizeof_field(struct mt7615_mcu_txd, txd));
	mcu_txd->pq_id = cpu_to_le16(MCU_PQ_ID(MT_TX_PORT_IDX_MCU, q_idx));
	mcu_txd->pkt_type = MCU_PKT_ID;
	mcu_txd->seq = seq;

	if (cmd < 0) {
		mcu_txd->cid = -cmd;
	} else {
		mcu_txd->cid = MCU_CMD_EXT_CID;
		mcu_txd->ext_cid = cmd;
		if (query != MCU_Q_NA)
			mcu_txd->ext_cid_ack = 1;
	}

	mcu_txd->set_query = query;
	mcu_txd->s2d_index = dest;

	if (wait_seq)
		*wait_seq = seq;

	return mt7615_tx_queue_mcu(dev, test_bit(MT76_STATE_MCU_RUNNING,
				   &dev->mt76.state) ? MT7615_TXQ_MCU :
				   MT7615_TXQ_FWDL, skb);
}

static int mt7615_mcu_msg_send(struct mt7615_dev *dev, struct sk_buff *skb,
			       int cmd, int query, int dest,
			       struct sk_buff **skb_ret)
{
	unsigned long expires = jiffies + 10 * HZ;
	struct mt7615_mcu_rxd *rxd;
	int ret, seq;

	mutex_lock(&dev->mt76.mmio.mcu.mutex);

	ret = __mt7615_mcu_msg_send(dev, skb, cmd, query, dest, &seq);
	if (ret)
		goto out;

	while (1) {
		skb = mt7615_mcu_get_response(dev, expires);
		if (!skb) {
			dev_err(dev->mt76.dev, "Message %d (seq %d) timeout\n",
				cmd, seq);
			ret = -ETIMEDOUT;
			break;
		}

		rxd = (struct mt7615_mcu_rxd *)skb->data;
		skb_pull(skb, test_bit(MT76_STATE_MCU_RUNNING, &dev->mt76.state) ?
			 sizeof(*rxd) : sizeof(*rxd) - 4);

		if (seq != rxd->seq)
			continue;

		if (skb_ret)
			*skb_ret = skb;
		else
			dev_kfree_skb(skb);

		break;
	}

out:
	mutex_unlock(&dev->mt76.mmio.mcu.mutex);

	return ret;
}

static int mt7615_mcu_init_download(struct mt7615_dev *dev, u32 addr,
				    u32 len, u32 mode)
{
	struct {
		__le32 addr;
		__le32 len;
		__le32 mode;
	} req = {
		.addr = cpu_to_le32(addr),
		.len = cpu_to_le32(len),
		.mode = cpu_to_le32(mode),
	};
	struct sk_buff *skb = mt7615_mcu_msg_alloc(&req, sizeof(req));

	return mt7615_mcu_msg_send(dev, skb, -MCU_CMD_TARGET_ADDRESS_LEN_REQ,
				   MCU_Q_NA, MCU_S2D_H2N, NULL);
}

static int mt7615_mcu_send_firmware(struct mt7615_dev *dev, const void *data,
				    int len)
{
	struct sk_buff *skb;
	int ret = 0;

	while (len > 0) {
		int cur_len = min_t(int, 4096 - sizeof(struct mt7615_mcu_txd),
				    len);

		skb = mt7615_mcu_msg_alloc(data, cur_len);
		if (!skb)
			return -ENOMEM;

		ret = __mt7615_mcu_msg_send(dev, skb, -MCU_CMD_FW_SCATTER,
					    MCU_Q_NA, MCU_S2D_H2N, NULL);
		if (ret)
			break;

		data += cur_len;
		len -= cur_len;
	}

	return ret;
}

static int mt7615_mcu_start_firmware(struct mt7615_dev *dev, u32 addr,
				     u32 option)
{
	struct {
		__le32 option;
		__le32 addr;
	} req = {
		.option = cpu_to_le32(option),
		.addr = cpu_to_le32(addr),
	};
	struct sk_buff *skb = mt7615_mcu_msg_alloc(&req, sizeof(req));

	return mt7615_mcu_msg_send(dev, skb, -MCU_CMD_FW_START_REQ,
				   MCU_Q_NA, MCU_S2D_H2N, NULL);
}

static int mt7615_mcu_restart(struct mt7615_dev *dev)
{
	struct sk_buff *skb = mt7615_mcu_msg_alloc(NULL, 0);

	return mt7615_mcu_msg_send(dev, skb, -MCU_CMD_RESTART_DL_REQ,
				   MCU_Q_NA, MCU_S2D_H2N, NULL);
}

static int mt7615_mcu_patch_sem_ctrl(struct mt7615_dev *dev, bool get)
{
	struct {
		__le32 operation;
	} req = {
		.operation = cpu_to_le32(get ? PATCH_SEM_GET :
					 PATCH_SEM_RELEASE),
	};
	struct event {
		u8 status;
		u8 reserved[3];
	} *resp;
	struct sk_buff *skb = mt7615_mcu_msg_alloc(&req, sizeof(req));
	struct sk_buff *skb_ret;
	int ret;

	ret = mt7615_mcu_msg_send(dev, skb, -MCU_CMD_PATCH_SEM_CONTROL,
				  MCU_Q_NA, MCU_S2D_H2N, &skb_ret);
	if (ret)
		goto out;

	resp = (struct event *)(skb_ret->data);
	ret = resp->status;
	dev_kfree_skb(skb_ret);

out:
	return ret;
}

static int mt7615_mcu_start_patch(struct mt7615_dev *dev)
{
	struct {
		u8 check_crc;
		u8 reserved[3];
	} req = {
		.check_crc = 0,
	};
	struct sk_buff *skb = mt7615_mcu_msg_alloc(&req, sizeof(req));

	return mt7615_mcu_msg_send(dev, skb, -MCU_CMD_PATCH_FINISH_REQ,
				   MCU_Q_NA, MCU_S2D_H2N, NULL);
}

static int mt7615_driver_own(struct mt7615_dev *dev)
{
	mt76_wr(dev, MT_CFG_LPCR_HOST, MT_CFG_LPCR_HOST_DRV_OWN);
	if (!mt76_poll_msec(dev, MT_CFG_LPCR_HOST,
			    MT_CFG_LPCR_HOST_FW_OWN, 0, 500)) {
		dev_err(dev->mt76.dev, "Timeout for driver own\n");
		return -EIO;
	}

	return 0;
}

static int mt7615_fw_own(struct mt7615_dev *dev)
{
	mt76_wr(dev, MT_CFG_LPCR_HOST, MT_CFG_LPCR_HOST_FW_OWN);

	return 0;
}

static int mt7615_load_patch(struct mt7615_dev *dev)
{
	const struct firmware *fw;
	const struct mt7615_patch_hdr *hdr;
	const char *firmware = MT7615_ROM_PATCH;
	int len, ret, sem;

	sem = mt7615_mcu_patch_sem_ctrl(dev, 1);
	switch (sem) {
	case PATCH_IS_DL:
		return 0;
	case PATCH_NOT_DL_SEM_SUCCESS:
		break;
	default:
		dev_err(dev->mt76.dev, "Failed to get patch semaphore\n");
		return -EAGAIN;
	}

	ret = request_firmware(&fw, firmware, dev->mt76.dev);
	if (ret)
		return ret;

	if (!fw || !fw->data || fw->size < sizeof(*hdr)) {
		dev_err(dev->mt76.dev, "Invalid firmware\n");
		ret = -EINVAL;
		goto out;
	}

	hdr = (const struct mt7615_patch_hdr *)(fw->data);

	dev_info(dev->mt76.dev, "HW/SW Version: 0x%x, Build Time: %.16s\n",
		 be32_to_cpu(hdr->hw_sw_ver), hdr->build_date);

	len = fw->size - sizeof(*hdr);

	ret = mt7615_mcu_init_download(dev, MCU_PATCH_ADDRESS, len,
				       DL_MODE_NEED_RSP);
	if (ret) {
		dev_err(dev->mt76.dev, "Download request failed\n");
		goto out;
	}

	ret = mt7615_mcu_send_firmware(dev, fw->data + sizeof(*hdr), len);
	if (ret) {
		dev_err(dev->mt76.dev, "Failed to send firmware to device\n");
		goto out;
	}

	ret = mt7615_mcu_start_patch(dev);
	if (ret) {
		dev_err(dev->mt76.dev, "Failed to start patch\n");
		goto out;
	}

	sem = mt7615_mcu_patch_sem_ctrl(dev, 0);
	switch (sem) {
	case PATCH_REL_SEM_SUCCESS:
		break;
	default:
		ret = -EAGAIN;
		dev_err(dev->mt76.dev, "Failed to release patch semaphore\n");
		break;
	}

out:
	release_firmware(fw);

	return ret;
}

static u32 gen_dl_mode(u8 feature_set, bool is_cr4)
{
	u32 ret = 0;

	ret |= (feature_set & FW_FEATURE_SET_ENCRYPT) ?
	       (DL_MODE_ENCRYPT | DL_MODE_RESET_SEC_IV) : 0;
	ret |= FIELD_PREP(DL_MODE_KEY_IDX,
			  FIELD_GET(FW_FEATURE_SET_KEY_IDX, feature_set));
	ret |= DL_MODE_NEED_RSP;
	ret |= is_cr4 ? DL_MODE_WORKING_PDA_CR4 : 0;

	return ret;
}

static int mt7615_load_ram(struct mt7615_dev *dev)
{
	const struct firmware *fw;
	const struct mt7615_fw_trailer *hdr;
	const char *n9_firmware = MT7615_FIRMWARE_N9;
	const char *cr4_firmware = MT7615_FIRMWARE_CR4;
	u32 n9_ilm_addr, offset;
	int i, ret;

	ret = request_firmware(&fw, n9_firmware, dev->mt76.dev);
	if (ret)
		return ret;

	if (!fw || !fw->data || fw->size < N9_REGION_NUM * sizeof(*hdr)) {
		dev_err(dev->mt76.dev, "Invalid firmware\n");
		ret = -EINVAL;
		goto out;
	}

	hdr = (const struct mt7615_fw_trailer *)(fw->data + fw->size -
					N9_REGION_NUM * sizeof(*hdr));

	dev_info(dev->mt76.dev, "N9 Firmware Version: %.10s, Build Time: %.15s\n",
		 hdr->fw_ver, hdr->build_date);

	n9_ilm_addr = le32_to_cpu(hdr->addr);

	for (offset = 0, i = 0; i < N9_REGION_NUM; i++) {
		u32 len, addr, mode;

		len = le32_to_cpu(hdr[i].len) + IMG_CRC_LEN;
		addr = le32_to_cpu(hdr[i].addr);
		mode = gen_dl_mode(hdr[i].feature_set, false);

		ret = mt7615_mcu_init_download(dev, addr, len, mode);
		if (ret) {
			dev_err(dev->mt76.dev, "Download request failed\n");
			goto out;
		}

		ret = mt7615_mcu_send_firmware(dev, fw->data + offset, len);
		if (ret) {
			dev_err(dev->mt76.dev, "Failed to send firmware to device\n");
			goto out;
		}

		offset += len;
	}

	ret = mt7615_mcu_start_firmware(dev, n9_ilm_addr, FW_START_OVERRIDE);
	if (ret) {
		dev_err(dev->mt76.dev, "Failed to start N9 firmware\n");
		goto out;
	}

	release_firmware(fw);

	ret = request_firmware(&fw, cr4_firmware, dev->mt76.dev);
	if (ret)
		return ret;

	if (!fw || !fw->data || fw->size < CR4_REGION_NUM * sizeof(*hdr)) {
		dev_err(dev->mt76.dev, "Invalid firmware\n");
		ret = -EINVAL;
		goto out;
	}

	hdr = (const struct mt7615_fw_trailer *)(fw->data + fw->size -
					CR4_REGION_NUM * sizeof(*hdr));

	dev_info(dev->mt76.dev, "CR4 Firmware Version: %.10s, Build Time: %.15s\n",
		 hdr->fw_ver, hdr->build_date);

	for (offset = 0, i = 0; i < CR4_REGION_NUM; i++) {
		u32 len, addr, mode;

		len = le32_to_cpu(hdr[i].len) + IMG_CRC_LEN;
		addr = le32_to_cpu(hdr[i].addr);
		mode = gen_dl_mode(hdr[i].feature_set, true);

		ret = mt7615_mcu_init_download(dev, addr, len, mode);
		if (ret) {
			dev_err(dev->mt76.dev, "Download request failed\n");
			goto out;
		}

		ret = mt7615_mcu_send_firmware(dev, fw->data + offset, len);
		if (ret) {
			dev_err(dev->mt76.dev, "Failed to send firmware to device\n");
			goto out;
		}

		offset += len;
	}

	ret = mt7615_mcu_start_firmware(dev, 0, FW_START_WORKING_PDA_CR4);
	if (ret) {
		dev_err(dev->mt76.dev, "Failed to start CR4 firmware\n");
		goto out;
	}

out:
	release_firmware(fw);

	return ret;
}

static int mt7615_load_firmware(struct mt7615_dev *dev)
{
	int ret;
	u32 val;

	val = mt76_get_field(dev, MT_TOP_MISC2, MT_TOP_MISC2_FW_STATE);

	if (val != FW_STATE_FW_DOWNLOAD) {
		dev_err(dev->mt76.dev, "Firmware is not ready for download\n");
		ret = -EIO;
		goto out;
	}

	ret = mt7615_load_patch(dev);
	if (ret)
		goto out;

	ret = mt7615_load_ram(dev);
	if (ret)
		goto out;

	if (!mt76_poll_msec(dev, MT_TOP_MISC2, MT_TOP_MISC2_FW_STATE,
			    FIELD_PREP(MT_TOP_MISC2_FW_STATE,
				       FW_STATE_CR4_RDY), 500)) {
		dev_err(dev->mt76.dev, "Timeout for initializing firmware\n");
		ret = -EIO;
		goto out;
	}

	dev_dbg(dev->mt76.dev, "Firmware init done\n");

out:
	return ret;
}

int mt7615_mcu_init(struct mt7615_dev *dev)
{
	int ret;

	ret = mt7615_driver_own(dev);
	if (ret)
		goto out;

	ret = mt7615_load_firmware(dev);

out:
	return ret;
}

void mt7615_mcu_exit(struct mt7615_dev *dev)
{
	struct sk_buff *skb;

	mt7615_mcu_restart(dev);
	mt7615_fw_own(dev);

	while ((skb = skb_dequeue(&dev->mt76.mmio.mcu.res_q)) != NULL)
		dev_kfree_skb(skb);
}

int mt7615_mcu_set_eeprom(struct mt7615_dev *dev)
{
	struct req_data {
		u8 val;
	} __packed;
	struct {
		u8 buffer_mode;
		u8 pad;
		u16 len;
	} __packed req_hdr = {
		.buffer_mode = 1,
		.len = __MT_EE_MAX - MT_EE_NIC_CONF_0,
	};
	struct sk_buff *skb;
	struct req_data *data;
	const int size = (__MT_EE_MAX - MT_EE_NIC_CONF_0) *
			 sizeof(struct req_data);
	u8 *eep = (u8 *)dev->mt76.eeprom.data;
	u16 off;

	skb = mt7615_mcu_msg_alloc(NULL, size + sizeof(req_hdr));
	memcpy(skb_put(skb, sizeof(req_hdr)), &req_hdr, sizeof(req_hdr));
	data = (struct req_data *)skb_put(skb, size);
	memset(data, 0, size);

	for (off = MT_EE_NIC_CONF_0; off < __MT_EE_MAX; off++)
		data[off - MT_EE_NIC_CONF_0].val = eep[off];

	return mt7615_mcu_msg_send(dev, skb, MCU_EXT_CMD_EFUSE_BUFFER_MODE,
				   MCU_Q_SET, MCU_S2D_H2N, NULL);
}

int mt7615_mcu_init_mac(struct mt7615_dev *dev)
{
	struct {
		u8 enable;
		u8 band;
		u8 rsv[2];
	} __packed req = {
		.enable = 1,
		.band = 0,
	};
	struct sk_buff *skb = mt7615_mcu_msg_alloc(&req, sizeof(req));

	return mt7615_mcu_msg_send(dev, skb, MCU_EXT_CMD_MAC_INIT_CTRL,
				   MCU_Q_SET, MCU_S2D_H2N, NULL);
}

int mt7615_mcu_ctrl_pm_state(struct mt7615_dev *dev, int enter)
{
#define ENTER_PM_STATE	1
#define EXIT_PM_STATE	2
	struct {
		u8 pm_number;
		u8 pm_state;
		u8 bssid[ETH_ALEN];
		u8 dtim_period;
		u8 wlan_idx;
		__le16 bcn_interval;
		__le32 aid;
		__le32 rx_filter;
		u8 band_idx;
		u8 rsv[3];
		__le32 feature;
		u8 omac_idx;
		u8 wmm_idx;
		u8 bcn_loss_cnt;
		u8 bcn_sp_duration;
	} __packed req = {
		.pm_number = 5,
		.pm_state = (enter) ? ENTER_PM_STATE : EXIT_PM_STATE,
		.band_idx = 0,
	};
	struct sk_buff *skb = mt7615_mcu_msg_alloc(&req, sizeof(req));

	return mt7615_mcu_msg_send(dev, skb, MCU_EXT_CMD_PM_STATE_CTRL,
				   MCU_Q_SET, MCU_S2D_H2N, NULL);
}
