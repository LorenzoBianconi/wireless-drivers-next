/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2019 MediaTek Inc. */

#ifndef __MT7615_MCU_H
#define __MT7615_MCU_H

struct mt7615_mcu_txd {
	__le32 txd[8];

	__le16 len;
	__le16 pq_id;

	u8 cid;
	u8 pkt_type;
	u8 set_query; /* FW don't care */
	u8 seq;

	u8 uc_d2b0_rev;
	u8 ext_cid;
	u8 s2d_index;
	u8 ext_cid_ack;

	u32 reserved[5];
} __packed __aligned(4);

struct mt7615_mcu_rxd {
	__le32 rxd[4];

	__le16 len;
	__le16 pkt_type_id;

	u8 eid;
	u8 seq;
	__le16 __rsv;

	u8 ext_eid;
	u8 __rsv1[2];
	u8 s2d_index;
};

#define MCU_PQ_ID(p, q)		(((p) << 15) | ((q) << 10))
#define MCU_PKT_ID		0xa0

enum {
	MCU_Q_QUERY,
	MCU_Q_SET,
	MCU_Q_RESERVED,
	MCU_Q_NA
};

enum {
	MCU_S2D_H2N,
	MCU_S2D_C2N,
	MCU_S2D_H2C,
	MCU_S2D_H2CN
};

enum {
	MCU_CMD_TARGET_ADDRESS_LEN_REQ = 0x01,
	MCU_CMD_FW_START_REQ = 0x02,
	MCU_CMD_INIT_ACCESS_REG = 0x3,
	MCU_CMD_PATCH_START_REQ = 0x05,
	MCU_CMD_PATCH_FINISH_REQ = 0x07,
	MCU_CMD_PATCH_SEM_CONTROL = 0x10,
	MCU_CMD_EXT_CID = 0xED,
	MCU_CMD_FW_SCATTER = 0xEE,
	MCU_CMD_RESTART_DL_REQ = 0xEF,
};

enum {
	MCU_EXT_CMD_PM_STATE_CTRL = 0x07,
	MCU_EXT_CMD_CHANNEL_SWITCH = 0x08,
	MCU_EXT_CMD_EFUSE_BUFFER_MODE = 0x21,
	MCU_EXT_CMD_MAC_INIT_CTRL = 0x46
};

enum {
	PATCH_SEM_RELEASE = 0x0,
	PATCH_SEM_GET	  = 0x1
};

enum {
	PATCH_NOT_DL_SEM_FAIL	 = 0x0,
	PATCH_IS_DL		 = 0x1,
	PATCH_NOT_DL_SEM_SUCCESS = 0x2,
	PATCH_REL_SEM_SUCCESS	 = 0x3
};

enum {
	FW_STATE_INITIAL          = 0,
	FW_STATE_FW_DOWNLOAD      = 1,
	FW_STATE_NORMAL_OPERATION = 2,
	FW_STATE_NORMAL_TRX       = 3,
	FW_STATE_CR4_RDY          = 7
};

#endif
