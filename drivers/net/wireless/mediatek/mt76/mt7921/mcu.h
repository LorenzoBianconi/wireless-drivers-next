/* SPDX-License-Identifier: ISC */
/* Copyright (C) 2020 MediaTek Inc. */

#ifndef __MT7921_MCU_H
#define __MT7921_MCU_H

struct mt7921_mcu_txd {
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

/**
 * struct mt7921_uni_txd - mcu command descriptor for firmware v3
 * @txd: hardware descriptor
 * @len: total length not including txd
 * @cid: command identifier
 * @pkt_type: must be 0xa0 (cmd packet by long format)
 * @frag_n: fragment number
 * @seq: sequence number
 * @checksum: 0 mean there is no checksum
 * @s2d_index: index for command source and destination
 *  Definition              | value | note
 *  CMD_S2D_IDX_H2N         | 0x00  | command from HOST to WM
 *  CMD_S2D_IDX_C2N         | 0x01  | command from WA to WM
 *  CMD_S2D_IDX_H2C         | 0x02  | command from HOST to WA
 *  CMD_S2D_IDX_H2N_AND_H2C | 0x03  | command from HOST to WA and WM
 *
 * @option: command option
 *  BIT[0]: UNI_CMD_OPT_BIT_ACK
 *          set to 1 to request a fw reply
 *          if UNI_CMD_OPT_BIT_0_ACK is set and UNI_CMD_OPT_BIT_2_SET_QUERY
 *          is set, mcu firmware will send response event EID = 0x01
 *          (UNI_EVENT_ID_CMD_RESULT) to the host.
 *  BIT[1]: UNI_CMD_OPT_BIT_UNI_CMD
 *          0: original command
 *          1: unified command
 *  BIT[2]: UNI_CMD_OPT_BIT_SET_QUERY
 *          0: QUERY command
 *          1: SET command
 */
struct mt7921_uni_txd {
	__le32 txd[8];

	/* DW1 */
	__le16 len;
	__le16 cid;

	/* DW2 */
	u8 reserved;
	u8 pkt_type;
	u8 frag_n;
	u8 seq;

	/* DW3 */
	__le16 checksum;
	u8 s2d_index;
	u8 option;

	/* DW4 */
	u8 reserved2[4];
} __packed __aligned(4);

/* event table */
enum {
	MCU_EVENT_TARGET_ADDRESS_LEN = 0x01,
	MCU_EVENT_FW_START = 0x01,
	MCU_EVENT_GENERIC = 0x01,
	MCU_EVENT_ACCESS_REG = 0x02,
	MCU_EVENT_MT_PATCH_SEM = 0x04,
	MCU_EVENT_REG_ACCESS = 0x05,
	MCU_EVENT_SCAN_DONE = 0x0d,
	MCU_EVENT_ROC = 0x10,
	MCU_EVENT_BSS_ABSENCE  = 0x11,
	MCU_EVENT_BSS_BEACON_LOSS = 0x13,
	MCU_EVENT_CH_PRIVILEGE = 0x18,
	MCU_EVENT_SCHED_SCAN_DONE = 0x23,
	MCU_EVENT_EXT = 0xed,
	MCU_EVENT_RESTART_DL = 0xef,
};

/* ext event table */
enum {
	MCU_EXT_EVENT_RATE_REPORT = 0x87,
};

enum {
	MCU_ATE_SET_TRX = 0x1,
	MCU_ATE_SET_FREQ_OFFSET = 0xa,
};

struct mt7921_mcu_rxd {
	__le32 rxd[6];

	__le16 len;
	__le16 pkt_type_id;

	u8 eid;
	u8 seq;
	__le16 __rsv;

	u8 ext_eid;
	u8 __rsv1[2];
	u8 s2d_index;
};

struct mt7921_mcu_eeprom_info {
	__le32 addr;
	__le32 valid;
	u8 data[16];
} __packed;

struct mt7921_mcu_ra_info {
	struct mt7921_mcu_rxd rxd;

	__le32 event_id;
	__le16 wlan_idx;
	__le16 ru_idx;
	__le16 direction;
	__le16 dump_group;

	__le32 suggest_rate;
	__le32 min_rate;	/* for dynamic sounding */
	__le32 max_rate;	/* for dynamic sounding */
	__le32 init_rate_down_rate;

	__le16 curr_rate;
	__le16 init_rate_down_total;
	__le16 init_rate_down_succ;
	__le16 success;
	__le16 attempts;

	__le16 prev_rate;
	__le16 prob_up_rate;
	u8 no_rate_up_cnt;
	u8 ppdu_cnt;
	u8 gi;

	u8 try_up_fail;
	u8 try_up_total;
	u8 suggest_wf;
	u8 try_up_check;
	u8 prob_up_period;
	u8 prob_down_pending;
} __packed;


struct mt7921_mcu_phy_rx_info {
	u8 category;
	u8 rate;
	u8 mode;
	u8 nsts;
	u8 gi;
	u8 coding;
	u8 stbc;
	u8 bw;
};

#define MT_RA_RATE_NSS			GENMASK(8, 6)
#define MT_RA_RATE_MCS			GENMASK(3, 0)
#define MT_RA_RATE_TX_MODE		GENMASK(12, 9)
#define MT_RA_RATE_DCM_EN		BIT(4)
#define MT_RA_RATE_BW			GENMASK(14, 13)

#define MCU_PQ_ID(p, q)			(((p) << 15) | ((q) << 10))
#define MCU_PKT_ID			0xa0

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

#define MCU_FW_PREFIX		BIT(31)
#define MCU_UNI_PREFIX		BIT(30)
#define MCU_CE_PREFIX		BIT(29)
#define MCU_QUERY_PREFIX	BIT(28)
#define MCU_CMD_MASK		~(MCU_FW_PREFIX | MCU_UNI_PREFIX |	\
				  MCU_CE_PREFIX | MCU_QUERY_PREFIX)

#define MCU_QUERY_MASK		BIT(16)

enum {
	MCU_CMD_TARGET_ADDRESS_LEN_REQ = MCU_FW_PREFIX | 0x01,
	MCU_CMD_FW_START_REQ = MCU_FW_PREFIX | 0x02,
	MCU_CMD_INIT_ACCESS_REG = 0x3,
	MCU_CMD_NIC_POWER_CTRL = MCU_FW_PREFIX | 0x4,
	MCU_CMD_PATCH_START_REQ = MCU_FW_PREFIX | 0x05,
	MCU_CMD_PATCH_FINISH_REQ = MCU_FW_PREFIX | 0x07,
	MCU_CMD_PATCH_SEM_CONTROL = MCU_FW_PREFIX | 0x10,
	MCU_CMD_BT_SEM_CONTROL = MCU_FW_PREFIX | 0x11,
	MCU_CMD_EXT_CID = 0xED,
	MCU_CMD_FW_SCATTER = MCU_FW_PREFIX | 0xEE,
	MCU_CMD_RESTART_DL_REQ = MCU_FW_PREFIX | 0xEF,
};

enum {
	MCU_EXT_CMD_EFUSE_ACCESS = 0x01,
	MCU_EXT_CMD_CHANNEL_SWITCH = 0x08,
	MCU_EXT_CMD_FW_LOG_2_HOST = 0x13,
	MCU_EXT_CMD_EFUSE_BUFFER_MODE = 0x21,
	MCU_EXT_CMD_EDCA_UPDATE = 0x27,
	MCU_EXT_CMD_THERMAL_CTRL = 0x2c,
	MCU_EXT_CMD_WTBL_UPDATE = 0x32,
	MCU_EXT_CMD_PROTECT_CTRL = 0x3e,
	MCU_EXT_CMD_MAC_INIT_CTRL = 0x46,
	MCU_EXT_CMD_RX_HDR_TRANS = 0x47,
	MCU_EXT_CMD_SET_RX_PATH = 0x4e,
	MCU_EXT_CMD_TX_POWER_FEATURE_CTRL = 0x58,
	MCU_EXT_CMD_MWDS_SUPPORT = 0x80,
	MCU_EXT_CMD_RATE_CTRL = 0x87,
	MCU_EXT_CMD_FW_DBG_CTRL = 0x95,
	MCU_EXT_CMD_PHY_STAT_INFO = 0xad,
};

enum {
	MCU_UNI_CMD_DEV_INFO_UPDATE = MCU_UNI_PREFIX | 0x01,
	MCU_UNI_CMD_BSS_INFO_UPDATE = MCU_UNI_PREFIX | 0x02,
	MCU_UNI_CMD_STA_REC_UPDATE = MCU_UNI_PREFIX | 0x03,
	MCU_UNI_CMD_SUSPEND = MCU_UNI_PREFIX | 0x05,
	MCU_UNI_CMD_OFFLOAD = MCU_UNI_PREFIX | 0x06,
	MCU_UNI_CMD_HIF_CTRL = MCU_UNI_PREFIX | 0x07,
};

struct mt7921_mcu_uni_event {
	u8 cid;
	u8 pad[3];
	__le32 status; /* 0: success, others: fail */
} __packed;

/* offload mcu commands */
enum {
	MCU_CMD_START_HW_SCAN = MCU_CE_PREFIX | 0x03,
	MCU_CMD_SET_PS_PROFILE = MCU_CE_PREFIX | 0x05,
	MCU_CMD_SET_CHAN_DOMAIN = MCU_CE_PREFIX | 0x0f,
	MCU_CMD_SET_BSS_CONNECTED = MCU_CE_PREFIX | 0x16,
	MCU_CMD_SET_BSS_ABORT = MCU_CE_PREFIX | 0x17,
	MCU_CMD_CANCEL_HW_SCAN = MCU_CE_PREFIX | 0x1b,
	MCU_CMD_SET_ROC = MCU_CE_PREFIX | 0x1c,
	MCU_CMD_SET_P2P_OPPPS = MCU_CE_PREFIX | 0x33,
	MCU_CMD_SCHED_SCAN_ENABLE = MCU_CE_PREFIX | 0x61,
	MCU_CMD_SCHED_SCAN_REQ = MCU_CE_PREFIX | 0x62,
	MCU_CMD_REG_WRITE = MCU_CE_PREFIX | 0xc0,
	MCU_CMD_REG_READ = MCU_CE_PREFIX | MCU_QUERY_MASK | 0xc0,
};

#define MCU_CMD_ACK		BIT(0)
#define MCU_CMD_UNI		BIT(1)
#define MCU_CMD_QUERY		BIT(2)

#define MCU_CMD_UNI_EXT_ACK	(MCU_CMD_ACK | MCU_CMD_UNI | MCU_CMD_QUERY)

enum {
	UNI_BSS_INFO_BASIC = 0,
	UNI_BSS_INFO_RLM = 2,
	UNI_BSS_INFO_HE_BASIC = 5,
	UNI_BSS_INFO_BCN_CONTENT = 7,
	UNI_BSS_INFO_QBSS = 15,
	UNI_BSS_INFO_UAPSD = 19,
};

enum {
	UNI_SUSPEND_MODE_SETTING,
	UNI_SUSPEND_WOW_CTRL,
	UNI_SUSPEND_WOW_GPIO_PARAM,
	UNI_SUSPEND_WOW_WAKEUP_PORT,
	UNI_SUSPEND_WOW_PATTERN,
};

enum {
	UNI_OFFLOAD_OFFLOAD_ARP,
	UNI_OFFLOAD_OFFLOAD_ND,
	UNI_OFFLOAD_OFFLOAD_GTK_REKEY,
	UNI_OFFLOAD_OFFLOAD_BMC_RPY_DETECT,
};


enum {
	PATCH_SEM_RELEASE,
	PATCH_SEM_GET
};

enum {
	PATCH_NOT_DL_SEM_FAIL,
	PATCH_IS_DL,
	PATCH_NOT_DL_SEM_SUCCESS,
	PATCH_REL_SEM_SUCCESS
};

enum {
	FW_STATE_INITIAL,
	FW_STATE_FW_DOWNLOAD,
	FW_STATE_NORMAL_OPERATION,
	FW_STATE_NORMAL_TRX,
	FW_STATE_WACPU_RDY        = 7
};

enum {
	EE_MODE_EFUSE,
	EE_MODE_BUFFER,
};

enum {
	EE_FORMAT_BIN,
	EE_FORMAT_WHOLE,
	EE_FORMAT_MULTIPLE,
};

enum {
	MCU_PHY_STATE_TX_RATE,
	MCU_PHY_STATE_RX_RATE,
	MCU_PHY_STATE_RSSI,
	MCU_PHY_STATE_CONTENTION_RX_RATE,
	MCU_PHY_STATE_OFDMLQ_CNINFO,
};

#define STA_TYPE_STA			BIT(0)
#define STA_TYPE_AP			BIT(1)
#define STA_TYPE_ADHOC			BIT(2)
#define STA_TYPE_WDS			BIT(4)
#define STA_TYPE_BC			BIT(5)

#define NETWORK_INFRA			BIT(16)
#define NETWORK_P2P			BIT(17)
#define NETWORK_IBSS			BIT(18)
#define NETWORK_WDS			BIT(21)

#define CONNECTION_INFRA_STA		(STA_TYPE_STA | NETWORK_INFRA)
#define CONNECTION_INFRA_AP		(STA_TYPE_AP | NETWORK_INFRA)
#define CONNECTION_P2P_GC		(STA_TYPE_STA | NETWORK_P2P)
#define CONNECTION_P2P_GO		(STA_TYPE_AP | NETWORK_P2P)
#define CONNECTION_IBSS_ADHOC		(STA_TYPE_ADHOC | NETWORK_IBSS)
#define CONNECTION_WDS			(STA_TYPE_WDS | NETWORK_WDS)
#define CONNECTION_INFRA_BC		(STA_TYPE_BC | NETWORK_INFRA)

#define CONN_STATE_DISCONNECT		0
#define CONN_STATE_CONNECT		1
#define CONN_STATE_PORT_SECURE		2

enum {
	DEV_INFO_ACTIVE,
	DEV_INFO_MAX_NUM
};

enum {
	SCS_SEND_DATA,
	SCS_SET_MANUAL_PD_TH,
	SCS_CONFIG,
	SCS_ENABLE,
	SCS_SHOW_INFO,
	SCS_GET_GLO_ADDR,
	SCS_GET_GLO_ADDR_EVENT,
};

enum {
	CMD_CBW_20MHZ = IEEE80211_STA_RX_BW_20,
	CMD_CBW_40MHZ = IEEE80211_STA_RX_BW_40,
	CMD_CBW_80MHZ = IEEE80211_STA_RX_BW_80,
	CMD_CBW_160MHZ = IEEE80211_STA_RX_BW_160,
	CMD_CBW_10MHZ,
	CMD_CBW_5MHZ,
	CMD_CBW_8080MHZ,

	CMD_HE_MCS_BW80 = 0,
	CMD_HE_MCS_BW160,
	CMD_HE_MCS_BW8080,
	CMD_HE_MCS_BW_NUM
};

struct tlv {
	__le16 tag;
	__le16 len;
} __packed;

struct bss_info_omac {
	__le16 tag;
	__le16 len;
	u8 hw_bss_idx;
	u8 omac_idx;
	u8 band_idx;
	u8 rsv0;
	__le32 conn_type;
	u32 rsv1;
} __packed;

struct bss_info_basic {
	__le16 tag;
	__le16 len;
	__le32 network_type;
	u8 active;
	u8 rsv0;
	__le16 bcn_interval;
	u8 bssid[ETH_ALEN];
	u8 wmm_idx;
	u8 dtim_period;
	u8 bmc_wcid_lo;
	u8 cipher;
	u8 phy_mode;
	u8 max_bssid;	/* max BSSID. range: 1 ~ 8, 0: MBSSID disabled */
	u8 non_tx_bssid;/* non-transmitted BSSID, 0: transmitted BSSID */
	u8 bmc_wcid_hi;	/* high Byte and version */
	u8 rsv[2];
} __packed;

struct bss_info_rf_ch {
	__le16 tag;
	__le16 len;
	u8 pri_ch;
	u8 center_ch0;
	u8 center_ch1;
	u8 bw;
	u8 he_ru26_block;	/* 1: don't send HETB in RU26, 0: allow */
	u8 he_all_disable;	/* 1: disallow all HETB, 0: allow */
	u8 rsv[2];
} __packed;

struct bss_info_ext_bss {
	__le16 tag;
	__le16 len;
	__le32 mbss_tsf_offset; /* in unit of us */
	u8 rsv[8];
} __packed;

struct bss_info_bmc_rate {
	__le16 tag;
	__le16 len;
	__le16 bc_trans;
	__le16 mc_trans;
	u8 short_preamble;
	u8 rsv[7];
} __packed;

struct bss_info_ra {
	__le16 tag;
	__le16 len;
	u8 op_mode;
	u8 adhoc_en;
	u8 short_preamble;
	u8 tx_streams;
	u8 rx_streams;
	u8 algo;
	u8 force_sgi;
	u8 force_gf;
	u8 ht_mode;
	u8 has_20_sta;		/* Check if any sta support GF. */
	u8 bss_width_trigger_events;
	u8 vht_nss_cap;
	u8 vht_bw_signal;	/* not use */
	u8 vht_force_sgi;	/* not use */
	u8 se_off;
	u8 antenna_idx;
	u8 train_up_rule;
	u8 rsv[3];
	unsigned short train_up_high_thres;
	short train_up_rule_rssi;
	unsigned short low_traffic_thres;
	__le16 max_phyrate;
	__le32 phy_cap;
	__le32 interval;
	__le32 fast_interval;
} __packed;

struct bss_info_hw_amsdu {
	__le16 tag;
	__le16 len;
	__le32 cmp_bitmap_0;
	__le32 cmp_bitmap_1;
	__le16 trig_thres;
	u8 enable;
	u8 rsv;
} __packed;

struct bss_info_he {
	__le16 tag;
	__le16 len;
	u8 he_pe_duration;
	u8 vht_op_info_present;
	__le16 he_rts_thres;
	__le16 max_nss_mcs[CMD_HE_MCS_BW_NUM];
	u8 rsv[6];
} __packed;

struct bss_info_uni_he {
	__le16 tag;
	__le16 len;
	__le16 he_rts_thres;
	u8 he_pe_duration;
	u8 su_disable;
	__le16 max_nss_mcs[CMD_HE_MCS_BW_NUM];
	u8 rsv[2];
} __packed;

struct bss_info_bcn {
	__le16 tag;
	__le16 len;
	u8 ver;
	u8 enable;
	__le16 sub_ntlv;
} __packed __aligned(4);

struct bss_info_bcn_csa {
	__le16 tag;
	__le16 len;
	u8 cnt;
	u8 rsv[3];
} __packed __aligned(4);

struct bss_info_bcn_bcc {
	__le16 tag;
	__le16 len;
	u8 cnt;
	u8 rsv[3];
} __packed __aligned(4);

struct bss_info_bcn_mbss {
#define MAX_BEACON_NUM	32
	__le16 tag;
	__le16 len;
	__le32 bitmap;
	__le16 offset[MAX_BEACON_NUM];
	u8 rsv[8];
} __packed __aligned(4);

struct bss_info_bcn_cont {
	__le16 tag;
	__le16 len;
	__le16 tim_ofs;
	__le16 csa_ofs;
	__le16 bcc_ofs;
	__le16 pkt_len;
} __packed __aligned(4);

enum {
	BSS_INFO_BCN_CSA,
	BSS_INFO_BCN_BCC,
	BSS_INFO_BCN_MBSSID,
	BSS_INFO_BCN_CONTENT,
	BSS_INFO_BCN_MAX
};

enum {
	BSS_INFO_OMAC,
	BSS_INFO_BASIC,
	BSS_INFO_RF_CH,		/* optional, for BT/LTE coex */
	BSS_INFO_PM,		/* sta only */
	BSS_INFO_UAPSD,		/* sta only */
	BSS_INFO_ROAM_DETECT,	/* obsoleted */
	BSS_INFO_LQ_RM,		/* obsoleted */
	BSS_INFO_EXT_BSS,
	BSS_INFO_BMC_RATE,	/* for bmc rate control in CR4 */
	BSS_INFO_SYNC_MODE,	/* obsoleted */
	BSS_INFO_RA,
	BSS_INFO_HW_AMSDU,
	BSS_INFO_BSS_COLOR,
	BSS_INFO_HE_BASIC,
	BSS_INFO_PROTECT_INFO,
	BSS_INFO_OFFLOAD,
	BSS_INFO_11V_MBSSID,
	BSS_INFO_MAX_NUM
};

enum {
	WTBL_RESET_AND_SET = 1,
	WTBL_SET,
	WTBL_QUERY,
	WTBL_RESET_ALL
};

struct wtbl_req_hdr {
	u8 wlan_idx_lo;
	u8 operation;
	__le16 tlv_num;
	u8 wlan_idx_hi;
	u8 rsv[3];
} __packed;

struct wtbl_generic {
	__le16 tag;
	__le16 len;
	u8 peer_addr[ETH_ALEN];
	u8 muar_idx;
	u8 skip_tx;
	u8 cf_ack;
	u8 qos;
	u8 mesh;
	u8 adm;
	__le16 partial_aid;
	u8 baf_en;
	u8 aad_om;
} __packed;

struct wtbl_rx {
	__le16 tag;
	__le16 len;
	u8 rcid;
	u8 rca1;
	u8 rca2;
	u8 rv;
	u8 rsv[4];
} __packed;

struct wtbl_ht {
	__le16 tag;
	__le16 len;
	u8 ht;
	u8 ldpc;
	u8 af;
	u8 mm;
	u8 rsv[4];
} __packed;

struct wtbl_vht {
	__le16 tag;
	__le16 len;
	u8 ldpc;
	u8 dyn_bw;
	u8 vht;
	u8 txop_ps;
	u8 rsv[4];
} __packed;

struct wtbl_hdr_trans {
	__le16 tag;
	__le16 len;
	u8 to_ds;
	u8 from_ds;
	u8 no_rx_trans;
	u8 _rsv;
};

enum {
	MT_BA_TYPE_INVALID,
	MT_BA_TYPE_ORIGINATOR,
	MT_BA_TYPE_RECIPIENT
};

enum {
	RST_BA_MAC_TID_MATCH,
	RST_BA_MAC_MATCH,
	RST_BA_NO_MATCH
};

struct wtbl_ba {
	__le16 tag;
	__le16 len;
	/* common */
	u8 tid;
	u8 ba_type;
	u8 rsv0[2];
	/* originator only */
	__le16 sn;
	u8 ba_en;
	u8 ba_winsize_idx;
	__le16 ba_winsize;
	/* recipient only */
	u8 peer_addr[ETH_ALEN];
	u8 rst_ba_tid;
	u8 rst_ba_sel;
	u8 rst_ba_sb;
	u8 band_idx;
	u8 rsv1[4];
} __packed;

struct wtbl_smps {
	__le16 tag;
	__le16 len;
	u8 smps;
	u8 rsv[3];
} __packed;

enum {
	WTBL_GENERIC,
	WTBL_RX,
	WTBL_HT,
	WTBL_VHT,
	WTBL_PEER_PS,		/* not used */
	WTBL_TX_PS,
	WTBL_HDR_TRANS,
	WTBL_SEC_KEY,
	WTBL_BA,
	WTBL_RDG,		/* obsoleted */
	WTBL_PROTECT,		/* not used */
	WTBL_CLEAR,		/* not used */
	WTBL_BF,
	WTBL_SMPS,
	WTBL_RAW_DATA,		/* debug only */
	WTBL_PN,
	WTBL_SPE,
	WTBL_MAX_NUM
};

struct sta_ntlv_hdr {
	u8 rsv[2];
	__le16 tlv_num;
} __packed;

struct sta_req_hdr {
	u8 bss_idx;
	u8 wlan_idx_lo;
	__le16 tlv_num;
	u8 is_tlv_append;
	u8 muar_idx;
	u8 wlan_idx_hi;
	u8 rsv;
} __packed;

struct sta_rec_basic {
	__le16 tag;
	__le16 len;
	__le32 conn_type;
	u8 conn_state;
	u8 qos;
	__le16 aid;
	u8 peer_addr[ETH_ALEN];
	__le16 extra_info;
} __packed;

struct sta_rec_ht {
	__le16 tag;
	__le16 len;
	__le16 ht_cap;
	u16 rsv;
} __packed;

struct sta_rec_vht {
	__le16 tag;
	__le16 len;
	__le32 vht_cap;
	__le16 vht_rx_mcs_map;
	__le16 vht_tx_mcs_map;
	u8 rts_bw_sig;
	u8 rsv[3];
} __packed;

struct sta_rec_uapsd {
	__le16 tag;
	__le16 len;
	u8 dac_map;
	u8 tac_map;
	u8 max_sp;
	u8 rsv0;
	__le16 listen_interval;
	u8 rsv1[2];
} __packed;

struct sta_rec_muru {
	__le16 tag;
	__le16 len;

	struct {
		bool ofdma_dl_en;
		bool ofdma_ul_en;
		bool mimo_dl_en;
		bool mimo_ul_en;
		u8 rsv[4];
	} cfg;

	struct {
		u8 punc_pream_rx;
		bool he_20m_in_40m_2g;
		bool he_20m_in_160m;
		bool he_80m_in_160m;
		bool lt16_sigb;
		bool rx_su_comp_sigb;
		bool rx_su_non_comp_sigb;
		u8 rsv;
	} ofdma_dl;

	struct {
		u8 t_frame_dur;
		u8 mu_cascading;
		u8 uo_ra;
		u8 he_2x996_tone;
		u8 rx_t_frame_11ac;
		u8 rsv[3];
	} ofdma_ul;

	struct {
		bool vht_mu_bfee;
		bool partial_bw_dl_mimo;
		u8 rsv[2];
	} mimo_dl;

	struct {
		bool full_ul_mimo;
		bool partial_ul_mimo;
		u8 rsv[2];
	} mimo_ul;
} __packed;

struct sta_rec_he {
	__le16 tag;
	__le16 len;

	__le32 he_cap;

	u8 t_frame_dur;
	u8 max_ampdu_exp;
	u8 bw_set;
	u8 device_class;
	u8 dcm_tx_mode;
	u8 dcm_tx_max_nss;
	u8 dcm_rx_mode;
	u8 dcm_rx_max_nss;
	u8 dcm_max_ru;
	u8 punc_pream_rx;
	u8 pkt_ext;
	u8 rsv1;

	__le16 max_nss_mcs[CMD_HE_MCS_BW_NUM];

	u8 rsv2[2];
} __packed;

struct sta_rec_ba {
	__le16 tag;
	__le16 len;
	u8 tid;
	u8 ba_type;
	u8 amsdu;
	u8 ba_en;
	__le16 ssn;
	__le16 winsize;
} __packed;

struct sta_rec_amsdu {
	__le16 tag;
	__le16 len;
	u8 max_amsdu_num;
	u8 max_mpdu_size;
	u8 amsdu_en;
	u8 rsv;
} __packed;

struct sec_key {
	u8 cipher_id;
	u8 cipher_len;
	u8 key_id;
	u8 key_len;
	u8 key[32];
} __packed;

struct sta_rec_sec {
	__le16 tag;
	__le16 len;
	u8 add;
	u8 n_cipher;
	u8 rsv[2];

	struct sec_key key[2];
} __packed;

struct ra_phy {
	u8 type;
	u8 flag;
	u8 stbc;
	u8 sgi;
	u8 bw;
	u8 ldpc;
	u8 mcs;
	u8 nss;
	u8 he_ltf;
};

struct sta_rec_ra {
	__le16 tag;
	__le16 len;

	u8 valid;
	u8 auto_rate;
	u8 phy_mode;
	u8 channel;
	u8 bw;
	u8 disable_cck;
	u8 ht_mcs32;
	u8 ht_gf;
	u8 ht_mcs[4];
	u8 mmps_mode;
	u8 gband_256;
	u8 af;
	u8 auth_wapi_mode;
	u8 rate_len;

	u8 supp_mode;
	u8 supp_cck_rate;
	u8 supp_ofdm_rate;
	__le32 supp_ht_mcs;
	__le16 supp_vht_mcs[4];

	u8 op_mode;
	u8 op_vht_chan_width;
	u8 op_vht_rx_nss;
	u8 op_vht_rx_nss_type;

	__le32 sta_status;

	struct ra_phy phy;
} __packed;

struct sta_rec_ra_fixed {
	__le16 tag;
	__le16 len;

	__le32 field;
	u8 op_mode;
	u8 op_vht_chan_width;
	u8 op_vht_rx_nss;
	u8 op_vht_rx_nss_type;

	struct ra_phy phy;

	u8 spe_en;
	u8 short_preamble;
	u8 is_5g;
	u8 mmps_mode;
} __packed;

#define RATE_PARAM_FIXED		3
#define RATE_PARAM_AUTO			20
#define RATE_CFG_MCS			GENMASK(3, 0)
#define RATE_CFG_NSS			GENMASK(7, 4)
#define RATE_CFG_GI			GENMASK(11, 8)
#define RATE_CFG_BW			GENMASK(15, 12)
#define RATE_CFG_STBC			GENMASK(19, 16)
#define RATE_CFG_LDPC			GENMASK(23, 20)
#define RATE_CFG_PHY_TYPE		GENMASK(27, 24)

struct sta_rec_bf {
	__le16 tag;
	__le16 len;

	__le16 pfmu;		/* 0xffff: no access right for PFMU */
	bool su_mu;		/* 0: SU, 1: MU */
	u8 bf_cap;		/* 0: iBF, 1: eBF */
	u8 sounding_phy;	/* 0: legacy, 1: OFDM, 2: HT, 4: VHT */
	u8 ndpa_rate;
	u8 ndp_rate;
	u8 rept_poll_rate;
	u8 tx_mode;		/* 0: legacy, 1: OFDM, 2: HT, 4: VHT ... */
	u8 nc;
	u8 nr;
	u8 bw;			/* 0: 20M, 1: 40M, 2: 80M, 3: 160M */

	u8 mem_total;
	u8 mem_20m;
	struct {
		u8 row;
		u8 col: 6, row_msb: 2;
	} mem[4];

	__le16 smart_ant;
	u8 se_idx;
	u8 auto_sounding;	/* b7: low traffic indicator
				 * b6: Stop sounding for this entry
				 * b5 ~ b0: postpone sounding
				 */
	u8 ibf_timeout;
	u8 ibf_dbw;
	u8 ibf_ncol;
	u8 ibf_nrow;
	u8 nr_bw160;
	u8 nc_bw160;
	u8 ru_start_idx;
	u8 ru_end_idx;

	bool trigger_su;
	bool trigger_mu;
	bool ng16_su;
	bool ng16_mu;
	bool codebook42_su;
	bool codebook75_mu;

	u8 he_ltf;
	u8 rsv[2];
} __packed;

struct sta_rec_bfee {
	__le16 tag;
	__le16 len;
	bool fb_identity_matrix;	/* 1: feedback identity matrix */
	bool ignore_feedback;		/* 1: ignore */
	u8 rsv[2];
} __packed;

struct sta_rec_state {
       __le16 tag;
       __le16 len;
       __le32 flags;
       u8 state;
       u8 vht_opmode;
       u8 action;
       u8 rsv[1];
} __packed;

#define HE_MAC_CAP_BYTE_NUM 6
#define HE_PHY_CAP_BYTE_NUM 11
#define HT_MCS_MASK_NUM 10

struct ht_vht_ba_size {
       u8 tx_ba;
       u8 rx_ba;
       u8 rsv[2];
} __packed;

struct he_ba_size {
       __le16 tx_ba;
       __le16 rx_ba;
} __packed;

union BA_SIZE {
       struct ht_vht_ba_size ht_vht;
       struct he_ba_size he;
};

struct sta_rec_phy {
       __le16 tag;
       __le16 len;
       __le16 legacy;
       u8 phy_type;
	u8 rx_mcs_bitmask[HT_MCS_MASK_NUM];
       u8 ampdu;
       u8 tx_ampdu;
       u8 rx_ampdu;
       u8 tx_amsdu_in_ampdu;
       u8 rx_amsdu_in_ampdu;
       u8 rts_policy;
       u8 rcpi;
       u8 uapsd_ac;
       u8 uapsd_sp;
       u8 he_mac_cap[HE_MAC_CAP_BYTE_NUM];
       u8 he_phy_cap[HE_PHY_CAP_BYTE_NUM];
       u8 rsv[5];
       __le16 he_6g_cap;
       __le16 basic_rate;
       __le32 tx_max_amsdu_len;
       union BA_SIZE ba_size;
} __packed;


enum {
	STA_REC_BASIC,
	STA_REC_RA,
	STA_REC_RA_CMM_INFO,
	STA_REC_RA_UPDATE,
	STA_REC_BF,
	STA_REC_AMSDU,
	STA_REC_BA,
        STA_REC_STATE,
	STA_REC_TX_PROC,	/* for hdr trans and CSO in CR4 */
	STA_REC_HT,
	STA_REC_VHT,
	STA_REC_APPS,
	STA_REC_KEY,
	STA_REC_WTBL,
	STA_REC_HE,
	STA_REC_HW_AMSDU,
	STA_REC_WTBL_AADOM,
	STA_REC_KEY_V2,
	STA_REC_MURU,
	STA_REC_MUEDCA,
	STA_REC_BFEE,
	STA_REC_PHY = 0x15,
	STA_REC_MAX_NUM
};

enum mt7921_cipher_type {
	MT_CIPHER_NONE,
	MT_CIPHER_WEP40,
	MT_CIPHER_WEP104,
	MT_CIPHER_WEP128,
	MT_CIPHER_TKIP,
	MT_CIPHER_AES_CCMP,
	MT_CIPHER_CCMP_256,
	MT_CIPHER_GCMP,
	MT_CIPHER_GCMP_256,
	MT_CIPHER_WAPI,
	MT_CIPHER_BIP_CMAC_128,
};

enum {
	CH_SWITCH_NORMAL = 0,
	CH_SWITCH_SCAN = 3,
	CH_SWITCH_MCC = 4,
	CH_SWITCH_DFS = 5,
	CH_SWITCH_BACKGROUND_SCAN_START = 6,
	CH_SWITCH_BACKGROUND_SCAN_RUNNING = 7,
	CH_SWITCH_BACKGROUND_SCAN_STOP = 8,
	CH_SWITCH_SCAN_BYPASS_DPD = 9
};

enum {
	THERMAL_SENSOR_TEMP_QUERY,
	THERMAL_SENSOR_MANUAL_CTRL,
	THERMAL_SENSOR_INFO_QUERY,
	THERMAL_SENSOR_TASK_CTRL,
};

enum {
	MT_EBF = BIT(0),	/* explicit beamforming */
	MT_IBF = BIT(1)		/* implicit beamforming */
};

#define MT7921_WTBL_UPDATE_MAX_SIZE	(sizeof(struct wtbl_req_hdr) +	\
					 sizeof(struct wtbl_generic) +	\
					 sizeof(struct wtbl_rx) +	\
					 sizeof(struct wtbl_ht) +	\
					 sizeof(struct wtbl_vht) +	\
					 sizeof(struct wtbl_hdr_trans) +\
					 sizeof(struct wtbl_ba) +	\
					 sizeof(struct wtbl_smps))

#define MT7921_STA_UPDATE_MAX_SIZE	(sizeof(struct sta_req_hdr) +	\
					 sizeof(struct sta_rec_basic) +	\
					 sizeof(struct sta_rec_ht) +	\
					 sizeof(struct sta_rec_he) +	\
					 sizeof(struct sta_rec_ba) +	\
					 sizeof(struct sta_rec_vht) +	\
					 sizeof(struct sta_rec_uapsd) + \
					 sizeof(struct sta_rec_amsdu) +	\
					 sizeof(struct tlv) +		\
					 MT7921_WTBL_UPDATE_MAX_SIZE)

#define MT7921_WTBL_UPDATE_BA_SIZE	(sizeof(struct wtbl_req_hdr) +	\
					 sizeof(struct wtbl_ba))

#define MT7921_BSS_UPDATE_MAX_SIZE	(sizeof(struct sta_req_hdr) +	\
					 sizeof(struct bss_info_omac) +	\
					 sizeof(struct bss_info_basic) +\
					 sizeof(struct bss_info_rf_ch) +\
					 sizeof(struct bss_info_ra) +	\
					 sizeof(struct bss_info_hw_amsdu) +\
					 sizeof(struct bss_info_he) +	\
					 sizeof(struct bss_info_bmc_rate) +\
					 sizeof(struct bss_info_ext_bss))

#define MT7921_BEACON_UPDATE_SIZE	(sizeof(struct sta_req_hdr) +	\
					 sizeof(struct bss_info_bcn_csa) + \
					 sizeof(struct bss_info_bcn_bcc) + \
					 sizeof(struct bss_info_bcn_mbss) + \
					 sizeof(struct bss_info_bcn_cont))

#define PHY_MODE_A			BIT(0)
#define PHY_MODE_B			BIT(1)
#define PHY_MODE_G			BIT(2)
#define PHY_MODE_GN			BIT(3)
#define PHY_MODE_AN			BIT(4)
#define PHY_MODE_AC			BIT(5)
#define PHY_MODE_AX_24G			BIT(6)
#define PHY_MODE_AX_5G			BIT(7)
#define PHY_MODE_AX_6G			BIT(8)

#define MODE_CCK			BIT(0)
#define MODE_OFDM			BIT(1)
#define MODE_HT				BIT(2)
#define MODE_VHT			BIT(3)
#define MODE_HE				BIT(4)

#define STA_CAP_WMM			BIT(0)
#define STA_CAP_SGI_20			BIT(4)
#define STA_CAP_SGI_40			BIT(5)
#define STA_CAP_TX_STBC			BIT(6)
#define STA_CAP_RX_STBC			BIT(7)
#define STA_CAP_VHT_SGI_80		BIT(16)
#define STA_CAP_VHT_SGI_160		BIT(17)
#define STA_CAP_VHT_TX_STBC		BIT(18)
#define STA_CAP_VHT_RX_STBC		BIT(19)
#define STA_CAP_VHT_LDPC		BIT(23)
#define STA_CAP_LDPC			BIT(24)
#define STA_CAP_HT			BIT(26)
#define STA_CAP_VHT			BIT(27)
#define STA_CAP_HE			BIT(28)

/* HE MAC */
#define STA_REC_HE_CAP_HTC			BIT(0)
#define STA_REC_HE_CAP_BQR			BIT(1)
#define STA_REC_HE_CAP_BSR			BIT(2)
#define STA_REC_HE_CAP_OM			BIT(3)
#define STA_REC_HE_CAP_AMSDU_IN_AMPDU		BIT(4)
/* HE PHY */
#define STA_REC_HE_CAP_DUAL_BAND		BIT(5)
#define STA_REC_HE_CAP_LDPC			BIT(6)
#define STA_REC_HE_CAP_TRIG_CQI_FK		BIT(7)
#define STA_REC_HE_CAP_PARTIAL_BW_EXT_RANGE	BIT(8)
/* STBC */
#define STA_REC_HE_CAP_LE_EQ_80M_TX_STBC	BIT(9)
#define STA_REC_HE_CAP_LE_EQ_80M_RX_STBC	BIT(10)
#define STA_REC_HE_CAP_GT_80M_TX_STBC		BIT(11)
#define STA_REC_HE_CAP_GT_80M_RX_STBC		BIT(12)
/* GI */
#define STA_REC_HE_CAP_SU_PPDU_1LTF_8US_GI	BIT(13)
#define STA_REC_HE_CAP_SU_MU_PPDU_4LTF_8US_GI	BIT(14)
#define STA_REC_HE_CAP_ER_SU_PPDU_1LTF_8US_GI	BIT(15)
#define STA_REC_HE_CAP_ER_SU_PPDU_4LTF_8US_GI	BIT(16)
#define STA_REC_HE_CAP_NDP_4LTF_3DOT2MS_GI	BIT(17)
/* 242 TONE */
#define STA_REC_HE_CAP_BW20_RU242_SUPPORT	BIT(18)
#define STA_REC_HE_CAP_TX_1024QAM_UNDER_RU242	BIT(19)
#define STA_REC_HE_CAP_RX_1024QAM_UNDER_RU242	BIT(20)

struct mt7921_mcu_reg_event {
	__le32 reg;
	__le32 val;
} __packed;

struct mt7921_bss_basic_tlv {
	__le16 tag;
	__le16 len;
	u8 active;
	u8 omac_idx;
	u8 hw_bss_idx;
	u8 band_idx;
	__le32 conn_type;
	u8 conn_state;
	u8 wmm_idx;
	u8 bssid[ETH_ALEN];
	__le16 bmc_tx_wlan_idx;
	__le16 bcn_interval;
	u8 dtim_period;
	u8 phymode; /* bit(0): A
		     * bit(1): B
		     * bit(2): G
		     * bit(3): GN
		     * bit(4): AN
		     * bit(5): AC
		     */
	__le16 sta_idx;
	u8 nonht_basic_phy;
	u8 pad[3];
} __packed;

struct mt7921_bss_qos_tlv {
	__le16 tag;
	__le16 len;
	u8 qos;
	u8 pad[3];
} __packed;

struct mt7921_mcu_scan_ssid {
	__le32 ssid_len;
	u8 ssid[IEEE80211_MAX_SSID_LEN];
} __packed;

struct mt7921_mcu_scan_channel {
	u8 band; /* 1: 2.4GHz
		  * 2: 5.0GHz
		  * Others: Reserved
		  */
	u8 channel_num;
} __packed;

struct mt7921_mcu_scan_match {
	__le32 rssi_th;
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	u8 ssid_len;
	u8 rsv[3];
} __packed;

struct mt7921_hw_scan_req {
	u8 seq_num;
	u8 bss_idx;
	u8 scan_type; /* 0: PASSIVE SCAN
		       * 1: ACTIVE SCAN
		       */
	u8 ssid_type; /* BIT(0) wildcard SSID
		       * BIT(1) P2P wildcard SSID
		       * BIT(2) specified SSID + wildcard SSID
		       * BIT(2) + ssid_type_ext BIT(0) specified SSID only
		       */
	u8 ssids_num;
	u8 probe_req_num; /* Number of probe request for each SSID */
	u8 scan_func; /* BIT(0) Enable random MAC scan
		       * BIT(1) Disable DBDC scan type 1~3.
		       * BIT(2) Use DBDC scan type 3 (dedicated one RF to scan).
		       */
	u8 version; /* 0: Not support fields after ies.
		     * 1: Support fields after ies.
		     */
	struct mt7921_mcu_scan_ssid ssids[4];
	__le16 probe_delay_time;
	__le16 channel_dwell_time; /* channel Dwell interval */
	__le16 timeout_value;
	u8 channel_type; /* 0: Full channels
			  * 1: Only 2.4GHz channels
			  * 2: Only 5GHz channels
			  * 3: P2P social channel only (channel #1, #6 and #11)
			  * 4: Specified channels
			  * Others: Reserved
			  */
	u8 channels_num; /* valid when channel_type is 4 */
	/* valid when channels_num is set */
	struct mt7921_mcu_scan_channel channels[32];
	__le16 ies_len;
	u8 ies[MT7921_SCAN_IE_LEN];
	/* following fields are valid if version > 0 */
	u8 ext_channels_num;
	u8 ext_ssids_num;
	__le16 channel_min_dwell_time;
	struct mt7921_mcu_scan_channel ext_channels[32];
	struct mt7921_mcu_scan_ssid ext_ssids[6];
	u8 bssid[ETH_ALEN];
	u8 random_mac[ETH_ALEN]; /* valid when BIT(1) in scan_func is set. */
	u8 pad[63];
	u8 ssid_type_ext;
} __packed;

#define SCAN_DONE_EVENT_MAX_CHANNEL_NUM	64
struct mt7921_hw_scan_done {
	u8 seq_num;
	u8 sparse_channel_num;
	struct mt7921_mcu_scan_channel sparse_channel;
	u8 complete_channel_num;
	u8 current_state;
	u8 version;
	u8 pad;
	__le32 beacon_scan_num;
	u8 pno_enabled;
	u8 pad2[3];
	u8 sparse_channel_valid_num;
	u8 pad3[3];
	u8 channel_num[SCAN_DONE_EVENT_MAX_CHANNEL_NUM];
	/* idle format for channel_idle_time
	 * 0: first bytes: idle time(ms) 2nd byte: dwell time(ms)
	 * 1: first bytes: idle time(8ms) 2nd byte: dwell time(8ms)
	 * 2: dwell time (16us)
	 */
	__le16 channel_idle_time[SCAN_DONE_EVENT_MAX_CHANNEL_NUM];
	/* beacon and probe response count */
	u8 beacon_probe_num[SCAN_DONE_EVENT_MAX_CHANNEL_NUM];
	u8 mdrdy_count[SCAN_DONE_EVENT_MAX_CHANNEL_NUM];
	__le32 beacon_2g_num;
	__le32 beacon_5g_num;
} __packed;

struct mt7921_mcu_bss_event {
	u8 bss_idx;
	u8 is_absent;
	u8 free_quota;
	u8 pad;
} __packed;

typedef enum _ENUM_PHY_TYPE_INDEX_T
{
    //PHY_TYPE_DSSS_INDEX,      /* DSSS PHY (clause 15) */ /* NOTE(Kevin): We don't use this now */
    PHY_TYPE_HR_DSSS_INDEX = 0, /* HR/DSSS PHY (clause 18) */
    PHY_TYPE_ERP_INDEX,         /* ERP PHY (clause 19) */
    PHY_TYPE_ERP_P2P_INDEX,     /* ERP PHY (clause 19) w/o HR/DSSS */
    PHY_TYPE_OFDM_INDEX,        /* OFDM 5 GHz PHY (clause 17) */
    PHY_TYPE_HT_INDEX,          /* HT PHY (clause 20) */
    PHY_TYPE_VHT_INDEX,
    PHY_TYPE_HE_INDEX,
    PHY_TYPE_INDEX_NUM // 7
} ENUM_PHY_TYPE_INDEX_T, *P_ENUM_PHY_TYPE_INDEX_T;

#define PHY_TYPE_BIT_HR_DSSS    BIT(PHY_TYPE_HR_DSSS_INDEX) /* HR/DSSS PHY (clause 18) */
#define PHY_TYPE_BIT_ERP        BIT(PHY_TYPE_ERP_INDEX)     /* ERP PHY (clause 19) */
#define PHY_TYPE_BIT_OFDM       BIT(PHY_TYPE_OFDM_INDEX)    /* OFDM 5 GHz PHY (clause 17) */
#define PHY_TYPE_BIT_HT         BIT(PHY_TYPE_HT_INDEX)      /* HT PHY (clause 20) */
#define PHY_TYPE_BIT_VHT        BIT(PHY_TYPE_VHT_INDEX)      /* HT PHY (clause 20) */
#define PHY_TYPE_BIT_HE         BIT(PHY_TYPE_HE_INDEX)      /* HT PHY (clause ) */

#endif
