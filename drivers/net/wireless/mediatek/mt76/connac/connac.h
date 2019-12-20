/* SPDX-License-Identifier: ISC */
/* Copyright (C) 2019 MediaTek Inc. */

#ifndef __CONNAC_H
#define __CONNAC_H

#include <linux/interrupt.h>
#include <linux/ktime.h>
#include "../mt76.h"
#include "regs.h"

#define CONNAC_USB_TXD_EXTRA_SIZE	(8 * 4)
#define CONNAC_USB_TXD_SIZE		(MT_TXD_SIZE + \
					 CONNAC_USB_TXD_EXTRA_SIZE)
#define CONNAC_USB_HDR_SIZE		(4)
#define CONNAC_USB_TAIL_SIZE		(4)

#define MTK_REBB	1

#define CONNAC_MAX_INTERFACES		4
#define CONNAC_MAX_WMM_SETS		4
#define CONNAC_WTBL_SIZE		128
#define CONNAC_WTBL_RESERVED		(CONNAC_WTBL_SIZE - 1)
#define CONNAC_WTBL_STA			(CONNAC_WTBL_RESERVED - \
					 CONNAC_MAX_INTERFACES)

#define CONNAC_WATCHDOG_TIME		(HZ / 10)
#define CONNAC_RATE_RETRY		2

#define CONNAC_TX_RING_SIZE		512
#define CONNAC_TX_MCU_RING_SIZE		128
#define CONNAC_TX_FWDL_RING_SIZE	128

#define CONNAC_RX_RING_SIZE		512
#define CONNAC_RX_MCU_RING_SIZE		512

#define MT7629_EMI_IEMI			"mt7629_WIFI_RAM_CODE_iemi.bin"
#define MT7629_EMI_DEMI			"mt7629_WIFI_RAM_CODE_demi.bin"
#define MT7629_FIRMWARE_N9		"mt7629_n9.bin"
#define MT7629_ROM_PATCH		"mt7629_rom_patch.bin"

#define MT7629_EMI_PHY_ADDR				0x41000000
#define MT7629_EMI_PHY_ADDR_SIZE		0x200000
#define MT7629_RAM_ILM_EMI_ADDR_OFFSET	0x75000		/* 0xF0075000 */
#define MT7629_RAM_DLM_EMI_ADDR_OFFSET	0x146800	/* 0xF0146800 */

#if MTK_REBB
#define MT7663_FIRMWARE_N9              "mediatek/mt7663_n9_rebb.bin"
#define MT7663_ROM_PATCH                "mediatek/mt7663pr2h_rebb.bin"
#else
#define MT7663_FIRMWARE_N9              "mediatek/mt7663_n9.bin"
#define MT7663_ROM_PATCH                "mediatek/mt7663pr2h.bin"
#endif

#define CONNAC_EEPROM_SIZE		1024
#define CONNAC_TOKEN_SIZE		4096

struct connac_vif;
struct connac_sta;

enum connac_hw_txq_id {
	CONNAC_TXQ_MAIN,
	CONNAC_TXQ_EXT,
	CONNAC_TXQ_FWDL = 3,
	CONNAC_TXQ_MGMT = 5,
	CONNAC_TXQ_MCU = 15,
};

struct connac_rate_set {
	struct ieee80211_tx_rate probe_rate;
	struct ieee80211_tx_rate rates[4];
};

struct connac_sta {
	struct mt76_wcid wcid; /* must be first */

	struct connac_vif *vif;

	struct ieee80211_tx_rate rates[4];

	struct connac_rate_set rateset[2];
	u32 rate_set_tsf;

	u8 rate_count;
	u8 n_rates;

	u8 rate_probe;
};

struct connac_vif {
	u8 idx;
	u8 omac_idx;
	u8 band_idx;
	u8 wmm_idx;

	struct connac_sta sta;
};

struct connac_dev {
	union { /* must be first */
		struct mt76_dev mt76;
		struct mt76_phy mphy;
	};

	u16 chainmask;
	u32 vif_mask;
	u32 omac_mask;

	struct {
		u8 n_pulses;
		u32 period;
		u16 width;
		s16 power;
	} radar_pattern;
	u32 hw_pattern;
	int dfs_state;

	int false_cca_ofdm, false_cca_cck;
	unsigned long last_cca_adj;
	u8 mac_work_count;
	s8 ofdm_sensitivity;
	s8 cck_sensitivity;
	bool scs_en;

	/* locks for accessing tokens */
	spinlock_t token_lock;
	struct idr token;

	u32 wtbl_idx;
	u32 token_idx;
	int pid_tmp;
	u32 amsdu_en;

	struct work_struct	rc_work;     /* deferred rate tuning */
	struct list_head	rc_processing;
	const u32 *regs;
	bool required_poweroff;
};

struct connac_rate_desc {
	int wcid;
	u8 bw;
	u8 bw_idx;
	u16 val[4];
	u16 probe_val;
	bool rateset;

	struct connac_sta *sta;
	struct list_head node;
};

enum {
	HW_BSSID_0 = 0x0,
	HW_BSSID_1,
	HW_BSSID_2,
	HW_BSSID_3,
	HW_BSSID_MAX,
	EXT_BSSID_START = 0x10,
	EXT_BSSID_1,
	EXT_BSSID_2,
	EXT_BSSID_3,
	EXT_BSSID_4,
	EXT_BSSID_5,
	EXT_BSSID_6,
	EXT_BSSID_7,
	EXT_BSSID_8,
	EXT_BSSID_9,
	EXT_BSSID_10,
	EXT_BSSID_11,
	EXT_BSSID_12,
	EXT_BSSID_13,
	EXT_BSSID_14,
	EXT_BSSID_15,
	EXT_BSSID_END
};

enum {
	MT_HW_RDD0,
	MT_HW_RDD1,
};

enum {
	MT_RX_SEL0,
	MT_RX_SEL1,
};

enum connac_rdd_cmd {
	RDD_STOP,
	RDD_START,
	RDD_DET_MODE,
	RDD_DET_STOP,
	RDD_CAC_START,
	RDD_CAC_END,
	RDD_NORMAL_START,
	RDD_DISABLE_DFS_CAL,
	RDD_PULSE_DBG,
	RDD_READ_PULSE,
	RDD_RESUME_BF,
};

extern const struct ieee80211_ops connac_ops;
extern struct pci_driver connac_pci_driver;
u32 connac_reg_map(struct connac_dev *dev, u32 addr);

int connac_register_device(struct connac_dev *dev);
void connac_unregister_device(struct connac_dev *dev);
int connac_eeprom_init(struct connac_dev *dev);
int connac_eeprom_get_power_index(struct ieee80211_channel *chan,
				  u8 chain_idx);
int connac_dma_init(struct connac_dev *dev);
void connac_dma_cleanup(struct connac_dev *dev);
int connac_mcu_init(struct connac_dev *dev);
int connac_mcu_set_dev_info(struct connac_dev *dev,
			    struct ieee80211_vif *vif, bool enable);
int connac_mcu_set_bss_info(struct connac_dev *dev, struct ieee80211_vif *vif,
			    int en);
void connac_mac_set_rates(struct connac_dev *dev, struct connac_sta *sta,
			  struct ieee80211_tx_rate *probe_rate,
			  struct ieee80211_tx_rate *rates);
int connac_mcu_wtbl_bmc(struct connac_dev *dev, struct ieee80211_vif *vif,
			bool enable);
int connac_mcu_add_wtbl(struct connac_dev *dev, struct ieee80211_vif *vif,
			struct ieee80211_sta *sta);
int connac_mcu_del_wtbl(struct connac_dev *dev, struct ieee80211_sta *sta);
int connac_mcu_del_wtbl_all(struct connac_dev *dev);
int connac_mcu_set_sta_rec_bmc(struct connac_dev *dev,
			       struct ieee80211_vif *vif, bool en);
int connac_mcu_set_sta_rec(struct connac_dev *dev, struct ieee80211_vif *vif,
			   struct ieee80211_sta *sta, bool en);
int connac_mcu_set_bcn(struct connac_dev *dev, struct ieee80211_vif *vif,
		       int en);
int connac_mcu_set_channel(struct connac_dev *dev);
int connac_mcu_set_wmm(struct connac_dev *dev, u8 queue,
		       const struct ieee80211_tx_queue_params *params);
int connac_mcu_set_tx_ba(struct connac_dev *dev,
			 struct ieee80211_ampdu_params *params,
			 bool add);
int connac_mcu_set_rx_ba(struct connac_dev *dev,
			 struct ieee80211_ampdu_params *params,
			 bool add);
int connac_mcu_set_ht_cap(struct connac_dev *dev, struct ieee80211_vif *vif,
			  struct ieee80211_sta *sta);
void connac_mcu_rx_event(struct connac_dev *dev, struct sk_buff *skb);
int connac_mcu_rdd_cmd(struct connac_dev *dev,
		       enum connac_rdd_cmd cmd, u8 index,
		       u8 rx_sel, u8 val);
int connac_dfs_start_radar_detector(struct connac_dev *dev);
int connac_dfs_stop_radar_detector(struct connac_dev *dev);
int connac_mcu_rdd_send_pattern(struct connac_dev *dev);

static inline void connac_dfs_check_channel(struct connac_dev *dev)
{
	enum nl80211_chan_width width = dev->mphy.chandef.width;
	u32 freq = dev->mphy.chandef.chan->center_freq;
	struct ieee80211_hw *hw = mt76_hw(dev);

	if (hw->conf.chandef.chan->center_freq != freq ||
	    hw->conf.chandef.width != width)
		dev->dfs_state = -1;
}

static inline void connac_irq_enable(struct connac_dev *dev, u32 mask)
{
	mt76_set_irq_mask(&dev->mt76, MT_INT_MASK_CSR(dev), 0, mask);
}

static inline void connac_irq_disable(struct connac_dev *dev, u32 mask)
{
	mt76_set_irq_mask(&dev->mt76, MT_INT_MASK_CSR(dev), mask, 0);
}

void connac_update_channel(struct mt76_dev *mdev);
void connac_mac_cca_stats_reset(struct connac_dev *dev);

int connac_mac_write_txwi(struct connac_dev *dev, __le32 *txwi,
			  struct sk_buff *skb, enum mt76_txq_id qid,
			  struct mt76_wcid *wcid,
			  struct ieee80211_sta *sta, int pid,
			  struct ieee80211_key_conf *key);
int connac_mac_fill_rx(struct connac_dev *dev, struct sk_buff *skb);
void connac_mac_add_txs(struct connac_dev *dev, void *data);
void connac_mac_tx_free(struct connac_dev *dev, struct sk_buff *skb);
int connac_mac_wtbl_set_key(struct connac_dev *dev, struct mt76_wcid *wcid,
			    struct ieee80211_key_conf *key,
			    enum set_key_cmd cmd);

int connac_mcu_set_eeprom(struct connac_dev *dev);
int connac_mcu_dbdc_ctrl(struct connac_dev *dev);
int connac_mcu_init_mac(struct connac_dev *dev, u8 band);
int connac_mcu_set_rts_thresh(struct connac_dev *dev, u32 val);
int connac_mcu_ctrl_pm_state(struct connac_dev *dev, int enter);
int connac_mcu_set_tx_power(struct connac_dev *dev);
void connac_mcu_exit(struct connac_dev *dev);
int connac_mcu_restart(struct mt76_dev *dev);
int connac_load_firmware(struct connac_dev *dev);
void connac_mcu_fill_msg(struct connac_dev *dev, struct sk_buff *skb,
			 int cmd, int *wait_seq);
int connac_mcu_wait_response(struct connac_dev *dev, int cmd, int seq);

int connac_tx_prepare_skb(struct mt76_dev *mdev, void *txwi_ptr,
			  enum mt76_txq_id qid, struct mt76_wcid *wcid,
			  struct ieee80211_sta *sta,
			  struct mt76_tx_info *tx_info);

void connac_tx_complete_skb(struct mt76_dev *mdev, enum mt76_txq_id qid,
			    struct mt76_queue_entry *e);

void connac_queue_rx_skb(struct mt76_dev *mdev, enum mt76_rxq_id q,
			 struct sk_buff *skb);
void connac_sta_ps(struct mt76_dev *mdev, struct ieee80211_sta *sta, bool ps);
int connac_sta_add(struct mt76_dev *mdev, struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta);
void connac_sta_assoc(struct mt76_dev *mdev, struct ieee80211_vif *vif,
		      struct ieee80211_sta *sta);
void connac_sta_remove(struct mt76_dev *mdev, struct ieee80211_vif *vif,
		       struct ieee80211_sta *sta);
void connac_mac_work(struct work_struct *work);
void connac_txp_skb_unmap(struct mt76_dev *dev,
			  struct mt76_txwi_cache *txwi);
int mt76_dfs_start_rdd(struct connac_dev *dev, bool force);
int connac_dfs_init_radar_detector(struct connac_dev *dev);

int connac_init_debugfs(struct connac_dev *dev);

void connac_mac_init(struct connac_dev *dev);
int connac_init_hardware(struct connac_dev *dev);

void connac_usb_mac_set_rates(struct connac_dev *dev, struct connac_sta *sta,
			      struct ieee80211_tx_rate *probe_rate,
			      struct ieee80211_tx_rate *rates);
#endif
