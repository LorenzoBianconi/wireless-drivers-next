/*
 * Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
 * Copyright (C) 2018 Stanislaw Gruszka <stf_xl@wp.pl>
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

#ifndef __MT76XX_UTIL_H
#define __MT76XX_UTIL_H

#include <linux/skbuff.h>
#include <net/mac80211.h>

#include "mt76.h"

#define MT_MCU_RESET_CTL		0x070C
#define MT_MCU_INT_LEVEL		0x0718
#define MT_MCU_COM_REG0			0x0730
#define MT_MCU_COM_REG1			0x0734
#define MT_MCU_COM_REG2			0x0738
#define MT_MCU_COM_REG3			0x073C

enum mcu_cmd {
	CMD_FUN_SET_OP = 1,
	CMD_LOAD_CR = 2,
	CMD_INIT_GAIN_OP = 3,
	CMD_DYNC_VGA_OP = 6,
	CMD_TDLS_CH_SW = 7,
	CMD_BURST_WRITE = 8,
	CMD_READ_MODIFY_WRITE = 9,
	CMD_RANDOM_READ = 10,
	CMD_BURST_READ = 11,
	CMD_RANDOM_WRITE = 12,
	CMD_LED_MODE_OP = 16,
	CMD_POWER_SAVING_OP = 20,
	CMD_WOW_CONFIG = 21,
	CMD_WOW_QUERY = 22,
	CMD_WOW_FEATURE = 24,
	CMD_CARRIER_DETECT_OP = 28,
	CMD_RADOR_DETECT_OP = 29,
	CMD_SWITCH_CHANNEL_OP = 30,
	CMD_CALIBRATION_OP = 31,
	CMD_BEACON_OP = 32,
	CMD_ANTENNA_OP = 33,
};

extern struct ieee80211_rate mt76xx_rates[12];

void mt76xx_configure_filter(struct ieee80211_hw *hw,
			     unsigned int changed_flags,
			     unsigned int *total_flags, u64 multicast);
int mt76xx_sta_add(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta);
int mt76xx_sta_remove(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		      struct ieee80211_sta *sta);

void mt76xx_vif_init(struct mt76_dev *dev, struct ieee80211_vif *vif,
		     unsigned int idx);
int mt76xx_add_interface(struct ieee80211_hw *hw,
			 struct ieee80211_vif *vif);
void mt76xx_remove_interface(struct ieee80211_hw *hw,
			     struct ieee80211_vif *vif);

int mt76xx_ampdu_action(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			struct ieee80211_ampdu_params *params);
int mt76xx_set_key(struct ieee80211_hw *hw, enum set_key_cmd cmd,
		   struct ieee80211_vif *vif, struct ieee80211_sta *sta,
		   struct ieee80211_key_conf *key);
int mt76xx_conf_tx(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		   u16 queue, const struct ieee80211_tx_queue_params *params);
void mt76xx_sta_rate_tbl_update(struct ieee80211_hw *hw,
				struct ieee80211_vif *vif,
				struct ieee80211_sta *sta);
int mt76xx_insert_hdr_pad(struct sk_buff *skb);
void mt76xx_remove_hdr_pad(struct sk_buff *skb, int len);
void mt76xx_tx_complete(struct mt76_dev *dev, struct sk_buff *skb);
void mt76xx_remove_dma_hdr(struct sk_buff *skb);
void mt76xx_tx_complete_skb(struct mt76_dev *mdev, struct mt76_queue *q,
			    struct mt76_queue_entry *e, bool flush);
int mt76xx_set_txinfo(struct sk_buff *skb, struct mt76_wcid *wcid, u8 ep);
bool mt76xx_tx_status_data(struct mt76_dev *dev, u8 *update);
int mt76xx_mcu_function_select(struct mt76_dev *dev, int func, u32 val);
int mt76xx_mcu_calibrate(struct mt76_dev *dev, int type, u32 val);

#endif
