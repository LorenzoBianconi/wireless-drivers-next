/*
 * Copyright (C) 2018 Lorenzo Bianconi <lorenzo.bianconi83@gmail.com>
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

#ifndef __MT76x2U_H
#define __MT76x2U_H

#include <linux/device.h>

#include "mt76x2.h"
#include "mt76x2_dma.h"
#include "mt76x2_mcu.h"

#define MT7612U_EEPROM_SIZE		512

#define MT_USB_AGGR_SIZE_LIMIT		21 /* 1024B unit */
#define MT_USB_AGGR_TIMEOUT		0x80 /* 33ns unit */

extern const struct ieee80211_ops mt76x2u_ops;

struct mt76x2_dev *mt76x2u_alloc_device(struct device *pdev);
int mt76x2u_register_device(struct mt76x2_dev *dev);
void mt76x2u_cleanup(struct mt76x2_dev *dev);
void mt76x2u_stop_hw(struct mt76x2_dev *dev);

void mt76x2u_mac_setaddr(struct mt76x2_dev *dev, u8 *addr);
int mt76x2u_mac_reset(struct mt76x2_dev *dev);
void mt76x2u_mac_resume(struct mt76x2_dev *dev);
int mt76x2u_mac_start(struct mt76x2_dev *dev);
int mt76x2u_mac_stop(struct mt76x2_dev *dev);

int mt76x2u_phy_set_channel(struct mt76x2_dev *dev,
			    struct cfg80211_chan_def *chandef);
void mt76x2u_phy_calibrate(struct work_struct *work);
void mt76x2u_phy_channel_calibrate(struct mt76x2_dev *dev);
void mt76x2u_phy_set_txdac(struct mt76x2_dev *dev);
void mt76x2u_phy_set_rxpath(struct mt76x2_dev *dev);

int mt76x2u_mcu_set_channel(struct mt76x2_dev *dev, u8 channel, u8 bw,
			    u8 bw_index, bool scan);
int mt76x2u_mcu_calibrate(struct mt76x2_dev *dev, enum mcu_calibration type,
			  u32 val);
int mt76x2u_mcu_tssi_comp(struct mt76x2_dev *dev,
			  struct mt76x2_tssi_comp *tssi_data);
int mt76x2u_mcu_init_gain(struct mt76x2_dev *dev, u8 channel, u32 gain,
			  bool force);
int mt76x2u_mcu_set_radio_state(struct mt76x2_dev *dev, bool val);
int mt76x2u_mcu_load_cr(struct mt76x2_dev *dev, u8 type,
			u8 temp_level, u8 channel);
int mt76x2u_mcu_init(struct mt76x2_dev *dev);
int mt76x2u_mcu_fw_init(struct mt76x2_dev *dev);
void mt76x2u_mcu_deinit(struct mt76x2_dev *dev);

int mt76x2u_dma_init(struct mt76x2_dev *dev);
void mt76x2u_dma_cleanup(struct mt76x2_dev *dev);
void mt76x2u_tx_status_data(struct work_struct *work);
int mt76x2u_tx_prepare_skb(struct mt76_dev *mdev, void *data,
			   struct sk_buff *skb, struct mt76_queue *q,
			   struct mt76_wcid *wcid, struct ieee80211_sta *sta,
			   u32 *tx_info);
void mt76x2u_tx_complete_skb(struct mt76_dev *mdev, struct mt76_queue *q,
			     struct mt76_queue_entry *e, bool flush);

static inline int mt76x2u_dma_skb_info(struct sk_buff *skb,
				       enum dma_msg_port port,
				       u32 flags)
{
	/* Buffer layout:
	 *	|   4B   | xfer len |      pad       |  4B  |
	 *	| TXINFO | pkt/cmd  | zero pad to 4B | zero |
	 *
	 * length field of TXINFO should be set to 'xfer len'.
	 */
	u32 info = FIELD_PREP(MT_TXD_INFO_LEN, round_up(skb->len, 4)) |
		   FIELD_PREP(MT_TXD_INFO_DPORT, port) | flags;

	put_unaligned_le32(info, skb_push(skb, sizeof(info)));
	return skb_put_padto(skb, round_up(skb->len, 4) + 4);
}

#endif /* __MT76x2U_H */
