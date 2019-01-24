/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2019 MediaTek Inc. */

#ifndef __MT7615_H
#define __MT7615_H

#include <linux/interrupt.h>
#include <linux/ktime.h>
#include "../mt76.h"
#include "regs.h"

#define MT7615_MAX_INTERFACES		4

#define MT7615_TX_RING_SIZE		1024
#define MT7615_TX_MCU_RING_SIZE		128
#define MT7615_TX_FWDL_RING_SIZE	128

#define MT7615_RX_RING_SIZE		1024
#define MT7615_RX_MCU_RING_SIZE		512

#define MT7615_FIRMWARE_CR4		"mt7615_cr4.bin"
#define MT7615_FIRMWARE_N9		"mt7615_n9.bin"
#define MT7615_ROM_PATCH		"mt7615_rom_patch.bin"

#define MT7615_EEPROM_SIZE		1024

struct mt7615_vif;
struct mt7615_sta;

struct mt7615_sta {
	struct mt76_wcid wcid; /* must be first */

	struct mt7615_vif *vif;
};

struct mt7615_vif {
	u8 idx;
	u8 omac_idx;
	u8 band_idx;
	u8 wmm_idx;

	struct mt7615_sta sta;
};

struct mt7615_dev {
	struct mt76_dev mt76; /* must be first */

	struct tasklet_struct tx_tasklet;
};

extern const struct ieee80211_ops mt7615_ops;
extern struct pci_driver mt7615_pci_driver;

u32 mt7615_reg_map(struct mt7615_dev *dev, u32 addr);

struct mt7615_dev *mt7615_alloc_device(struct device *pdev);

int mt7615_register_device(struct mt7615_dev *dev);
void mt7615_unregister_device(struct mt7615_dev *dev);
int mt7615_eeprom_init(struct mt7615_dev *dev);
int mt7615_dma_init(struct mt7615_dev *dev);
void mt7615_dma_cleanup(struct mt7615_dev *dev);
void mt7615_dma_start(struct mt7615_dev *dev);
int mt7615_mcu_init(struct mt7615_dev *dev);
int mt7615_tx_queue_mcu(struct mt7615_dev *dev, enum mt7615_txq_id qid,
			struct sk_buff *skb);
void mt7615_mcu_rx_event(struct mt7615_dev *dev, struct sk_buff *skb);

void mt7615_set_irq_mask(struct mt7615_dev *dev, u32 clear, u32 set);

static inline void mt7615_irq_enable(struct mt7615_dev *dev, u32 mask)
{
	mt7615_set_irq_mask(dev, 0, mask);
}

static inline void mt7615_irq_disable(struct mt7615_dev *dev, u32 mask)
{
	mt7615_set_irq_mask(dev, mask, 0);
}

int mt7615_mac_write_txwi(struct mt7615_dev *dev, __le32 *txwi,
			  struct sk_buff *skb, struct mt76_wcid *wcid,
			  struct ieee80211_sta *sta,
			  struct ieee80211_key_conf *key);
int mt7615_mac_fill_rx(struct mt7615_dev *dev, struct sk_buff *skb);

int mt7615_mcu_set_eeprom(struct mt7615_dev *dev);
int mt7615_mcu_init_mac(struct mt7615_dev *dev);
int mt7615_mcu_ctrl_pm_state(struct mt7615_dev *dev, int enter);
void mt7615_mcu_exit(struct mt7615_dev *dev);

int mt7615_tx_prepare_skb(struct mt76_dev *mdev, void *txwi_ptr,
			  struct sk_buff *skb, struct mt76_queue *q,
			  struct mt76_wcid *wcid, struct ieee80211_sta *sta,
			  u32 *tx_info);

void mt7615_tx_complete_skb(struct mt76_dev *mdev, struct mt76_queue *q,
			    struct mt76_queue_entry *e, bool flush);

void mt7615_queue_rx_skb(struct mt76_dev *mdev, enum mt76_rxq_id q,
			 struct sk_buff *skb);
void mt7615_rx_poll_complete(struct mt76_dev *mdev, enum mt76_rxq_id q);
void mt7615_sta_ps(struct mt76_dev *mdev, struct ieee80211_sta *sta, bool ps);

#endif
