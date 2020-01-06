// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 *         Roy Luo <royluo@google.com>
 *         Lorenzo Bianconi <lorenzo@kernel.org>
 *         Felix Fietkau <nbd@nbd.name>
 *	   Chih-Min Chen <chih-min.chen@mediatek.com>
 *	   Sean Wang <sean.wang@mediatek.com>
 */

#include "mt7663.h"
#include "../dma.h"
#include "regs.h"
#include "mac.h"

void mt7663_queue_rx_skb(struct mt76_dev *mdev, enum mt76_rxq_id q,
			 struct sk_buff *skb)
{
	struct mt7663_dev *dev = container_of(mdev, struct mt7663_dev, mt76);
	__le32 *rxd = (__le32 *)skb->data;
	__le32 *end = (__le32 *)&skb->data[skb->len];
	enum rx_pkt_type type;

	type = FIELD_GET(MT_RXD0_PKT_TYPE, le32_to_cpu(rxd[0]));

	switch (type) {
	case PKT_TYPE_TXS:
		for (rxd++; rxd + 7 <= end; rxd += 7)
			mt7663_mac_add_txs(dev, rxd);
		dev_kfree_skb(skb);
		break;
	case PKT_TYPE_TXRX_NOTIFY:
		mt7663_mac_tx_free(dev, skb);
		break;
	case PKT_TYPE_RX_EVENT:
		mt7663_mcu_rx_event(dev, skb);
		break;
	case PKT_TYPE_NORMAL:
		if (!mt7663_mac_fill_rx(dev, skb)) {
			mt76_rx(&dev->mt76, q, skb);
			return;
		}
		/* fall through */
	default:
		dev_kfree_skb(skb);
		break;
	}
}
EXPORT_SYMBOL_GPL(mt7663_queue_rx_skb);

void mt7663_dma_cleanup(struct mt7663_dev *dev)
{
	mt76_clear(dev, MT_WPDMA_GLO_CFG,
		   MT_WPDMA_GLO_CFG_TX_DMA_EN |
		   MT_WPDMA_GLO_CFG_RX_DMA_EN);
	mt76_set(dev, MT_WPDMA_GLO_CFG, MT_WPDMA_GLO_CFG_SW_RESET);

	tasklet_kill(&dev->mt76.tx_tasklet);
	mt76_dma_cleanup(&dev->mt76);
}
