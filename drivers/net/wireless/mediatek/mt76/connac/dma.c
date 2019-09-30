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

#include "connac.h"
#include "../dma.h"
#include "mac.h"

static int
connac_init_tx_queue(struct connac_dev *dev, struct mt76_sw_queue *q,
		     int idx, int n_desc)
{
	struct mt76_queue *hwq;
	int err;

	hwq = devm_kzalloc(dev->mt76.dev, sizeof(*hwq), GFP_KERNEL);
	if (!hwq)
		return -ENOMEM;

	err = mt76_queue_alloc(dev, hwq, idx, n_desc, 0, MT_TX_RING_BASE(dev));
	if (err < 0)
		return err;

	INIT_LIST_HEAD(&q->swq);
	q->q = hwq;

	if (dev->flag & CONNAC_MMIO)
		connac_irq_enable(dev, MT_INT_TX_DONE(idx));

	return 0;
}

void connac_queue_rx_skb(struct mt76_dev *mdev, enum mt76_rxq_id q,
			 struct sk_buff *skb)
{
	struct connac_dev *dev = container_of(mdev, struct connac_dev, mt76);
	__le32 *rxd = (__le32 *)skb->data;
	__le32 *end = (__le32 *)&skb->data[skb->len];
	enum rx_pkt_type type;

	type = FIELD_GET(MT_RXD0_PKT_TYPE, le32_to_cpu(rxd[0]));

	switch (type) {
	case PKT_TYPE_TXS:
		for (rxd++; rxd + 7 <= end; rxd += 7)
			connac_mac_add_txs(dev, rxd);
		dev_kfree_skb(skb);
		break;
	case PKT_TYPE_TXRX_NOTIFY:
		connac_mac_tx_free(dev, skb);
		break;
	case PKT_TYPE_RX_EVENT:
		connac_mcu_rx_event(dev, skb);
		break;
	case PKT_TYPE_NORMAL:
		if (!connac_mac_fill_rx(dev, skb)) {
			mt76_rx(&dev->mt76, q, skb);
			return;
		}
		/* fall through */
	default:
		dev_kfree_skb(skb);
		break;
	}
}

static int connac_poll_tx(struct napi_struct *napi, int budget)
{
	struct connac_dev *dev;
	int i;

	dev = container_of(napi, struct connac_dev, mt76.tx_napi);

	for (i = MT_TXQ_MCU; i >= 0; i--)
		mt76_queue_tx_cleanup(dev, i, false);

	if (napi_complete_done(napi, 0))
		connac_irq_enable(dev, MT_INT_TX_DONE_ALL);

	for (i = MT_TXQ_MCU; i >= 0; i--)
		mt76_queue_tx_cleanup(dev, i, false);

	tasklet_schedule(&dev->mt76.tx_tasklet);

	return 0;
}

int connac_dma_init(struct connac_dev *dev)
{
	int i, ret;
	static const u8 wmm_queue_map[] = {
		[IEEE80211_AC_BK] = 0,
		[IEEE80211_AC_BE] = 1,
		[IEEE80211_AC_VI] = 2,
		[IEEE80211_AC_VO] = 4,
	};

	mt76_dma_attach(&dev->mt76);

	mt76_wr(dev, MT_WPDMA_GLO_CFG(dev),
		MT_WPDMA_GLO_CFG_TX_WRITEBACK_DONE |
		MT_WPDMA_GLO_CFG_FIFO_LITTLE_ENDIAN |
		MT_WPDMA_GLO_CFG_OMIT_TX_INFO);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG(dev),
		       MT_WPDMA_GLO_CFG_FW_RING_BP_TX_SCH, 0x1);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG(dev),
		       MT_WPDMA_GLO_CFG_TX_BT_SIZE_BIT21, 0x1);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG(dev),
		       MT_WPDMA_GLO_CFG_DMA_BURST_SIZE, 0x3);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG(dev),
		       MT_WPDMA_GLO_CFG_MULTI_DMA_EN, 0x3);

	mt76_wr(dev, MT_WPDMA_RST_IDX(dev), ~0);

	for (i = 0; i < ARRAY_SIZE(wmm_queue_map); i++) {
		ret = connac_init_tx_queue(dev, &dev->mt76.q_tx[i],
					   wmm_queue_map[i],
					   CONNAC_TX_RING_SIZE);
		if (ret)
			return ret;
	}

	ret = connac_init_tx_queue(dev, &dev->mt76.q_tx[MT_TXQ_PSD],
				   CONNAC_TXQ_MGMT, CONNAC_TX_RING_SIZE);
	if (ret)
		return ret;

	ret = connac_init_tx_queue(dev, &dev->mt76.q_tx[MT_TXQ_MCU],
				   CONNAC_TXQ_MCU, CONNAC_TX_MCU_RING_SIZE);
	if (ret)
		return ret;

	ret = connac_init_tx_queue(dev, &dev->mt76.q_tx[MT_TXQ_FWDL],
				   CONNAC_TXQ_FWDL, CONNAC_TX_FWDL_RING_SIZE);
	if (ret)
		return ret;

	/* bcn quueue init,only use for hw queue idx mapping */
	ret = connac_init_tx_queue(dev, &dev->mt76.q_tx[MT_TXQ_BEACON],
				   MT_LMAC_BCN0, CONNAC_TX_RING_SIZE);

	/* init rx queues */
	ret = mt76_queue_alloc(dev, &dev->mt76.q_rx[MT_RXQ_MCU], 1,
			       CONNAC_RX_MCU_RING_SIZE, MT_RX_BUF_SIZE,
			       MT_RX_RING_BASE(dev));
	if (ret)
		return ret;

	ret = mt76_queue_alloc(dev, &dev->mt76.q_rx[MT_RXQ_MAIN], 0,
			       CONNAC_RX_RING_SIZE, MT_RX_BUF_SIZE,
			       MT_RX_RING_BASE(dev));
	if (ret)
		return ret;

	mt76_wr(dev, MT_DELAY_INT_CFG(dev), 0);

	ret = mt76_init_queues(dev);
	if (ret < 0)
		return ret;

	netif_tx_napi_add(&dev->mt76.napi_dev, &dev->mt76.tx_napi,
			  connac_poll_tx, NAPI_POLL_WEIGHT);
	napi_enable(&dev->mt76.tx_napi);

	mt76_poll(dev, MT_WPDMA_GLO_CFG(dev),
		  MT_WPDMA_GLO_CFG_TX_DMA_BUSY |
		  MT_WPDMA_GLO_CFG_RX_DMA_BUSY, 0, 1000);

	/* start dma engine */
	mt76_set(dev, MT_WPDMA_GLO_CFG(dev),
		 MT_WPDMA_GLO_CFG_TX_DMA_EN |
		 MT_WPDMA_GLO_CFG_RX_DMA_EN);

	/* enable interrupts for TX/RX rings */
	connac_irq_enable(dev, MT_INT_RX_DONE_ALL | MT_INT_TX_DONE_ALL);

	return 0;
}

void connac_dma_cleanup(struct connac_dev *dev)
{
	mt76_clear(dev, MT_WPDMA_GLO_CFG(dev),
		   MT_WPDMA_GLO_CFG_TX_DMA_EN |
		   MT_WPDMA_GLO_CFG_RX_DMA_EN);
	mt76_set(dev, MT_WPDMA_GLO_CFG(dev), MT_WPDMA_GLO_CFG_SW_RESET);

	tasklet_kill(&dev->mt76.tx_tasklet);
	mt76_dma_cleanup(&dev->mt76);
}
