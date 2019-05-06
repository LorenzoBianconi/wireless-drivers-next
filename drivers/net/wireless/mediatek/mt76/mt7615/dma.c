// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 *         Roy Luo <royluo@google.com>
 *         Lorenzo Bianconi <lorenzo@kernel.org>
 *         Felix Fietkau <nbd@nbd.name>
 */

#include "mt7615.h"
#include "../dma.h"
#include "mac.h"

static int
mt7615_init_tx_queues(struct mt7615_dev *dev, int n_desc)
{
	struct mt76_sw_queue *q;
	struct mt76_queue *hwq;
	int err, i;

	hwq = devm_kzalloc(dev->mt76.dev, sizeof(*hwq), GFP_KERNEL);
	if (!hwq)
		return -ENOMEM;

	err = mt76_queue_alloc(dev, hwq, 0, n_desc, 0, MT_TX_RING_BASE);
	if (err < 0)
		return err;

	for (i = 0; i < MT_TXQ_MCU; i++) {
		q = &dev->mt76.q_tx[i];
		INIT_LIST_HEAD(&q->swq);
		q->q = hwq;
	}

	return 0;
}

static int
mt7615_init_mcu_queue(struct mt7615_dev *dev, struct mt76_sw_queue *q,
		      int idx, int n_desc)
{
	struct mt76_queue *hwq;
	int err;

	hwq = devm_kzalloc(dev->mt76.dev, sizeof(*hwq), GFP_KERNEL);
	if (!hwq)
		return -ENOMEM;

	err = mt76_queue_alloc(dev, hwq, idx, n_desc, 0, MT_TX_RING_BASE);
	if (err < 0)
		return err;

	INIT_LIST_HEAD(&q->swq);
	q->q = hwq;

	return 0;
}

void mt7615_queue_rx_skb(struct mt76_dev *mdev, enum mt76_rxq_id q,
			 struct sk_buff *skb)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	__le32 *rxd = (__le32 *)skb->data;
	__le32 *end = (__le32 *)&skb->data[skb->len];
	enum rx_pkt_type type;

	type = FIELD_GET(MT_RXD0_PKT_TYPE, le32_to_cpu(rxd[0]));

	switch (type) {
	case PKT_TYPE_TXS:
		for (rxd++; rxd + 7 <= end; rxd += 7)
			mt7615_mac_add_txs(dev, rxd);
		dev_kfree_skb(skb);
		break;
	case PKT_TYPE_TXRX_NOTIFY:
		mt7615_mac_tx_free(dev, skb);
		break;
	case PKT_TYPE_RX_EVENT:
		mt76_mcu_rx_event(&dev->mt76, skb);
		break;
	case PKT_TYPE_NORMAL:
		if (!mt7615_mac_fill_rx(dev, skb)) {
			mt76_rx(&dev->mt76, q, skb);
			return;
		}
		/* fall through */
	default:
		dev_kfree_skb(skb);
		break;
	}
}

static void mt7615_tx_tasklet(unsigned long data)
{
	struct mt7615_dev *dev = (struct mt7615_dev *)data;

	mt76_txq_schedule_all(&dev->mt76);
}

static int mt7615_poll_tx(struct napi_struct *napi, int budget)
{
	static const u8 queue_map[] = {
		MT_TXQ_MCU,
		MT_TXQ_BE
	};
	struct mt7615_dev *dev;
	int i;

	dev = container_of(napi, struct mt7615_dev, mt76.tx_napi);

	for (i = 0; i < ARRAY_SIZE(queue_map); i++)
		mt76_queue_tx_cleanup(dev, queue_map[i], false);

	if (napi_complete_done(napi, 0))
		mt7615_irq_enable(dev, MT_INT_TX_DONE_ALL);

	for (i = 0; i < ARRAY_SIZE(queue_map); i++)
		mt76_queue_tx_cleanup(dev, queue_map[i], false);

	tasklet_schedule(&dev->mt76.tx_tasklet);

	return 0;
}

static void
mt7615_get_beacon_irq_mask(int hw_idx, u32 *reg, u32 *mask)
{
	switch (hw_idx) {
	case HW_BSSID_1:
		*mask = MT_HW_INT0_TBTT1 | MT_HW_INT0_PRETBTT1;
		break;
	case HW_BSSID_2:
		*mask = MT_HW_INT0_TBTT2 | MT_HW_INT0_PRETBTT2;
		break;
	case HW_BSSID_3:
		*mask = MT_HW_INT0_TBTT3 | MT_HW_INT0_PRETBTT3;
		break;
	case HW_BSSID_0:
	default:
		*mask = MT_HW_INT3_TBTT0 | MT_HW_INT3_PRE_TBTT0;
		break;
	}
	*reg = hw_idx ? MT_HW_INT_MASK(0) : MT_HW_INT_MASK(3);
}

int mt7615_beacon_set_timer(struct mt7615_dev *dev,
			    struct ieee80211_vif *vif,
			    int idx, int hw_idx, int intval)
{
	u32 reg, mask, val, opmode = 0;

	if (hw_idx >= HW_BSSID_MAX)
		return -EINVAL;

	if (idx >= 0) {
		if (intval)
			dev->mt76.beacon_mask |= BIT(idx);
		else
			dev->mt76.beacon_mask &= ~BIT(idx);
	}

	mt7615_get_beacon_irq_mask(hw_idx, &reg, &mask);
	if (!dev->mt76.beacon_mask || (!intval && idx < 0)) {
		mt7615_irq_disable(dev, MT_INT_MAC_IRQ3);
		mt76_clear(dev, reg, mask);
		return 0;
	}

	/* set ARB opmode */
	val = mt76_rr(dev, MT_ARB_SCR);
	if (vif->type == NL80211_IFTYPE_AP) {
		val |= MT_ARB_SCR_BM_CTRL | MT_ARB_SCR_BCN_CTRL |
		       MT_ARB_SCR_BCN_EMPTY;
		opmode = 1;

		mt76_set(dev, MT_LPON_TCR(hw_idx),
			 MT_TSF_TIMER_HW_MODE_TICK_ONLY);
	}
	val |= (opmode << (hw_idx * 2));
	mt76_wr(dev, MT_ARB_SCR, val);

	/* pre-tbtt 5ms */
	mt76_set(dev, MT_LPON_PISR, 0x50 << (8 * hw_idx));

	/* MPTCR */
	val = (MT_TBTT_TIMEUP_EN | MT_TBTT_PERIOD_TIMER_EN |
	       MT_PRETBTT_TIMEUP_EN |
	       MT_PRETBTT_TIMEUP_EN) << ((hw_idx % 2) << 8);
	mt76_set(dev, MT_LPON_MPTCR(2 * (hw_idx / 2)), val);

	/* beacon period */
	mt76_wr(dev, MT_LPON_TTPCR(hw_idx),
		FIELD_PREP(MT_TBTT_PERIOD, intval) | MT_TBTT_CAL_ENABLE);

	/* host irq pin */
	mt76_set(dev, reg, mask);
	mt7615_irq_enable(dev, MT_INT_MAC_IRQ3);

	return 0;
}

int mt7615_dma_init(struct mt7615_dev *dev)
{
	int ret;

	mt76_dma_attach(&dev->mt76);

	tasklet_init(&dev->mt76.tx_tasklet, mt7615_tx_tasklet,
		     (unsigned long)dev);

	mt76_wr(dev, MT_WPDMA_GLO_CFG,
		MT_WPDMA_GLO_CFG_TX_WRITEBACK_DONE |
		MT_WPDMA_GLO_CFG_FIFO_LITTLE_ENDIAN |
		MT_WPDMA_GLO_CFG_FIRST_TOKEN_ONLY |
		MT_WPDMA_GLO_CFG_OMIT_TX_INFO);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG,
		       MT_WPDMA_GLO_CFG_TX_BT_SIZE_BIT0, 0x1);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG,
		       MT_WPDMA_GLO_CFG_TX_BT_SIZE_BIT21, 0x1);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG,
		       MT_WPDMA_GLO_CFG_DMA_BURST_SIZE, 0x3);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG,
		       MT_WPDMA_GLO_CFG_MULTI_DMA_EN, 0x3);

	mt76_wr(dev, MT_WPDMA_GLO_CFG1, 0x1);
	mt76_wr(dev, MT_WPDMA_TX_PRE_CFG, 0xf0000);
	mt76_wr(dev, MT_WPDMA_RX_PRE_CFG, 0xf7f0000);
	mt76_wr(dev, MT_WPDMA_ABT_CFG, 0x4000026);
	mt76_wr(dev, MT_WPDMA_ABT_CFG1, 0x18811881);
	mt76_set(dev, 0x7158, BIT(16));
	mt76_clear(dev, 0x7000, BIT(23));
	mt76_wr(dev, MT_WPDMA_RST_IDX, ~0);

	ret = mt7615_init_tx_queues(dev, MT7615_TX_RING_SIZE);
	if (ret)
		return ret;

	ret = mt7615_init_mcu_queue(dev, &dev->mt76.q_tx[MT_TXQ_MCU],
				    MT7615_TXQ_MCU,
				    MT7615_TX_MCU_RING_SIZE);
	if (ret)
		return ret;

	ret = mt7615_init_mcu_queue(dev, &dev->mt76.q_tx[MT_TXQ_FWDL],
				    MT7615_TXQ_FWDL,
				    MT7615_TX_FWDL_RING_SIZE);
	if (ret)
		return ret;

	/* init rx queues */
	ret = mt76_queue_alloc(dev, &dev->mt76.q_rx[MT_RXQ_MCU], 1,
			       MT7615_RX_MCU_RING_SIZE, MT_RX_BUF_SIZE,
			       MT_RX_RING_BASE);
	if (ret)
		return ret;

	ret = mt76_queue_alloc(dev, &dev->mt76.q_rx[MT_RXQ_MAIN], 0,
			       MT7615_RX_RING_SIZE, MT_RX_BUF_SIZE,
			       MT_RX_RING_BASE);
	if (ret)
		return ret;

	mt76_wr(dev, MT_DELAY_INT_CFG, 0);

	ret = mt76_init_queues(dev);
	if (ret < 0)
		return ret;

	netif_tx_napi_add(&dev->mt76.napi_dev, &dev->mt76.tx_napi,
			  mt7615_poll_tx, NAPI_POLL_WEIGHT);
	napi_enable(&dev->mt76.tx_napi);

	mt76_poll(dev, MT_WPDMA_GLO_CFG,
		  MT_WPDMA_GLO_CFG_TX_DMA_BUSY |
		  MT_WPDMA_GLO_CFG_RX_DMA_BUSY, 0, 1000);

	/* start dma engine */
	mt76_set(dev, MT_WPDMA_GLO_CFG,
		 MT_WPDMA_GLO_CFG_TX_DMA_EN |
		 MT_WPDMA_GLO_CFG_RX_DMA_EN);

	/* enable interrupts for TX/RX rings */
	mt7615_irq_enable(dev, MT_INT_RX_DONE_ALL | MT_INT_TX_DONE_ALL);

	return 0;
}

void mt7615_dma_cleanup(struct mt7615_dev *dev)
{
	mt76_clear(dev, MT_WPDMA_GLO_CFG,
		   MT_WPDMA_GLO_CFG_TX_DMA_EN |
		   MT_WPDMA_GLO_CFG_RX_DMA_EN);
	mt76_set(dev, MT_WPDMA_GLO_CFG, MT_WPDMA_GLO_CFG_SW_RESET);

	tasklet_kill(&dev->mt76.tx_tasklet);
	mt76_dma_cleanup(&dev->mt76);
}
