// SPDX-License-Identifier: ISC
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 *         Felix Fietkau <nbd@nbd.name>
 *	   Sean Wang <sean.wang@mediatek.com>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pci.h>

#include "connac.h"
#include "mac.h"
#include "regs.h"
#include "../dma.h"

static int connac_mmio_start(struct ieee80211_hw *hw)
{
	struct connac_dev *dev = hw->priv;

	dev->mphy.survey_time = ktime_get_boottime();
	set_bit(MT76_STATE_RUNNING, &dev->mphy.state);
	ieee80211_queue_delayed_work(mt76_hw(dev), &dev->mt76.mac_work,
				     CONNAC_WATCHDOG_TIME);

	return 0;
}

static void connac_mmio_stop(struct ieee80211_hw *hw)
{
	struct connac_dev *dev = hw->priv;

	clear_bit(MT76_STATE_RUNNING, &dev->mphy.state);
	cancel_delayed_work_sync(&dev->mt76.mac_work);
}

static void
connac_mmio_sta_rate_tbl_update(struct ieee80211_hw *hw,
				struct ieee80211_vif *vif,
				struct ieee80211_sta *sta)
{
	struct connac_dev *dev = hw->priv;
	struct connac_sta *msta = (struct connac_sta *)sta->drv_priv;
	struct ieee80211_sta_rates *sta_rates = rcu_dereference(sta->rates);
	int i;

	spin_lock_bh(&dev->mt76.lock);
	for (i = 0; i < ARRAY_SIZE(msta->rates); i++) {
		msta->rates[i].idx = sta_rates->rate[i].idx;
		msta->rates[i].count = sta_rates->rate[i].count;
		msta->rates[i].flags = sta_rates->rate[i].flags;

		if (msta->rates[i].idx < 0 || !msta->rates[i].count)
			break;
	}
	msta->n_rates = i;
	connac_mac_set_rates(dev, msta, NULL, msta->rates);
	msta->rate_probe = false;
	spin_unlock_bh(&dev->mt76.lock);
}

void connac_tx_complete_skb(struct mt76_dev *mdev, enum mt76_txq_id qid,
			    struct mt76_queue_entry *e)
{
	if (!e->txwi) {
		dev_kfree_skb_any(e->skb);
		return;
	}

	/* error path */
	if (e->skb == DMA_DUMMY_DATA) {
		struct mt76_txwi_cache *t = NULL;

		t = e->txwi;
		e->skb = t ? t->skb : NULL;
	}

	if (e->skb)
		mt76_tx_complete_skb(mdev, e->skb);
}

int connac_tx_prepare_skb(struct mt76_dev *mdev, void *txwi_ptr,
			  enum mt76_txq_id qid, struct mt76_wcid *wcid,
			  struct ieee80211_sta *sta,
			  struct mt76_tx_info *tx_info)
{
	struct connac_dev *dev = container_of(mdev, struct connac_dev, mt76);
	struct connac_sta *msta = container_of(wcid, struct connac_sta, wcid);
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx_info->skb);
	struct ieee80211_key_conf *key = info->control.hw_key;
	int i, pid, id, nbuf = tx_info->nbuf - 1;
	u8 *txwi = (u8 *)txwi_ptr;
	struct mt76_txwi_cache *t;
	struct connac_txp *txp;
	struct txd_ptr_len *txp_ptr_len;

	if (!wcid)
		wcid = &dev->mt76.global_wcid;

	pid = mt76_tx_status_skb_add(mdev, wcid, tx_info->skb);

	if (info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE) {
		spin_lock_bh(&dev->mt76.lock);
		connac_mac_set_rates(dev, msta, &info->control.rates[0],
				     msta->rates);
		msta->rate_probe = true;
		spin_unlock_bh(&dev->mt76.lock);
	}

	connac_mac_write_txwi(dev, txwi_ptr, tx_info->skb, qid, wcid, sta,
			      pid, key);

	txp = (struct connac_txp *)(txwi + MT_TXD_SIZE);

	t = (struct mt76_txwi_cache *)(txwi + mdev->drv->txwi_size);
	t->skb = tx_info->skb;
	//t->nbuf = nbuf;

	/* Write back nbuf to minus 1, for dmad of connac only need one
	 * segment.
	 */
	tx_info->nbuf = nbuf;

	for (i = 0; i < nbuf; i++) {
		txp_ptr_len = &txp->ptr_len[i / 2];
		if ((i & 0x1) == 0x0) {
			txp_ptr_len->u4ptr0 = cpu_to_le32(tx_info->buf[i + 1].addr);
			txp_ptr_len->u2len0 = cpu_to_le16((tx_info->buf[i + 1].len & TXD_LEN_MASK_V2) | TXD_LEN_ML_V2);
		} else {
			txp_ptr_len->u4ptr1 = cpu_to_le32(tx_info->buf[i + 1].addr);
			txp_ptr_len->u2len1 = cpu_to_le16((tx_info->buf[i + 1].len & TXD_LEN_MASK_V2) | TXD_LEN_ML_V2);
		}

		spin_lock_bh(&dev->token_lock);
		id = idr_alloc(&dev->token, t, 0, CONNAC_TOKEN_SIZE,
			       GFP_ATOMIC);
		spin_unlock_bh(&dev->token_lock);
		if (id < 0)
			return id;

		txp->buf[i] = cpu_to_le16(id | TXD_MSDU_ID_VLD);
	}

	tx_info->skb = DMA_DUMMY_DATA;

	return 0;
}

static void connac_phy_init(struct connac_dev *dev)
{
	/* CONNAC : no need */
}

static void connac_irq_enable(struct connac_dev *dev, u32 mask)
{
	mt76_set_irq_mask(&dev->mt76, MT_INT_MASK_CSR, 0, mask);
}

static void connac_irq_disable(struct connac_dev *dev, u32 mask)
{
	mt76_set_irq_mask(&dev->mt76, MT_INT_MASK_CSR, mask, 0);
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

static int
connac_init_tx_queue(struct connac_dev *dev, struct mt76_sw_queue *q,
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

	if (mt76_is_mmio(&dev->mt76))
		connac_irq_enable(dev, MT_INT_TX_DONE(idx));

	return 0;
}

static int
connac_mmio_dma_init(struct connac_dev *dev)
{
	int i, ret;
	static const u8 wmm_queue_map[] = {
		[IEEE80211_AC_BK] = 0,
		[IEEE80211_AC_BE] = 1,
		[IEEE80211_AC_VI] = 2,
		[IEEE80211_AC_VO] = 4,
	};

	mt76_dma_attach(&dev->mt76);

	mt76_wr(dev, MT_WPDMA_GLO_CFG,
		MT_WPDMA_GLO_CFG_TX_WRITEBACK_DONE |
		MT_WPDMA_GLO_CFG_FIFO_LITTLE_ENDIAN |
		MT_WPDMA_GLO_CFG_OMIT_TX_INFO);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG,
		       MT_WPDMA_GLO_CFG_FW_RING_BP_TX_SCH, 0x1);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG,
		       MT_WPDMA_GLO_CFG_TX_BT_SIZE_BIT21, 0x1);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG,
		       MT_WPDMA_GLO_CFG_DMA_BURST_SIZE, 0x3);

	mt76_rmw_field(dev, MT_WPDMA_GLO_CFG,
		       MT_WPDMA_GLO_CFG_MULTI_DMA_EN, 0x3);

	mt76_wr(dev, MT_WPDMA_RST_IDX, ~0);

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
			       MT_RX_RING_BASE);
	if (ret)
		return ret;

	ret = mt76_queue_alloc(dev, &dev->mt76.q_rx[MT_RXQ_MAIN], 0,
			       CONNAC_RX_RING_SIZE, MT_RX_BUF_SIZE,
			       MT_RX_RING_BASE);
	if (ret)
		return ret;

	mt76_wr(dev, MT_DELAY_INT_CFG, 0);

	ret = mt76_init_queues(dev);
	if (ret < 0)
		return ret;

	netif_tx_napi_add(&dev->mt76.napi_dev, &dev->mt76.tx_napi,
			  connac_poll_tx, NAPI_POLL_WEIGHT);
	napi_enable(&dev->mt76.tx_napi);

	mt76_poll(dev, MT_WPDMA_GLO_CFG,
		  MT_WPDMA_GLO_CFG_TX_DMA_BUSY |
		  MT_WPDMA_GLO_CFG_RX_DMA_BUSY, 0, 1000);

	/* start dma engine */
	mt76_set(dev, MT_WPDMA_GLO_CFG,
		 MT_WPDMA_GLO_CFG_TX_DMA_EN |
		 MT_WPDMA_GLO_CFG_RX_DMA_EN);

	/* enable interrupts for TX/RX rings */
	connac_irq_enable(dev, MT_INT_RX_DONE_ALL | MT_INT_TX_DONE_ALL);

	return 0;
}

static irqreturn_t connac_irq_handler(int irq, void *dev_instance)
{
	struct connac_dev *dev = dev_instance;
	u32 intr;

	intr = mt76_rr(dev, MT_INT_SOURCE_CSR);
	mt76_wr(dev, MT_INT_SOURCE_CSR, intr);

	if (!test_bit(MT76_STATE_INITIALIZED, &dev->mphy.state))
		return IRQ_NONE;

	intr &= dev->mt76.mmio.irqmask;

	if (intr & MT_INT_TX_DONE_ALL) {
		connac_irq_disable(dev, MT_INT_TX_DONE_ALL);
		napi_schedule(&dev->mt76.tx_napi);
	}

	if (intr & MT_INT_RX_DONE(0)) {
		connac_irq_disable(dev, MT_INT_RX_DONE(0));
		napi_schedule(&dev->mt76.napi[0]);
	}

	if (intr & MT_INT_RX_DONE(1)) {
		connac_irq_disable(dev, MT_INT_RX_DONE(1));
		napi_schedule(&dev->mt76.napi[1]);
	}

	return IRQ_HANDLED;
}

static int
connac_mmio_dma_sched_init(struct connac_dev *dev)
{
	u32 val;

	val = mt76_rr(dev, MT_HIF_DMA_SHDL_PKT_MAX_SIZE);
	val &= ~(PLE_PKT_MAX_SIZE_MASK | PSE_PKT_MAX_SIZE_MASK);
	val |= PLE_PKT_MAX_SIZE_NUM(0x1);
	val |= PSE_PKT_MAX_SIZE_NUM(0x8);
	mt76_wr(dev, MT_HIF_DMA_SHDL_PKT_MAX_SIZE, val);

	/* Enable refill Control Group 0, 1, 2, 4, 5 */
	mt76_wr(dev, MT_HIF_DMA_SHDL_REFILL_CTRL, 0xffc80000);
	/* Group 0, 1, 2, 4, 5, 15 joint the ask round robin */
	mt76_wr(dev, MT_HIF_DMA_SHDL_OPTION_CTRL, 0x70068037);
	/*Each group min quota must larger then PLE_PKT_MAX_SIZE_NUM*/
	val = MT_DMA_SHDL_MIN_QUOTA_NUM(0x40);
	val |= MT_DMA_SHDL_MAX_QUOTA_NUM(0x800);

	mt76_wr(dev, MT_HIF_DMA_SHDL_GROUP0_CTRL, val);
	mt76_wr(dev, MT_HIF_DMA_SHDL_GROUP1_CTRL, val);
	mt76_wr(dev, MT_HIF_DMA_SHDL_GROUP2_CTRL, val);
	mt76_wr(dev, MT_HIF_DMA_SHDL_GROUP4_CTRL, val);
	val = MT_DMA_SHDL_MIN_QUOTA_NUM(0x40);
	val |= MT_DMA_SHDL_MAX_QUOTA_NUM(0x40);
	mt76_wr(dev, MT_HIF_DMA_SHDL_GROUP5_CTRL, val);

	val = MT_DMA_SHDL_MIN_QUOTA_NUM(0x20);
	val |= MT_DMA_SHDL_MAX_QUOTA_NUM(0x20);
	mt76_wr(dev, MT_HIF_DMA_SHDL_GROUP15_CTRL, val);

	mt76_wr(dev, MT_HIF_DMA_SHDL_Q_MAP0, 0x42104210);
	mt76_wr(dev, MT_HIF_DMA_SHDL_Q_MAP1, 0x42104210);
	/* ALTX0 and ALTX1 QID mapping to group 5 */
	mt76_wr(dev, MT_HIF_DMA_SHDL_Q_MAP2, 0x00050005);
	mt76_wr(dev, MT_HIF_DMA_SHDL_Q_MAP3, 0x0);
	mt76_wr(dev, MT_HIF_DMA_SHDL_SHDL_SET0, 0x6012345f);
	mt76_wr(dev, MT_HIF_DMA_SHDL_SHDL_SET1, 0xedcba987);

	return 0;
}

static void connac_mac_init(struct connac_dev *dev)
{
	bool init_mac1 = dev->mt76.rev == 0x76630010;
	u32 val;

	/* enable band 0 clk */
	mt76_rmw(dev, MT_CFG_CCR,
		 MT_CFG_CCR_MAC_D0_1X_GC_EN | MT_CFG_CCR_MAC_D0_2X_GC_EN,
		 MT_CFG_CCR_MAC_D0_1X_GC_EN | MT_CFG_CCR_MAC_D0_2X_GC_EN);

	/* Hdr translation off*/
	mt76_wr(dev, MT_DMA_DCR0, 0x471000);

	/* CCA Setting */
	val = mt76_rmw(dev, MT_TMAC_TRCR0,
		       MT_TMAC_TRCR_CCA_SEL | MT_TMAC_TRCR_SEC_CCA_SEL,
		       FIELD_PREP(MT_TMAC_TRCR_CCA_SEL, 0x2) |
		       FIELD_PREP(MT_TMAC_TRCR_SEC_CCA_SEL, 0x0));

	mt76_rmw_field(dev, MT_TMAC_CTCR0,
		       MT_TMAC_CTCR0_INS_DDLMT_REFTIME, 0x3f);
	mt76_rmw_field(dev, MT_TMAC_CTCR0,
		       MT_TMAC_CTCR0_INS_DDLMT_DENSITY, 0x3);
	mt76_rmw(dev, MT_TMAC_CTCR0,
		 MT_TMAC_CTCR0_INS_DDLMT_VHT_SMPDU_EN |
		 MT_TMAC_CTCR0_INS_DDLMT_EN,
		 MT_TMAC_CTCR0_INS_DDLMT_VHT_SMPDU_EN |
		 MT_TMAC_CTCR0_INS_DDLMT_EN);
	connac_mcu_set_rts_thresh(dev, 0x92b);

	mt76_rmw(dev, MT_AGG_SCR, MT_AGG_SCR_NLNAV_MID_PTEC_DIS,
		 MT_AGG_SCR_NLNAV_MID_PTEC_DIS);

	connac_mcu_init_mac(dev, 0);

	if (init_mac1)
		connac_mcu_init_mac(dev, 1);

#define RF_LOW_BEACON_BAND0 0x11900
#define RF_LOW_BEACON_BAND1 0x11d00
	mt76_wr(dev, RF_LOW_BEACON_BAND0, 0x200);
	mt76_wr(dev, RF_LOW_BEACON_BAND1, 0x200);
	mt76_wr(dev, 0x7010, 0x8208);
	mt76_wr(dev, 0x44064, 0x2000000);
	mt76_wr(dev, MT_WF_AGG(0x160), 0x5c341c02);
	mt76_wr(dev, MT_WF_AGG(0x164), 0x70708040);

	 /* Disable AMSDU de-aggregation */
	mt76_wr(dev, MT_WF_DMA(0x0), 0x0046f000);
}

static int connac_mmio_init_hardware(struct connac_dev *dev)
{
	u32 base = connac_reg_map(dev, MT_EFUSE_BASE);
	bool init_dbdc = true;
	int ret, idx;

	switch (dev->mt76.rev) {
	case 0x76630010:
		init_dbdc = false;
		break;
	}

	mt76_wr(dev, MT_INT_SOURCE_CSR, ~0);

	spin_lock_init(&dev->token_lock);
	idr_init(&dev->token);

	ret = connac_eeprom_init(dev, base);
	if (ret < 0)
		return ret;

	ret = connac_mmio_dma_init(dev);
	if (ret)
		return ret;

	/* CONNAC : init before f/w download*/
	ret = connac_mmio_dma_sched_init(dev);
	if (ret)
		return ret;

	set_bit(MT76_STATE_INITIALIZED, &dev->mphy.state);

	ret = connac_mcu_init(dev);
	if (ret)
		return ret;

	connac_mcu_set_eeprom(dev);

	if (init_dbdc)
		connac_mcu_dbdc_ctrl(dev);

	connac_mac_init(dev);
	connac_phy_init(dev);

	connac_mcu_ctrl_pm_state(dev, 0);
	/* CONNAC : F/W halWtblClearAllWtbl() will do this in init. */
	/* connac_mcu_del_wtbl_all(dev); */

	/* Beacon and mgmt frames should occupy wcid 0 */
	idx = mt76_wcid_alloc(dev->mt76.wcid_mask, CONNAC_WTBL_STA - 1);
	if (idx)
		return -ENOSPC;

	dev->mt76.global_wcid.idx = idx;
	dev->mt76.global_wcid.hw_key_idx = -1;
	rcu_assign_pointer(dev->mt76.wcid[idx], &dev->mt76.global_wcid);

	return 0;
}

void connac_mmio_rx_poll_complete(struct mt76_dev *mdev,
				  enum mt76_rxq_id q)
{
	struct connac_dev *dev = container_of(mdev, struct connac_dev, mt76);

	connac_irq_enable(dev, MT_INT_RX_DONE(q));
}

int connac_mmio_init_device(struct connac_dev *dev, int irq)
{
	struct ieee80211_hw *hw = mt76_hw(dev);
	int err;

	err = devm_request_irq(dev->mt76.dev, irq, connac_irq_handler,
			       IRQF_SHARED, KBUILD_MODNAME, dev);
	if (err)
		return err;

	err = connac_mmio_init_hardware(dev);
	if (err)
		return err;

	hw->max_tx_fragments = MT_TXP_MAX_BUF_NUM;

	return connac_register_device(dev);
}

static int
connac_mac_wtbl_update_pk(struct connac_dev *dev, struct mt76_wcid *wcid,
			  enum connac_cipher_type cipher, int keyidx,
			  enum set_key_cmd cmd)
{
	u32 addr = connac_mac_wtbl_addr(dev, wcid->idx), w0, w1;

	if (!mt76_poll(dev, MT_WTBL_UPDATE, MT_WTBL_UPDATE_BUSY, 0, 5000))
		return -ETIMEDOUT;

	w0 = mt76_rr(dev, addr);
	w1 = mt76_rr(dev, addr + 4);
	if (cmd == SET_KEY) {
		w0 |= MT_WTBL_W0_RX_KEY_VALID |
		      FIELD_PREP(MT_WTBL_W0_RX_IK_VALID,
				 cipher == MT_CIPHER_BIP_CMAC_128);
		if (cipher != MT_CIPHER_BIP_CMAC_128 ||
		    !wcid->cipher)
			w0 |= FIELD_PREP(MT_WTBL_W0_KEY_IDX, keyidx);
	}  else {
		if (!(wcid->cipher & ~BIT(cipher)))
			w0 &= ~(MT_WTBL_W0_RX_KEY_VALID |
				MT_WTBL_W0_KEY_IDX);
		if (cipher == MT_CIPHER_BIP_CMAC_128)
			w0 &= ~MT_WTBL_W0_RX_IK_VALID;
	}
	mt76_wr(dev, MT_WTBL_RICR0, w0);
	mt76_wr(dev, MT_WTBL_RICR1, w1);

	mt76_wr(dev, MT_WTBL_UPDATE,
		FIELD_PREP(MT_WTBL_UPDATE_WLAN_IDX, wcid->idx) |
		MT_WTBL_UPDATE_RXINFO_UPDATE);

	if (!mt76_poll(dev, MT_WTBL_UPDATE, MT_WTBL_UPDATE_BUSY, 0, 5000))
		return -ETIMEDOUT;

	return 0;
}

static int
connac_mac_wtbl_set_key(struct connac_dev *dev,
			struct mt76_wcid *wcid,
			struct ieee80211_key_conf *key,
			enum set_key_cmd cmd)
{
	u32 addr = connac_mac_wtbl_addr(dev, wcid->idx);
	enum connac_cipher_type cipher;
	int err;

	cipher = connac_mac_get_cipher(key->cipher);
	if (cipher == MT_CIPHER_NONE)
		return -EOPNOTSUPP;

	mutex_lock(&dev->mt76.mutex);

	connac_mac_wtbl_update_cipher(dev, wcid, addr, cipher, cmd);
	err = connac_mac_wtbl_update_key(dev, wcid, addr, key, cipher, cmd);
	if (err < 0)
		goto out;

	err = connac_mac_wtbl_update_pk(dev, wcid, cipher, key->keyidx,
					cmd);
	if (err < 0)
		goto out;

	if (cmd == SET_KEY)
		wcid->cipher |= BIT(cipher);
	else
		wcid->cipher &= ~BIT(cipher);

out:
	mutex_unlock(&dev->mt76.mutex);

	return err;
}

static int
connac_set_key(struct ieee80211_hw *hw, enum set_key_cmd cmd,
	       struct ieee80211_vif *vif, struct ieee80211_sta *sta,
	       struct ieee80211_key_conf *key)
{
	struct connac_vif *mvif = (struct connac_vif *)vif->drv_priv;
	struct connac_dev *dev = hw->priv;
	struct connac_sta *msta;
	int err;

	msta = sta ? (struct connac_sta *)sta->drv_priv : &mvif->sta;
	err = connac_check_key(dev, cmd, vif, &msta->wcid, key);
	if (err < 0)
		return err;

	return connac_mac_wtbl_set_key(dev, &msta->wcid, key, cmd);
}

const struct ieee80211_ops connac_mmio_ops = {
	.tx = connac_tx,
	.start = connac_mmio_start,
	.stop = connac_mmio_stop,
	.add_interface = connac_add_interface,
	.remove_interface = connac_remove_interface,
	.config = connac_config,
	.conf_tx = connac_conf_tx,
	.configure_filter = connac_configure_filter,
	.bss_info_changed = connac_bss_info_changed,
	.sta_state = mt76_sta_state,
	.set_key = connac_set_key,
	.ampdu_action = connac_ampdu_action,
	.set_rts_threshold = connac_set_rts_threshold,
	.wake_tx_queue = mt76_wake_tx_queue,
	.sta_rate_tbl_update = connac_mmio_sta_rate_tbl_update,
	.sw_scan_start = mt76_sw_scan,
	.sw_scan_complete = mt76_sw_scan_complete,
	.release_buffered_frames = mt76_release_buffered_frames,
	.get_txpower = mt76_get_txpower,
	.get_survey = mt76_get_survey,
};

static int __init connac_mmio_init(void)
{
	int ret;

	ret = pci_register_driver(&connac_pci_driver);
	if (ret)
		return ret;

	ret = platform_driver_register(&mt7629_wmac_driver);
	if (ret)
		pci_unregister_driver(&connac_pci_driver);

	return ret;
}

static void __exit connac_mmio_exit(void)
{
	platform_driver_unregister(&mt7629_wmac_driver);
	pci_unregister_driver(&connac_pci_driver);
}

module_init(connac_mmio_init);
module_exit(connac_mmio_exit);
MODULE_LICENSE("Dual BSD/GPL");
