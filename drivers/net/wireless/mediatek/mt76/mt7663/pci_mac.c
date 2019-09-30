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

#include "mt7663.h"
#include "mac.h"
#include "regs.h"
#include "../dma.h"

void mt7663_mac_cca_stats_reset(struct mt7663_dev *dev)
{
	mt76_clear(dev, MT_WF_PHY_R0_B0_PHYMUX_5, GENMASK(22, 20));
	mt76_set(dev, MT_WF_PHY_R0_B0_PHYMUX_5, BIT(22) | BIT(20));
}

void mt7663_tx_complete_skb(struct mt76_dev *mdev, enum mt76_txq_id qid,
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

static void
mt7663_write_hw_txp(struct mt7663_dev *dev, struct mt76_tx_info *tx_info,
		    struct mt7663_txp *txp, u32 id)
{
	struct mt7663_txp_ptr *ptr = &txp->ptr[0];
	int i, nbuf = tx_info->nbuf - 1;

	memset(txp, 0, sizeof(*txp));
	tx_info->buf[0].len = MT_TXD_SIZE + sizeof(*txp);
	tx_info->nbuf = 1;

	txp->msdu_id[0] = id | TXD_MSDU_ID_VLD;
	for (i = 0; i < nbuf; i++) {
		u32 addr = tx_info->buf[i + 1].addr;
		u16 len = tx_info->buf[i + 1].len;

		if (i == nbuf - 1)
			len |= TXD_LEN_ML | TXD_LEN_AL;

		if (i & 1) {
			ptr->buf1 = cpu_to_le32(addr);
			ptr->len1 = cpu_to_le16(len);
			ptr++;
		} else {
			ptr->buf0 = cpu_to_le32(addr);
			ptr->len0 = cpu_to_le16(len);
		}
	}
}

int mt7663_tx_prepare_skb(struct mt76_dev *mdev, void *txwi_ptr,
			  enum mt76_txq_id qid, struct mt76_wcid *wcid,
			  struct ieee80211_sta *sta,
			  struct mt76_tx_info *tx_info)
{
	struct mt7663_dev *dev = container_of(mdev, struct mt7663_dev, mt76);
	struct mt7663_sta *msta = container_of(wcid, struct mt7663_sta, wcid);
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx_info->skb);
	struct ieee80211_key_conf *key = info->control.hw_key;
	u8 *txwi = (u8 *)txwi_ptr;
	struct mt76_txwi_cache *t;
	struct mt7663_txp *txp;
	int pid, id;

	if (!wcid)
		wcid = &dev->mt76.global_wcid;

	pid = mt76_tx_status_skb_add(mdev, wcid, tx_info->skb);

	if (info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE) {
		spin_lock_bh(&dev->mt76.lock);
		mt7663_mac_set_rates(dev, msta, &info->control.rates[0],
				     msta->rates);
		msta->rate_probe = true;
		spin_unlock_bh(&dev->mt76.lock);
	}

	t = (struct mt76_txwi_cache *)(txwi + mdev->drv->txwi_size);
	t->skb = tx_info->skb;

	spin_lock_bh(&dev->token_lock);
	id = idr_alloc(&dev->token, t, 0, MT7663_TOKEN_SIZE, GFP_ATOMIC);
	spin_unlock_bh(&dev->token_lock);
	if (id < 0)
		return id;

	mt7663_mac_write_txwi(dev, txwi_ptr, tx_info->skb, qid, wcid, sta,
			      pid, key);

	txp = (struct mt7663_txp *)(txwi + MT_TXD_SIZE);
	mt7663_write_hw_txp(dev, tx_info, txp, id);

	tx_info->skb = DMA_DUMMY_DATA;

	return 0;
}

static int
mt7663_mac_wtbl_update_pk(struct mt7663_dev *dev, struct mt76_wcid *wcid,
			  enum mt7663_cipher_type cipher, int keyidx,
			  enum set_key_cmd cmd)
{
	u32 addr = mt7663_mac_wtbl_addr(dev, wcid->idx), w0, w1;

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

int mt7663_mac_wtbl_set_key(struct mt7663_dev *dev,
			    struct mt76_wcid *wcid,
			    struct ieee80211_key_conf *key,
			    enum set_key_cmd cmd)
{
	u32 addr = mt7663_mac_wtbl_addr(dev, wcid->idx);
	enum mt7663_cipher_type cipher;
	int err;

	cipher = mt7663_mac_get_cipher(key->cipher);
	if (cipher == MT_CIPHER_NONE)
		return -EOPNOTSUPP;

	mutex_lock(&dev->mt76.mutex);

	mt7663_mac_wtbl_update_cipher(dev, wcid, addr, cipher, cmd);
	err = mt7663_mac_wtbl_update_key(dev, wcid, addr, key, cipher, cmd);
	if (err < 0)
		goto out;

	err = mt7663_mac_wtbl_update_pk(dev, wcid, cipher, key->keyidx,
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
