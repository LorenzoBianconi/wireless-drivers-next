// SPDX-License-Identifier: ISC
/* Copyright (C) 2020 MediaTek Inc. */

#include "mt7915.h"
#include "eeprom.h"
#include "mcu.h"

/** global debugfs **/

struct hw_queue_map {
	const char *name;
	u8 index;
	u8 pid;
	u8 qid;
};

static int
mt7915_implicit_txbf_set(void *data, u64 val)
{
	struct mt7915_dev *dev = data;

	if (test_bit(MT76_STATE_RUNNING, &dev->mphy.state))
		return -EBUSY;

	dev->ibf = !!val;

	return mt7915_mcu_set_txbf(dev, MT_BF_TYPE_UPDATE);
}

static int
mt7915_implicit_txbf_get(void *data, u64 *val)
{
	struct mt7915_dev *dev = data;

	*val = dev->ibf;

	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(fops_implicit_txbf, mt7915_implicit_txbf_get,
			 mt7915_implicit_txbf_set, "%lld\n");

/* test knob of system layer 1/2 error recovery */
static int mt7915_ser_trigger_set(void *data, u64 val)
{
	enum {
		SER_SET_RECOVER_L1 = 1,
		SER_SET_RECOVER_L2,
		SER_ENABLE = 2,
		SER_RECOVER
	};
	struct mt7915_dev *dev = data;
	int ret = 0;

	switch (val) {
	case SER_SET_RECOVER_L1:
	case SER_SET_RECOVER_L2:
		ret = mt7915_mcu_set_ser(dev, SER_ENABLE, BIT(val), 0);
		if (ret)
			return ret;

		return mt7915_mcu_set_ser(dev, SER_RECOVER, val, 0);
	default:
		break;
	}

	return ret;
}

DEFINE_DEBUGFS_ATTRIBUTE(fops_ser_trigger, NULL,
			 mt7915_ser_trigger_set, "%lld\n");

static int
mt7915_radar_trigger(void *data, u64 val)
{
	struct mt7915_dev *dev = data;

	return mt7915_mcu_rdd_cmd(dev, RDD_RADAR_EMULATE, 1, 0, 0);
}

DEFINE_DEBUGFS_ATTRIBUTE(fops_radar_trigger, NULL,
			 mt7915_radar_trigger, "%lld\n");

static int
mt7915_fw_debug_set(void *data, u64 val)
{
	struct mt7915_dev *dev = data;
	enum {
		DEBUG_TXCMD = 62,
		DEBUG_CMD_RPT_TX,
		DEBUG_CMD_RPT_TRIG,
		DEBUG_SPL,
		DEBUG_RPT_RX,
	} debug;

	dev->fw_debug = !!val;

	mt7915_mcu_fw_log_2_host(dev, dev->fw_debug ? 2 : 0);

	for (debug = DEBUG_TXCMD; debug <= DEBUG_RPT_RX; debug++)
		mt7915_mcu_fw_dbg_ctrl(dev, debug, dev->fw_debug);

	return 0;
}

static int
mt7915_fw_debug_get(void *data, u64 *val)
{
	struct mt7915_dev *dev = data;

	*val = dev->fw_debug;

	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(fops_fw_debug, mt7915_fw_debug_get,
			 mt7915_fw_debug_set, "%lld\n");

static void
mt7915_ampdu_stat_read_phy(struct mt7915_phy *phy,
			   struct seq_file *file)
{
	struct mt7915_dev *dev = file->private;
	bool ext_phy = phy != &dev->phy;
	int bound[15], range[4], i, n;

	if (!phy)
		return;

	/* Tx ampdu stat */
	for (i = 0; i < ARRAY_SIZE(range); i++)
		range[i] = mt76_rr(dev, MT_MIB_ARNG(ext_phy, i));

	for (i = 0; i < ARRAY_SIZE(bound); i++)
		bound[i] = MT_MIB_ARNCR_RANGE(range[i / 4], i % 4) + 1;

	seq_printf(file, "\nPhy %d\n", ext_phy);

	seq_printf(file, "Length: %8d | ", bound[0]);
	for (i = 0; i < ARRAY_SIZE(bound) - 1; i++)
		seq_printf(file, "%3d -%3d | ",
			   bound[i] + 1, bound[i + 1]);

	seq_puts(file, "\nCount:  ");
	n = ext_phy ? ARRAY_SIZE(dev->mt76.aggr_stats) / 2 : 0;
	for (i = 0; i < ARRAY_SIZE(bound); i++)
		seq_printf(file, "%8d | ", dev->mt76.aggr_stats[i + n]);
	seq_puts(file, "\n");

	seq_printf(file, "BA miss count: %d\n", phy->mib.ba_miss_cnt);
}

static void
mt7915_txbf_stat_read_phy(struct mt7915_phy *phy, struct seq_file *s)
{
	struct mt7915_dev *dev = s->private;
	bool ext_phy = phy != &dev->phy;
	static const char * const bw[] = {
		"BW20", "BW40", "BW80", "BW160"
	};
	int cnt;

	if (!phy)
		return;

	/* Tx Beamformer monitor */
	seq_puts(s, "\nTx Beamformer applied PPDU counts: ");

	cnt = mt76_rr(dev, MT_ETBF_TX_APP_CNT(ext_phy));
	seq_printf(s, "iBF: %ld, eBF: %ld\n",
		   FIELD_GET(MT_ETBF_TX_IBF_CNT, cnt),
		   FIELD_GET(MT_ETBF_TX_EBF_CNT, cnt));

	/* Tx Beamformer Rx feedback monitor */
	seq_puts(s, "Tx Beamformer Rx feedback statistics: ");

	cnt = mt76_rr(dev, MT_ETBF_RX_FB_CNT(ext_phy));
	seq_printf(s, "All: %ld, HE: %ld, VHT: %ld, HT: %ld, ",
		   FIELD_GET(MT_ETBF_RX_FB_ALL, cnt),
		   FIELD_GET(MT_ETBF_RX_FB_HE, cnt),
		   FIELD_GET(MT_ETBF_RX_FB_VHT, cnt),
		   FIELD_GET(MT_ETBF_RX_FB_HT, cnt));
	cnt = mt76_rr(dev, MT_ETBF_RX_FB_CONT(ext_phy));
	seq_printf(s, "%s, NC: %ld, NR: %ld\n",
		   bw[FIELD_GET(MT_ETBF_RX_FB_BW, cnt)],
		   FIELD_GET(MT_ETBF_RX_FB_NC, cnt),
		   FIELD_GET(MT_ETBF_RX_FB_NR, cnt));

	/* Tx Beamformee Rx NDPA & Tx feedback report */
	cnt = mt76_rr(dev, MT_ETBF_TX_NDP_BFRP(ext_phy));
	seq_printf(s, "Tx Beamformee successful feedback frames: %ld\n",
		   FIELD_GET(MT_ETBF_TX_FB_CPL, cnt));
	seq_printf(s, "Tx Beamformee feedback triggered counts: %ld\n",
		   FIELD_GET(MT_ETBF_TX_FB_TRI, cnt));

	/* Tx SU & MU counters */
	cnt = mt76_rr(dev, MT_MIB_SDR34(ext_phy));
	seq_printf(s, "Tx multi-user Beamforming counts: %ld\n",
		   FIELD_GET(MT_MIB_MU_BF_TX_CNT, cnt));
	cnt = mt76_rr(dev, MT_MIB_DR8(ext_phy));
	seq_printf(s, "Tx multi-user MPDU counts: %d\n", cnt);
	cnt = mt76_rr(dev, MT_MIB_DR9(ext_phy));
	seq_printf(s, "Tx multi-user successful MPDU counts: %d\n", cnt);
	cnt = mt76_rr(dev, MT_MIB_DR11(ext_phy));
	seq_printf(s, "Tx single-user successful MPDU counts: %d\n", cnt);

	seq_puts(s, "\n");
}

static int
mt7915_tx_stats_show(struct seq_file *file, void *data)
{
	struct mt7915_dev *dev = file->private;
	int stat[8], i, n;

	mt7915_ampdu_stat_read_phy(&dev->phy, file);
	mt7915_txbf_stat_read_phy(&dev->phy, file);

	mt7915_ampdu_stat_read_phy(mt7915_ext_phy(dev), file);
	mt7915_txbf_stat_read_phy(mt7915_ext_phy(dev), file);

	/* Tx amsdu info */
	seq_puts(file, "Tx MSDU statistics:\n");
	for (i = 0, n = 0; i < ARRAY_SIZE(stat); i++) {
		stat[i] = mt76_rr(dev,  MT_PLE_AMSDU_PACK_MSDU_CNT(i));
		n += stat[i];
	}

	for (i = 0; i < ARRAY_SIZE(stat); i++) {
		seq_printf(file, "AMSDU pack count of %d MSDU in TXD: 0x%x ",
			   i + 1, stat[i]);
		if (n != 0)
			seq_printf(file, "(%d%%)\n", stat[i] * 100 / n);
		else
			seq_puts(file, "\n");
	}

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(mt7915_tx_stats);

static void
mt7915_hw_queue_read(struct seq_file *s, u32 base, u32 size,
		     const struct hw_queue_map *map)
{
	struct mt7915_dev *dev = dev_get_drvdata(s->private);
	u32 i, val;

	val = mt76_rr(dev, base + MT_FL_Q_EMPTY);
	for (i = 0; i < size; i++) {
		u32 ctrl, head, tail, queued;

		if (val & BIT(map[i].index))
			continue;

		ctrl = BIT(31) | (map[i].pid << 10) | (map[i].qid << 24);
		mt76_wr(dev, base + MT_FL_Q0_CTRL, ctrl);

		head = mt76_get_field(dev, base + MT_FL_Q2_CTRL,
				      GENMASK(11, 0));
		tail = mt76_get_field(dev, base + MT_FL_Q2_CTRL,
				      GENMASK(27, 16));
		queued = mt76_get_field(dev, base + MT_FL_Q3_CTRL,
					GENMASK(11, 0));

		seq_printf(s, "\t%s: ", map[i].name);
		seq_printf(s, "queued:0x%03x head:0x%03x tail:0x%03x\n",
			   queued, head, tail);
	}
}

static void
mt7915_sta_hw_queue_read(void *data, struct ieee80211_sta *sta)
{
	struct mt7915_sta *msta = (struct mt7915_sta *)sta->drv_priv;
	struct mt7915_dev *dev = msta->vif->phy->dev;
	struct seq_file *s = data;
	u8 ac;

	for (ac = 0; ac < 4; ac++) {
		u32 qlen, ctrl, val;
		u32 idx = msta->wcid.idx >> 5;
		u8 offs = msta->wcid.idx & GENMASK(4, 0);

		ctrl = BIT(31) | BIT(11) | (ac << 24);
		val = mt76_rr(dev, MT_PLE_AC_QEMPTY(ac, idx));

		if (val & BIT(offs))
			continue;

		mt76_wr(dev, MT_PLE_BASE + MT_FL_Q0_CTRL, ctrl | msta->wcid.idx);
		qlen = mt76_get_field(dev, MT_PLE_BASE + MT_FL_Q3_CTRL,
				      GENMASK(11, 0));
		seq_printf(s, "\tSTA %pM wcid %d: AC%d%d queued:%d\n",
			   sta->addr, msta->wcid.idx, msta->vif->wmm_idx,
			   ac, qlen);
	}
}

static int
mt7915_hw_queues_read(struct seq_file *s, void *data)
{
	struct mt7915_dev *dev = dev_get_drvdata(s->private);
	struct mt7915_phy *phy = mt7915_ext_phy(dev);
	static const struct hw_queue_map ple_queue_map[] = {
		{"CPU_Q0",  0,  1, MT_CTX0},
		{"CPU_Q1",  1,  1, MT_CTX0 + 1},
		{"CPU_Q2",  2,  1, MT_CTX0 + 2},
		{"CPU_Q3",  3,  1, MT_CTX0 + 3},
		{"ALTX_Q0", 8,  2, MT_LMAC_ALTX0},
		{"BMC_Q0",  9,  2, MT_LMAC_BMC0},
		{"BCN_Q0",  10, 2, MT_LMAC_BCN0},
		{"PSMP_Q0", 11, 2, MT_LMAC_PSMP0},
		{"ALTX_Q1", 12, 2, MT_LMAC_ALTX0 + 4},
		{"BMC_Q1",  13, 2, MT_LMAC_BMC0 + 4},
		{"BCN_Q1",  14, 2, MT_LMAC_BCN0 + 4},
		{"PSMP_Q1", 15, 2, MT_LMAC_PSMP0 + 4},
	};
	static const struct hw_queue_map pse_queue_map[] = {
		{"CPU Q0",  0,  1, MT_CTX0},
		{"CPU Q1",  1,  1, MT_CTX0 + 1},
		{"CPU Q2",  2,  1, MT_CTX0 + 2},
		{"CPU Q3",  3,  1, MT_CTX0 + 3},
		{"HIF_Q0",  8,  0, MT_HIF0},
		{"HIF_Q1",  9,  0, MT_HIF0 + 1},
		{"HIF_Q2",  10, 0, MT_HIF0 + 2},
		{"HIF_Q3",  11, 0, MT_HIF0 + 3},
		{"HIF_Q4",  12, 0, MT_HIF0 + 4},
		{"HIF_Q5",  13, 0, MT_HIF0 + 5},
		{"LMAC_Q",  16, 2, 0},
		{"MDP_TXQ", 17, 2, 1},
		{"MDP_RXQ", 18, 2, 2},
		{"SEC_TXQ", 19, 2, 3},
		{"SEC_RXQ", 20, 2, 4},
	};
	u32 val, head, tail;

	/* ple queue */
	val = mt76_rr(dev, MT_PLE_FREEPG_CNT);
	head = mt76_get_field(dev, MT_PLE_FREEPG_HEAD_TAIL, GENMASK(11, 0));
	tail = mt76_get_field(dev, MT_PLE_FREEPG_HEAD_TAIL, GENMASK(27, 16));
	seq_puts(s, "PLE page info:\n");
	seq_printf(s, "\tTotal free page: 0x%08x head: 0x%03x tail: 0x%03x\n",
		   val, head, tail);

	val = mt76_rr(dev, MT_PLE_PG_HIF_GROUP);
	head = mt76_get_field(dev, MT_PLE_HIF_PG_INFO, GENMASK(11, 0));
	tail = mt76_get_field(dev, MT_PLE_HIF_PG_INFO, GENMASK(27, 16));
	seq_printf(s, "\tHIF free page: 0x%03x res: 0x%03x used: 0x%03x\n",
		   val, head, tail);

	seq_puts(s, "PLE non-empty queue info:\n");
	mt7915_hw_queue_read(s, MT_PLE_BASE, ARRAY_SIZE(ple_queue_map),
			     &ple_queue_map[0]);

	/* iterate per-sta ple queue */
	ieee80211_iterate_stations_atomic(dev->mphy.hw,
					  mt7915_sta_hw_queue_read, s);
	if (phy)
		ieee80211_iterate_stations_atomic(phy->mt76->hw,
						  mt7915_sta_hw_queue_read, s);

	/* pse queue */
	seq_puts(s, "PSE non-empty queue info:\n");
	mt7915_hw_queue_read(s, MT_PSE_BASE, ARRAY_SIZE(pse_queue_map),
			     &pse_queue_map[0]);

	return 0;
}

static int
mt7915_queues_read(struct seq_file *s, void *data)
{
	struct mt7915_dev *dev = dev_get_drvdata(s->private);
	struct mt76_phy *mphy_ext = dev->mt76.phy2;
	struct mt76_queue *ext_q = mphy_ext ? mphy_ext->q_tx[MT_TXQ_BE] : NULL;
	struct {
		struct mt76_queue *q;
		char *queue;
	} queue_map[] = {
		{ dev->mphy.q_tx[MT_TXQ_BE],	 "WFDMA0" },
		{ ext_q,			 "WFDMA1" },
		{ dev->mphy.q_tx[MT_TXQ_BE],	 "WFDMA0" },
		{ dev->mt76.q_mcu[MT_MCUQ_WM],	 "MCUWM"  },
		{ dev->mt76.q_mcu[MT_MCUQ_WA],	 "MCUWA"  },
		{ dev->mt76.q_mcu[MT_MCUQ_FWDL], "MCUFWQ" },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(queue_map); i++) {
		struct mt76_queue *q = queue_map[i].q;

		if (!q)
			continue;

		seq_printf(s,
			   "%s:	queued=%d head=%d tail=%d\n",
			   queue_map[i].queue, q->queued, q->head,
			   q->tail);
	}

	return 0;
}

static void
mt7915_puts_rate_txpower(struct seq_file *s, struct mt7915_phy *phy)
{
	static const char * const sku_group_name[] = {
		"CCK", "OFDM", "HT20", "HT40",
		"VHT20", "VHT40", "VHT80", "VHT160",
		"RU26", "RU52", "RU106", "RU242/SU20",
		"RU484/SU40", "RU996/SU80", "RU2x996/SU160"
	};
	s8 txpower[MT7915_SKU_RATE_NUM], *buf;
	int i;

	if (!phy)
		return;

	seq_printf(s, "\nBand %d\n", phy != &phy->dev->phy);

	mt7915_mcu_get_txpower_sku(phy, txpower, sizeof(txpower));
	for (i = 0, buf = txpower; i < ARRAY_SIZE(mt7915_sku_group_len); i++) {
		u8 mcs_num = mt7915_sku_group_len[i];

		if (i >= SKU_VHT_BW20 && i <= SKU_VHT_BW160)
			mcs_num = 10;

		mt76_seq_puts_array(s, sku_group_name[i], buf, mcs_num);
		buf += mt7915_sku_group_len[i];
	}
}

static int
mt7915_read_rate_txpower(struct seq_file *s, void *data)
{
	struct mt7915_dev *dev = dev_get_drvdata(s->private);

	mt7915_puts_rate_txpower(s, &dev->phy);
	mt7915_puts_rate_txpower(s, mt7915_ext_phy(dev));

	return 0;
}

int mt7915_init_debugfs(struct mt7915_dev *dev)
{
	struct dentry *dir;

	dir = mt76_register_debugfs(&dev->mt76);
	if (!dir)
		return -ENOMEM;

	debugfs_create_devm_seqfile(dev->mt76.dev, "queues", dir,
				    mt7915_queues_read);
	debugfs_create_devm_seqfile(dev->mt76.dev, "hw-queues", dir,
				    mt7915_hw_queues_read);
	debugfs_create_file("tx_stats", 0400, dir, dev, &mt7915_tx_stats_fops);
	debugfs_create_file("fw_debug", 0600, dir, dev, &fops_fw_debug);
	debugfs_create_file("implicit_txbf", 0600, dir, dev,
			    &fops_implicit_txbf);
	debugfs_create_u32("dfs_hw_pattern", 0400, dir, &dev->hw_pattern);
	/* test knobs */
	debugfs_create_file("radar_trigger", 0200, dir, dev,
			    &fops_radar_trigger);
	debugfs_create_file("ser_trigger", 0200, dir, dev, &fops_ser_trigger);
	debugfs_create_devm_seqfile(dev->mt76.dev, "txpower_sku", dir,
				    mt7915_read_rate_txpower);

	return 0;
}

#ifdef CONFIG_MAC80211_DEBUGFS
/** per-station debugfs **/

static int mt7915_sta_fixed_rate_set(void *data, u64 rate)
{
	struct ieee80211_sta *sta = data;
	struct mt7915_sta *msta = (struct mt7915_sta *)sta->drv_priv;

	/* usage: <he ltf> <tx mode> <ldpc> <stbc> <bw> <gi> <nss> <mcs>
	 * <tx mode>: see enum mt76_phy_type
	 */
	return mt7915_mcu_set_fixed_rate(msta->vif->phy->dev, sta, rate);
}

DEFINE_DEBUGFS_ATTRIBUTE(fops_fixed_rate, NULL,
			 mt7915_sta_fixed_rate_set, "%llx\n");

static int
mt7915_queues_show(struct seq_file *s, void *data)
{
	struct ieee80211_sta *sta = s->private;

	mt7915_sta_hw_queue_read(s, sta);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(mt7915_queues);

void mt7915_sta_add_debugfs(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			    struct ieee80211_sta *sta, struct dentry *dir)
{
	debugfs_create_file("fixed_rate", 0600, dir, sta, &fops_fixed_rate);
	debugfs_create_file("hw-queues", 0400, dir, sta, &mt7915_queues_fops);
}

#endif
