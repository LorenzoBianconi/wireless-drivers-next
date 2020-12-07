// SPDX-License-Identifier: ISC
/* Copyright (C) 2020 MediaTek Inc. */

#include "mt7921.h"
#include "eeprom.h"

/** global debugfs **/

static int
mt7921_fw_debug_set(void *data, u64 val)
{
	struct mt7921_dev *dev = data;
	enum {
		DEBUG_TXCMD = 62,
		DEBUG_CMD_RPT_TX,
		DEBUG_CMD_RPT_TRIG,
		DEBUG_SPL,
		DEBUG_RPT_RX,
	} debug;

	dev->fw_debug = !!val;

	mt7921_mcu_fw_log_2_host(dev, dev->fw_debug ? 2 : 0);

	for (debug = DEBUG_TXCMD; debug <= DEBUG_RPT_RX; debug++)
		mt7921_mcu_fw_dbg_ctrl(dev, debug, dev->fw_debug);

	return 0;
}

static int
mt7921_fw_debug_get(void *data, u64 *val)
{
	struct mt7921_dev *dev = data;

	*val = dev->fw_debug;

	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(fops_fw_debug, mt7921_fw_debug_get,
			 mt7921_fw_debug_set, "%lld\n");

static void
mt7921_ampdu_stat_read_phy(struct mt7921_phy *phy,
			   struct seq_file *file)
{
	struct mt7921_dev *dev = file->private;
	bool ext_phy = phy != &dev->phy;
	int bound[15], range[4], i, n;

	if (!phy)
		return;

	/* Tx ampdu stat */
	for (i = 0; i < ARRAY_SIZE(range); i++)
		range[i] = mt76_rr(dev, MT_MIB_ARNG(ext_phy, i));

	for (i = 0; i < ARRAY_SIZE(bound); i++)
		bound[i] = MT_MIB_ARNCR_RANGE(range[i / 4], i) + 1;

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

static int
mt7921_tx_stats_read(struct seq_file *file, void *data)
{
	struct mt7921_dev *dev = file->private;
	int stat[8], i, n;

	mt7921_ampdu_stat_read_phy(&dev->phy, file);
	mt7921_ampdu_stat_read_phy(mt7921_ext_phy(dev), file);

	/* Tx amsdu info */
	seq_puts(file, "Tx MSDU stat:\n");
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

static int
mt7921_tx_stats_open(struct inode *inode, struct file *f)
{
	return single_open(f, mt7921_tx_stats_read, inode->i_private);
}

static const struct file_operations fops_tx_stats = {
	.open = mt7921_tx_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.owner = THIS_MODULE,
};

static int
mt7921_queues_acq(struct seq_file *s, void *data)
{
	struct mt7921_dev *dev = dev_get_drvdata(s->private);
	int i;

	for (i = 0; i < 16; i++) {
		int j, acs = i / 4, index = i % 4;
		u32 ctrl, val, qlen = 0;

		val = mt76_rr(dev, MT_PLE_AC_QEMPTY(acs, index));
		ctrl = BIT(31) | BIT(15) | (acs << 8);

		for (j = 0; j < 32; j++) {
			if (val & BIT(j))
				continue;

			mt76_wr(dev, MT_PLE_FL_Q0_CTRL,
				ctrl | (j + (index << 5)));
			qlen += mt76_get_field(dev, MT_PLE_FL_Q3_CTRL,
					       GENMASK(11, 0));
		}
		seq_printf(s, "AC%d%d: queued=%d\n", acs, index, qlen);
	}

	return 0;
}

static int
mt7921_queues_read(struct seq_file *s, void *data)
{
	struct mt7921_dev *dev = dev_get_drvdata(s->private);
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

int mt7921_init_debugfs(struct mt7921_dev *dev)
{
	struct dentry *dir;

	dir = mt76_register_debugfs(&dev->mt76);
	if (!dir)
		return -ENOMEM;

	debugfs_create_devm_seqfile(dev->mt76.dev, "queues", dir,
				    mt7921_queues_read);
	debugfs_create_devm_seqfile(dev->mt76.dev, "acq", dir,
				    mt7921_queues_acq);
	debugfs_create_file("tx_stats", 0400, dir, dev, &fops_tx_stats);
	debugfs_create_file("fw_debug", 0600, dir, dev, &fops_fw_debug);

	return 0;
}

#ifdef CONFIG_MAC80211_DEBUGFS
/** per-station debugfs **/

static int
mt7921_sta_stats_read(struct seq_file *s, void *data)
{
	struct ieee80211_sta *sta = s->private;
	struct mt7921_sta *msta = (struct mt7921_sta *)sta->drv_priv;
	struct mt7921_sta_stats *stats = &msta->stats;
	struct rate_info *rate = &stats->prob_rate;
	static const char * const bw[] = {
		"BW20", "BW5", "BW10", "BW40",
		"BW80", "BW160", "BW_HE_RU"
	};

	if (!rate->legacy && !rate->flags)
		return 0;

	seq_puts(s, "Probing rate - ");
	if (rate->flags & RATE_INFO_FLAGS_MCS)
		seq_puts(s, "HT ");
	else if (rate->flags & RATE_INFO_FLAGS_VHT_MCS)
		seq_puts(s, "VHT ");
	else if (rate->flags & RATE_INFO_FLAGS_HE_MCS)
		seq_puts(s, "HE ");
	else
		seq_printf(s, "Bitrate %d\n", rate->legacy);

	if (rate->flags) {
		seq_printf(s, "%s NSS%d MCS%d ",
			   bw[rate->bw], rate->nss, rate->mcs);

		if (rate->flags & RATE_INFO_FLAGS_SHORT_GI)
			seq_puts(s, "SGI ");
		else if (rate->he_gi)
			seq_puts(s, "HE GI ");

		if (rate->he_dcm)
			seq_puts(s, "DCM ");
	}

	seq_printf(s, "\nPPDU PER: %ld.%1ld%%\n",
		   stats->per / 10, stats->per % 10);

	return 0;
}

static int
mt7921_sta_stats_open(struct inode *inode, struct file *f)
{
	return single_open(f, mt7921_sta_stats_read, inode->i_private);
}

static const struct file_operations fops_sta_stats = {
	.open = mt7921_sta_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.owner = THIS_MODULE,
};

void mt7921_sta_add_debugfs(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			    struct ieee80211_sta *sta, struct dentry *dir)
{
	debugfs_create_file("stats", 0400, dir, sta, &fops_sta_stats);
}
#endif
