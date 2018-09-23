/*
 * Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
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

#include <linux/kernel.h>

#include "mt76.h"
#include "mt76x02_phy.h"

static u32
mt76x02_tx_power_mask(u8 v1, u8 v2, u8 v3, u8 v4)
{
	u32 val = 0;

	val |= (v1 & (BIT(6) - 1)) << 0;
	val |= (v2 & (BIT(6) - 1)) << 8;
	val |= (v3 & (BIT(6) - 1)) << 16;
	val |= (v4 & (BIT(6) - 1)) << 24;
	return val;
}

int mt76x02_get_max_rate_power(struct mt76_rate_power *r)
{
	s8 ret = 0;
	int i;

	for (i = 0; i < sizeof(r->all); i++)
		ret = max(ret, r->all[i]);

	return ret;
}
EXPORT_SYMBOL_GPL(mt76x02_get_max_rate_power);

void mt76x02_limit_rate_power(struct mt76_rate_power *r, int limit)
{
	int i;

	for (i = 0; i < sizeof(r->all); i++)
		if (r->all[i] > limit)
			r->all[i] = limit;
}
EXPORT_SYMBOL_GPL(mt76x02_limit_rate_power);

void mt76x02_add_rate_power_offset(struct mt76_rate_power *r, int offset)
{
	int i;

	for (i = 0; i < sizeof(r->all); i++)
		r->all[i] += offset;
}
EXPORT_SYMBOL_GPL(mt76x02_add_rate_power_offset);

void mt76x02_phy_set_txpower(struct mt76_dev *dev, int txp_0, int txp_1)
{
	struct mt76_rate_power *t = &dev->rate_power;

	__mt76_rmw_field(dev, MT_TX_ALC_CFG_0, MT_TX_ALC_CFG_0_CH_INIT_0,
			 txp_0);
	__mt76_rmw_field(dev, MT_TX_ALC_CFG_0, MT_TX_ALC_CFG_0_CH_INIT_1,
			 txp_1);

	__mt76_wr(dev, MT_TX_PWR_CFG_0,
		  mt76x02_tx_power_mask(t->cck[0], t->cck[2], t->ofdm[0],
					t->ofdm[2]));
	__mt76_wr(dev, MT_TX_PWR_CFG_1,
		  mt76x02_tx_power_mask(t->ofdm[4], t->ofdm[6], t->ht[0],
					t->ht[2]));
	__mt76_wr(dev, MT_TX_PWR_CFG_2,
		  mt76x02_tx_power_mask(t->ht[4], t->ht[6], t->ht[8],
					t->ht[10]));
	__mt76_wr(dev, MT_TX_PWR_CFG_3,
		  mt76x02_tx_power_mask(t->ht[12], t->ht[14], t->stbc[0],
					t->stbc[2]));
	__mt76_wr(dev, MT_TX_PWR_CFG_4,
		  mt76x02_tx_power_mask(t->stbc[4], t->stbc[6], 0, 0));
	__mt76_wr(dev, MT_TX_PWR_CFG_7,
		  mt76x02_tx_power_mask(t->ofdm[7], t->vht[8], t->ht[7],
					t->vht[9]));
	__mt76_wr(dev, MT_TX_PWR_CFG_8,
		  mt76x02_tx_power_mask(t->ht[14], 0, t->vht[8], t->vht[9]));
	__mt76_wr(dev, MT_TX_PWR_CFG_9,
		  mt76x02_tx_power_mask(t->ht[7], 0, t->stbc[8], t->stbc[9]));
}
EXPORT_SYMBOL_GPL(mt76x02_phy_set_txpower);
