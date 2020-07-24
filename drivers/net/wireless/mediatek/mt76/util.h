/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
 * Copyright (C) 2004 - 2009 Ivo van Doorn <IvDoorn@gmail.com>
 */

#ifndef __MT76_UTIL_H
#define __MT76_UTIL_H

#include <linux/skbuff.h>
#include <linux/bitops.h>
#include <linux/bitfield.h>

struct mt76_worker
{
	struct task_struct *task;
	void (*fn)(struct mt76_worker *);
	unsigned long state;
};

#define MT76_INCR(_var, _size) \
	(_var = (((_var) + 1) % (_size)))

int mt76_wcid_alloc(u32 *mask, int size);

static inline bool
mt76_wcid_mask_test(u32 *mask, int idx)
{
	return mask[idx / 32] & BIT(idx % 32);
}

static inline void
mt76_wcid_mask_set(u32 *mask, int idx)
{
	mask[idx / 32] |= BIT(idx % 32);
}

static inline void
mt76_wcid_mask_clear(u32 *mask, int idx)
{
	mask[idx / 32] &= ~BIT(idx % 32);
}

static inline void
mt76_skb_set_moredata(struct sk_buff *skb, bool enable)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;

	if (enable)
		hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_MOREDATA);
	else
		hdr->frame_control &= ~cpu_to_le16(IEEE80211_FCTL_MOREDATA);
}

int __mt76_worker_fn(void *ptr);

#define mt76_worker_setup(_dev, _worker, _fn, _name)			\
({									\
	(_worker)->fn = _fn;						\
	(_worker)->task = kthread_create(__mt76_worker_fn, _worker,	\
					 "mt76-%s %s", _name,		\
					 dev_name((_dev)->dev));	\
	PTR_ERR_OR_ZERO((_worker)->task);				\
})

static inline void mt76_worker_schedule(struct mt76_worker *w)
{
	if (!test_and_set_bit(0, &w->state))
		wake_up_process(w->task);
}

static inline void mt76_worker_disable(struct mt76_worker *w)
{
	kthread_park(w->task);
	WRITE_ONCE(w->state, 0);
}

static inline void mt76_worker_enable(struct mt76_worker *w)
{
	kthread_unpark(w->task);
}

static inline void mt76_worker_teardown(struct mt76_worker *w)
{
	kthread_stop(w->task);
}

#endif
