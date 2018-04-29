/*
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

#include "mt76.h"
#include "trace.h"
#include "dma.h"

#define MT_VEND_REQ_MAX_RETRY	10
#define MT_VEND_REQ_TOUT_MS	300

/* should be called with usb_ctrl_mtx locked */
static int __mt76_usb_vendor_request(struct mt76_dev *dev, u8 req,
				     u8 req_type, u16 val, u16 offset,
				     void *buf, size_t len)
{
	struct usb_interface *intf = to_usb_interface(dev->dev);
	struct usb_device *udev = interface_to_usbdev(intf);
	unsigned int pipe;
	int i, ret;

	pipe = (req_type & USB_DIR_IN) ? usb_rcvctrlpipe(udev, 0)
				       : usb_sndctrlpipe(udev, 0);
	for (i = 0; i < MT_VEND_REQ_MAX_RETRY; i++) {
		if (test_bit(MT76_REMOVED, &dev->state))
			return -EIO;

		ret = usb_control_msg(udev, pipe, req, req_type, val,
				      offset, buf, len, MT_VEND_REQ_TOUT_MS);
		if (ret == -ENODEV)
			set_bit(MT76_REMOVED, &dev->state);
		if (ret >= 0 || ret == -ENODEV)
			return ret;
		msleep(5);
	}

	dev_err(dev->dev, "vendor request req:%02x off:%04x failed:%d\n",
		req, offset, ret);
	return ret;
}

int mt76_usb_vendor_request(struct mt76_dev *dev, u8 req,
			    u8 req_type, u16 val, u16 offset,
			    void *buf, size_t len)
{
	int ret;

	mutex_lock(&dev->usb.usb_ctrl_mtx);
	ret = __mt76_usb_vendor_request(dev, req, req_type,
					val, offset, buf, len);
	trace_reg_wr(dev, offset, val);
	mutex_unlock(&dev->usb.usb_ctrl_mtx);

	return ret;
}
EXPORT_SYMBOL_GPL(mt76_usb_vendor_request);

/* should be called with usb_ctrl_mtx locked */
static u32 __mt76_usb_rr(struct mt76_dev *dev, u32 addr)
{
	struct mt76_usb *usb = &dev->usb;
	u32 data = ~0;
	u16 offset;
	int ret;
	u8 req;

	switch (addr & MT_VEND_TYPE_MASK) {
	case MT_VEND_TYPE_EEPROM:
		req = MT_VEND_READ_EEPROM;
		break;
	case MT_VEND_TYPE_CFG:
		req = MT_VEND_READ_CFG;
		break;
	default:
		req = MT_VEND_MULTI_READ;
		break;
	}
	offset = addr & ~MT_VEND_TYPE_MASK;

	ret = __mt76_usb_vendor_request(dev, req,
					USB_DIR_IN | USB_TYPE_VENDOR,
					0, offset, usb->data, sizeof(__le32));
	if (ret == sizeof(__le32))
		data = get_unaligned_le32(usb->data);
	trace_reg_rr(dev, addr, data);

	return data;
}

static u32 mt76_usb_rr(struct mt76_dev *dev, u32 addr)
{
	u32 ret;

	mutex_lock(&dev->usb.usb_ctrl_mtx);
	ret = __mt76_usb_rr(dev, addr);
	mutex_unlock(&dev->usb.usb_ctrl_mtx);

	return ret;
}

/* should be called with usb_ctrl_mtx locked */
static void __mt76_usb_wr(struct mt76_dev *dev, u32 addr, u32 val)
{
	struct mt76_usb *usb = &dev->usb;
	u16 offset;
	u8 req;

	switch (addr & MT_VEND_TYPE_MASK) {
	case MT_VEND_TYPE_CFG:
		req = MT_VEND_WRITE_CFG;
		break;
	default:
		req = MT_VEND_MULTI_WRITE;
		break;
	}
	offset = addr & ~MT_VEND_TYPE_MASK;

	put_unaligned_le32(val, usb->data);
	__mt76_usb_vendor_request(dev, req,
				  USB_DIR_OUT | USB_TYPE_VENDOR, 0,
				  offset, usb->data, sizeof(__le32));
	trace_reg_wr(dev, addr, val);
}

static void mt76_usb_wr(struct mt76_dev *dev, u32 addr, u32 val)
{
	mutex_lock(&dev->usb.usb_ctrl_mtx);
	__mt76_usb_wr(dev, addr, val);
	mutex_unlock(&dev->usb.usb_ctrl_mtx);
}

static u32 mt76_usb_rmw(struct mt76_dev *dev, u32 addr, u32 mask,
			u32 val)
{
	mutex_lock(&dev->usb.usb_ctrl_mtx);
	val |= __mt76_usb_rr(dev, addr) & ~mask;
	__mt76_usb_wr(dev, addr, val);
	mutex_unlock(&dev->usb.usb_ctrl_mtx);

	return val;
}

static void mt76_usb_copy(struct mt76_dev *dev, u32 offset, const void *data,
			  int len)
{
	struct mt76_usb *usb = &dev->usb;
	const __le32 *val = data;
	int i, ret;

	mutex_lock(&usb->usb_ctrl_mtx);
	for (i = 0; i < (len / 4); i++) {
		put_unaligned_le32(val[i], usb->data);
		ret = __mt76_usb_vendor_request(dev, MT_VEND_MULTI_WRITE,
						USB_DIR_OUT | USB_TYPE_VENDOR,
						0, offset + i * 4, usb->data,
						sizeof(__le32));
		if (ret < 0)
			break;
	}
	mutex_unlock(&usb->usb_ctrl_mtx);
}

void mt76_usb_single_wr(struct mt76_dev *dev, const u8 req,
			const u16 offset, const u32 val)
{
	mutex_lock(&dev->usb.usb_ctrl_mtx);
	__mt76_usb_vendor_request(dev, req,
				  USB_DIR_OUT | USB_TYPE_VENDOR,
				  val & 0xffff, offset, NULL, 0);
	__mt76_usb_vendor_request(dev, req,
				  USB_DIR_OUT | USB_TYPE_VENDOR,
				  val >> 16, offset + 2, NULL, 0);
	mutex_unlock(&dev->usb.usb_ctrl_mtx);
}
EXPORT_SYMBOL_GPL(mt76_usb_single_wr);

static int mt76_usb_set_endpoints(struct usb_interface *intf,
				  struct mt76_usb *usb)
{
	struct usb_host_interface *intf_desc = intf->cur_altsetting;
	struct usb_endpoint_descriptor *ep_desc;
	int i, in_ep = 0, out_ep = 0;

	for (i = 0; i < intf_desc->desc.bNumEndpoints; i++) {
		ep_desc = &intf_desc->endpoint[i].desc;

		if (usb_endpoint_is_bulk_in(ep_desc) &&
		    in_ep < __MT_EP_IN_MAX) {
			usb->in_ep[in_ep] = usb_endpoint_num(ep_desc);
			usb->in_max_packet = usb_endpoint_maxp(ep_desc);
			in_ep++;
		} else if (usb_endpoint_is_bulk_out(ep_desc) &&
			   out_ep < __MT_EP_OUT_MAX) {
			usb->out_ep[out_ep] = usb_endpoint_num(ep_desc);
			usb->out_max_packet = usb_endpoint_maxp(ep_desc);
			out_ep++;
		}
	}

	if (in_ep != __MT_EP_IN_MAX || out_ep != __MT_EP_OUT_MAX)
		return -EINVAL;
	return 0;
}

int mt76_usb_buf_alloc(struct mt76_dev *dev, struct mt76_usb_buf *buf,
		       size_t len)
{
	struct usb_interface *intf = to_usb_interface(dev->dev);
	struct usb_device *udev = interface_to_usbdev(intf);

	buf->urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!buf->urb)
		return -ENOMEM;

	buf->buf = usb_alloc_coherent(udev, MT_URB_SIZE, GFP_KERNEL,
				      &buf->dma);
	if (!buf->buf) {
		usb_free_urb(buf->urb);
		return -ENOMEM;
	}
	skb_queue_head_init(&buf->tx_pending);
	buf->len = len;
	buf->dev = dev;

	return 0;
}
EXPORT_SYMBOL_GPL(mt76_usb_buf_alloc);

void mt76_usb_buf_free(struct mt76_dev *dev, struct mt76_usb_buf *buf)
{
	struct usb_interface *intf = to_usb_interface(dev->dev);
	struct usb_device *udev = interface_to_usbdev(intf);
	struct sk_buff_head skbs;

	__skb_queue_head_init(&skbs);
	skb_queue_splice_init(&buf->tx_pending, &skbs);

	usb_free_coherent(udev, MT_URB_SIZE, buf->buf, buf->dma);
	usb_free_urb(buf->urb);

	while (!skb_queue_empty(&skbs)) {
		struct sk_buff *skb = __skb_dequeue(&skbs);

		ieee80211_free_txskb(dev->hw, skb);
	}
}
EXPORT_SYMBOL_GPL(mt76_usb_buf_free);

int mt76_usb_submit_buf(struct mt76_dev *dev, int dir, int index,
			struct mt76_usb_buf *buf, gfp_t gfp,
			usb_complete_t complete_fn, void *context)
{
	struct usb_interface *intf = to_usb_interface(dev->dev);
	struct usb_device *udev = interface_to_usbdev(intf);
	unsigned pipe;

	if (dir == USB_DIR_IN)
		pipe = usb_rcvbulkpipe(udev, dev->usb.in_ep[index]);
	else
		pipe = usb_sndbulkpipe(udev, dev->usb.out_ep[index]);

	usb_fill_bulk_urb(buf->urb, udev, pipe, buf->buf, buf->len,
			  complete_fn, context);
	buf->urb->transfer_dma = buf->dma;
	buf->urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;

	return usb_submit_urb(buf->urb, gfp);
}
EXPORT_SYMBOL_GPL(mt76_usb_submit_buf);

static inline struct mt76_usb_buf
*mt76_usb_get_next_rx_entry(struct mt76_dev *dev)
{
	struct mt76_queue *q = &dev->q_rx[MT_RXQ_MAIN];
	struct mt76_usb_buf *buf = NULL;
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	if (q->head != q->tail) {
		buf = &q->entry[q->head].ubuf;
		q->head = (q->head + 1) % q->ndesc;
	}
	spin_unlock_irqrestore(&q->lock, flags);

	return buf;
}

static int mt76_usb_get_rx_entry_len(u8 *data, u32 data_len)
{
	u16 dma_len, min_len;

	dma_len = get_unaligned_le16(data);
	min_len = MT_DMA_HDR_LEN + MT_RX_RXWI_LEN +
		  MT_FCE_INFO_LEN;

	if (data_len < min_len || WARN_ON(!dma_len) ||
	    WARN_ON(dma_len + MT_DMA_HDR_LEN > data_len) ||
	    WARN_ON(dma_len & 0x3))
		return -EINVAL;
	return dma_len;
}

static int
mt76_usb_process_rx_entry(struct mt76_dev *dev,
			  struct mt76_usb_buf *buf)
{
	int len, data_len = buf->urb->actual_length;
	u8 *data = buf->buf;
	struct sk_buff *skb;

	if (!test_bit(MT76_STATE_INITIALIZED, &dev->state))
		return 0;

	while (data_len > 0) {
		len = mt76_usb_get_rx_entry_len(data, data_len);
		if (len < 0)
			return len;

		skb = dev_alloc_skb(len);
		if (!skb)
			return -ENOMEM;

		data += MT_DMA_HDR_LEN;
		skb_put_data(skb, data, len);

		dev->drv->rx_skb(dev, MT_RXQ_MAIN, skb);

		data_len -= (MT_DMA_HDR_LEN + len + MT_FCE_INFO_LEN);
		data += (len + MT_FCE_INFO_LEN);
	}

	return 0;
}

static void mt76_usb_complete_rx(struct urb *urb)
{
	struct mt76_dev *dev = urb->context;
	struct mt76_queue *q = &dev->q_rx[MT_RXQ_MAIN];
	unsigned long flags;

	if (mt76_usb_urb_error(urb))
		dev_err(dev->dev, "rx urb failed: %d\n", urb->status);

	spin_lock_irqsave(&q->lock, flags);
	if (WARN_ONCE(q->entry[q->tail].ubuf.urb != urb, "rx urb mismatch"))
		goto out;

	q->tail = (q->tail + 1) % q->ndesc;
	tasklet_schedule(&dev->usb.rx_tasklet);
out:
	spin_unlock_irqrestore(&q->lock, flags);
}

static void mt76_usb_rx_tasklet(unsigned long data)
{
	struct mt76_dev *dev = (struct mt76_dev*)data;
	struct mt76_usb_buf *buf;
	int err;

	rcu_read_lock();

	while (true) {
		buf = mt76_usb_get_next_rx_entry(dev);
		if (!buf)
			break;

		mt76_usb_process_rx_entry(dev, buf);
		err = mt76_usb_submit_buf(dev, USB_DIR_IN, MT_EP_IN_PKT_RX,
					  buf, GFP_ATOMIC,
					  mt76_usb_complete_rx, dev);
		if (err < 0)
			break;
	}
	mt76_rx_poll_complete(dev, MT_RXQ_MAIN, NULL);

	rcu_read_unlock();
}

int mt76_usb_alloc_rx(struct mt76_dev *dev)
{
	struct mt76_queue *q = &dev->q_rx[MT_RXQ_MAIN];
	int i, err;

	spin_lock_init(&q->lock);
	q->entry = devm_kzalloc(dev->dev,
				MT_NUM_RX_ENTRIES * sizeof(*q->entry),
				GFP_KERNEL);
	if (!q->entry)
		return -ENOMEM;

	q->ndesc = MT_NUM_RX_ENTRIES;
	for (i = 0; i < q->ndesc; i++) {
		err = mt76_usb_buf_alloc(dev, &q->entry[i].ubuf, MT_URB_SIZE);
		if (err < 0)
			return err;

		err = mt76_usb_submit_buf(dev, USB_DIR_IN, MT_EP_IN_PKT_RX,
					  &q->entry[i].ubuf, GFP_KERNEL,
					  mt76_usb_complete_rx, dev);
		if (err < 0)
			return err;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(mt76_usb_alloc_rx);

void mt76_usb_free_rx(struct mt76_dev *dev)
{
	struct mt76_queue *q = &dev->q_rx[MT_RXQ_MAIN];
	struct mt76_usb_buf *buf;
	int i;

	for (i = 0; i < q->ndesc; i++) {
		buf = &q->entry[i].ubuf;
		if (!buf->urb)
			continue;

		mt76_usb_buf_free(dev, buf);
	}
}
EXPORT_SYMBOL_GPL(mt76_usb_free_rx);

void mt76_usb_stop_rx(struct mt76_dev *dev)
{
	struct mt76_queue *q = &dev->q_rx[MT_RXQ_MAIN];
	int i;

	for (i = 0; i < q->ndesc; i++)
		usb_kill_urb(q->entry[i].ubuf.urb);
}
EXPORT_SYMBOL_GPL(mt76_usb_stop_rx);

static void mt76_usb_tx_tasklet(unsigned long data)
{
	struct mt76_dev *dev = (struct mt76_dev *)data;

	set_bit(MT76_PENDING_STATS, &dev->state);
	dev->drv->tx_complete_skb(dev, NULL, NULL, false);
}

static void mt76_usb_complete_tx(struct urb *urb)
{
	struct mt76_usb_buf *buf = urb->context;
	struct mt76_dev *dev = buf->dev;

	if (mt76_usb_urb_error(urb))
		dev_err(dev->dev, "tx urb failed: %d\n", urb->status);
	buf->done = true;

	tasklet_schedule(&dev->usb.tx_tasklet);
}

static int mt76_usb_tx_queue_skb(struct mt76_dev *dev, struct mt76_queue *q,
				 struct sk_buff *skb, struct mt76_wcid *wcid,
				 struct ieee80211_sta *sta, bool last)
{
	struct mt76_usb_buf *buf = &q->entry[q->tail].ubuf;
	u32 tx_info = last;
	int err;

	if (buf->len + skb->len > MT_URB_SIZE)
		return -ENOSPC;

	err = dev->drv->tx_prepare_skb(dev, NULL, skb, q, wcid, sta, &tx_info);
	if (err < 0)
		return err;

	__skb_queue_tail(&buf->tx_pending, skb);
	memcpy(buf->buf + buf->len, skb->data, skb->len);
	buf->len += skb->len;
	buf->done = false;

	return q->tail;
}

static void mt76_usb_tx_kick(struct mt76_dev *dev, struct mt76_queue *q)
{
	struct mt76_usb_buf *buf = &q->entry[q->tail].ubuf;
	int err;

	err = mt76_usb_submit_buf(dev, USB_DIR_OUT, q2ep(q->hw_idx),
				  buf, GFP_ATOMIC, mt76_usb_complete_tx,
				  buf);
	if (err < 0) {
		if (err == -ENODEV)
			set_bit(MT76_REMOVED, &dev->state);
		else
			dev_err(dev->dev, "tx urb submit failed:%d\n", err);
		return;
	}
	q->tail = (q->tail + 1) % q->ndesc;
	q->queued++;
}

int mt76_usb_alloc_tx(struct mt76_dev *dev)
{
	struct mt76_queue *q;
	int i, j, err;

	for (i = 0; i < IEEE80211_NUM_ACS; i++) {
		q = &dev->q_tx[i];
		spin_lock_init(&q->lock);
		INIT_LIST_HEAD(&q->swq);
		q->hw_idx = q2hwq(i);

		q->entry = devm_kzalloc(dev->dev,
					MT_NUM_TX_ENTRIES * sizeof(*q->entry),
					GFP_KERNEL);
		if (!q->entry)
			return -ENOMEM;

		q->ndesc = MT_NUM_TX_ENTRIES;
		for (j = 0; j < q->ndesc; j++) {
			err = mt76_usb_buf_alloc(dev, &q->entry[j].ubuf, 0);
			if (err < 0)
				return err;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(mt76_usb_alloc_tx);

void mt76_usb_free_tx(struct mt76_dev *dev)
{
	struct mt76_usb_buf *buf;
	struct mt76_queue *q;
	int i, j;

	for (i = 0; i < IEEE80211_NUM_ACS; i++) {
		q = &dev->q_tx[i];
		for (j = 0; j < q->ndesc; j++) {
			buf = &q->entry[j].ubuf;
			if (!buf->urb)
				continue;

			mt76_usb_buf_free(dev, buf);
		}
	}
}
EXPORT_SYMBOL_GPL(mt76_usb_free_tx);

void mt76_usb_stop_tx(struct mt76_dev *dev)
{
	struct mt76_queue *q;
	int i, j;

	for (i = 0; i < IEEE80211_NUM_ACS; i++) {
		q = &dev->q_tx[i];
		for (j = 0; j < q->ndesc; j++)
			usb_kill_urb(q->entry[i].ubuf.urb);
	}
}
EXPORT_SYMBOL_GPL(mt76_usb_stop_tx);

static const struct mt76_queue_ops usb_queue_ops = {
	.tx_queue_skb = mt76_usb_tx_queue_skb,
	.kick = mt76_usb_tx_kick,
};

int mt76_usb_init(struct mt76_dev *dev,
		  struct usb_interface *intf)
{
	static const struct mt76_bus_ops mt76_usb_ops = {
		.rr = mt76_usb_rr,
		.wr = mt76_usb_wr,
		.rmw = mt76_usb_rmw,
		.copy = mt76_usb_copy,
	};
	struct mt76_usb *usb = &dev->usb;

	tasklet_init(&usb->rx_tasklet, mt76_usb_rx_tasklet, (unsigned long)dev);
	tasklet_init(&usb->tx_tasklet, mt76_usb_tx_tasklet, (unsigned long)dev);
	skb_queue_head_init(&dev->rx_skb[MT_RXQ_MAIN]);

	mutex_init(&usb->usb_ctrl_mtx);
	dev->bus = &mt76_usb_ops;
	dev->queue_ops = &usb_queue_ops;

	return mt76_usb_set_endpoints(intf, usb);
}
EXPORT_SYMBOL_GPL(mt76_usb_init);

