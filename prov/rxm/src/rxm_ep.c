/*
 * Copyright (c) 2013-2016 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <inttypes.h>
#include <math.h>

#include "ofi.h"
#include <ofi_util.h>

#include "rxm.h"

static int rxm_match_noop(struct dlist_entry *item, const void *arg)
{
	OFI_UNUSED(item);
	OFI_UNUSED(arg);
	return 1;
}

static int rxm_match_recv_entry(struct dlist_entry *item, const void *arg)
{
	struct rxm_recv_match_attr *attr = (struct rxm_recv_match_attr *) arg;
	struct rxm_recv_entry *recv_entry =
		container_of(item, struct rxm_recv_entry, entry);
	return ofi_match_addr(recv_entry->addr, attr->addr);
}

static int rxm_match_recv_entry_tag(struct dlist_entry *item, const void *arg)
{
	struct rxm_recv_match_attr *attr = (struct rxm_recv_match_attr *)arg;
	struct rxm_recv_entry *recv_entry =
		container_of(item, struct rxm_recv_entry, entry);
	return ofi_match_tag(recv_entry->tag, recv_entry->ignore, attr->tag);
}

static int rxm_match_recv_entry_tag_addr(struct dlist_entry *item, const void *arg)
{
	struct rxm_recv_match_attr *attr = (struct rxm_recv_match_attr *)arg;
	struct rxm_recv_entry *recv_entry =
		container_of(item, struct rxm_recv_entry, entry);
	return ofi_match_addr(recv_entry->addr, attr->addr) &&
		ofi_match_tag(recv_entry->tag, recv_entry->ignore, attr->tag);
}

static int rxm_match_recv_entry_context(struct dlist_entry *item, const void *context)
{
	struct rxm_recv_entry *recv_entry =
		container_of(item, struct rxm_recv_entry, entry);
	return recv_entry->context == context;
}

static int rxm_match_unexp_msg(struct dlist_entry *item, const void *arg)
{
	struct rxm_recv_match_attr *attr = (struct rxm_recv_match_attr *)arg;
	struct rxm_unexp_msg *unexp_msg =
		container_of(item, struct rxm_unexp_msg, entry);
	return ofi_match_addr(attr->addr, unexp_msg->addr);
}

static int rxm_match_unexp_msg_tag(struct dlist_entry *item, const void *arg)
{
	struct rxm_recv_match_attr *attr = (struct rxm_recv_match_attr *)arg;
	struct rxm_unexp_msg *unexp_msg =
		container_of(item, struct rxm_unexp_msg, entry);
	return ofi_match_tag(attr->tag, attr->ignore, unexp_msg->tag);
}

static int rxm_match_unexp_msg_tag_addr(struct dlist_entry *item, const void *arg)
{
	struct rxm_recv_match_attr *attr = (struct rxm_recv_match_attr *)arg;
	struct rxm_unexp_msg *unexp_msg =
		container_of(item, struct rxm_unexp_msg, entry);
	return ofi_match_addr(attr->addr, unexp_msg->addr) &&
		ofi_match_tag(attr->tag, attr->ignore, unexp_msg->tag);
}

static inline int
rxm_mr_buf_reg(struct rxm_ep *rxm_ep, void *addr, size_t len, void **context)
{
	int ret = FI_SUCCESS;
	struct fid_mr *mr;
	struct rxm_domain *rxm_domain = container_of(rxm_ep->util_ep.domain,
						     struct rxm_domain, util_domain);

	*context = NULL;
	if (rxm_ep->msg_mr_local) {
		struct fid_domain *msg_domain =
			(struct fid_domain *)rxm_domain->msg_domain;

		ret = fi_mr_reg(msg_domain, addr, len,
				FI_SEND | FI_RECV | FI_READ | FI_WRITE,
				0, 0, 0, &mr, NULL);
		*context = mr;
	}

	return ret;
}

static int rxm_buf_reg(void *pool_ctx, void *addr, size_t len, void **context)
{
	struct rxm_buf_pool *pool = (struct rxm_buf_pool *)pool_ctx;
	size_t i, entry_sz = pool->pool->entry_sz;
	int ret;
	struct rxm_tx_buf *tx_buf;
	struct rxm_rx_buf *rx_buf;
	void *mr_desc;

	if (pool->type != RXM_BUF_POOL_TX_INJECT) {
		ret = rxm_mr_buf_reg(pool->rxm_ep, addr, len, context);
		if (ret)
			return ret;
	} else {
		*context = NULL;
	}

	mr_desc = (*context != NULL) ? fi_mr_desc((struct fid_mr *)*context) : NULL;

	for (i = 0; i < pool->pool->attr.chunk_cnt; i++) {
		if (pool->type == RXM_BUF_POOL_RX) {
			rx_buf = (struct rxm_rx_buf *)((char *)addr + i * entry_sz);
			rx_buf->ep = pool->rxm_ep;
			rx_buf->hdr.desc = mr_desc;
		} else {
			tx_buf = (struct rxm_tx_buf *)((char *)addr + i * entry_sz);
			tx_buf->type = pool->type;
			tx_buf->pkt.ctrl_hdr.version = RXM_CTRL_VERSION;
			tx_buf->pkt.hdr.version = OFI_OP_VERSION;
			tx_buf->hdr.desc = mr_desc;

			switch (pool->type) {
			case RXM_BUF_POOL_RMA:
				tx_buf->pkt.hdr.op = ofi_op_msg;
				/* fall through */
			case RXM_BUF_POOL_TX:
			case RXM_BUF_POOL_TX_INJECT:
				tx_buf->pkt.ctrl_hdr.type = ofi_ctrl_data;
				break;
			case RXM_BUF_POOL_TX_ACK:
				tx_buf->pkt.ctrl_hdr.type = ofi_ctrl_ack;
				tx_buf->pkt.hdr.op = ofi_op_msg;
				break;
			case RXM_BUF_POOL_TX_LMT:
				tx_buf->pkt.ctrl_hdr.type = ofi_ctrl_large_data;
				break;
			case RXM_BUF_POOL_TX_SAR:
				tx_buf->pkt.ctrl_hdr.type = ofi_ctrl_seg_data;
				tx_buf->hdr.state = RXM_SAR_TX;
				break;
			default:
				assert(0);
				break;
			}
		}
	}

	return FI_SUCCESS;
}

static inline void rxm_buf_close(void *pool_ctx, void *context)
{
	struct rxm_buf_pool *pool = (struct rxm_buf_pool *)pool_ctx;
	struct rxm_ep *rxm_ep = pool->rxm_ep;

	if ((rxm_ep->msg_mr_local) && (pool->type != RXM_BUF_POOL_TX_INJECT)) {
		/* We would get a (fid_mr *) in context but
		 * it is safe to cast it into (fid *) */
		fi_close((struct fid *)context);
	}
}

static void rxm_buf_pool_destroy(struct rxm_buf_pool *pool)
{
	/* This indicates whether the pool is allocated or not */
	if (pool->rxm_ep) {
		fastlock_destroy(&pool->lock);
		util_buf_pool_destroy(pool->pool);
	}
}

static int rxm_buf_pool_create(struct rxm_ep *rxm_ep,
			       size_t chunk_count, size_t size,
			       struct rxm_buf_pool *pool,
			       enum rxm_buf_pool_type type)
{
	struct util_buf_attr attr = {
		.size		= size,
		.alignment	= 16,
		.max_cnt	= 0,
		.chunk_cnt	= chunk_count,
		.alloc_hndlr	= rxm_buf_reg,
		.free_hndlr	= rxm_buf_close,
		.ctx		= pool,
		.track_used	= 0,
	};
	int ret;

	pool->rxm_ep = rxm_ep;
	pool->type = type;
	ret = util_buf_pool_create_attr(&attr, &pool->pool);
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "Unable to create buf pool\n");
		return -FI_ENOMEM;
	}
	fastlock_init(&pool->lock);
	return 0;
}

static void rxm_txe_init(struct rxm_tx_entry *entry, void *arg)
{
	struct rxm_send_queue *send_queue = arg;
	entry->ep = send_queue->rxm_ep;
	dlist_init(&entry->deferred_tx_entry);
}

int rxm_send_queue_init(struct rxm_ep *rxm_ep, struct rxm_send_queue **send_queue, size_t size)
{
	*send_queue = calloc(1, sizeof(**send_queue));
	if (!send_queue)
		return -FI_ENOMEM;
	(*send_queue)->rxm_ep = rxm_ep;
	(*send_queue)->fs = rxm_txe_fs_create(size, rxm_txe_init, *send_queue);
	if (!(*send_queue)->fs) {
		free(*send_queue);
		return -FI_ENOMEM;
	}
	fastlock_init(&(*send_queue)->lock);
	return 0;
}

void rxm_send_queue_close(struct rxm_send_queue *send_queue)
{
	if (send_queue->fs) {
		struct rxm_tx_entry *tx_entry;
		ssize_t i;

		for (i = send_queue->fs->size - 1; i >= 0; i--) {
			tx_entry = &send_queue->fs->entry[i].buf;
			if (tx_entry->tx_buf) {
				rxm_tx_buf_release(tx_entry->ep, tx_entry->tx_buf);
				tx_entry->tx_buf = NULL;
			}
		}
		rxm_txe_fs_free(send_queue->fs);
	}
	fastlock_destroy(&send_queue->lock);
	free(send_queue);
}

static void rxm_recv_entry_init(struct rxm_recv_entry *entry, void *arg)
{
	struct rxm_recv_queue *recv_queue = arg;

	assert(recv_queue->type != RXM_RECV_QUEUE_UNSPEC);

	entry->recv_queue = recv_queue;
	entry->sar.msg_id = RXM_SAR_RX_INIT;
	entry->sar.total_recv_len = 0;
	entry->comp_flags = FI_RECV;

	if (recv_queue->type == RXM_RECV_QUEUE_MSG)
		entry->comp_flags |= FI_MSG;
	else
		entry->comp_flags |= FI_TAGGED;
}

static int rxm_recv_queue_init(struct rxm_ep *rxm_ep,  struct rxm_recv_queue *recv_queue,
			       size_t size, enum rxm_recv_queue_type type)
{
	recv_queue->rxm_ep = rxm_ep;
	recv_queue->type = type;
	recv_queue->fs = rxm_recv_fs_create(size, rxm_recv_entry_init, recv_queue);
	if (!recv_queue->fs)
		return -FI_ENOMEM;

	dlist_init(&recv_queue->recv_list);
	dlist_init(&recv_queue->unexp_msg_list);
	if (type == RXM_RECV_QUEUE_MSG) {
		if (rxm_ep->rxm_info->caps & FI_DIRECTED_RECV) {
			recv_queue->match_recv = rxm_match_recv_entry;
			recv_queue->match_unexp = rxm_match_unexp_msg;
		} else {
			recv_queue->match_recv = rxm_match_noop;
			recv_queue->match_unexp = rxm_match_noop;
		}
	} else {
		if (rxm_ep->rxm_info->caps & FI_DIRECTED_RECV) {
			recv_queue->match_recv = rxm_match_recv_entry_tag_addr;
			recv_queue->match_unexp = rxm_match_unexp_msg_tag_addr;
		} else {
			recv_queue->match_recv = rxm_match_recv_entry_tag;
			recv_queue->match_unexp = rxm_match_unexp_msg_tag;
		}
	}
	fastlock_init(&recv_queue->lock);
	return 0;
}

static void rxm_recv_queue_close(struct rxm_recv_queue *recv_queue)
{
	if (recv_queue->fs)
		rxm_recv_fs_free(recv_queue->fs);
	fastlock_destroy(&recv_queue->lock);
	// TODO cleanup recv_list and unexp msg list
}

static int rxm_ep_txrx_pool_create(struct rxm_ep *rxm_ep)
{
	int ret, i;
	size_t queue_sizes[RXM_BUF_POOL_MAX] = {
		rxm_ep->msg_info->rx_attr->size,	/* RX */
		rxm_ep->msg_info->tx_attr->size,	/* TX */
		rxm_ep->msg_info->tx_attr->size,	/* TX INJECT */
		rxm_ep->msg_info->tx_attr->size,	/* TX ACK */
		rxm_ep->msg_info->tx_attr->size,	/* TX LMT */
		rxm_ep->msg_info->tx_attr->size,	/* TX SAR */
		rxm_ep->msg_info->tx_attr->size,	/* RMA */
	};
	size_t entry_sizes[RXM_BUF_POOL_MAX] = {
		rxm_ep->rxm_info->tx_attr->inject_size +
		sizeof(struct rxm_rx_buf),			/* RX */
		rxm_ep->rxm_info->tx_attr->inject_size +
		sizeof(struct rxm_tx_buf),			/* TX */
		rxm_ep->msg_info->tx_attr->inject_size +
		sizeof(struct rxm_tx_buf),			/* TX INJECT */
		sizeof(struct rxm_tx_buf),			/* TX ACK */
		sizeof(struct rxm_rndv_hdr) + rxm_ep->buffered_min +
		sizeof(struct rxm_tx_buf),			/* TX LMT */
		rxm_ep->rxm_info->tx_attr->inject_size +
		sizeof(struct rxm_tx_buf),			/* TX SAR */
		rxm_ep->rxm_info->tx_attr->inject_size +
		sizeof(struct rxm_rma_buf),			/* RMA */
	};

	dlist_init(&rxm_ep->repost_ready_list);

	rxm_ep->buf_pools = calloc(1, RXM_BUF_POOL_MAX * sizeof(*rxm_ep->buf_pools));
	if (!rxm_ep->buf_pools)
		return -FI_ENOMEM;

	for (i = 0; i < RXM_BUF_POOL_MAX; i++) {
		if ((i == RXM_BUF_POOL_TX_INJECT) &&
		    (rxm_ep->util_ep.domain->threading != FI_THREAD_SAFE))
			continue;

		ret = rxm_buf_pool_create(rxm_ep, queue_sizes[i], entry_sizes[i],
					  &rxm_ep->buf_pools[i], i);
		if (ret)
			goto err;
	}

	return FI_SUCCESS;
err:
	while (--i >= RXM_BUF_POOL_START)
		rxm_buf_pool_destroy(&rxm_ep->buf_pools[i]);
	free(rxm_ep->inject_tx_pkt);
	free(rxm_ep->tinject_tx_pkt);
	free(rxm_ep->buf_pools);
	return ret;
}

static void rxm_ep_txrx_pool_destroy(struct rxm_ep *rxm_ep)
{
	size_t i;

	for (i = RXM_BUF_POOL_START; i < RXM_BUF_POOL_MAX; i++)
		rxm_buf_pool_destroy(&rxm_ep->buf_pools[i]);
	free(rxm_ep->buf_pools);
}

static int rxm_ep_txrx_queue_init(struct rxm_ep *rxm_ep)
{
	int ret, param = 1;

	if (!fi_param_get_bool(&rxm_prov, "use_fair_tx_queues", &param) && !param) {
		ret = rxm_send_queue_init(rxm_ep, &rxm_ep->send_queue,
					  rxm_ep->rxm_info->tx_attr->size);
		if (ret)
			return ret;
	}

	ret = rxm_recv_queue_init(rxm_ep, &rxm_ep->recv_queue,
				  rxm_ep->rxm_info->rx_attr->size,
				  RXM_RECV_QUEUE_MSG);
	if (ret)
		goto err_recv;

	ret = rxm_recv_queue_init(rxm_ep, &rxm_ep->trecv_queue,
				  rxm_ep->rxm_info->rx_attr->size,
				  RXM_RECV_QUEUE_TAGGED);
	if (ret)
		goto err_recv_tag;

	return FI_SUCCESS;
err_recv_tag:
	rxm_recv_queue_close(&rxm_ep->recv_queue);
err_recv:
	rxm_send_queue_close(rxm_ep->send_queue);
	return ret;
}

static void rxm_ep_txrx_queue_close(struct rxm_ep *rxm_ep)
{
	if (rxm_ep->send_queue)
		rxm_send_queue_close(rxm_ep->send_queue);
	rxm_recv_queue_close(&rxm_ep->trecv_queue);
	rxm_recv_queue_close(&rxm_ep->recv_queue);
}

static void rxm_ep_txrx_res_close(struct rxm_ep *rxm_ep)
{
	rxm_ep_txrx_queue_close(rxm_ep);
	if (rxm_ep->buf_pools)
		rxm_ep_txrx_pool_destroy(rxm_ep);
	if (rxm_ep->util_ep.domain->threading != FI_THREAD_SAFE) {
		free(rxm_ep->inject_tx_pkt);
		rxm_ep->inject_tx_pkt = NULL;
		free(rxm_ep->tinject_tx_pkt);
		rxm_ep->tinject_tx_pkt = NULL;
	}
}

static int rxm_setname(fid_t fid, void *addr, size_t addrlen)
{
	struct rxm_ep *rxm_ep;

	rxm_ep = container_of(fid, struct rxm_ep, util_ep.ep_fid.fid);
	return fi_setname(&rxm_ep->msg_pep->fid, addr, addrlen);
}

static int rxm_getname(fid_t fid, void *addr, size_t *addrlen)
{
	struct rxm_ep *rxm_ep;

	rxm_ep = container_of(fid, struct rxm_ep, util_ep.ep_fid.fid);
	return fi_getname(&rxm_ep->msg_pep->fid, addr, addrlen);
}

static struct fi_ops_cm rxm_ops_cm = {
	.size = sizeof(struct fi_ops_cm),
	.setname = rxm_setname,
	.getname = rxm_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown,
	.join = fi_no_join,
};

static int rxm_ep_cancel_recv(struct rxm_ep *rxm_ep,
			      struct rxm_recv_queue *recv_queue, void *context)
{
	struct fi_cq_err_entry err_entry;
	struct rxm_recv_entry *recv_entry;
	struct dlist_entry *entry;

	rxm_ep->res_fastlock_acquire(&recv_queue->lock);
	entry = dlist_remove_first_match(&recv_queue->recv_list,
					 rxm_match_recv_entry_context,
					 context);
	rxm_ep->res_fastlock_release(&recv_queue->lock);
	if (entry) {
		recv_entry = container_of(entry, struct rxm_recv_entry, entry);
		memset(&err_entry, 0, sizeof(err_entry));
		err_entry.op_context = recv_entry->context;
		err_entry.flags |= recv_entry->comp_flags;
		err_entry.tag = recv_entry->tag;
		err_entry.err = FI_ECANCELED;
		err_entry.prov_errno = -FI_ECANCELED;
		rxm_recv_entry_release(recv_queue, recv_entry);
		return ofi_cq_write_error(rxm_ep->util_ep.rx_cq, &err_entry);
	}
	return 0;
}

static ssize_t rxm_ep_cancel(fid_t fid_ep, void *context)
{
	struct rxm_ep *rxm_ep = container_of(fid_ep, struct rxm_ep, util_ep.ep_fid);
	int ret;

	ret = rxm_ep_cancel_recv(rxm_ep, &rxm_ep->recv_queue, context);
	if (ret)
		return ret;

	ret = rxm_ep_cancel_recv(rxm_ep, &rxm_ep->trecv_queue, context);
	if (ret)
		return ret;

	return 0;
}

static int rxm_ep_getopt(fid_t fid, int level, int optname, void *optval,
			 size_t *optlen)
{
	struct rxm_ep *rxm_ep =
		container_of(fid, struct rxm_ep, util_ep.ep_fid);

	if (level != FI_OPT_ENDPOINT)
		return -FI_ENOPROTOOPT;

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:
		assert(sizeof(rxm_ep->min_multi_recv_size) == sizeof(size_t));
		*(size_t *)optval = rxm_ep->min_multi_recv_size;
		*optlen = sizeof(size_t);
		break;
	case FI_OPT_BUFFERED_MIN:
		assert(sizeof(rxm_ep->buffered_min) == sizeof(size_t));
		*(size_t *)optval = rxm_ep->buffered_min;
		*optlen = sizeof(size_t);
		break;
	case FI_OPT_BUFFERED_LIMIT:
		assert(sizeof(rxm_ep->buffered_limit) == sizeof(size_t));
		*(size_t *)optval = rxm_ep->buffered_limit;
		*optlen = sizeof(size_t);
		break;
	default:
		return -FI_ENOPROTOOPT;
	}
	return FI_SUCCESS;
}

static int rxm_ep_setopt(fid_t fid, int level, int optname,
			 const void *optval, size_t optlen)
{
	struct rxm_ep *rxm_ep =
		container_of(fid, struct rxm_ep, util_ep.ep_fid);
	int ret = FI_SUCCESS;

	if (level != FI_OPT_ENDPOINT)
		return -FI_ENOPROTOOPT;

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:
		rxm_ep->min_multi_recv_size = *(size_t *)optval;
		break;
	case FI_OPT_BUFFERED_MIN:
		if (rxm_ep->buf_pools) {
			FI_WARN(&rxm_prov, FI_LOG_EP_DATA,
				"Endpoint already enabled. Can't set opt now!\n");
			ret = -FI_EOPBADSTATE;
		} else if (*(size_t *)optval > rxm_ep->buffered_limit) {
			FI_WARN(&rxm_prov, FI_LOG_EP_DATA,
			"Invalid value for FI_OPT_BUFFERED_MIN: %zu "
			"( > FI_OPT_BUFFERED_LIMIT: %zu)\n",
			*(size_t *)optval, rxm_ep->buffered_limit);
			ret = -FI_EINVAL;
		} else {
			rxm_ep->buffered_min = *(size_t *)optval;
		}
		break;
	case FI_OPT_BUFFERED_LIMIT:
		if (rxm_ep->buf_pools) {
			FI_WARN(&rxm_prov, FI_LOG_EP_DATA,
				"Endpoint already enabled. Can't set opt now!\n");
			ret = -FI_EOPBADSTATE;
		/* We do not check for maximum as we allow sizes up to SIZE_MAX */
		} else if (*(size_t *)optval < rxm_ep->buffered_min) {
			FI_WARN(&rxm_prov, FI_LOG_EP_DATA,
			"Invalid value for FI_OPT_BUFFERED_LIMIT: %zu"
			" ( < FI_OPT_BUFFERED_MIN: %zu)\n",
			*(size_t *)optval, rxm_ep->buffered_min);
			ret = -FI_EINVAL;
		} else {
			rxm_ep->buffered_limit = *(size_t *)optval;
		}
		break;
	default:
		ret = -FI_ENOPROTOOPT;
	}
	return ret;
}

static struct fi_ops_ep rxm_ops_ep = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = rxm_ep_cancel,
	.getopt = rxm_ep_getopt,
	.setopt = rxm_ep_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

static int rxm_ep_discard_recv(struct rxm_ep *rxm_ep, struct rxm_rx_buf *rx_buf,
			       void *context)
{
	RXM_DBG_ADDR_TAG(FI_LOG_EP_DATA, "Discarding message",
			 rx_buf->unexp_msg.addr, rx_buf->unexp_msg.tag);

	rxm_ep->res_fastlock_acquire(&rxm_ep->util_ep.lock);
	dlist_insert_tail(&rx_buf->repost_entry,
			  &rx_buf->ep->repost_ready_list);
	rxm_ep->res_fastlock_release(&rxm_ep->util_ep.lock);

	return ofi_cq_write(rxm_ep->util_ep.rx_cq, context, FI_TAGGED | FI_RECV,
			    0, NULL, rx_buf->pkt.hdr.data, rx_buf->pkt.hdr.tag);
}

static int rxm_ep_peek_recv(struct rxm_ep *rxm_ep, fi_addr_t addr, uint64_t tag,
			    uint64_t ignore, void *context, uint64_t flags,
			    struct rxm_recv_queue *recv_queue)
{
	struct rxm_rx_buf *rx_buf;

	RXM_DBG_ADDR_TAG(FI_LOG_EP_DATA, "Peeking message", addr, tag);

	rxm_ep_progress_multi(&rxm_ep->util_ep);

	rxm_ep->res_fastlock_acquire(&recv_queue->lock);

	rx_buf = rxm_check_unexp_msg_list(recv_queue, addr, tag, ignore);
	if (!rx_buf) {
		rxm_ep->res_fastlock_release(&recv_queue->lock);
		FI_DBG(&rxm_prov, FI_LOG_EP_DATA, "Message not found\n");
		return ofi_cq_write_error_peek(rxm_ep->util_ep.rx_cq, tag,
					       context);
	}

	FI_DBG(&rxm_prov, FI_LOG_EP_DATA, "Message found\n");

	if (flags & FI_DISCARD) {
		dlist_remove(&rx_buf->unexp_msg.entry);
		rxm_ep->res_fastlock_release(&recv_queue->lock);
		return rxm_ep_discard_recv(rxm_ep, rx_buf, context);
	}

	if (flags & FI_CLAIM) {
		FI_DBG(&rxm_prov, FI_LOG_EP_DATA, "Marking message for Claim\n");
		((struct fi_context *)context)->internal[0] = rx_buf;
		dlist_remove(&rx_buf->unexp_msg.entry);
	}
	rxm_ep->res_fastlock_release(&recv_queue->lock);

	return ofi_cq_write(rxm_ep->util_ep.rx_cq, context, FI_TAGGED | FI_RECV,
			    rx_buf->pkt.hdr.size, NULL,
			    rx_buf->pkt.hdr.data, rx_buf->pkt.hdr.tag);
}

static inline ssize_t
rxm_ep_format_rx_res(struct rxm_ep *rxm_ep, const struct iovec *iov,
		     void **desc, size_t count, fi_addr_t src_addr,
		     uint64_t tag, uint64_t ignore, void *context,
		     uint64_t flags, struct rxm_recv_queue *recv_queue,
		     struct rxm_recv_entry **recv_entry)
{
	size_t i;

	*recv_entry = rxm_recv_entry_get(recv_queue);
	if (OFI_UNLIKELY(!*recv_entry))
		return -FI_EAGAIN;

	(*recv_entry)->rxm_iov.count 	= (uint8_t)count;
	(*recv_entry)->addr 		= src_addr;
	(*recv_entry)->context 		= context;
	(*recv_entry)->flags 		= flags;
	(*recv_entry)->ignore 		= ignore;
	(*recv_entry)->tag		= tag;

	for (i = 0; i < count; i++) {
		(*recv_entry)->rxm_iov.iov[i].iov_base = iov[i].iov_base;
		(*recv_entry)->total_len +=
			(*recv_entry)->rxm_iov.iov[i].iov_len = iov[i].iov_len;
		if (desc)
			(*recv_entry)->rxm_iov.desc[i] = desc[i];
	}

	(*recv_entry)->multi_recv.len	= (*recv_entry)->total_len;
	(*recv_entry)->multi_recv.buf	= iov[0].iov_base;

	return FI_SUCCESS;
}

static inline ssize_t
rxm_ep_recv_common(struct rxm_ep *rxm_ep, const struct iovec *iov,
		   void **desc, size_t count, fi_addr_t src_addr,
		   uint64_t tag, uint64_t ignore, void *context,
		   uint64_t op_flags, struct rxm_recv_queue *recv_queue)
{
	struct rxm_recv_entry *recv_entry;
	ssize_t ret;

	assert(count <= rxm_ep->rxm_info->rx_attr->iov_limit);

	ret = rxm_ep_format_rx_res(rxm_ep, iov, desc, count, src_addr,
				   tag, ignore, context, op_flags,
				   recv_queue, &recv_entry);
	if (OFI_UNLIKELY(ret))
		return ret;
	FI_DBG(&rxm_prov, FI_LOG_EP_DATA, "Posting recv with length: %zu "
	       "tag: 0x%" PRIx64 " ignore: 0x%" PRIx64 "\n",
	       recv_entry->total_len, recv_entry->tag, recv_entry->ignore);
	return rxm_process_recv_entry(recv_queue, recv_entry);
}

static ssize_t rxm_ep_recv_common_flags(struct rxm_ep *rxm_ep, const struct iovec *iov,
					void **desc, size_t count, fi_addr_t src_addr,
					uint64_t tag, uint64_t ignore, void *context,
					uint64_t flags, uint64_t op_flags,
					struct rxm_recv_queue *recv_queue)
{
	struct rxm_recv_entry *recv_entry;
	struct fi_recv_context *recv_ctx;
	struct rxm_rx_buf *rx_buf;
	ssize_t ret;

	assert(count <= rxm_ep->rxm_info->rx_attr->iov_limit);
	assert(!(flags & FI_PEEK) ||
		(recv_queue->type == RXM_RECV_QUEUE_TAGGED));
	assert(!(flags & (FI_MULTI_RECV)) ||
		(recv_queue->type == RXM_RECV_QUEUE_MSG));

	if (rxm_ep->rxm_info->mode & FI_BUFFERED_RECV) {
		assert(!(flags & FI_PEEK));
		recv_ctx = context;
		context = recv_ctx->context;
		rx_buf = container_of(recv_ctx, struct rxm_rx_buf, recv_context);

		if (flags & FI_CLAIM) {
			FI_DBG(&rxm_prov, FI_LOG_EP_DATA,
			       "Claiming buffered receive\n");
			goto claim;
		}

		assert(flags & FI_DISCARD);
		FI_DBG(&rxm_prov, FI_LOG_EP_DATA, "Discarding buffered receive\n");
		dlist_insert_tail(&rx_buf->repost_entry,
				  &rx_buf->ep->repost_ready_list);
		return 0;
	}

	if (flags & FI_PEEK)
		return rxm_ep_peek_recv(rxm_ep, src_addr, tag, ignore,
					context, flags, recv_queue);

	if (!(flags & FI_CLAIM))
		return rxm_ep_recv_common(rxm_ep, iov, desc, count, src_addr,
					  tag, ignore, context, flags | op_flags,
					  recv_queue);

	rx_buf = ((struct fi_context *)context)->internal[0];
	assert(rx_buf);
	FI_DBG(&rxm_prov, FI_LOG_EP_DATA, "Claim message\n");

	if (flags & FI_DISCARD)
		return rxm_ep_discard_recv(rxm_ep, rx_buf, context);

claim:
	ret = rxm_ep_format_rx_res(rxm_ep, iov, desc, count, src_addr,
				   tag, ignore, context, flags | op_flags,
				   recv_queue, &recv_entry);
	if (OFI_UNLIKELY(ret))
		return ret;

	if (rxm_ep->rxm_info->mode & FI_BUFFERED_RECV)
		recv_entry->comp_flags |= FI_CLAIM;

	rx_buf->recv_entry = recv_entry;
	return rxm_cq_handle_rx_buf(rx_buf);
}

static ssize_t rxm_ep_recvmsg(struct fid_ep *ep_fid, const struct fi_msg *msg,
			       uint64_t flags)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_recv_common_flags(rxm_ep, msg->msg_iov, msg->desc, msg->iov_count,
					msg->addr, 0, 0, msg->context,
					flags, (rxm_ep_rx_flags(rxm_ep) & FI_COMPLETION),
					&rxm_ep->recv_queue);
}

static ssize_t rxm_ep_recv(struct fid_ep *ep_fid, void *buf, size_t len, void *desc,
			    fi_addr_t src_addr, void *context)
{
	struct rxm_ep *rxm_ep =
		container_of(ep_fid, struct rxm_ep, util_ep.ep_fid.fid);
	struct iovec iov = {
		.iov_base	= buf,
		.iov_len	= len,
	};

	return rxm_ep_recv_common(rxm_ep, &iov, &desc, 1, src_addr, 0, 0,
				  context, rxm_ep_rx_flags(rxm_ep),
				  &rxm_ep->recv_queue);
}

static ssize_t rxm_ep_recvv(struct fid_ep *ep_fid, const struct iovec *iov,
		void **desc, size_t count, fi_addr_t src_addr, void *context)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_recv_common(rxm_ep, iov, desc, count, src_addr, 0, 0,
				  context, rxm_ep_rx_flags(rxm_ep),
				  &rxm_ep->recv_queue);
}

static void rxm_rndv_hdr_init(struct rxm_ep *rxm_ep, void *buf,
			      const struct iovec *iov, size_t count,
			      struct fid_mr **mr)
{
	struct rxm_rndv_hdr *rndv_hdr = (struct rxm_rndv_hdr *)buf;
	size_t i;

	for (i = 0; i < count; i++) {
		rndv_hdr->iov[i].addr = RXM_MR_VIRT_ADDR(rxm_ep->msg_info) ?
			(uintptr_t)iov[i].iov_base : 0;
		rndv_hdr->iov[i].len = (uint64_t)iov[i].iov_len;
		rndv_hdr->iov[i].key = fi_mr_key(mr[i]);
	}
	rndv_hdr->count = (uint8_t)count;
}

static inline ssize_t
rxm_ep_inject_send(struct rxm_ep *rxm_ep, struct rxm_conn *rxm_conn,
		   struct rxm_pkt *tx_pkt, size_t pkt_size)
{
	FI_DBG(&rxm_prov, FI_LOG_EP_DATA, "Posting inject with length: %" PRIu64
	       " tag: 0x%" PRIx64 "\n", pkt_size, tx_pkt->hdr.tag);
	ssize_t ret = fi_inject(rxm_conn->msg_ep, tx_pkt, pkt_size, 0);
	if (OFI_LIKELY(!ret)) {
		rxm_cntr_inc(rxm_ep->util_ep.tx_cntr);
	} else {
		FI_DBG(&rxm_prov, FI_LOG_EP_DATA,
		       "fi_inject for MSG provider failed with ret - %" PRId64"\n",
		       ret);
		if (OFI_LIKELY(ret == -FI_EAGAIN))
			rxm_ep_progress_multi(&rxm_ep->util_ep);
	}
	return ret;
}

static inline ssize_t
rxm_ep_normal_send(struct rxm_ep *rxm_ep, struct rxm_conn *rxm_conn,
		   struct rxm_tx_entry *tx_entry, size_t pkt_size)
{
	FI_DBG(&rxm_prov, FI_LOG_EP_DATA, "Posting send with length: %" PRIu64
	       " tag: 0x%" PRIx64 "\n", pkt_size, tx_entry->tx_buf->pkt.hdr.tag);
	return fi_send(rxm_conn->msg_ep, &tx_entry->tx_buf->pkt, pkt_size,
		       tx_entry->tx_buf->hdr.desc, 0, tx_entry);
}

static inline ssize_t
rxm_ep_format_tx_res_lightweight(struct rxm_ep *rxm_ep, struct rxm_conn *rxm_conn,
				 size_t len, uint64_t data, uint64_t flags, uint64_t tag,
				 struct rxm_tx_buf **tx_buf, struct rxm_buf_pool *pool)
{
	*tx_buf = (struct rxm_tx_buf *)rxm_buf_get(pool);
	if (OFI_UNLIKELY(!*tx_buf)) {
		FI_WARN(&rxm_prov, FI_LOG_EP_DATA, "TX queue full!\n");
		return -FI_EAGAIN;
	}

	assert((((*tx_buf)->pkt.ctrl_hdr.type == ofi_ctrl_data) &&
		 (len <= rxm_ep->rxm_info->tx_attr->inject_size)) ||
	       (((*tx_buf)->pkt.ctrl_hdr.type == ofi_ctrl_seg_data)) ||
	       ((*tx_buf)->pkt.ctrl_hdr.type == ofi_ctrl_large_data));

	(*tx_buf)->pkt.ctrl_hdr.conn_id = rxm_conn->handle.remote_key;

	(*tx_buf)->pkt.hdr.size = len;
	(*tx_buf)->pkt.hdr.tag = tag;

	if (flags & FI_REMOTE_CQ_DATA) {
		(*tx_buf)->pkt.hdr.flags |= FI_REMOTE_CQ_DATA;
		(*tx_buf)->pkt.hdr.data = data;
	}

	return FI_SUCCESS;
}

static inline ssize_t
rxm_ep_format_tx_entry(struct rxm_conn *rxm_conn, void *context, uint8_t count,
		       uint64_t flags, uint64_t comp_flags,
		       struct rxm_tx_buf *tx_buf, struct rxm_tx_entry **tx_entry)
{
	*tx_entry = rxm_tx_entry_get(rxm_conn->send_queue);
	if (OFI_UNLIKELY(!*tx_entry))
		return -FI_EAGAIN;
	rxm_fill_tx_entry(rxm_conn, context, count, flags,
			  comp_flags, tx_buf, *tx_entry);
	return FI_SUCCESS;
}

static inline ssize_t
rxm_ep_format_tx_res(struct rxm_ep *rxm_ep, struct rxm_conn *rxm_conn, void *context,
		     uint8_t count, size_t len, uint64_t data, uint64_t flags,
		     uint64_t comp_flags, uint64_t tag, struct rxm_tx_buf **tx_buf,
		     struct rxm_tx_entry **tx_entry, struct rxm_buf_pool *pool)
{
	ssize_t ret;

	ret = rxm_ep_format_tx_res_lightweight(rxm_ep, rxm_conn, len, data,
					       flags, tag, tx_buf, pool);
	if (OFI_UNLIKELY(ret))
		return ret;

	ret = rxm_ep_format_tx_entry(rxm_conn, context, count, flags,
				     comp_flags, *tx_buf, tx_entry);
	if (OFI_UNLIKELY(ret))
		goto err;

	return FI_SUCCESS;
err:
	rxm_tx_buf_release(rxm_ep, *tx_buf);
	*tx_buf = NULL;
	return ret;
}

static inline ssize_t
rxm_ep_alloc_lmt_tx_res(struct rxm_ep *rxm_ep, struct rxm_conn *rxm_conn, void *context,
			uint8_t count, const struct iovec *iov, void **desc, size_t data_len,
			uint64_t data, uint64_t flags, uint64_t comp_flags, uint64_t tag,
			uint8_t op, struct rxm_tx_entry **tx_entry)
{
	struct rxm_tx_buf *tx_buf;
	struct fid_mr **mr_iov;
	ssize_t ret;

	/* Use LMT buf pool instead of buf pool provided to the function */
	ret = rxm_ep_format_tx_res(rxm_ep, rxm_conn, context, (uint8_t)count, data_len,
				   data, flags, comp_flags, tag, &tx_buf, tx_entry,
				   &rxm_ep->buf_pools[RXM_BUF_POOL_TX_LMT]);
	if (OFI_UNLIKELY(ret))
		return ret;
	tx_buf->pkt.hdr.op = op;
	tx_buf->pkt.hdr.flags |= comp_flags;
	tx_buf->pkt.ctrl_hdr.msg_id = rxm_txe_fs_index(rxm_conn->send_queue->fs,
						       (*tx_entry));
	if (!rxm_ep->rxm_mr_local) {
		ret = rxm_ep_msg_mr_regv(rxm_ep, iov, (*tx_entry)->count,
					 FI_REMOTE_READ, (*tx_entry)->mr);
		if (ret)
			goto err;
		mr_iov = (*tx_entry)->mr;
	} else {
		/* desc is msg fid_mr * array */
		mr_iov = (struct fid_mr **)desc;
	}

	rxm_rndv_hdr_init(rxm_ep, &(*tx_entry)->tx_buf->pkt.data, iov,
			  (*tx_entry)->count, mr_iov);

	ret = sizeof(struct rxm_pkt) + sizeof(struct rxm_rndv_hdr);

	if (rxm_ep->rxm_info->mode & FI_BUFFERED_RECV) {
		ofi_copy_from_iov(rxm_pkt_rndv_data(&tx_buf->pkt),
				  rxm_ep->buffered_min, iov, count, 0);
		ret += rxm_ep->buffered_min;
	}
	return ret;
err:
	rxm_tx_entry_release(rxm_conn->send_queue, (*tx_entry));
	rxm_tx_buf_release(rxm_ep, tx_buf);
	return ret;
}

static inline ssize_t
rxm_ep_lmt_tx_send(struct rxm_ep *rxm_ep, struct rxm_conn *rxm_conn,
		   struct rxm_tx_entry *tx_entry, size_t pkt_size)
{
	ssize_t ret;

	RXM_LOG_STATE(FI_LOG_EP_DATA, tx_entry->tx_buf->pkt,
		      RXM_TX, RXM_LMT_TX);
	if (pkt_size <= rxm_ep->msg_info->tx_attr->inject_size) {
		RXM_LOG_STATE(FI_LOG_CQ, tx_entry->tx_buf->pkt,
			      RXM_LMT_TX, RXM_LMT_ACK_WAIT);
		tx_entry->state = RXM_LMT_ACK_WAIT;

		ret = fi_inject(rxm_conn->msg_ep, &tx_entry->tx_buf->pkt, pkt_size, 0);
	} else {
		tx_entry->state = RXM_LMT_TX;

		ret = rxm_ep_normal_send(rxm_ep, rxm_conn, tx_entry, pkt_size);
	}
	if (OFI_UNLIKELY(ret))
		goto err;
	return FI_SUCCESS;
err:
	FI_DBG(&rxm_prov, FI_LOG_EP_DATA,
	       "Transmit for MSG provider failed\n");
	if (!rxm_ep->rxm_mr_local)
		rxm_ep_msg_mr_closev(tx_entry->mr, tx_entry->count);
	rxm_tx_buf_release(rxm_ep, tx_entry->tx_buf);
	rxm_tx_entry_release(rxm_conn->send_queue, tx_entry);
	return ret;
}

static inline size_t
rxm_ep_sar_calc_segs_cnt(struct rxm_ep *rxm_ep, size_t data_len)
{
	return (data_len + rxm_ep->rxm_info->tx_attr->inject_size - 1) /
	       rxm_ep->rxm_info->tx_attr->inject_size;
}

static inline struct rxm_tx_buf *
rxm_ep_sar_tx_prepare_segment(struct rxm_ep *rxm_ep, struct rxm_conn *rxm_conn,
			      size_t total_len, size_t seg_len, size_t seg_no,
			      size_t offset, uint64_t data, uint64_t flags,
			      uint64_t tag, uint64_t comp_flags, uint8_t op,
			      enum rxm_sar_seg_type seg_type,
			      struct rxm_tx_entry *tx_entry)
{
	struct rxm_tx_buf *tx_buf;
	ssize_t ret;

	ret = rxm_ep_format_tx_res_lightweight(rxm_ep, rxm_conn, total_len,
					       data, flags, tag, &tx_buf,
					       &rxm_ep->buf_pools[RXM_BUF_POOL_TX_SAR]);
	if (OFI_UNLIKELY(ret))
		return NULL;

	tx_buf->pkt.hdr.op = op;
	tx_buf->pkt.ctrl_hdr.msg_id = tx_entry->msg_id;
	tx_buf->pkt.ctrl_hdr.seg_size = seg_len;
	tx_buf->pkt.ctrl_hdr.seg_no = seg_no;
	rxm_sar_set_seg_type(&tx_buf->pkt.ctrl_hdr, seg_type);
	assert(offset <= (uint32_t)-1);
	rxm_sar_set_offset(&tx_buf->pkt.ctrl_hdr, offset);

	tx_buf->pkt.hdr.flags |= comp_flags;

	tx_buf->tx_entry = tx_entry;

	ofi_copy_from_iov(tx_buf->pkt.data, seg_len, tx_entry->rxm_iov.iov,
			  tx_entry->rxm_iov.count, tx_entry->iov_offset);
	tx_entry->iov_offset += seg_len;

	return tx_buf;
}

static void
rxm_ep_sar_tx_clenup(struct rxm_ep *rxm_ep, struct rxm_conn *rxm_conn,
		     struct rxm_tx_entry *tx_entry, size_t total_segs_cnt,
		     size_t seg_no)
{
	struct rxm_tx_buf *tx_buf;

	/* Cleanup allocated resources */
	/* TODO: handle multi-threaded case */
	while (!dlist_empty(&tx_entry->deferred_tx_buf_list)) {
		dlist_pop_front(&tx_entry->deferred_tx_buf_list,
				struct rxm_tx_buf, tx_buf, hdr.entry);
		rxm_tx_buf_release(tx_entry->ep, tx_buf);
	}
	if (!dlist_empty(&tx_entry->deferred_tx_entry))
		rxm_ep_dequeue_deferred_tx_queue(tx_entry);
	/* TX entry will be released in the rxm_finish_sar_segment_send() */
	tx_entry->msg_id = RXM_SAR_TX_ERROR;
	/* Updates TX entry's `fail_segs_cnt` field to the value that's should
	 * be used by `rxm_finish_sar_segment_send()` to finish SAR operation.
	 * This value indicates how many segments can't be sent and we should
	 * awaiting of completions for all segments have to be end up */
	tx_entry->fail_segs_cnt = total_segs_cnt - seg_no;
	if (!(tx_entry->segs_left - tx_entry->fail_segs_cnt)) {
		/* If we don't have outgoing SAR segemnts,
		 * release TX entry here */
		rxm_tx_entry_release(rxm_conn->send_queue, tx_entry);
	}
}

static inline ssize_t
rxm_ep_sar_tx_prepare_and_send_segment(struct rxm_ep *rxm_ep, struct rxm_conn *rxm_conn,
				       size_t data_len, size_t *remain_len, size_t seg_len,
				       size_t seg_no, size_t total_segs_cnt, size_t offset,
				       uint64_t data, uint64_t flags, uint64_t tag,
				       uint64_t comp_flags, uint8_t op,
				       enum rxm_sar_seg_type seg_type,
				       struct rxm_tx_entry *tx_entry)
{
	struct rxm_tx_buf *tx_buf;
	ssize_t ret;

	tx_buf = rxm_ep_sar_tx_prepare_segment(rxm_ep, rxm_conn, data_len,
					       seg_len, seg_no, offset, data,
					       flags, tag, comp_flags, op,
					       seg_type, tx_entry);
	if (OFI_UNLIKELY(!tx_buf)) {
		rxm_ep_sar_tx_clenup(rxm_ep, rxm_conn, tx_entry,
				     total_segs_cnt, seg_no);
		return -FI_EAGAIN;
	}

	if (!dlist_empty(&tx_entry->deferred_tx_buf_list)) {
		dlist_insert_tail(&tx_buf->hdr.entry,
				  &tx_entry->deferred_tx_buf_list);
		*remain_len -= seg_len;
		return FI_SUCCESS;
	}

	ret = fi_send(rxm_conn->msg_ep, &tx_buf->pkt,
		      sizeof(struct rxm_pkt) + tx_buf->pkt.ctrl_hdr.seg_size,
		      tx_buf->hdr.desc, 0, tx_buf);
	if (OFI_UNLIKELY(ret)) {
		if (OFI_UNLIKELY(ret != -FI_EAGAIN)) {
			rxm_ep_sar_tx_clenup(rxm_ep, rxm_conn, tx_entry,
				     total_segs_cnt, seg_no);
			return ret;
		}
		if (seg_type == RXM_SAR_SEG_FIRST) {
			/* if the sending for the first segment fails,
			 * release resources and report this to user */
			rxm_tx_buf_release(tx_entry->ep, tx_buf);
			rxm_tx_entry_release(rxm_conn->send_queue, tx_entry);
			return -FI_EAGAIN;
		}
		dlist_insert_tail(&tx_buf->hdr.entry,
				  &tx_entry->deferred_tx_buf_list);
		rxm_ep_enqueue_deferred_tx_queue(tx_entry);
	}
	*remain_len -= seg_len;
	return FI_SUCCESS;
}

static inline ssize_t
rxm_ep_sar_tx_send(struct rxm_ep *rxm_ep, struct rxm_conn *rxm_conn, void *context,
		   uint8_t count, const struct iovec *iov, size_t data_len,
		   size_t segs_cnt, uint64_t data, uint64_t flags,
		   uint64_t comp_flags, uint64_t tag, uint8_t op)
{
	struct rxm_tx_entry *tx_entry;
	size_t i, remain_len = data_len;
	ssize_t ret;

	ret = rxm_ep_format_tx_entry(rxm_conn, context, count, flags,
				     comp_flags, NULL, &tx_entry);
	if (OFI_UNLIKELY(ret))
		return ret;

	dlist_init(&tx_entry->deferred_tx_buf_list);
	tx_entry->iov_offset = 0;
	for (i = 0; i < count; i++)
		tx_entry->rxm_iov.iov[i] = iov[i];

	tx_entry->rxm_iov.count = count;
	tx_entry->msg_id = rxm_txe_fs_index(rxm_conn->send_queue->fs, tx_entry);
	tx_entry->segs_left = segs_cnt;
	tx_entry->fail_segs_cnt = 0;
	tx_entry->state = RXM_SAR_TX;

	assert(tx_entry->segs_left >= 2);

	ret = rxm_ep_sar_tx_prepare_and_send_segment(
				rxm_ep, rxm_conn, data_len, &remain_len,
				rxm_ep->rxm_info->tx_attr->inject_size,
				0, segs_cnt, data_len - remain_len,
				data, flags, tag, comp_flags, op,
				RXM_SAR_SEG_FIRST, tx_entry);
	if (OFI_UNLIKELY(ret))
		return ret;

	for (i = 1; i < segs_cnt - 1; i++) {
		ret = rxm_ep_sar_tx_prepare_and_send_segment(
					rxm_ep, rxm_conn, data_len, &remain_len,
					rxm_ep->rxm_info->tx_attr->inject_size, i,
					segs_cnt, data_len - remain_len, data, flags, tag,
					comp_flags, op, RXM_SAR_SEG_MIDDLE, tx_entry);
		if (OFI_UNLIKELY(ret))
			return ret;
	}


	ret = rxm_ep_sar_tx_prepare_and_send_segment(
				rxm_ep, rxm_conn, data_len, &remain_len, remain_len,
				segs_cnt - 1, segs_cnt, data_len - remain_len, data,
				flags, tag, comp_flags, op, RXM_SAR_SEG_LAST, tx_entry);
	if (OFI_UNLIKELY(ret))
		return ret;

	assert(!remain_len);

	return 0;
}

void rxm_ep_sar_handle_send_segment_failure(struct rxm_tx_entry *tx_entry, ssize_t ret)
{
	struct rxm_tx_buf *tx_buf;

	rxm_cq_write_error(tx_entry->ep->util_ep.tx_cq,
			   tx_entry->ep->util_ep.tx_cntr,
			   tx_entry->context, ret);
	while (!dlist_empty(&tx_entry->deferred_tx_buf_list)) {
		tx_buf = container_of(tx_entry->deferred_tx_buf_list.next,
				      struct rxm_tx_buf, hdr.entry);
		dlist_remove(&tx_buf->hdr.entry);
	}
	rxm_ep_dequeue_deferred_tx_queue(tx_entry);
	rxm_tx_entry_release(tx_entry->conn->send_queue, tx_entry);
}

static inline void
rxm_ep_fill_tx_inject_buf(const void *buf, size_t len, uint8_t op,
			  uint64_t comp_flags, struct rxm_tx_buf *tx_buf)
{
	tx_buf->pkt.hdr.op = op;
	tx_buf->pkt.hdr.flags |= comp_flags;
	memcpy(tx_buf->pkt.data, buf, len);
}

static inline ssize_t
rxm_ep_format_tx_inject_buf(struct rxm_ep *rxm_ep, struct rxm_conn *rxm_conn,
			    const void *buf, size_t len, uint64_t data,
			    uint64_t flags, uint64_t tag, uint8_t op,
			    uint64_t comp_flags, struct rxm_tx_buf **tx_buf)
{
	if (OFI_UNLIKELY(rxm_ep_format_tx_res_lightweight(
				rxm_ep, rxm_conn, len, data, flags, tag, tx_buf,
				&rxm_ep->buf_pools[RXM_BUF_POOL_TX_INJECT]))) {
		return -FI_EAGAIN;
	}
	rxm_ep_fill_tx_inject_buf(buf, len, op, comp_flags, *tx_buf);
	return 0;
}

static inline void
rxm_ep_fill_tx_inject_iov(const struct iovec *iov, size_t count, uint8_t op,
			  uint64_t comp_flags, struct rxm_tx_buf *tx_buf)
{
	tx_buf->pkt.hdr.op = op;
	tx_buf->pkt.hdr.flags |= comp_flags;
	ofi_copy_from_iov(tx_buf->pkt.data, tx_buf->pkt.hdr.size,
			  iov, count, 0);
}

static inline ssize_t
rxm_ep_format_tx_inject_iov(struct rxm_ep *rxm_ep, struct rxm_conn *rxm_conn,
			    size_t len, const struct iovec *iov, size_t count,
			    uint64_t data, uint64_t flags, uint64_t tag,
			    uint8_t op, uint64_t comp_flags, struct rxm_tx_buf **tx_buf)
{
	if (OFI_UNLIKELY(rxm_ep_format_tx_res_lightweight(
				rxm_ep, rxm_conn, len, data, flags, tag, tx_buf,
				&rxm_ep->buf_pools[RXM_BUF_POOL_TX_INJECT]))) {
		return -FI_EAGAIN;
	}
	rxm_ep_fill_tx_inject_iov(iov, count, op, comp_flags, *tx_buf);
	return 0;
}

static inline ssize_t
rxm_ep_emulate_inject(struct rxm_ep *rxm_ep, struct rxm_conn *rxm_conn,
		      const void *buf, size_t len, size_t pkt_size,
		      uint64_t data, uint64_t flags, uint64_t tag,
		      uint8_t op, uint64_t comp_flags)
{
	struct rxm_tx_buf *tx_buf;
	struct rxm_tx_entry *tx_entry;
	ssize_t ret;

	FI_DBG(&rxm_prov, FI_LOG_EP_DATA, "passed data (size = %zu) "
	       "is too big for MSG provider (max inject size = %zd)\n",
	       pkt_size, rxm_ep->msg_info->tx_attr->inject_size);

	ret = rxm_ep_format_tx_res(rxm_ep, rxm_conn, NULL, 1,
				   len, data, flags, comp_flags,
				   tag, &tx_buf, &tx_entry,
				   &rxm_ep->buf_pools[RXM_BUF_POOL_TX]);
	if (OFI_UNLIKELY(ret))
		return ret;
	rxm_ep_fill_tx_inject_buf(buf, len, op, comp_flags, tx_buf);
	tx_entry->state = RXM_TX;
	ret = rxm_ep_normal_send(rxm_ep, rxm_conn, tx_entry, pkt_size);
	if (OFI_UNLIKELY(ret)) {
		if (ret == -FI_EAGAIN)
			rxm_ep_progress_multi(&rxm_ep->util_ep);
		rxm_tx_entry_release(rxm_conn->send_queue, tx_entry);
	}
	return ret;
}

static inline ssize_t
rxm_ep_inject_common_data_fast(struct rxm_ep *rxm_ep, const void *buf, size_t len,
			       fi_addr_t dest_addr, uint64_t data, uint64_t flags,
			       uint64_t tag, struct rxm_pkt *inject_pkt)
{
	struct rxm_conn *rxm_conn;
	size_t pkt_size = sizeof(struct rxm_pkt) + len;
	ssize_t ret;

	assert(len <= rxm_ep->rxm_info->tx_attr->inject_size);

	ret = rxm_acquire_conn_connect(rxm_ep, dest_addr, &rxm_conn);
	if (OFI_UNLIKELY(ret))
		return ret;

	if (OFI_UNLIKELY(!dlist_empty(&rxm_conn->deferred_tx_queue))) {
		rxm_ep_progress_multi(&rxm_ep->util_ep);
		if (!dlist_empty(&rxm_conn->deferred_tx_queue))
			return -FI_EAGAIN;
	}

	if (pkt_size <= rxm_ep->msg_info->tx_attr->inject_size) {
		inject_pkt->hdr.size = len;
		inject_pkt->hdr.tag = tag;
		inject_pkt->hdr.flags |= FI_REMOTE_CQ_DATA;
		inject_pkt->hdr.data = data;
		inject_pkt->ctrl_hdr.conn_id = rxm_conn->handle.remote_key;
		memcpy(inject_pkt->data, buf, len);
		ret = rxm_ep_inject_send(rxm_ep, rxm_conn, inject_pkt, pkt_size);
		inject_pkt->hdr.flags &= ~FI_REMOTE_CQ_DATA;
		return ret;
	} else {
		return rxm_ep_emulate_inject(rxm_ep, rxm_conn, buf, len, pkt_size, data, flags,
					     tag, inject_pkt->hdr.op, inject_pkt->hdr.flags);
	}
}

static inline ssize_t
rxm_ep_inject_common_fast(struct rxm_ep *rxm_ep, const void *buf, size_t len,
			  fi_addr_t dest_addr, uint64_t flags, uint64_t tag,
			  struct rxm_pkt *inject_pkt)
{
	struct rxm_conn *rxm_conn;
	size_t pkt_size = sizeof(struct rxm_pkt) + len;
	ssize_t ret;

	assert(len <= rxm_ep->rxm_info->tx_attr->inject_size);

	ret = rxm_acquire_conn_connect(rxm_ep, dest_addr, &rxm_conn);
	if (OFI_UNLIKELY(ret))
		return ret;

	if (OFI_UNLIKELY(!dlist_empty(&rxm_conn->deferred_tx_queue))) {
		rxm_ep_progress_multi(&rxm_ep->util_ep);
		if (!dlist_empty(&rxm_conn->deferred_tx_queue))
			return -FI_EAGAIN;
	}

	if (pkt_size <= rxm_ep->msg_info->tx_attr->inject_size) {
		inject_pkt->hdr.size = len;
		inject_pkt->hdr.tag = tag;
		inject_pkt->ctrl_hdr.conn_id = rxm_conn->handle.remote_key;
		memcpy(inject_pkt->data, buf, len);
		return rxm_ep_inject_send(rxm_ep, rxm_conn, inject_pkt, pkt_size);
	} else {
		return rxm_ep_emulate_inject(rxm_ep, rxm_conn, buf, len, pkt_size, 0, flags,
					     tag, inject_pkt->hdr.op, inject_pkt->hdr.flags);
	}
}

static inline ssize_t
rxm_ep_inject_common(struct rxm_ep *rxm_ep, const void *buf, size_t len,
		     fi_addr_t dest_addr, uint64_t data, uint64_t flags,
		     uint64_t tag, uint8_t op, uint64_t comp_flags)
{
	struct rxm_conn *rxm_conn;
	size_t pkt_size = sizeof(struct rxm_pkt) + len;
	ssize_t ret;

	assert(len <= rxm_ep->rxm_info->tx_attr->inject_size);
	assert(!(comp_flags & ~(FI_MSG | FI_TAGGED)));

	ret = rxm_acquire_conn_connect(rxm_ep, dest_addr, &rxm_conn);
	if (OFI_UNLIKELY(ret))
		return ret;

	if (OFI_UNLIKELY(!dlist_empty(&rxm_conn->deferred_tx_queue))) {
		rxm_ep_progress_multi(&rxm_ep->util_ep);
		if (!dlist_empty(&rxm_conn->deferred_tx_queue))
			return -FI_EAGAIN;
	}

	if (pkt_size <= rxm_ep->msg_info->tx_attr->inject_size) {
		struct rxm_tx_buf *tx_buf;
		ret = rxm_ep_format_tx_inject_buf(rxm_ep, rxm_conn, buf,
						  len, data, flags, tag,
						  op, comp_flags, &tx_buf);
		if (OFI_UNLIKELY(ret))
	    		return ret;
		ret = rxm_ep_inject_send(rxm_ep, rxm_conn, &tx_buf->pkt, pkt_size);
		/* release allocated buffer for further reuse */
		rxm_tx_buf_release(rxm_ep, tx_buf);
		return ret;
	} else {
		return rxm_ep_emulate_inject(rxm_ep, rxm_conn, buf, len, pkt_size,
					     data, flags, tag, op, comp_flags);
	}
}

static ssize_t
rxm_ep_send_inject(struct rxm_ep *rxm_ep, const struct iovec *iov, size_t count,
		   struct rxm_conn *rxm_conn, void *context, uint64_t data,
		   uint64_t flags, uint64_t tag, uint8_t op, uint64_t comp_flags,
		   size_t data_len, size_t total_len, struct rxm_pkt *inject_pkt)
{
	struct rxm_tx_buf *tx_buf;
	int ret;

	if (rxm_ep->util_ep.domain->threading != FI_THREAD_SAFE) {
		inject_pkt->hdr.size = data_len;
		inject_pkt->hdr.tag = tag;
		if (flags & FI_REMOTE_CQ_DATA) {
			inject_pkt->hdr.flags |= FI_REMOTE_CQ_DATA;
			inject_pkt->hdr.data = data;
		}
		inject_pkt->ctrl_hdr.conn_id = rxm_conn->handle.remote_key;
		ofi_copy_from_iov(inject_pkt->data, inject_pkt->hdr.size,
				  iov, count, 0);
		ret = rxm_ep_inject_send(rxm_ep, rxm_conn,
					 inject_pkt, total_len);
		inject_pkt->hdr.flags &= ~FI_REMOTE_CQ_DATA;
	} else {
		ret = rxm_ep_format_tx_inject_iov(rxm_ep, rxm_conn, data_len,
						  iov, count, data, flags, tag,
						  op, comp_flags, &tx_buf);
		if (OFI_UNLIKELY(ret))
			return ret;
		ret = rxm_ep_inject_send(rxm_ep, rxm_conn, &tx_buf->pkt, total_len);
		/* release allocated buffer for further reuse */
		rxm_tx_buf_release(rxm_ep, tx_buf);
	}
	if (ret)
		return ret;

	if (flags & FI_COMPLETION) {
		ret = ofi_cq_write(rxm_ep->util_ep.tx_cq, context,
				   comp_flags | FI_SEND, 0, NULL, 0, 0);
		if (OFI_UNLIKELY(ret)) {
			FI_WARN(&rxm_prov, FI_LOG_CQ,
				"Unable to report completion\n");
			return ret;
		}
		rxm_cq_log_comp(comp_flags);
	}
	if (rxm_ep->util_ep.flags & OFI_CNTR_ENABLED)
		rxm_cntr_inc(rxm_ep->util_ep.tx_cntr);
	return FI_SUCCESS;
}

static ssize_t
rxm_ep_send_common(struct rxm_ep *rxm_ep, const struct iovec *iov, void **desc,
		   size_t count, fi_addr_t dest_addr, void *context, uint64_t data,
		   uint64_t flags, uint64_t tag, uint8_t op, uint64_t comp_flags,
		   struct rxm_pkt *inject_pkt)
{
	struct rxm_conn *rxm_conn;
	struct rxm_tx_entry *tx_entry;
	struct rxm_tx_buf *tx_buf;
	size_t data_len = ofi_total_iov_len(iov, count);
	ssize_t ret;

	assert(count <= rxm_ep->rxm_info->tx_attr->iov_limit);
	assert(!(comp_flags & ~(FI_MSG | FI_TAGGED)));

	ret = rxm_acquire_conn_connect(rxm_ep, dest_addr, &rxm_conn);
	if (OFI_UNLIKELY(ret))
		return ret;

	if (OFI_UNLIKELY(!dlist_empty(&rxm_conn->deferred_tx_queue))) {
		rxm_ep_progress_multi(&rxm_ep->util_ep);
		if (!dlist_empty(&rxm_conn->deferred_tx_queue))
			return -FI_EAGAIN;
	}

	if (data_len <= rxm_ep->rxm_info->tx_attr->inject_size) {
		size_t total_len = sizeof(struct rxm_pkt) + data_len;

		if (total_len <= rxm_ep->msg_info->tx_attr->inject_size)
			return rxm_ep_send_inject(rxm_ep, iov, count, rxm_conn,
						  context, data, flags, tag, op,
						  comp_flags, data_len, total_len,
						  inject_pkt);

		ret = rxm_ep_format_tx_res(rxm_ep, rxm_conn, context,
					   (uint8_t)count, data_len, data, flags,
					   comp_flags, tag, &tx_buf, &tx_entry,
					   &rxm_ep->buf_pools[RXM_BUF_POOL_TX]);
		if (OFI_UNLIKELY(ret))
			return ret;
		rxm_ep_fill_tx_inject_iov(iov, count, op, comp_flags, tx_buf);
		tx_entry->state = RXM_TX;
		ret = rxm_ep_normal_send(rxm_ep, rxm_conn, tx_entry, total_len);
		if (OFI_UNLIKELY(ret)) {
			if (ret == -FI_EAGAIN)
				rxm_ep_progress_multi(&rxm_ep->util_ep);
			rxm_tx_entry_release(rxm_conn->send_queue, tx_entry);
		}
		return ret;
	} else {
		assert(!(flags & FI_INJECT));
		if (data_len <= rxm_ep->sar.limit) {
			size_t segs_cnt = rxm_ep_sar_calc_segs_cnt(rxm_ep, data_len);
			return rxm_ep_sar_tx_send(rxm_ep, rxm_conn, context, count, iov,
						  data_len, segs_cnt, data, flags,
						  comp_flags, tag, op);
		}
		ret = rxm_ep_alloc_lmt_tx_res(rxm_ep, rxm_conn, context, (uint8_t)count,
					      iov, desc, data_len, data, flags, comp_flags,
					      tag, op, &tx_entry);
		if (OFI_UNLIKELY(ret < 0))
			return ret;
		return rxm_ep_lmt_tx_send(rxm_ep, rxm_conn, tx_entry, ret);
	}
}

static void
rxm_ep_conn_progress_deferred_queue(struct rxm_ep *rxm_ep,
				    struct rxm_conn *rxm_conn)
{
	struct rxm_tx_entry *tx_entry;
	ssize_t ret = 0;
	while (!dlist_empty(&rxm_conn->deferred_tx_queue) && !ret) {
		tx_entry = container_of(rxm_conn->deferred_tx_queue.next,
					struct rxm_tx_entry, deferred_tx_entry);
		switch (tx_entry->state) {
		case RXM_LMT_ACK_DEFERRED:	/* RNDV (LMT TX ack) */
			ret = fi_send(tx_entry->rx_buf->conn->msg_ep,
				      &tx_entry->rx_buf->recv_entry->rndv.tx_buf->pkt,
				      tx_entry->deferred_pkt_size,
				      tx_entry->rx_buf->recv_entry->rndv.tx_buf->hdr.desc,
				      0, tx_entry->rx_buf);
			if (OFI_UNLIKELY(ret)) {
				if (OFI_LIKELY(ret == -FI_EAGAIN))
					break;
				rxm_cq_write_error(tx_entry->ep->util_ep.rx_cq,
						   tx_entry->ep->util_ep.rx_cntr,
						   tx_entry->context, ret);
			}
			rxm_ep_dequeue_deferred_tx_queue(tx_entry);
			free(tx_entry);
			break;
		case RXM_LMT_READ:
			ret = fi_readv(tx_entry->conn->msg_ep,
				       tx_entry->rma_buf->rxm_iov.iov,
				       tx_entry->rma_buf->rxm_iov.desc,
				       tx_entry->rma_buf->rxm_iov.count, 0,
				       tx_entry->rma_buf->rxm_rma_iov.iov[0].addr,
				       tx_entry->rma_buf->rxm_rma_iov.iov[0].key,
				       tx_entry->rx_buf);
			if (OFI_UNLIKELY(ret)) {
				if (OFI_LIKELY(ret == -FI_EAGAIN))
					break;
				rxm_cq_write_error(tx_entry->ep->util_ep.rx_cq,
						   tx_entry->ep->util_ep.rx_cntr,
						   tx_entry->context, ret);
				break;
			}
			rxm_ep_dequeue_deferred_tx_queue(tx_entry);
			free(tx_entry->rma_buf);
			free(tx_entry);
			break;
		case RXM_SAR_TX:	/* SAR (TX segments) */
			ret = rxm_ep_progress_sar_deferred_tx_queue(tx_entry);
			break;
		default:
			FI_WARN(&rxm_prov, FI_LOG_EP_DATA,
				"The deferred operation (TX state - %d) "
				"doesn't have registered hanlder\n",
				tx_entry->state);
			ret = -FI_EAGAIN;
			assert(0);
			break;
		}
	}
}

void rxm_ep_progress_deferred_queues(struct rxm_ep *rxm_ep)
{
	struct dlist_entry *conn_entry_tmp;
	struct rxm_conn *rxm_conn;
	dlist_foreach_container_safe(&rxm_ep->deferred_tx_conn_queue, struct rxm_conn,
				     rxm_conn, deferred_conn_entry, conn_entry_tmp) {
		rxm_ep_conn_progress_deferred_queue(rxm_ep, rxm_conn);
	}
}

static ssize_t rxm_ep_sendmsg(struct fid_ep *ep_fid, const struct fi_msg *msg,
			      uint64_t flags)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_send_common(rxm_ep, msg->msg_iov, msg->desc, msg->iov_count,
				  msg->addr, msg->context, msg->data,
				  flags | (rxm_ep_tx_flags(rxm_ep) & FI_COMPLETION),
				  0, ofi_op_msg, FI_MSG, rxm_ep->inject_tx_pkt);
}

static ssize_t rxm_ep_send(struct fid_ep *ep_fid, const void *buf, size_t len,
			   void *desc, fi_addr_t dest_addr, void *context)
{
	struct iovec iov = {
		.iov_base = (void *)buf,
		.iov_len = len,
	};
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_send_common(rxm_ep, &iov, &desc, 1, dest_addr, context, 0,
				  rxm_ep_tx_flags(rxm_ep), 0, ofi_op_msg, FI_MSG,
				  rxm_ep->inject_tx_pkt);
}

static ssize_t rxm_ep_sendv(struct fid_ep *ep_fid, const struct iovec *iov,
			    void **desc, size_t count, fi_addr_t dest_addr,
			    void *context)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_send_common(rxm_ep, iov, desc, count, dest_addr, context, 0,
				  rxm_ep_tx_flags(rxm_ep), 0, ofi_op_msg, FI_MSG,
				  rxm_ep->inject_tx_pkt);
}

static ssize_t rxm_ep_inject(struct fid_ep *ep_fid, const void *buf, size_t len,
			     fi_addr_t dest_addr)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_inject_common(rxm_ep, buf, len, dest_addr, 0,
				    rxm_ep->util_ep.inject_op_flags, 0,
				    ofi_op_msg, FI_MSG);
}

static ssize_t rxm_ep_inject_fast(struct fid_ep *ep_fid, const void *buf, size_t len,
				  fi_addr_t dest_addr)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_inject_common_fast(rxm_ep, buf, len, dest_addr,
					 rxm_ep->util_ep.inject_op_flags, 0,
					 rxm_ep->inject_tx_pkt);
}

static ssize_t rxm_ep_senddata(struct fid_ep *ep_fid, const void *buf, size_t len,
			       void *desc, uint64_t data, fi_addr_t dest_addr,
			       void *context)
{
	struct iovec iov = {
		.iov_base = (void *)buf,
		.iov_len = len,
	};
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_send_common(rxm_ep, &iov, desc, 1, dest_addr, context, data,
				  rxm_ep_tx_flags(rxm_ep) | FI_REMOTE_CQ_DATA,
				  0, ofi_op_msg, FI_MSG, rxm_ep->inject_tx_pkt);
}

static ssize_t rxm_ep_injectdata(struct fid_ep *ep_fid, const void *buf, size_t len,
				 uint64_t data, fi_addr_t dest_addr)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_inject_common(rxm_ep, buf, len, dest_addr, data,
				    rxm_ep->util_ep.inject_op_flags | FI_REMOTE_CQ_DATA,
				    0, ofi_op_msg, FI_MSG);
}

static ssize_t rxm_ep_injectdata_fast(struct fid_ep *ep_fid, const void *buf, size_t len,
				      uint64_t data, fi_addr_t dest_addr)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_inject_common_data_fast(rxm_ep, buf, len, dest_addr, data,
					      rxm_ep->util_ep.inject_op_flags |
					      FI_REMOTE_CQ_DATA,
					      0, rxm_ep->inject_tx_pkt);
}

static struct fi_ops_msg rxm_ops_msg = {
	.size = sizeof(struct fi_ops_msg),
	.recv = rxm_ep_recv,
	.recvv = rxm_ep_recvv,
	.recvmsg = rxm_ep_recvmsg,
	.send = rxm_ep_send,
	.sendv = rxm_ep_sendv,
	.sendmsg = rxm_ep_sendmsg,
	.inject = rxm_ep_inject,
	.senddata = rxm_ep_senddata,
	.injectdata = rxm_ep_injectdata,
};

static ssize_t rxm_ep_trecvmsg(struct fid_ep *ep_fid, const struct fi_msg_tagged *msg,
			       uint64_t flags)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_recv_common_flags(rxm_ep, msg->msg_iov, msg->desc, msg->iov_count,
					msg->addr, msg->tag, msg->ignore, msg->context,
					flags, (rxm_ep_rx_flags(rxm_ep) & FI_COMPLETION),
					&rxm_ep->trecv_queue);
}

static ssize_t rxm_ep_trecv(struct fid_ep *ep_fid, void *buf, size_t len,
			    void *desc, fi_addr_t src_addr, uint64_t tag,
			    uint64_t ignore, void *context)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);
	struct iovec iov = {
		.iov_base	= buf,
		.iov_len	= len,
	};

	return rxm_ep_recv_common(rxm_ep, &iov, &desc, 1, src_addr, tag, ignore,
				  context, rxm_ep_rx_flags(rxm_ep),
				  &rxm_ep->trecv_queue);
}

static ssize_t rxm_ep_trecvv(struct fid_ep *ep_fid, const struct iovec *iov,
			     void **desc, size_t count, fi_addr_t src_addr,
			     uint64_t tag, uint64_t ignore, void *context)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_recv_common(rxm_ep, iov, desc, count, src_addr, tag, ignore,
				  context, rxm_ep_rx_flags(rxm_ep),
				  &rxm_ep->trecv_queue);
}

static ssize_t rxm_ep_tsendmsg(struct fid_ep *ep_fid, const struct fi_msg_tagged *msg,
			       uint64_t flags)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_send_common(rxm_ep, msg->msg_iov, msg->desc, msg->iov_count,
				  msg->addr, msg->context, msg->data,
				  flags | (rxm_ep_tx_flags(rxm_ep) & FI_COMPLETION),
				  msg->tag, ofi_op_tagged, FI_TAGGED, rxm_ep->tinject_tx_pkt);
}

static ssize_t rxm_ep_tsend(struct fid_ep *ep_fid, const void *buf, size_t len,
			    void *desc, fi_addr_t dest_addr, uint64_t tag,
			    void *context)
{
	struct iovec iov = {
		.iov_base = (void *)buf,
		.iov_len = len,
	};
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_send_common(rxm_ep, &iov, &desc, 1, dest_addr, context, 0,
				  rxm_ep_tx_flags(rxm_ep), tag, ofi_op_tagged, FI_TAGGED,
				  rxm_ep->tinject_tx_pkt);
}

static ssize_t rxm_ep_tsendv(struct fid_ep *ep_fid, const struct iovec *iov,
			     void **desc, size_t count, fi_addr_t dest_addr,
			     uint64_t tag, void *context)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_send_common(rxm_ep, iov, desc, count, dest_addr, context, 0,
				  rxm_ep_tx_flags(rxm_ep), tag, ofi_op_tagged, FI_TAGGED,
				  rxm_ep->tinject_tx_pkt);
}

static ssize_t rxm_ep_tinject(struct fid_ep *ep_fid, const void *buf, size_t len,
			      fi_addr_t dest_addr, uint64_t tag)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_inject_common(rxm_ep, buf, len, dest_addr, 0,
				    rxm_ep->util_ep.inject_op_flags, tag,
				    ofi_op_tagged, FI_TAGGED);
}

static ssize_t rxm_ep_tinject_fast(struct fid_ep *ep_fid, const void *buf, size_t len,
			      fi_addr_t dest_addr, uint64_t tag)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_inject_common_fast(rxm_ep, buf, len, dest_addr,
					 rxm_ep->util_ep.inject_op_flags, tag,
					 rxm_ep->tinject_tx_pkt);
}

static ssize_t rxm_ep_tsenddata(struct fid_ep *ep_fid, const void *buf, size_t len,
				void *desc, uint64_t data, fi_addr_t dest_addr,
				uint64_t tag, void *context)
{
	struct iovec iov = {
		.iov_base = (void *)buf,
		.iov_len = len,
	};
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_send_common(rxm_ep, &iov, desc, 1, dest_addr, context, data,
				  rxm_ep_tx_flags(rxm_ep) | FI_REMOTE_CQ_DATA,
				  tag, ofi_op_tagged, FI_TAGGED, rxm_ep->tinject_tx_pkt);
}

static ssize_t rxm_ep_tinjectdata(struct fid_ep *ep_fid, const void *buf, size_t len,
				  uint64_t data, fi_addr_t dest_addr, uint64_t tag)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_inject_common(rxm_ep, buf, len, dest_addr, data,
				    rxm_ep->util_ep.inject_op_flags | FI_REMOTE_CQ_DATA,
				    tag, ofi_op_tagged, FI_TAGGED);
}

static ssize_t rxm_ep_tinjectdata_fast(struct fid_ep *ep_fid, const void *buf, size_t len,
				       uint64_t data, fi_addr_t dest_addr, uint64_t tag)
{
	struct rxm_ep *rxm_ep = container_of(ep_fid, struct rxm_ep,
					     util_ep.ep_fid.fid);

	return rxm_ep_inject_common_data_fast(rxm_ep, buf, len, dest_addr, data,
					      rxm_ep->util_ep.inject_op_flags |
					      FI_REMOTE_CQ_DATA,
					      tag, rxm_ep->tinject_tx_pkt);
}

struct fi_ops_tagged rxm_ops_tagged = {
	.size = sizeof(struct fi_ops_tagged),
	.recv = rxm_ep_trecv,
	.recvv = rxm_ep_trecvv,
	.recvmsg = rxm_ep_trecvmsg,
	.send = rxm_ep_tsend,
	.sendv = rxm_ep_tsendv,
	.sendmsg = rxm_ep_tsendmsg,
	.inject = rxm_ep_tinject,
	.senddata = rxm_ep_tsenddata,
	.injectdata = rxm_ep_tinjectdata,
};

static int rxm_ep_msg_res_close(struct rxm_ep *rxm_ep)
{
	int ret, retv = 0;

	if (rxm_ep->srx_ctx) {
		ret = fi_close(&rxm_ep->srx_ctx->fid);
		if (ret) {
			FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, \
				"Unable to close msg shared ctx\n");
			retv = ret;
		}
	}

	fi_freeinfo(rxm_ep->msg_info);
	return retv;
}

static int rxm_listener_close(struct rxm_ep *rxm_ep)
{
	int ret, retv = 0;

	if (rxm_ep->msg_pep) {
		ret = fi_close(&rxm_ep->msg_pep->fid);
		if (ret) {
			FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
				"Unable to close msg pep\n");
			retv = ret;
		}
	}
	if (rxm_ep->msg_eq) {
		ret = fi_close(&rxm_ep->msg_eq->fid);
		if (ret) {
			FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
				"Unable to close msg EQ\n");
			retv = ret;
		}
	}
	return retv;
}

static int rxm_ep_close(struct fid *fid)
{
	int ret, retv = 0;
	struct rxm_ep *rxm_ep =
		container_of(fid, struct rxm_ep, util_ep.ep_fid.fid);

	if (rxm_ep->cmap)
		rxm_cmap_free(rxm_ep->cmap);

	ret = rxm_listener_close(rxm_ep);
	if (ret)
		retv = ret;

	rxm_ep_txrx_res_close(rxm_ep);

	ret = fi_close(&rxm_ep->msg_cq->fid);
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "Unable to close msg CQ\n");
		retv = ret;
	}

	ret = rxm_ep_msg_res_close(rxm_ep);
	if (ret)
		retv = ret;

	ofi_endpoint_close(&rxm_ep->util_ep);
	fi_freeinfo(rxm_ep->rxm_info);
	free(rxm_ep);
	return retv;
}

static int rxm_ep_msg_get_wait_cq_fd(struct rxm_ep *rxm_ep,
				     enum fi_wait_obj wait_obj)
{
	int ret = FI_SUCCESS;

	if ((wait_obj != FI_WAIT_NONE) && (!rxm_ep->msg_cq_fd)) {
		ret = fi_control(&rxm_ep->msg_cq->fid, FI_GETWAIT, &rxm_ep->msg_cq_fd);
		if (ret)
			FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
				"Unable to get MSG CQ fd\n");
	}
	return ret;
}

static int rxm_ep_msg_cq_open(struct rxm_ep *rxm_ep, enum fi_wait_obj wait_obj)
{
	struct rxm_domain *rxm_domain;
	struct fi_cq_attr cq_attr = { 0 };
	int ret;

	assert((wait_obj == FI_WAIT_NONE) || (wait_obj == FI_WAIT_FD));

	cq_attr.size = (rxm_ep->msg_info->tx_attr->size +
			rxm_ep->msg_info->rx_attr->size) * rxm_def_univ_size;
	cq_attr.format = FI_CQ_FORMAT_DATA;
	cq_attr.wait_obj = wait_obj;

	rxm_domain = container_of(rxm_ep->util_ep.domain, struct rxm_domain, util_domain);

	ret = fi_cq_open(rxm_domain->msg_domain, &cq_attr, &rxm_ep->msg_cq, NULL);
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "Unable to open MSG CQ\n");
		return ret;
	}

	ret = rxm_ep_msg_get_wait_cq_fd(rxm_ep, wait_obj);
	if (ret)
		goto err;

	return 0;
err:
	fi_close(&rxm_ep->msg_cq->fid);
	return ret;
}

static int rxm_ep_eq_entry_list_trywait(void *arg)
{
	struct rxm_ep *rxm_ep = (struct rxm_ep *)arg;

	fastlock_acquire(&rxm_ep->msg_eq_entry_list_lock);
	if (!slistfd_empty(&rxm_ep->msg_eq_entry_list)) {
		fastlock_release(&rxm_ep->msg_eq_entry_list_lock);
		return -FI_EAGAIN;
	}
	fastlock_release(&rxm_ep->msg_eq_entry_list_lock);
	return 0;
}

static int rxm_ep_trywait(void *arg)
{
	struct rxm_fabric *rxm_fabric;
	struct rxm_ep *rxm_ep = (struct rxm_ep *)arg;
	struct fid *fids[1] = {&rxm_ep->msg_cq->fid};

	rxm_fabric = container_of(rxm_ep->util_ep.domain->fabric,
				  struct rxm_fabric, util_fabric);
	return fi_trywait(rxm_fabric->msg_fabric, fids, 1);
}

static int rxm_ep_wait_fd_add(struct rxm_ep *rxm_ep, struct util_wait *wait)
{
	int ret;

	ret = ofi_wait_fd_add(wait, rxm_ep->msg_cq_fd, FI_EPOLL_IN,
			      rxm_ep_trywait, rxm_ep,
			      &rxm_ep->util_ep.ep_fid.fid);
	if (ret)
		return ret;

	if (rxm_ep->util_ep.domain->data_progress == FI_PROGRESS_MANUAL) {
		ret = ofi_wait_fd_add(
				wait, slistfd_get_fd(&rxm_ep->msg_eq_entry_list),
				FI_EPOLL_IN, rxm_ep_eq_entry_list_trywait,
				rxm_ep, &rxm_ep->util_ep.ep_fid.fid);
		if (ret) {
			ofi_wait_fd_del(wait, rxm_ep->msg_cq_fd);
			return ret;
		}
	}
	return 0;
}

static int rxm_ep_bind(struct fid *ep_fid, struct fid *bfid, uint64_t flags)
{
	struct rxm_ep *rxm_ep =
		container_of(ep_fid, struct rxm_ep, util_ep.ep_fid.fid);
	struct util_cq *cq;
	struct util_av *av;
	struct util_cntr *cntr;
	int ret = 0;

	switch (bfid->fclass) {
	case FI_CLASS_AV:
		av = container_of(bfid, struct util_av, av_fid.fid);
		ret = ofi_ep_bind_av(&rxm_ep->util_ep, av);
		if (ret)
			return ret;

		ret = fi_listen(rxm_ep->msg_pep);
		if (ret) {
			FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
				"Unable to set msg PEP to listen state\n");
			return ret;
		}

		ret = rxm_conn_cmap_alloc(rxm_ep);
		if (ret)
			return ret;

		break;
	case FI_CLASS_CQ:
		cq = container_of(bfid, struct util_cq, cq_fid.fid);

		ret = ofi_ep_bind_cq(&rxm_ep->util_ep, cq, flags);
		if (ret)
			return ret;

		if (!rxm_ep->msg_cq) {
			ret = rxm_ep_msg_cq_open(rxm_ep, cq->wait ?
						 FI_WAIT_FD : FI_WAIT_NONE);
			if (ret)
				return ret;
		}

		if (cq->wait) {
			ret = rxm_ep_wait_fd_add(rxm_ep, cq->wait);
			if (ret)
				goto err;
		}
		break;
	case FI_CLASS_CNTR:
		cntr = container_of(bfid, struct util_cntr, cntr_fid.fid);

		ret = ofi_ep_bind_cntr(&rxm_ep->util_ep, cntr, flags);
		if (ret)
			return ret;

		if (!rxm_ep->msg_cq) {
			ret = rxm_ep_msg_cq_open(rxm_ep, cntr->wait ?
						 FI_WAIT_FD : FI_WAIT_NONE);
			if (ret)
				return ret;
		} else if (!rxm_ep->msg_cq_fd && cntr->wait) {
			/* Reopen CQ with WAIT fd set */
			ret = fi_close(&rxm_ep->msg_cq->fid);
			if (ret)
				FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
					"Unable to close msg CQ\n");
			ret = rxm_ep_msg_cq_open(rxm_ep, FI_WAIT_FD);
			if (ret)
				return ret;
		}

		if (cntr->wait) {
			ret = rxm_ep_wait_fd_add(rxm_ep, cntr->wait);
			if (ret)
				goto err;
		}
		break;
	case FI_CLASS_EQ:
		break;
	default:
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "invalid fid class\n");
		ret = -FI_EINVAL;
		break;
	}
	return ret;
err:
	if (fi_close(&rxm_ep->msg_cq->fid))
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "Unable to close msg CQ\n");
	return ret;
}

static int rxm_ep_ctrl(struct fid *fid, int command, void *arg)
{
	struct rxm_ep *rxm_ep;
	int ret;

	rxm_ep = container_of(fid, struct rxm_ep, util_ep.ep_fid.fid);

	switch (command) {
	case FI_ENABLE:
		if (!rxm_ep->util_ep.rx_cq || !rxm_ep->util_ep.tx_cq)
			return -FI_ENOCQ;
		if (!rxm_ep->util_ep.av || !rxm_ep->cmap)
			return -FI_EOPBADSTATE;

		/* At the time of enabling endpoint, FI_OPT_BUFFERED_MIN,
		 * FI_OPT_BUFFERED_LIMIT should have been frozen so we can
		 * create the rendezvous protocol message pool with the right
		 * size */
		ret = rxm_ep_txrx_pool_create(rxm_ep);
		if (ret)
			return ret;

		if (rxm_ep->srx_ctx) {
			ret = rxm_ep_prepost_buf(rxm_ep, rxm_ep->srx_ctx);
			if (ret) {
				rxm_cmap_free(rxm_ep->cmap);
				FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
					"Unable to prepost recv bufs\n");
				goto err;
			}
		}
		break;
	default:
		return -FI_ENOSYS;
	}
	return 0;
err:
	rxm_ep_txrx_pool_destroy(rxm_ep);
	return ret;
}

static struct fi_ops rxm_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = rxm_ep_close,
	.bind = rxm_ep_bind,
	.control = rxm_ep_ctrl,
	.ops_open = fi_no_ops_open,
};

static int rxm_listener_open(struct rxm_ep *rxm_ep)
{
	struct rxm_fabric *rxm_fabric;
	struct fi_eq_attr eq_attr;
	eq_attr.wait_obj = FI_WAIT_UNSPEC;
	eq_attr.flags = FI_WRITE;
	int ret;

	rxm_fabric = container_of(rxm_ep->util_ep.domain->fabric,
				  struct rxm_fabric, util_fabric);

	ret = fi_eq_open(rxm_fabric->msg_fabric, &eq_attr, &rxm_ep->msg_eq, NULL);
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "Unable to open msg EQ\n");
		return ret;
	}

	ret = fi_passive_ep(rxm_fabric->msg_fabric, rxm_ep->msg_info,
			    &rxm_ep->msg_pep, rxm_ep);
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "Unable to open msg PEP\n");
		goto err;
	}

	ret = fi_pep_bind(rxm_ep->msg_pep, &rxm_ep->msg_eq->fid, 0);
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
				"Unable to bind msg PEP to msg EQ\n");
		goto err;
	}

	return 0;
err:
	rxm_listener_close(rxm_ep);
	return ret;
}

static int rxm_info_to_core_srx_ctx(uint32_t version, const struct fi_info *rxm_hints,
				    struct fi_info *core_hints)
{
	int ret;

	ret = rxm_info_to_core(version, rxm_hints, core_hints);
	if (ret)
		return ret;
	core_hints->ep_attr->rx_ctx_cnt = FI_SHARED_CONTEXT;
	return 0;
}

static int rxm_ep_get_core_info(uint32_t version, const struct fi_info *hints,
				struct fi_info **info)
{
	int ret;

	ret = ofi_get_core_info(version, NULL, NULL, 0, &rxm_util_prov, hints,
				rxm_info_to_core_srx_ctx, info);
	if (!ret)
		return 0;

	FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "Shared receive context not "
		"supported by MSG provider.\n");

	return ofi_get_core_info(version, NULL, NULL, 0, &rxm_util_prov, hints,
				 rxm_info_to_core, info);
}

static int rxm_ep_msg_res_open(struct rxm_ep *rxm_ep)
{
	int ret;
	size_t max_prog_val;
	int use_srx;
	struct rxm_domain *rxm_domain =
		container_of(rxm_ep->util_ep.domain, struct rxm_domain, util_domain);

	ret = rxm_ep_get_core_info(rxm_ep->util_ep.domain->fabric->fabric_fid.api_version,
				   rxm_ep->rxm_info, &rxm_ep->msg_info);
	if (ret)
		return ret;

	max_prog_val = MIN(rxm_ep->msg_info->tx_attr->size,
			   rxm_ep->msg_info->rx_attr->size) / 2;
	rxm_ep->comp_per_progress = (rxm_ep->comp_per_progress > max_prog_val) ?
				    max_prog_val : rxm_ep->comp_per_progress;
	rxm_ep->eager_pkt_size =
		rxm_ep->rxm_info->tx_attr->inject_size + sizeof(struct rxm_pkt);

	if (fi_param_get_bool(&rxm_prov, "use_srx", &use_srx))
		use_srx = 0;

	if ((rxm_ep->msg_info->ep_attr->rx_ctx_cnt == FI_SHARED_CONTEXT) && use_srx) {
		ret = fi_srx_context(rxm_domain->msg_domain, rxm_ep->msg_info->rx_attr,
				     &rxm_ep->srx_ctx, NULL);
		if (ret) {
			FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
				"Unable to open shared receive context\n");
			goto err1;
		}
	}

	ret = rxm_listener_open(rxm_ep);
	if (ret)
		goto err2;

	/* Zero out the port as we would be creating multiple MSG EPs for a single
	 * RXM EP and we don't want address conflicts. */
	if (rxm_ep->msg_info->src_addr) {
		if (((struct sockaddr *)rxm_ep->msg_info->src_addr)->sa_family == AF_INET)
			((struct sockaddr_in *)(rxm_ep->msg_info->src_addr))->sin_port = 0;
		else
			((struct sockaddr_in6 *)(rxm_ep->msg_info->src_addr))->sin6_port = 0;
	}
	return 0;
err2:
	if (rxm_ep->srx_ctx)
		fi_close(&rxm_ep->srx_ctx->fid);
err1:
	fi_freeinfo(rxm_ep->msg_info);
	return ret;
}

static void rxm_ep_sar_init(struct rxm_ep *rxm_ep)
{
	size_t param;

	if (!fi_param_get_size_t(&rxm_prov, "sar_limit", &param)) {
		if (param < rxm_info.tx_attr->inject_size) {
			FI_WARN(&rxm_prov, FI_LOG_CORE,
				"Requested SAR limit (%zd) less than inject size (%zd). "
				"SAR protocol won't be used. Messages of size <= (>) inject "
				"size would would be transmitted via eager (rendezvous) "
				"protocol.\n", param, rxm_info.tx_attr->inject_size);
		} else {
			rxm_ep->sar.limit = param;
		}
	} else {
		size_t segs_cnt_limit = rxm_ep->msg_info->tx_attr->size;
		rxm_ep->sar.limit = segs_cnt_limit * rxm_info.tx_attr->inject_size;
		if (rxm_ep->sar.limit > RXM_SAR_LIMIT)
			rxm_ep->sar.limit = RXM_SAR_LIMIT;
	}
}

static int
rxm_ep_inject_pkt_alloc(struct rxm_ep *rxm_ep, struct rxm_pkt **inject_pkt,
			uint8_t op, uint64_t comp_flags)
{
	*inject_pkt = calloc(1, rxm_ep->msg_info->tx_attr->inject_size +
				sizeof(**inject_pkt));
	if (!(*inject_pkt))
		return -FI_ENOMEM;

	(*inject_pkt)->ctrl_hdr.version = RXM_CTRL_VERSION;
	(*inject_pkt)->ctrl_hdr.type = ofi_ctrl_data;
	(*inject_pkt)->hdr.version = OFI_OP_VERSION;
	(*inject_pkt)->hdr.op = op;
	(*inject_pkt)->hdr.flags = comp_flags;

	return FI_SUCCESS;
}

static int rxm_ep_txrx_res_open(struct rxm_ep *rxm_ep)
{
	int ret;

	FI_DBG(&rxm_prov, FI_LOG_EP_CTRL,
	       "MSG provider mr_mode & FI_MR_LOCAL: %d\n",
	       rxm_ep->msg_mr_local);

	if (rxm_ep->util_ep.domain->threading != FI_THREAD_SAFE) {
		rxm_ep->res_fastlock_acquire = ofi_fastlock_acquire_noop;
		rxm_ep->res_fastlock_release = ofi_fastlock_release_noop;

		ret = rxm_ep_inject_pkt_alloc(rxm_ep, &rxm_ep->inject_tx_pkt,
					      ofi_op_msg, FI_MSG);
		if (ret)
			return ret;
		ret = rxm_ep_inject_pkt_alloc(rxm_ep, &rxm_ep->tinject_tx_pkt,
					      ofi_op_tagged, FI_TAGGED);
		if (ret) {
			free(rxm_ep->inject_tx_pkt);
			return ret;
		}

		rxm_ops_msg.inject = rxm_ep_inject_fast;
		rxm_ops_msg.injectdata = rxm_ep_injectdata_fast;
		rxm_ops_tagged.inject = rxm_ep_tinject_fast;
		rxm_ops_tagged.injectdata = rxm_ep_tinjectdata_fast;
	} else {
		rxm_ep->res_fastlock_acquire = ofi_fastlock_acquire;
		rxm_ep->res_fastlock_release = ofi_fastlock_release;
	}

	dlist_init(&rxm_ep->deferred_tx_conn_queue);

	ret = rxm_ep_txrx_queue_init(rxm_ep);
	if (ret)
		goto err1;

	rxm_ep_sar_init(rxm_ep);

	return FI_SUCCESS;
err1:
	if (rxm_ep->util_ep.domain->threading != FI_THREAD_SAFE) {
		free(rxm_ep->inject_tx_pkt);
		free(rxm_ep->tinject_tx_pkt);
	}
	return ret;
}

int rxm_endpoint(struct fid_domain *domain, struct fi_info *info,
		 struct fid_ep **ep_fid, void *context)
{
	struct rxm_ep *rxm_ep;
	int ret;

	rxm_ep = calloc(1, sizeof(*rxm_ep));
	if (!rxm_ep)
		return -FI_ENOMEM;

	rxm_ep->rxm_info = fi_dupinfo(info);
	if (!rxm_ep->rxm_info) {
		ret = -FI_ENOMEM;
		goto err1;
	}

	if (!fi_param_get_int(&rxm_prov, "comp_per_progress",
			     (int *)&rxm_ep->comp_per_progress)) {
		ret = ofi_endpoint_init(domain, &rxm_util_prov,
					info, &rxm_ep->util_ep,
					context, &rxm_ep_progress_multi);
	} else {
		rxm_ep->comp_per_progress = 1;
		ret = ofi_endpoint_init(domain, &rxm_util_prov,
					info, &rxm_ep->util_ep,
					context, &rxm_ep_progress_one);
		if (ret)
			goto err1;
	}
	if (ret)
		goto err1;

	ret = rxm_ep_msg_res_open(rxm_ep);
	if (ret)
		goto err2;

	rxm_ep->msg_mr_local = ofi_mr_local(rxm_ep->msg_info);
	rxm_ep->rxm_mr_local = ofi_mr_local(rxm_ep->rxm_info);

	rxm_ep->min_multi_recv_size = rxm_ep->rxm_info->tx_attr->inject_size;

	if (rxm_ep->msg_info->tx_attr->inject_size >
	    (sizeof(struct rxm_pkt) + sizeof(struct rxm_rndv_hdr)))
		rxm_ep->buffered_min = (rxm_ep->msg_info->tx_attr->inject_size -
					(sizeof(struct rxm_pkt) +
					 sizeof(struct rxm_rndv_hdr)));
	else
		assert(!rxm_ep->buffered_min);

	rxm_ep->buffered_limit = rxm_ep->rxm_info->tx_attr->inject_size;

	ret = rxm_ep_txrx_res_open(rxm_ep);
	if (ret)
		goto err3;

	slistfd_init(&rxm_ep->msg_eq_entry_list);
	fastlock_init(&rxm_ep->msg_eq_entry_list_lock);

	*ep_fid = &rxm_ep->util_ep.ep_fid;
	(*ep_fid)->fid.ops = &rxm_ep_fi_ops;
	(*ep_fid)->ops = &rxm_ops_ep;
	(*ep_fid)->cm = &rxm_ops_cm;
	(*ep_fid)->msg = &rxm_ops_msg;
	(*ep_fid)->tagged = &rxm_ops_tagged;
	(*ep_fid)->rma = &rxm_ops_rma;

	return 0;
err3:
	rxm_ep_msg_res_close(rxm_ep);
err2:
	ofi_endpoint_close(&rxm_ep->util_ep);
err1:
	if (rxm_ep->rxm_info)
		fi_freeinfo(rxm_ep->rxm_info);
	free(rxm_ep);
	return ret;
}
