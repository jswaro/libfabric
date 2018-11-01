/*
 * Copyright (c) 2016 Intel Corporation, Inc.  All rights reserved.
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

#include <stdlib.h>
#include <string.h>

#include <ofi.h>
#include <ofi_util.h>
#include "rxm.h"

static struct rxm_cmap_handle *rxm_conn_alloc(struct rxm_cmap *cmap);
static void rxm_conn_connected_handler(struct rxm_cmap_handle *handle);
static void rxm_conn_close_saved(struct rxm_cmap_handle *handle);
static void rxm_conn_close(struct rxm_cmap_handle *handle);
static void rxm_conn_save(struct rxm_cmap_handle *handle);
static int
rxm_conn_connect(struct util_ep *util_ep, struct rxm_cmap_handle *handle,
		 const void *addr, size_t addrlen);
static int rxm_conn_signal(struct util_ep *util_ep, void *context,
			   enum rxm_cmap_signal signal);
static void
rxm_conn_av_updated_handler(struct rxm_cmap_handle *handle);
static void *rxm_conn_progress(void *arg);
static void *rxm_conn_eq_read(void *arg);


/*
 * Connection map
 */

/* Caller should hold cmap->lock */
static void rxm_cmap_set_key(struct rxm_cmap_handle *handle)
{
	handle->key = ofi_idx2key(&handle->cmap->key_idx,
		ofi_idx_insert(&handle->cmap->handles_idx, handle));
}

/* Caller should hold cmap->lock */
static void rxm_cmap_clear_key(struct rxm_cmap_handle *handle)
{
	int index = ofi_key2idx(&handle->cmap->key_idx, handle->key);

	if (!ofi_idx_is_valid(&handle->cmap->handles_idx, index))
		FI_WARN(handle->cmap->av->prov, FI_LOG_AV, "Invalid key!\n");
	else
		ofi_idx_remove(&handle->cmap->handles_idx, index);
}

struct rxm_cmap_handle *rxm_cmap_key2handle(struct rxm_cmap *cmap, uint64_t key)
{
	struct rxm_cmap_handle *handle;

	cmap->acquire(&cmap->lock);
	if (!(handle = ofi_idx_lookup(&cmap->handles_idx,
				      ofi_key2idx(&cmap->key_idx, key)))) {
		FI_WARN(cmap->av->prov, FI_LOG_AV, "Invalid key!\n");
	} else {
		if (handle->key != key) {
			FI_WARN(cmap->av->prov, FI_LOG_AV,
				"handle->key not matching given key\n");
			handle = NULL;
		}
	}
	cmap->release(&cmap->lock);
	return handle;
}

/* Caller must hold cmap->lock */
static void rxm_cmap_init_handle(struct rxm_cmap_handle *handle,
				  struct rxm_cmap *cmap,
				  enum rxm_cmap_state state,
				  fi_addr_t fi_addr,
				  struct rxm_cmap_peer *peer)
{
	handle->cmap = cmap;
	handle->state = state;
	rxm_cmap_set_key(handle);
	handle->fi_addr = fi_addr;
	handle->peer = peer;
}

static int rxm_cmap_match_peer(struct dlist_entry *entry, const void *addr)
{
	struct rxm_cmap_peer *peer;

	peer = container_of(entry, struct rxm_cmap_peer, entry);
	return !memcmp(peer->addr, addr, peer->handle->cmap->av->addrlen);
}

/* Caller must hold cmap->lock */
static int rxm_cmap_del_handle(struct rxm_cmap_handle *handle)
{
	struct rxm_cmap *cmap = handle->cmap;
	int ret;

	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
	       "Deleting connection handle: %p\n", handle);
	if (handle->peer) {
		dlist_remove(&handle->peer->entry);
		free(handle->peer);
		handle->peer = NULL;
	} else {
		cmap->handles_av[handle->fi_addr] = 0;
	}
	rxm_cmap_clear_key(handle);

	handle->state = RXM_CMAP_SHUTDOWN;
	/* Signal CM thread to delete the handle. This is required
	 * so that the CM thread handles any pending events for this
	 * ep correctly. Handle would be freed finally after processing the
	 * events */
	ret = rxm_conn_signal(cmap->ep, handle, RXM_CMAP_FREE);
	if (ret) {
		FI_WARN(cmap->av->prov, FI_LOG_FABRIC,
			"Unable to signal CM thread\n");
		return ret;
	}
	return 0;
}

static inline int
rxm_cmap_check_and_realloc_handles_table(struct rxm_cmap *cmap,
					 fi_addr_t fi_addr)
{
	int ret = FI_SUCCESS;

	if (OFI_LIKELY(fi_addr < cmap->num_allocated))
		return ret;

	while (fi_addr >= cmap->num_allocated) {
		struct rxm_cmap_handle **handles_av_new =
				realloc(cmap->handles_av,
					(cmap->av->count +
					 cmap->num_allocated) *
					sizeof(*cmap->handles_av));
		if (OFI_LIKELY(*handles_av_new != NULL)) {
			cmap->handles_av = handles_av_new;
 			memset(&cmap->handles_av[cmap->num_allocated],
			       0, sizeof(*cmap->handles_av) *
				  cmap->av->count);
			cmap->num_allocated += cmap->av->count;
		} else {
			ret = -FI_ENOMEM;
			break;
		}
	}
	return ret;
}

static int rxm_conn_send_queue_init(struct rxm_ep *rxm_ep,
				    struct rxm_conn *rxm_conn,
				    size_t size)
{
	if (!rxm_ep->send_queue) {
		return rxm_send_queue_init(rxm_ep, &rxm_conn->send_queue, size);
	} else {
		rxm_conn->send_queue = rxm_ep->send_queue;
	}
	return 0;
}

static void
rxm_conn_send_queue_close(struct rxm_conn *rxm_conn)
{
	if (!rxm_conn->send_queue->rxm_ep->send_queue) {
		rxm_send_queue_close(rxm_conn->send_queue);
	} else {
		rxm_conn->send_queue = NULL;
	}
}

void rxm_cmap_del_handle_ts(struct rxm_cmap_handle *handle)
{
	struct rxm_cmap *cmap = handle->cmap;
	cmap->acquire(&cmap->lock);
	rxm_cmap_del_handle(handle);
	cmap->release(&cmap->lock);
}

static void rxm_conn_free(struct rxm_cmap_handle *handle)
{
	struct rxm_conn *rxm_conn =
		container_of(handle, struct rxm_conn, handle);

	/* This handles case when saved_msg_ep wasn't closed */
	if (rxm_conn->saved_msg_ep) {
		if (fi_close(&rxm_conn->saved_msg_ep->fid)) {
			FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
				"Unable to close saved msg_ep\n");
		} else {
			FI_DBG(&rxm_prov, FI_LOG_EP_CTRL,
			       "Closed saved msg_ep\n");
		}
		rxm_conn->saved_msg_ep = NULL;
	}

	if (!rxm_conn->msg_ep)
		return;
	/* Assuming fi_close also shuts down the connection gracefully if the
	 * endpoint is in connected state */
	if (fi_close(&rxm_conn->msg_ep->fid)) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
			"Unable to close msg_ep\n");
	} else {
		FI_DBG(&rxm_prov, FI_LOG_EP_CTRL,
		       "Closed msg_ep\n");
	}
	rxm_conn->msg_ep = NULL;
	rxm_conn_send_queue_close(rxm_conn);

	free(container_of(handle, struct rxm_conn, handle));
}

/* Caller must hold cmap->lock */
static int rxm_cmap_alloc_handle(struct rxm_cmap *cmap, fi_addr_t fi_addr,
				 enum rxm_cmap_state state,
				 struct rxm_cmap_handle **handle)
{
	int ret;

	*handle = rxm_conn_alloc(cmap);
	if (OFI_UNLIKELY(!*handle))
		return -FI_ENOMEM;
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
	       "Allocated handle: %p for fi_addr: %" PRIu64 "\n",
	       *handle, fi_addr);
	ret = rxm_cmap_check_and_realloc_handles_table(cmap, fi_addr);
	if (OFI_UNLIKELY(ret)) {
		rxm_conn_free(*handle);
		return ret;
	}
	rxm_cmap_init_handle(*handle, cmap, state, fi_addr, NULL);
	cmap->handles_av[fi_addr] = *handle;
	return 0;
}

/* Caller must hold cmap->lock */
static int rxm_cmap_alloc_handle_peer(struct rxm_cmap *cmap, void *addr,
				       enum rxm_cmap_state state,
				       struct rxm_cmap_handle **handle)
{
	struct rxm_cmap_peer *peer;

	peer = calloc(1, sizeof(*peer) + cmap->av->addrlen);
	if (!peer)
		return -FI_ENOMEM;
	*handle = rxm_conn_alloc(cmap);
	if (!*handle) {
		free(peer);
		return -FI_ENOMEM;
	}
	ofi_straddr_dbg(cmap->av->prov, FI_LOG_AV, "Allocated handle for addr",
			addr);
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL, "handle: %p\n", *handle);
	rxm_cmap_init_handle(*handle, cmap, state, FI_ADDR_NOTAVAIL, peer);
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL, "Adding handle to peer list\n");
	peer->handle = *handle;
	memcpy(peer->addr, addr, cmap->av->addrlen);
	dlist_insert_tail(&peer->entry, &cmap->peer_list);
	return 0;
}

/* Caller must hold cmap->lock */
static struct rxm_cmap_handle *
rxm_cmap_get_handle_peer(struct rxm_cmap *cmap, const void *addr)
{
	struct rxm_cmap_peer *peer;
	struct dlist_entry *entry;

	entry = dlist_find_first_match(&cmap->peer_list, rxm_cmap_match_peer,
				       addr);
	if (!entry)
		return NULL;
	ofi_straddr_dbg(cmap->av->prov, FI_LOG_AV,
			"handle found in peer list for addr", addr);
	peer = container_of(entry, struct rxm_cmap_peer, entry);
	return peer->handle;
}

int rxm_cmap_move_handle_to_peer_list(struct rxm_cmap *cmap, int index)
{
	struct rxm_cmap_handle *handle = cmap->handles_av[index];
	int ret = 0;

	cmap->acquire(&cmap->lock);
	if (!handle)
		goto unlock;

	handle->peer = calloc(1, sizeof(*handle->peer) + cmap->av->addrlen);
	if (!handle->peer) {
		ret = -FI_ENOMEM;
		goto unlock;
	}
	handle->peer->handle = handle;
	memcpy(handle->peer->addr, ofi_av_get_addr(cmap->av, index),
	       cmap->av->addrlen);
	dlist_insert_tail(&handle->peer->entry, &cmap->peer_list);
unlock:
	cmap->release(&cmap->lock);
	return ret;
}

/* Caller must hold cmap->lock */
static int rxm_cmap_move_handle(struct rxm_cmap_handle *handle,
				fi_addr_t fi_addr)
{
	int ret;

	dlist_remove(&handle->peer->entry);
	free(handle->peer);
	handle->peer = NULL;
	handle->fi_addr = fi_addr;
	ret = rxm_cmap_check_and_realloc_handles_table(handle->cmap, fi_addr);
	if (OFI_UNLIKELY(ret))
		return ret;
	handle->cmap->handles_av[fi_addr] = handle;
	return 0;
}

int rxm_cmap_update(struct rxm_cmap *cmap, const void *addr, fi_addr_t fi_addr)
{
	struct rxm_cmap_handle *handle;
	int ret;

	cmap->acquire(&cmap->lock);
	handle = rxm_cmap_get_handle_peer(cmap, addr);
	if (!handle) {
		ret = rxm_cmap_alloc_handle(cmap, fi_addr,
					    RXM_CMAP_IDLE, &handle);
		cmap->release(&cmap->lock);
		return ret;
	}
	ret = rxm_cmap_move_handle(handle, fi_addr);
	cmap->release(&cmap->lock);
	if (ret)
		return ret;

	rxm_conn_av_updated_handler(handle);
	return 0;
}

/* Caller must hold cmap->lock */

void rxm_cmap_process_shutdown(struct rxm_cmap *cmap,
			       struct rxm_cmap_handle *handle)
{
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
		"Processing shutdown for handle: %p\n", handle);
	cmap->acquire(&cmap->lock);
	if (handle->state > RXM_CMAP_SHUTDOWN) {
		FI_WARN(cmap->av->prov, FI_LOG_EP_CTRL,
			"Invalid handle on shutdown event\n");
	} else if (handle->state != RXM_CMAP_SHUTDOWN) {
		FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL, "Got remote shutdown\n");
		rxm_cmap_del_handle(handle);
	} else {
		FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL, "Got local shutdown\n");
	}
	cmap->release(&cmap->lock);
}

/* Caller must hold cmap->lock */
void rxm_cmap_process_conn_notify(struct rxm_cmap *cmap,
				  struct rxm_cmap_handle *handle)
{
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
	       "Processing connection notification for handle: %p.\n", handle);
	handle->state = RXM_CMAP_CONNECTED;
	rxm_conn_connected_handler(handle);
}

/* Caller must hold cmap->lock */
void rxm_cmap_process_connect(struct rxm_cmap *cmap,
			      struct rxm_cmap_handle *handle,
			      uint64_t *remote_key)
{
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
	       "Processing connect for handle: %p\n", handle);
	handle->state = RXM_CMAP_CONNECTED_NOTIFY;
	if (remote_key)
		handle->remote_key = *remote_key;
}

void rxm_cmap_process_reject(struct rxm_cmap *cmap,
			     struct rxm_cmap_handle *handle,
			     enum rxm_cmap_reject_flag cm_reject_flag)
{
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
		"Processing reject for handle: %p\n", handle);
	cmap->acquire(&cmap->lock);
	switch (handle->state) {
	case RXM_CMAP_CONNREQ_RECV:
	case RXM_CMAP_CONNECTED:
	case RXM_CMAP_CONNECTED_NOTIFY:
		/* Handle is being re-used for incoming connection request */
		FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
			"Connection handle is being re-used. Close saved connection\n");
		rxm_conn_close_saved(handle);
		break;
	case RXM_CMAP_CONNREQ_SENT:
		if (cm_reject_flag == RXM_CMAP_REJECT_GENUINE) {
			FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
			       "Deleting connection handle\n");
			rxm_cmap_del_handle_ts(handle);
		} else {
			FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
			       "Connection handle is being re-used. Close the connection\n");
			rxm_conn_close(handle);
		}
		break;
	case RXM_CMAP_SHUTDOWN:
		FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
			"Connection handle already being deleted\n");
		break;
	default:
		FI_WARN(cmap->av->prov, FI_LOG_EP_CTRL, "Invalid cmap state: "
			"%d when receiving connection reject\n", handle->state);
		assert(0);
	}
	cmap->release(&cmap->lock);
}

int rxm_cmap_process_connreq(struct rxm_cmap *cmap, void *addr,
			     struct rxm_cmap_handle **handle_ret,
			     enum rxm_cmap_reject_flag *cm_reject_flag)
{
	struct rxm_cmap_handle *handle;
	int ret = 0, cmp;
	fi_addr_t fi_addr = ofi_ip_av_get_fi_addr(cmap->av, addr);

	/* Reset flag to initial state */
	*cm_reject_flag = RXM_CMAP_REJECT_GENUINE;

	ofi_straddr_dbg(cmap->av->prov, FI_LOG_EP_CTRL,
			"Processing connreq for addr", addr);

	cmap->acquire(&cmap->lock);
	if (fi_addr == FI_ADDR_NOTAVAIL)
		handle = rxm_cmap_get_handle_peer(cmap, addr);
	else
		handle = rxm_cmap_acquire_handle(cmap, fi_addr);

	if (!handle) {
		if (fi_addr == FI_ADDR_NOTAVAIL)
			ret = rxm_cmap_alloc_handle_peer(cmap, addr,
							 RXM_CMAP_CONNREQ_RECV,
							 &handle);
		else
			ret = rxm_cmap_alloc_handle(cmap, fi_addr,
						    RXM_CMAP_CONNREQ_RECV,
						    &handle);
		if (ret)
			goto unlock;
	}

	switch (handle->state) {
	case RXM_CMAP_CONNECTED_NOTIFY:
	case RXM_CMAP_CONNECTED:
		FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
			"Connection already present.\n");
		ret = -FI_EALREADY;
		break;
	case RXM_CMAP_CONNREQ_SENT:
		ofi_straddr_dbg(cmap->av->prov, FI_LOG_EP_CTRL, "local_name",
				cmap->attr.name);
		ofi_straddr_dbg(cmap->av->prov, FI_LOG_EP_CTRL, "remote_name",
				addr);

		cmp = ofi_addr_cmp(cmap->av->prov, addr, cmap->attr.name);

		if (cmp < 0) {
			FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
				"Remote name lower than local name.\n");
			*cm_reject_flag = RXM_CMAP_REJECT_SIMULT_CONN;
			ret = -FI_EALREADY;
			break;
		} else if (cmp > 0) {
			FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
				"Re-using handle: %p to accept remote "
				"connection\n", handle);
			/* Re-use handle. If it receives FI_REJECT the handle
			 * would not be deleted in this state */
			rxm_conn_save(handle);
		} else {
			FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL,
				"Endpoint connects to itself\n");
			ret = rxm_cmap_alloc_handle_peer(cmap, addr,
							  RXM_CMAP_CONNREQ_RECV,
							  &handle);
			if (ret)
				goto unlock;
			assert(fi_addr != FI_ADDR_NOTAVAIL);
			handle->fi_addr = fi_addr;
		}
		/* Fall through */
	case RXM_CMAP_IDLE:
		handle->state = RXM_CMAP_CONNREQ_RECV;
		/* Fall through */
	case RXM_CMAP_CONNREQ_RECV:
		*handle_ret = handle;
		break;
	default:
		FI_WARN(cmap->av->prov, FI_LOG_EP_CTRL,
		       "Invalid cmap state\n");
		assert(0);
		ret = -FI_EOPBADSTATE;
	}
unlock:
	cmap->release(&cmap->lock);
	return ret;
}

/* Caller must hold `cmap::lock` */
int rxm_cmap_handle_connect(struct rxm_cmap *cmap, fi_addr_t fi_addr,
			    struct rxm_cmap_handle *handle)
{
	int ret;

	if (handle->state == RXM_CMAP_CONNECTED_NOTIFY ||
	    handle->state == RXM_CMAP_CONNECTED)
		return FI_SUCCESS;

	switch (handle->state) {
	case RXM_CMAP_IDLE:
		ret = rxm_conn_connect(cmap->ep, handle,
				       ofi_av_get_addr(cmap->av, fi_addr),
				       cmap->av->addrlen);
		if (ret) {
			rxm_cmap_del_handle(handle);
			return ret;
		}
		handle->state = RXM_CMAP_CONNREQ_SENT;
		ret = -FI_EAGAIN;
		// TODO sleep on event fd instead of busy polling
		break;
	case RXM_CMAP_CONNREQ_SENT:
	case RXM_CMAP_CONNREQ_RECV:
	case RXM_CMAP_ACCEPT:
	case RXM_CMAP_SHUTDOWN:
		ret = -FI_EAGAIN;
		break;
	default:
		FI_WARN(cmap->av->prov, FI_LOG_EP_CTRL,
			"Invalid cmap handle state\n");
		assert(0);
		ret = -FI_EOPBADSTATE;
	}
	return ret;
}

int rxm_cmap_get_handle(struct rxm_cmap *cmap, fi_addr_t fi_addr,
			struct rxm_cmap_handle **handle_ret)
{
	int ret;

	cmap->acquire(&cmap->lock);
	*handle_ret = rxm_cmap_acquire_handle(cmap, fi_addr);
	if (OFI_UNLIKELY(!*handle_ret)) {
		ret = -FI_EAGAIN;
		goto unlock;
	}

	ret = rxm_cmap_handle_connect(cmap, fi_addr, *handle_ret);
unlock:
	cmap->release(&cmap->lock);
	return ret;
}

static int rxm_cmap_cm_thread_close(struct rxm_cmap *cmap)
{
	int ret;

	ret = rxm_conn_signal(cmap->ep, NULL, RXM_CMAP_EXIT);
	if (ret) {
		FI_WARN(cmap->av->prov, FI_LOG_FABRIC,
			"Unable to signal CM thread\n");
		return ret;
	}
	/* Release lock so that CM thread could process shutdown events */
	cmap->release(&cmap->lock);
	ret = pthread_join(cmap->cm_thread, NULL);
	cmap->acquire(&cmap->lock);
	if (ret) {
		FI_WARN(cmap->av->prov, FI_LOG_FABRIC,
			"Unable to join CM thread\n");
		return ret;
	}
	return 0;
}

static int rxm_conn_cleanup(void *arg)
{
	return rxm_conn_process_eq_events(container_of(arg, struct rxm_ep,
						       util_ep));
}


void rxm_cmap_free(struct rxm_cmap *cmap)
{
	struct rxm_cmap_peer *peer;
	struct dlist_entry *entry;
	size_t i;

	cmap->acquire(&cmap->lock);
	FI_DBG(cmap->av->prov, FI_LOG_EP_CTRL, "Closing cmap\n");
	for (i = 0; i < cmap->num_allocated; i++) {
		if (cmap->handles_av[i])
			rxm_cmap_del_handle(cmap->handles_av[i]);
	}
	while(!dlist_empty(&cmap->peer_list)) {
		entry = cmap->peer_list.next;
		peer = container_of(entry, struct rxm_cmap_peer, entry);
		rxm_cmap_del_handle(peer->handle);
	}
	rxm_cmap_cm_thread_close(cmap);
	cmap->release(&cmap->lock);

	/* cleanup function would be used in manual progress mode */
	if (cmap->ep->domain->data_progress != FI_PROGRESS_AUTO)
		rxm_conn_cleanup(cmap->ep);

	free(cmap->handles_av);
	free(cmap->attr.name);
	ofi_idx_reset(&cmap->handles_idx);
	if (!cmap->attr.serial_access)
		fastlock_destroy(&cmap->lock);
	free(cmap);
}

static int
rxm_cmap_update_addr(struct util_av *av, void *addr,
		     fi_addr_t fi_addr, void *arg)
{
	return rxm_cmap_update((struct rxm_cmap *)arg, addr, fi_addr);
}

int rxm_cmap_bind_to_av(struct rxm_cmap *cmap, struct util_av *av)
{
	cmap->av = av;
	return ofi_av_elements_iter(av, rxm_cmap_update_addr, (void *)cmap);
}

int rxm_cmap_alloc(struct rxm_ep *rxm_ep, struct rxm_cmap_attr *attr)
{
	struct rxm_cmap *cmap;
	struct util_ep *ep = &rxm_ep->util_ep;
	int ret;

	cmap = calloc(1, sizeof *cmap);
	if (!cmap)
		return -FI_ENOMEM;

	cmap->ep = ep;
	cmap->av = ep->av;

	cmap->handles_av = calloc(cmap->av->count, sizeof(*cmap->handles_av));
	if (!cmap->handles_av) {
		ret = -FI_ENOMEM;
		goto err1;
	}
	cmap->num_allocated = ep->av->count;

	cmap->attr = *attr;
	cmap->attr.name = mem_dup(attr->name, ep->av->addrlen);
	if (!cmap->attr.name) {
		ret = -FI_ENOMEM;
		goto err2;
	}

	memset(&cmap->handles_idx, 0, sizeof(cmap->handles_idx));
	ofi_key_idx_init(&cmap->key_idx, RXM_CMAP_IDX_BITS);

	dlist_init(&cmap->peer_list);

	if (cmap->attr.serial_access) {
		cmap->acquire = ofi_fastlock_acquire_noop;
		cmap->release = ofi_fastlock_release_noop;
	} else {
		fastlock_init(&cmap->lock);
		cmap->acquire = ofi_fastlock_acquire;
		cmap->release = ofi_fastlock_release;
	}

	rxm_ep->cmap = cmap;

	if (ep->domain->data_progress == FI_PROGRESS_AUTO) {
		if (pthread_create(&cmap->cm_thread, 0,
				   rxm_conn_progress, ep)) {
			FI_WARN(ep->av->prov, FI_LOG_FABRIC,
				"Unable to create cmap thread\n");
			ret = -ofi_syserr();
			goto err3;
		}
	} else {
		if (pthread_create(&cmap->cm_thread, 0,
				   rxm_conn_eq_read, ep)) {
			FI_WARN(ep->av->prov, FI_LOG_FABRIC,
				"Unable to create cmap thread\n");
			ret = -ofi_syserr();
			goto err3;
		}
	}

	assert(ep->av);
	ret = rxm_cmap_bind_to_av(cmap, ep->av);
	if (ret)
		goto err4;

	return FI_SUCCESS;
err4:
	rxm_cmap_cm_thread_close(cmap);
err3:
	free(cmap->attr.name);
err2:
	free(cmap->handles_av);
err1:
	rxm_ep->cmap = NULL;
	return ret;
}

static int rxm_msg_ep_open(struct rxm_ep *rxm_ep, struct fi_info *msg_info,
			   struct rxm_conn *rxm_conn, void *context)
{
	struct rxm_domain *rxm_domain;
	struct fid_ep *msg_ep;
	int ret;

	rxm_domain = container_of(rxm_ep->util_ep.domain, struct rxm_domain,
			util_domain);
	ret = fi_endpoint(rxm_domain->msg_domain, msg_info, &msg_ep, context);
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "Unable to create msg_ep\n");
		return ret;
	}

	ret = fi_ep_bind(msg_ep, &rxm_ep->msg_eq->fid, 0);
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_FABRIC, "Unable to bind msg EP to EQ\n");
		goto err;
	}

	if (rxm_ep->srx_ctx) {
		ret = fi_ep_bind(msg_ep, &rxm_ep->srx_ctx->fid, 0);
		if (ret) {
			FI_WARN(&rxm_prov, FI_LOG_FABRIC,
				"Unable to bind msg EP to shared RX ctx\n");
			goto err;
		}
	}

	// TODO add other completion flags
	ret = fi_ep_bind(msg_ep, &rxm_ep->msg_cq->fid, FI_TRANSMIT | FI_RECV);
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
				"Unable to bind msg_ep to msg_cq\n");
		goto err;
	}

	ret = fi_enable(msg_ep);
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "Unable to enable msg_ep\n");
		goto err;
	}

	if (!rxm_ep->srx_ctx) {
		ret = rxm_ep_prepost_buf(rxm_ep, msg_ep);
		if (ret)
			goto err;
	}

	rxm_conn->msg_ep = msg_ep;
	return 0;
err:
	fi_close(&msg_ep->fid);
	return ret;
}

static void rxm_conn_close(struct rxm_cmap_handle *handle)
{
	struct rxm_conn *rxm_conn =
		container_of(handle, struct rxm_conn, handle);

	if (!rxm_conn->msg_ep)
		return;

	if (handle->cmap->attr.serial_access) {
		if (fi_close(&rxm_conn->msg_ep->fid)) {
			FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
				"Unable to close msg_ep\n");
		} else {
			FI_DBG(&rxm_prov, FI_LOG_EP_CTRL,
			       "Closed msg_ep\n");
		}
	} else {
		rxm_conn->saved_msg_ep = rxm_conn->msg_ep;
		FI_DBG(&rxm_prov, FI_LOG_EP_CTRL,
		       "Saved MSG EP fid for further deletion in main thread\n");
	}
	rxm_conn->msg_ep = NULL;
}

static void rxm_conn_save(struct rxm_cmap_handle *handle)
{
	struct rxm_conn *rxm_conn =
		container_of(handle, struct rxm_conn, handle);

	if (!rxm_conn->msg_ep)
		return;

	rxm_conn->saved_msg_ep = rxm_conn->msg_ep;
	FI_DBG(&rxm_prov, FI_LOG_EP_CTRL,
	       "Saved MSG EP fid for further deletion\n");
	rxm_conn->msg_ep = NULL;
}

static void rxm_conn_close_saved(struct rxm_cmap_handle *handle)
{
	struct rxm_conn *rxm_conn =
		container_of(handle, struct rxm_conn, handle);

	if (!rxm_conn->saved_msg_ep)
		return;

	/* If user doesn't guarantee for serializing access to cmap
	 * objects, postpone the closing of the saved MSG EP for
	 * further deletion in main thread  */
	if (handle->cmap->attr.serial_access) {
		if (fi_close(&rxm_conn->saved_msg_ep->fid)) {
			FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
				"Unable to close saved msg_ep\n");
		} else {
			FI_DBG(&rxm_prov, FI_LOG_EP_CTRL,
			       "Closed saved msg_ep\n");
		}
		rxm_conn->saved_msg_ep = NULL;
	}
}

static void rxm_conn_connected_handler(struct rxm_cmap_handle *handle)
{
	struct rxm_conn *rxm_conn = container_of(handle, struct rxm_conn, handle);

	if (!rxm_conn->saved_msg_ep)
		return;
	/* Assuming fi_close also shuts down the connection gracefully if the
	 * endpoint is in connected state */
	if (fi_close(&rxm_conn->saved_msg_ep->fid))
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "Unable to close saved msg_ep\n");
	FI_DBG(&rxm_prov, FI_LOG_EP_CTRL, "Closed saved msg_ep\n");
	rxm_conn->saved_msg_ep = NULL;
}

static int rxm_conn_reprocess_directed_recvs(struct rxm_recv_queue *recv_queue)
{
	struct rxm_rx_buf *rx_buf;
	struct dlist_entry *entry, *tmp_entry;
	struct rxm_recv_match_attr match_attr;
	struct dlist_entry rx_buf_list;
	struct fi_cq_err_entry err_entry = {0};
	int ret, count = 0;

	dlist_init(&rx_buf_list);

	recv_queue->rxm_ep->cmap->acquire(&recv_queue->rxm_ep->cmap->lock);
	recv_queue->rxm_ep->res_fastlock_acquire(&recv_queue->lock);

	dlist_foreach_container_safe(&recv_queue->unexp_msg_list,
				     struct rxm_rx_buf, rx_buf,
				     unexp_msg.entry, tmp_entry) {
		if (rx_buf->unexp_msg.addr == rx_buf->conn->handle.fi_addr)
			continue;

		assert(rx_buf->unexp_msg.addr == FI_ADDR_NOTAVAIL);

		match_attr.addr = rx_buf->unexp_msg.addr =
			rx_buf->conn->handle.fi_addr;
		match_attr.tag = rx_buf->unexp_msg.tag;

		entry = dlist_remove_first_match(&recv_queue->recv_list,
						 recv_queue->match_recv,
						 &match_attr);
		if (!entry)
			continue;

		dlist_remove(&rx_buf->unexp_msg.entry);
		rx_buf->recv_entry = container_of(entry, struct rxm_recv_entry,
						  entry);
		dlist_insert_tail(&rx_buf->unexp_msg.entry, &rx_buf_list);
	}
	recv_queue->rxm_ep->res_fastlock_release(&recv_queue->lock);
	recv_queue->rxm_ep->cmap->release(&recv_queue->rxm_ep->cmap->lock);

	while (!dlist_empty(&rx_buf_list)) {
		dlist_pop_front(&rx_buf_list, struct rxm_rx_buf,
				rx_buf, unexp_msg.entry);
		ret = rxm_cq_handle_rx_buf(rx_buf);
		if (ret) {
			err_entry.op_context = rx_buf;
			err_entry.flags = rx_buf->recv_entry->comp_flags;
			err_entry.len = rx_buf->pkt.hdr.size;
			err_entry.data = rx_buf->pkt.hdr.data;
			err_entry.tag = rx_buf->pkt.hdr.tag;
			err_entry.err = ret;
			err_entry.prov_errno = ret;
			ofi_cq_write_error(recv_queue->rxm_ep->util_ep.rx_cq,
					   &err_entry);
			if (rx_buf->ep->util_ep.flags & OFI_CNTR_ENABLED)
				rxm_cntr_incerr(rx_buf->ep->util_ep.rx_cntr);

			rxm_enqueue_rx_buf_for_repost_check(rx_buf);

			if (!(rx_buf->recv_entry->flags & FI_MULTI_RECV))
				rxm_recv_entry_release(recv_queue,
						       rx_buf->recv_entry);
		}
		count++;
	}
	return count;
}

static void
rxm_conn_av_updated_handler(struct rxm_cmap_handle *handle)
{
	struct rxm_ep *rxm_ep = container_of(handle->cmap->ep, struct rxm_ep, util_ep);
	int count = 0;

	if (rxm_ep->rxm_info->caps & FI_DIRECTED_RECV) {
		count += rxm_conn_reprocess_directed_recvs(&rxm_ep->recv_queue);
		count += rxm_conn_reprocess_directed_recvs(&rxm_ep->trecv_queue);

		FI_DBG(&rxm_prov, FI_LOG_EP_CTRL,
		       "Reprocessed directed recvs - %d\n", count);
	}
}

static struct rxm_cmap_handle *rxm_conn_alloc(struct rxm_cmap *cmap)
{
	int ret;
	struct rxm_ep *rxm_ep = container_of(cmap->ep, struct rxm_ep, util_ep);
	struct rxm_conn *rxm_conn = calloc(1, sizeof(*rxm_conn));
	if (OFI_UNLIKELY(!rxm_conn))
		return NULL;

	dlist_init(&rxm_conn->deferred_conn_entry);
	dlist_init(&rxm_conn->deferred_tx_queue);
	ret = rxm_conn_send_queue_init(rxm_ep, rxm_conn,
				       rxm_ep->msg_info->tx_attr->size);
	if (ret) {
		free(rxm_conn);
		return NULL;
	}
	dlist_init(&rxm_conn->sar_rx_msg_list);
	return &rxm_conn->handle;
}

static inline int
rxm_conn_verify_cm_data(struct rxm_cm_data *remote_cm_data,
			struct rxm_cm_data *local_cm_data)
{
	if (remote_cm_data->proto.endianness != local_cm_data->proto.endianness) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
			"endianness of two peers (%"PRIu8" vs %"PRIu8")"
			"are mismatched\n",
			remote_cm_data->proto.endianness,
			local_cm_data->proto.endianness);
		goto err;
	}
	if (remote_cm_data->proto.ctrl_version != local_cm_data->proto.ctrl_version) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
			"ctrl_version of two peers (%"PRIu8" vs %"PRIu8")"
			"are mismatched\n",
			remote_cm_data->proto.ctrl_version,
			local_cm_data->proto.ctrl_version);
		goto err;
	}
	if (remote_cm_data->proto.op_version != local_cm_data->proto.op_version) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
			"op_version of two peers (%"PRIu8" vs %"PRIu8")"
			"are mismatched\n",
			remote_cm_data->proto.op_version,
			local_cm_data->proto.op_version);
		goto err;
	}
	if (remote_cm_data->proto.eager_size != local_cm_data->proto.eager_size) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
			"inject_size of two peers (%"PRIu64" vs %"PRIu64")"
			"are mismatched\n",
			remote_cm_data->proto.eager_size,
			local_cm_data->proto.eager_size);
		goto err;
	}
	return FI_SUCCESS;
err:
	return -FI_EINVAL;
}

static int
rxm_msg_process_connreq(struct rxm_ep *rxm_ep, struct fi_info *msg_info,
			void *data)
{
	struct rxm_conn *rxm_conn;
	struct rxm_cm_data *remote_cm_data = data;
	struct rxm_cm_data cm_data = {
		.proto = {
			.ctrl_version = RXM_CTRL_VERSION,
			.op_version = RXM_OP_VERSION,
			.endianness = ofi_detect_endianness(),
			.eager_size = rxm_ep->rxm_info->tx_attr->inject_size,
		},
	};
	struct rxm_cmap_handle *handle;
	int ret;
	enum rxm_cmap_reject_flag cm_reject_flag = RXM_CMAP_REJECT_GENUINE;

	remote_cm_data->proto.eager_size = ntohll(remote_cm_data->proto.eager_size);

	if (rxm_conn_verify_cm_data(remote_cm_data, &cm_data)) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
			"CM data mismatch was detected\n");
		ret = -FI_EINVAL;
		goto err1;
	}

	ret = rxm_cmap_process_connreq(rxm_ep->cmap,
				       &remote_cm_data->name,
				       &handle, &cm_reject_flag);
	if (ret)
		goto err1;

	rxm_conn = container_of(handle, struct rxm_conn, handle);

	rxm_conn->handle.remote_key = remote_cm_data->conn_id;

	ret = rxm_msg_ep_open(rxm_ep, msg_info, rxm_conn, handle);
	if (ret)
		goto err2;

	cm_data.conn_id = rxm_conn->handle.key;
	cm_data.proto.eager_size = htonll(cm_data.proto.eager_size);

	ret = fi_accept(rxm_conn->msg_ep, &cm_data, sizeof(cm_data));
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_FABRIC,
			"Unable to accept incoming connection\n");
		goto err2;
	}
	return ret;
err2:
	rxm_cmap_del_handle_ts(&rxm_conn->handle);
err1:
	FI_DBG(&rxm_prov, FI_LOG_EP_CTRL,
	       "Rejecting incoming connection request (reject flag - %d)\n",
	       cm_reject_flag);
	if (fi_reject(rxm_ep->msg_pep, msg_info->handle,
		      &cm_reject_flag, sizeof(cm_reject_flag)))
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
			"Unable to reject incoming connection\n");
	return ret;
}

static int rxm_conn_handle_notify(struct fi_eq_entry *eq_entry)
{
	if ((enum rxm_cmap_signal)eq_entry->data == RXM_CMAP_FREE) {
		rxm_conn_free((struct rxm_cmap_handle *)eq_entry->context);
		return 0;
	} else {
		FI_WARN(&rxm_prov, FI_LOG_FABRIC, "Unknown cmap signal\n");
		assert(0);
		return -FI_EOTHER;
	}
}

static void rxm_conn_wake_up_wait_obj(struct rxm_ep *rxm_ep)
{
	if (rxm_ep->util_ep.tx_cq->wait)
		util_cq_signal(rxm_ep->util_ep.tx_cq);
	if (rxm_ep->util_ep.tx_cntr && rxm_ep->util_ep.tx_cntr->wait)
		util_cntr_signal(rxm_ep->util_ep.tx_cntr);
}

static int
rxm_conn_handle_event(struct rxm_ep *rxm_ep, struct rxm_msg_eq_entry *entry)
{
	struct rxm_cm_data *cm_data;

	if (entry->rd == -FI_ECONNREFUSED) {
		enum rxm_cmap_reject_flag cm_reject_flag;

		if (OFI_LIKELY(entry->err_entry.err_data_size >=
				sizeof(enum rxm_cmap_reject_flag))) {
			assert(entry->err_entry.err_data);
			cm_reject_flag = *((enum rxm_cmap_reject_flag *)
						entry->err_entry.err_data);
		} else {
			FI_WARN(&rxm_prov, FI_LOG_FABRIC,
				"Error -FI_ECONNREFUSED was provided without error data\n");
			cm_reject_flag = RXM_CMAP_REJECT_GENUINE;
		}

		FI_DBG(&rxm_prov, FI_LOG_FABRIC,
		       "Received reject (reject flag - %d)\n",
		       cm_reject_flag);
		assert((cm_reject_flag == RXM_CMAP_REJECT_GENUINE) ||
		       (cm_reject_flag == RXM_CMAP_REJECT_SIMULT_CONN));
		rxm_cmap_process_reject(rxm_ep->cmap, entry->context,
					cm_reject_flag);
		return 0;
	}

	switch(entry->event) {
	case FI_NOTIFY:
		if (rxm_conn_handle_notify((struct fi_eq_entry *)&entry->cm_entry))
			goto err;
		break;
	case FI_CONNREQ:
		FI_DBG(&rxm_prov, FI_LOG_FABRIC, "Got new connection\n");
		if ((size_t)entry->rd != RXM_CM_ENTRY_SZ) {
			FI_WARN(&rxm_prov, FI_LOG_FABRIC,
				"Received size (%zd) not matching "
				"expected (%zu)\n", entry->rd, RXM_CM_ENTRY_SZ);
			goto err;
		}
		rxm_msg_process_connreq(rxm_ep, entry->cm_entry.info, entry->cm_entry.data);
		fi_freeinfo(entry->cm_entry.info);
		break;
	case FI_CONNECTED:
		FI_DBG(&rxm_prov, FI_LOG_FABRIC,
		       "Connection successful\n");
		rxm_ep->cmap->acquire(&rxm_ep->cmap->lock);
		cm_data = (void *)entry->cm_entry.data;
		rxm_cmap_process_connect(rxm_ep->cmap,
					 entry->cm_entry.fid->context,
					 ((entry->rd - sizeof(entry->cm_entry)) ?
					  &cm_data->conn_id : NULL));
		rxm_conn_wake_up_wait_obj(rxm_ep);
		rxm_ep->cmap->release(&rxm_ep->cmap->lock);
		break;
	case FI_SHUTDOWN:
		FI_DBG(&rxm_prov, FI_LOG_FABRIC,
		       "Received connection shutdown\n");
		rxm_cmap_process_shutdown(rxm_ep->cmap,
					  entry->cm_entry.fid->context);
		break;
	default:
		FI_WARN(&rxm_prov, FI_LOG_FABRIC,
			"Unknown event: %u\n", entry->event);
		goto err;
	}
	return 0;
err:
	return -FI_EOTHER;
}

int rxm_conn_process_eq_events(struct rxm_ep *rxm_ep)
{
	struct rxm_msg_eq_entry *entry;
	struct slist_entry *slist_entry;
	int ret;

	fastlock_acquire(&rxm_ep->msg_eq_entry_list_lock);
	while (!slistfd_empty(&rxm_ep->msg_eq_entry_list)) {
		slist_entry = slistfd_remove_head(&rxm_ep->msg_eq_entry_list);
		entry = container_of(slist_entry, struct rxm_msg_eq_entry,
				     slist_entry);

		fastlock_release(&rxm_ep->msg_eq_entry_list_lock);

		ret = rxm_conn_handle_event(rxm_ep, entry);
		free(entry);
		fastlock_acquire(&rxm_ep->msg_eq_entry_list_lock);
		if (ret)
			break;
	}
	fastlock_release(&rxm_ep->msg_eq_entry_list_lock);
	return ret;
}

static ssize_t rxm_eq_sread(struct rxm_ep *rxm_ep, size_t len,
			    struct rxm_msg_eq_entry *entry)
{
	ssize_t rd;
	int once = 1;

	do {
		rd = fi_eq_sread(rxm_ep->msg_eq, &entry->event, &entry->cm_entry,
				 len, -1, 0);
		if (rd >= 0)
			return rd;
		if (rd == -FI_EINTR && once) {
			FI_DBG(&rxm_prov, FI_LOG_EP_CTRL, "Ignoring EINTR\n");
			once = 0;
		}
	} while (rd == -FI_EINTR);

	if (rd != -FI_EAVAIL) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
			"Unable to fi_eq_sread: %zu\n", rd);
		return rd;
	}

	OFI_EQ_READERR(&rxm_prov, FI_LOG_EP_CTRL, rxm_ep->msg_eq, rd, entry->err_entry);

	if (entry->err_entry.err == ECONNREFUSED) {
		FI_DBG(&rxm_prov, FI_LOG_EP_CTRL, "Connection refused\n");
		entry->context = entry->err_entry.fid->context;
		return -FI_ECONNREFUSED;
	} else {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "Unknown error: %d\n",
			entry->err_entry.err);
		return rd;
	}
}

static void *rxm_conn_eq_read(void *arg)
{
	struct rxm_ep *rxm_ep = arg;
	struct rxm_msg_eq_entry *entry;

	while (1) {
		entry = calloc(1, RXM_MSG_EQ_ENTRY_SZ);
		if (!entry) {
			FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
				"Unable to allocate memory!\n");
			return NULL;
		}

		entry->rd = rxm_eq_sread(rxm_ep, RXM_CM_ENTRY_SZ, entry);
		if (entry->rd < 0 && entry->rd != -FI_ECONNREFUSED)
			goto exit;

		if (entry->event == FI_NOTIFY &&
		    (enum rxm_cmap_signal)((struct fi_eq_entry *)
					   &entry->cm_entry)->data == RXM_CMAP_EXIT) {
			FI_DBG(&rxm_prov, FI_LOG_EP_CTRL, "Closing CM thread\n");
			goto exit;
		}

		FI_DBG(&rxm_prov, FI_LOG_EP_CTRL,
		       "Enqueing event: %d\n", entry->event);
		fastlock_acquire(&rxm_ep->msg_eq_entry_list_lock);
		slistfd_insert_tail(&entry->slist_entry,
				    &rxm_ep->msg_eq_entry_list);
		fastlock_release(&rxm_ep->msg_eq_entry_list_lock);
	}
exit:
	free(entry);
	return NULL;
}

static void *rxm_conn_progress(void *arg)
{
	struct rxm_ep *rxm_ep = container_of(arg, struct rxm_ep, util_ep);
	struct rxm_msg_eq_entry *entry;
	int ret;

	entry = calloc(1, RXM_MSG_EQ_ENTRY_SZ);
	if (!entry) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
			"Unable to allocate memory!\n");
		return NULL;
	}
	FI_DBG(&rxm_prov, FI_LOG_EP_CTRL, "Starting conn event handler\n");

	while (1) {
		entry->rd = rxm_eq_sread(rxm_ep, RXM_CM_ENTRY_SZ, entry);
		if (entry->rd < 0 && entry->rd != -FI_ECONNREFUSED)
			goto exit;

		if (entry->event == FI_NOTIFY &&
		    (enum rxm_cmap_signal)((struct fi_eq_entry *)
					   &entry->cm_entry)->data == RXM_CMAP_EXIT) {
			FI_DBG(&rxm_prov, FI_LOG_EP_CTRL,
			       "Closing CM thread\n");
			goto exit;
		}
		ret = rxm_conn_handle_event(rxm_ep, entry);
		if (ret)
			goto exit;
		memset(entry, 0, RXM_MSG_EQ_ENTRY_SZ);
	}
exit:
	free(entry);
	return NULL;
}

static int rxm_prepare_cm_data(struct fid_pep *pep, struct rxm_cmap_handle *handle,
		struct rxm_cm_data *cm_data)
{
	size_t cm_data_size = 0;
	size_t name_size = sizeof(cm_data->name);
	size_t opt_size = sizeof(cm_data_size);
	int ret;

	ret = fi_getopt(&pep->fid, FI_OPT_ENDPOINT, FI_OPT_CM_DATA_SIZE,
			&cm_data_size, &opt_size);
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "fi_getopt failed\n");
		return ret;
	}

	if (cm_data_size < sizeof(*cm_data)) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "MSG EP CM data size too small\n");
		return -FI_EOTHER;
	}

	ret = fi_getname(&pep->fid, &cm_data->name, &name_size);
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "Unable to get msg pep name\n");
		return ret;
	}

	cm_data->conn_id = handle->key;
	return 0;
}

static int
rxm_conn_connect(struct util_ep *util_ep, struct rxm_cmap_handle *handle,
		 const void *addr, size_t addrlen)
{
	struct fi_info *msg_info;
	int ret;
	struct rxm_ep *rxm_ep =
		container_of(util_ep, struct rxm_ep, util_ep);
	struct rxm_conn *rxm_conn =
		container_of(handle, struct rxm_conn, handle);
	struct rxm_cm_data cm_data = {
		.proto = {
			.ctrl_version = RXM_CTRL_VERSION,
			.op_version = RXM_OP_VERSION,
			.endianness = ofi_detect_endianness(),
			.eager_size = rxm_ep->rxm_info->tx_attr->inject_size,
		},
	};

	free(rxm_ep->msg_info->dest_addr);
	rxm_ep->msg_info->dest_addrlen = addrlen;

	rxm_ep->msg_info->dest_addr = mem_dup(addr, rxm_ep->msg_info->dest_addrlen);
	if (!rxm_ep->msg_info->dest_addr)
		return -FI_ENOMEM;

	ret = fi_getinfo(rxm_ep->util_ep.domain->fabric->fabric_fid.api_version,
			 NULL, NULL, 0, rxm_ep->msg_info, &msg_info);
	if (ret)
		return ret;

	ret = rxm_msg_ep_open(rxm_ep, msg_info, rxm_conn, &rxm_conn->handle);
	if (ret)
		goto err1;

	/* We have to send passive endpoint's address to the server since the
	 * address from which connection request would be sent would have a
	 * different port. */
	ret = rxm_prepare_cm_data(rxm_ep->msg_pep, &rxm_conn->handle, &cm_data);
	if (ret)
		goto err2;

	cm_data.proto.eager_size = htonll(cm_data.proto.eager_size);

	ret = fi_connect(rxm_conn->msg_ep, msg_info->dest_addr, &cm_data, sizeof(cm_data));
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL, "Unable to connect msg_ep\n");
		goto err2;
	}
	fi_freeinfo(msg_info);
	return 0;
err2:
	fi_close(&rxm_conn->msg_ep->fid);
	rxm_conn->msg_ep = NULL;
err1:
	fi_freeinfo(msg_info);
	return ret;
}

static int rxm_conn_signal(struct util_ep *util_ep, void *context,
			   enum rxm_cmap_signal signal)
{
	struct rxm_ep *rxm_ep = container_of(util_ep, struct rxm_ep, util_ep);
	struct fi_eq_entry entry = {0};
	ssize_t rd;

	entry.context = context;
	entry.data = (uint64_t)signal;

	rd = fi_eq_write(rxm_ep->msg_eq, FI_NOTIFY, &entry, sizeof(entry), 0);
	if (rd != sizeof(entry)) {
		FI_WARN(&rxm_prov, FI_LOG_FABRIC, "Unable to signal\n");
		return (int)rd;
	}
	return 0;
}

int rxm_conn_cmap_alloc(struct rxm_ep *rxm_ep)
{
	struct rxm_cmap_attr attr;
	int ret;
	size_t len = rxm_ep->util_ep.av->addrlen;
	void *name = calloc(1, len);
	if (!name) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
			"Unable to allocate memory for EP name\n");
		return -FI_ENOMEM;
	}

	/* Passive endpoint should already have fi_setname or fi_listen
	 * called on it for this to work */
	ret = fi_getname(&rxm_ep->msg_pep->fid, name, &len);
	if (ret) {
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
			"Unable to fi_getname on msg_ep\n");
		goto fn;
	}
	ofi_straddr_dbg(&rxm_prov, FI_LOG_EP_CTRL, "local_name", name);

	attr.name		= name;

	if (rxm_ep->util_ep.domain->threading == FI_THREAD_DOMAIN &&
	    rxm_ep->util_ep.domain->data_progress == FI_PROGRESS_MANUAL)
		attr.serial_access = 1;
	else
		attr.serial_access = 0;

	ret = rxm_cmap_alloc(rxm_ep, &attr);
	if (ret)
		FI_WARN(&rxm_prov, FI_LOG_EP_CTRL,
			"Unable to allocate CMAP\n");
fn:
	free(name);
	return ret;
}
