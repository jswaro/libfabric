/*
 * Copyright (c) 2015 Cray Inc. All rights reserved.
 * Copyright (c) 2015 Los Alamos National Security, LLC. All rights reserved.
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
#include <assert.h>

#include "gnix.h"
#include "gnix_cm_nic.h"
#include "gnix_nic.h"
#include "gnix_util.h"
#include "gnix_ep.h"
#include "gnix_hashtable.h"
#include "gnix_vc.h"
#include "gnix_cntr.h"
#include "gnix_av.h"

/*******************************************************************************
 * helper functions
 ******************************************************************************/

static void __gnix_msg_queues(struct gnix_fid_ep *ep,
			      int tagged,
			      fastlock_t **queue_lock,
			      struct gnix_tag_storage **posted_queue,
			      struct gnix_tag_storage **unexp_queue)
{
	if (tagged) {
		*queue_lock = &ep->tagged_queue_lock;
		*posted_queue = &ep->tagged_posted_recv_queue;
		*unexp_queue = &ep->tagged_unexp_recv_queue;
	} else {
		*queue_lock = &ep->recv_queue_lock;
		*posted_queue = &ep->posted_recv_queue;
		*unexp_queue = &ep->unexp_recv_queue;
	}
}


static int __gnix_recv_completion(struct gnix_fid_ep *ep,
				  struct gnix_fab_req *req)
{
	struct gnix_fid_cq *cq;
	int rc;

	cq = ep->recv_cq;
	assert(cq != NULL);

	rc = _gnix_cq_add_event(cq,
				req->user_context,
				FI_RECV | FI_MSG,
				req->msg.recv_len,
				(void *)req->msg.recv_addr,
				req->msg.imm,
				0);
	if (rc != FI_SUCCESS)  {
		GNIX_WARN((FI_LOG_CQ | FI_LOG_EP_DATA),
				"_gnix_cq_add_event returned %d\n",
				rc);
	}

	if (ep->recv_cntr) {
		rc = _gnix_cntr_inc(ep->recv_cntr);
		if (rc != FI_SUCCESS)
			GNIX_WARN(FI_LOG_CQ,
				  "_gnix_cntr_inc() failed: %d\n",
				  rc);
	}

	return FI_SUCCESS;
}

static int __gnix_send_completion(struct gnix_fid_ep *ep,
				  struct gnix_fab_req *req)
{
	struct gnix_fid_cq *cq;
	int rc;

	cq = ep->send_cq;
	assert(cq != NULL);

	rc = _gnix_cq_add_event(cq,
				req->user_context,
				FI_SEND | FI_MSG,
				req->msg.send_len,
				(void *)req->msg.send_addr,
				req->msg.imm,
				0);
	if (rc != FI_SUCCESS)  {
		GNIX_WARN((FI_LOG_CQ | FI_LOG_EP_DATA),
				"_gnix_cq_add_event returned %d\n",
				rc);
	}

	if (ep->send_cntr) {
		rc = _gnix_cntr_inc(ep->send_cntr);
		if (rc != FI_SUCCESS)
			GNIX_WARN(FI_LOG_CQ,
				  "_gnix_cntr_inc() failed: %d\n",
				  rc);
	}

	return FI_SUCCESS;
}

static int __gnix_rndzv_req_complete(void *arg)
{
	struct gnix_tx_descriptor *txd = (struct gnix_tx_descriptor *)arg;
	struct gnix_fab_req *req = txd->req;
	struct gnix_nic *nic;
	struct gnix_fid_ep *ep;
	gni_return_t status;

	GNIX_INFO(FI_LOG_EP_DATA, "Completed RNDZV GET, req: %p\n", req);

	ep = req->gnix_ep;
	assert(ep != NULL);

	nic = ep->nic;
	assert(nic != NULL);

	txd->rndzv_fin_hdr.req_addr = req->msg.rma_id;

	txd->req = req;
	txd->completer_fn = gnix_ep_smsg_completers[GNIX_SMSG_T_RNDZV_FIN];

	fastlock_acquire(&nic->lock);
	status = GNI_SmsgSendWTag(req->vc->gni_ep,
			&txd->rndzv_fin_hdr, sizeof(txd->rndzv_fin_hdr),
			NULL, 0, txd->id, GNIX_SMSG_T_RNDZV_FIN);
	fastlock_release(&nic->lock);

	if (status == GNI_RC_NOT_DONE) {
		GNIX_INFO(FI_LOG_EP_DATA,
			  "GNI_SmsgSendWTag returned %s\n",
			  gni_err_str[status]);
	} else if (status != GNI_RC_SUCCESS) {
		GNIX_WARN(FI_LOG_EP_DATA,
			  "GNI_SmsgSendWTag returned %s\n",
			  gni_err_str[status]);
	}

	GNIX_INFO(FI_LOG_EP_DATA, "Initiated RNDZV_FIN, req: %p\n", req);

	return gnixu_to_fi_errno(status);
}

static int __gnix_rndzv_req(struct gnix_fab_req *req)
{
	struct gnix_fid_ep *ep = req->gnix_ep;
	struct gnix_nic *nic = ep->nic;
	struct gnix_tx_descriptor *txd;
	gni_return_t status;
	int rc;

	rc = _gnix_nic_tx_alloc(nic, &txd);
	if (rc) {
		GNIX_INFO(FI_LOG_EP_DATA, "_gnix_nic_tx_alloc() failed: %d\n",
			 rc);
		return -FI_EAGAIN;
	}

	txd->completer_fn = __gnix_rndzv_req_complete;
	txd->req = req;

	txd->gni_desc.type = GNI_POST_RDMA_GET;
	txd->gni_desc.cq_mode = GNI_CQMODE_GLOBAL_EVENT;
	txd->gni_desc.dlvr_mode = GNI_DLVMODE_PERFORMANCE;
	txd->gni_desc.local_addr = (uint64_t)req->msg.recv_addr;
	txd->gni_desc.local_mem_hndl = req->msg.recv_md->mem_hndl;
	txd->gni_desc.remote_addr = (uint64_t)req->msg.send_addr;
	txd->gni_desc.remote_mem_hndl = req->msg.rma_mdh;
	txd->gni_desc.length = req->msg.recv_len;
	txd->gni_desc.rdma_mode = 0;
	txd->gni_desc.src_cq_hndl = nic->tx_cq;

	/* TODO NIC lock is held for now */
	status = GNI_PostRdma(req->vc->gni_ep, &txd->gni_desc);
	if (status != GNI_RC_SUCCESS) {
		GNIX_INFO(FI_LOG_EP_DATA, "GNI_PostRdma failed: %s\n",
			  gni_err_str[status]);
	}

	GNIX_INFO(FI_LOG_EP_DATA, "Initiated RNDZV GET, req: %p\n", req);

	return gnixu_to_fi_errno(status);
}

/*******************************************************************************
 * GNI SMSG callbacks invoked upon completion of an SMSG message at the sender.
 ******************************************************************************/

static int __comp_eager_msg_w_data(void *data)
{
	int ret = FI_SUCCESS;
	struct gnix_tx_descriptor *tdesc;
	struct gnix_fid_ep *ep;
	struct gnix_fab_req *req;

	tdesc = (struct gnix_tx_descriptor *)data;
	req = tdesc->req;

	ep = req->gnix_ep;
	assert(ep != NULL);

	__gnix_send_completion(ep, req);

	atomic_dec(&req->vc->outstanding_tx_reqs);
	_gnix_nic_tx_free(req->gnix_ep->nic, tdesc);

	/* We could have requests waiting for TXDs or FI_FENCE operations.
	 * Schedule this VC to push any such TXs. */
	_gnix_vc_schedule_tx(req->vc);

	_gnix_fr_free(ep, req);

	return ret;
}

static int __comp_eager_msg_w_data_ack(void *data)
{
	return -FI_ENOSYS;
}

static int __comp_eager_msg_data_at_src(void *data)
{
	return -FI_ENOSYS;
}

static int __comp_eager_msg_data_at_src_ack(void *data)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_rts(void *data)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_rtr(void *data)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_cookie(void *data)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_send_done(void *data)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_recv_done(void *data)
{
	return -FI_ENOSYS;
}

/* Completed request to start rendezvous send. */
static int __comp_rndzv_start(void *data)
{
	struct gnix_tx_descriptor *txd = (struct gnix_tx_descriptor *)data;

	_gnix_nic_tx_free(txd->req->gnix_ep->nic, txd);

	/* Request remains active until remote peer notifies us they're done
	 * with the send buffer.
	 *
	 * TODO: check for unlikely case where RNDZV_FIN was received before
	 * this RNDZV_START completion. */

	GNIX_INFO(FI_LOG_EP_DATA, "Completed RNDZV_START, req: %p\n", txd->req);

	return FI_SUCCESS;
}

/* Notified sender that rendezvous data has been moved.  Rendezvous send
 * complete.  Generate Completions. */
static int __comp_rndzv_fin(void *data)
{
	int ret = FI_SUCCESS;
	struct gnix_tx_descriptor *tdesc;
	struct gnix_fid_ep *ep;
	struct gnix_fab_req *req;

	tdesc = (struct gnix_tx_descriptor *)data;
	req = tdesc->req;

	GNIX_INFO(FI_LOG_EP_DATA, "Completed RNDZV_FIN, req: %p\n", req);

	ep = req->gnix_ep;
	assert(ep != NULL);

	__gnix_recv_completion(ep, req);

	_gnix_nic_tx_free(ep->nic, tdesc);

	/* We could have requests waiting for TXDs.  Schedule this VC to push
	 * any such TXs. */
	_gnix_vc_schedule_tx(req->vc);

	_gnix_fr_free(ep, req);

	return ret;
}

smsg_completer_fn_t gnix_ep_smsg_completers[] = {
	[GNIX_SMSG_T_EGR_W_DATA] = __comp_eager_msg_w_data,
	[GNIX_SMSG_T_EGR_W_DATA_ACK] = __comp_eager_msg_w_data_ack,
	[GNIX_SMSG_T_EGR_GET] = __comp_eager_msg_data_at_src,
	[GNIX_SMSG_T_EGR_GET_ACK] = __comp_eager_msg_data_at_src_ack,
	[GNIX_SMSG_T_RNDZV_RTS] = __comp_rndzv_msg_rts,
	[GNIX_SMSG_T_RNDZV_RTR] = __comp_rndzv_msg_rtr,
	[GNIX_SMSG_T_RNDZV_COOKIE] = __comp_rndzv_msg_cookie,
	[GNIX_SMSG_T_RNDZV_SDONE] = __comp_rndzv_msg_send_done,
	[GNIX_SMSG_T_RNDZV_RDONE] = __comp_rndzv_msg_recv_done,
	[GNIX_SMSG_T_RNDZV_START] = __comp_rndzv_start,
	[GNIX_SMSG_T_RNDZV_FIN] = __comp_rndzv_fin
};


/*******************************************************************************
 * GNI SMSG callbacks invoked upon receipt of an SMSG message.
 * These callback functions are invoked with the lock for the nic
 * associated with the vc already held.
 ******************************************************************************/

/*
 * Handle SMSG message with tag GNIX_SMSG_T_EGR_W_DATA
 */

static int __smsg_eager_msg_w_data(void *data, void *msg)
{
	int ret = FI_SUCCESS;
	gni_return_t status;
	struct gnix_vc *vc = (struct gnix_vc *)data;
	struct gnix_smsg_eager_hdr *hdr = (struct gnix_smsg_eager_hdr *)msg;
	struct gnix_fid_ep *ep;
	struct gnix_fab_req *req = NULL;
	void *data_ptr;
	struct gnix_tag_storage *unexp_queue;
	struct gnix_tag_storage *posted_queue;
	fastlock_t *queue_lock;
	int tagged;

	ep = vc->ep;
	assert(ep);

	data_ptr = (void *)((char *)msg + sizeof(*hdr));

	tagged = !!(hdr->flags & GNIX_MSG_TAGGED);
	__gnix_msg_queues(ep, tagged, &queue_lock, &posted_queue, &unexp_queue);

	fastlock_acquire(queue_lock);

	req = _gnix_match_tag(posted_queue, hdr->msg_tag, 0, 0, NULL,
			      &vc->peer_addr);
	if (req) {
		req->modes |= GNIX_FAB_RQ_M_MATCHED;

		GNIX_INFO(FI_LOG_EP_DATA, "matched req: %p\n",
			  req);

		req->addr = vc->peer_addr;
		req->gnix_ep = ep;
		req->vc = vc;

		req->msg.send_len = hdr->len;
		req->msg.send_flags = hdr->flags;
		req->msg.tag = hdr->msg_tag;
		req->msg.imm = hdr->imm;

		req->msg.recv_len = MIN(req->msg.send_len, req->msg.recv_len);
		memcpy((void *)req->msg.recv_addr, data_ptr, req->msg.recv_len);

		__gnix_recv_completion(ep, req);
		_gnix_fr_free(ep, req);
	} else {
		/* Add new unexpected receive request. */
		req = _gnix_fr_alloc(ep);
		if (req == NULL) {
			fastlock_release(queue_lock);
			return -FI_ENOMEM;
		}

		req->msg.recv_addr = (uint64_t)malloc(hdr->len);
		if (unlikely(req->msg.recv_addr == 0ULL)) {
			fastlock_release(queue_lock);
			_gnix_fr_free(ep, req);
			return -FI_EAGAIN;
		}

		GNIX_INFO(FI_LOG_EP_DATA, "New req: %p\n",
			  req);

		req->type = GNIX_FAB_RQ_RECV;
		req->addr = vc->peer_addr;
		req->gnix_ep = ep;
		req->vc = vc;

		req->msg.send_len = hdr->len;
		req->msg.send_flags = hdr->flags;
		req->msg.tag = hdr->msg_tag;
		req->msg.imm = hdr->imm;

		memcpy((void *)req->msg.recv_addr, data_ptr, hdr->len);
		req->addr = vc->peer_addr;

		_gnix_insert_tag(unexp_queue, req->msg.tag, req, ~0);
	}

	fastlock_release(queue_lock);

	status = GNI_SmsgRelease(vc->gni_ep);
	if (unlikely(status != GNI_RC_SUCCESS)) {
		GNIX_WARN(FI_LOG_EP_DATA,
				"GNI_SmsgRelease returned %s\n",
				gni_err_str[status]);
		ret = gnixu_to_fi_errno(status);
	}

	return ret;
}

/*
 * this function will probably not be used unless we need
 * some kind of explicit flow control to handle unexpected
 * receives
 */

static int __smsg_eager_msg_w_data_ack(void *data, void *msg)
{
	return -FI_ENOSYS;
}

/*
 * Handle SMSG message with tag GNIX_SMSG_T_EGR_GET
 */
static int __smsg_eager_msg_data_at_src(void *data, void *msg)
{
	return -FI_ENOSYS;
}

/*
 * Handle SMSG message with tag GNIX_SMSG_T_EGR_GET_ACK
 */
static int  __smsg_eager_msg_data_at_src_ack(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_rts(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_rtr(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_cookie(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_send_done(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_recv_done(void *data, void *msg)
{
	return -FI_ENOSYS;
}

/* Received SMSG rendezvous start message.  Try to match a posted receive and
 * start pulling data. */
static int __smsg_rndzv_start(void *data, void *msg)
{
	int ret = FI_SUCCESS;
	gni_return_t status;
	struct gnix_vc *vc = (struct gnix_vc *)data;
	struct gnix_smsg_rndzv_start_hdr *hdr =
			(struct gnix_smsg_rndzv_start_hdr *)msg;
	struct gnix_fid_ep *ep;
	struct gnix_fab_req *req = NULL;
	struct gnix_tag_storage *unexp_queue;
	struct gnix_tag_storage *posted_queue;
	fastlock_t *queue_lock;
	int tagged;

	ep = vc->ep;
	assert(ep);

	tagged = !!(hdr->flags & GNIX_MSG_TAGGED);
	__gnix_msg_queues(ep, tagged, &queue_lock, &posted_queue, &unexp_queue);

	fastlock_acquire(queue_lock);

	req = _gnix_match_tag(posted_queue, hdr->msg_tag, 0, 0, NULL,
			      &vc->peer_addr);
	if (req) {
		req->modes |= GNIX_FAB_RQ_M_MATCHED;

		GNIX_INFO(FI_LOG_EP_DATA, "matched req: %p\n", req);

		req->addr = vc->peer_addr;
		req->gnix_ep = ep;
		req->vc = vc;

		req->msg.send_addr = hdr->addr;
		req->msg.send_len = hdr->len;
		req->msg.send_flags = hdr->flags;
		req->msg.tag = hdr->msg_tag;
		req->msg.imm = hdr->imm;
		req->msg.rma_mdh = hdr->mdh;
		req->msg.rma_id = hdr->req_addr;

		/* Initiate pull of source data. */
		ret = __gnix_rndzv_req(req);
		if (ret) {
			/* TODO queue TX */
			GNIX_INFO(FI_LOG_EP_DATA,
				  "__gnix_rndzv_req failed: %dn",
				  ret);
			return ret;
		}
	} else {
		/* Add new unexpected receive request. */
		req = _gnix_fr_alloc(ep);
		if (req == NULL) {
			fastlock_release(queue_lock);
			return -FI_ENOMEM;
		}

		GNIX_INFO(FI_LOG_EP_DATA, "New req: %p\n",
			  req);

		req->type = GNIX_FAB_RQ_RECV;
		req->addr = vc->peer_addr;
		req->gnix_ep = ep;
		req->vc = vc;

		req->msg.send_addr = hdr->addr;
		req->msg.send_len = hdr->len;
		req->msg.send_flags = hdr->flags;
		req->msg.tag = hdr->msg_tag;
		req->msg.imm = hdr->imm;
		req->msg.rma_mdh = hdr->mdh;
		req->msg.rma_id = hdr->req_addr;

		_gnix_insert_tag(unexp_queue, req->msg.tag, req, ~0);
	}

	fastlock_release(queue_lock);

	status = GNI_SmsgRelease(vc->gni_ep);
	if (unlikely(status != GNI_RC_SUCCESS)) {
		GNIX_WARN(FI_LOG_EP_DATA,
				"GNI_SmsgRelease returned %s\n",
				gni_err_str[status]);
		ret = gnixu_to_fi_errno(status);
	}

	return ret;
}

/* Received SMSG rendezvous fin message.  The peer has finished pulling send
 * data.  Free the send request and generate completions. */
static int __smsg_rndzv_fin(void *data, void *msg)
{
	int ret = FI_SUCCESS;
	gni_return_t status;
	struct gnix_vc *vc = (struct gnix_vc *)data;
	struct gnix_smsg_rndzv_fin_hdr *hdr =
			(struct gnix_smsg_rndzv_fin_hdr *)msg;
	struct gnix_fab_req *req;
	struct gnix_fid_ep *ep;

	req = (struct gnix_fab_req *)hdr->req_addr;
	assert(req);

	GNIX_INFO(FI_LOG_EP_DATA, "Received RNDZV_FIN, req: %p\n", req);

	ep = req->gnix_ep;
	assert(ep != NULL);

	__gnix_send_completion(ep, req);

	_gnix_fr_free(ep, req);

	status = GNI_SmsgRelease(vc->gni_ep);
	if (unlikely(status != GNI_RC_SUCCESS)) {
		GNIX_WARN(FI_LOG_EP_DATA,
				"GNI_SmsgRelease returned %s\n",
				gni_err_str[status]);
		ret = gnixu_to_fi_errno(status);
	}

	return ret;
}

smsg_callback_fn_t gnix_ep_smsg_callbacks[] = {
	[GNIX_SMSG_T_EGR_W_DATA] = __smsg_eager_msg_w_data,
	[GNIX_SMSG_T_EGR_W_DATA_ACK] = __smsg_eager_msg_w_data_ack,
	[GNIX_SMSG_T_EGR_GET] = __smsg_eager_msg_data_at_src,
	[GNIX_SMSG_T_EGR_GET_ACK] = __smsg_eager_msg_data_at_src_ack,
	[GNIX_SMSG_T_RNDZV_RTS] = __smsg_rndzv_msg_rts,
	[GNIX_SMSG_T_RNDZV_RTR] = __smsg_rndzv_msg_rtr,
	[GNIX_SMSG_T_RNDZV_COOKIE] = __smsg_rndzv_msg_cookie,
	[GNIX_SMSG_T_RNDZV_SDONE] = __smsg_rndzv_msg_send_done,
	[GNIX_SMSG_T_RNDZV_RDONE] = __smsg_rndzv_msg_recv_done,
	[GNIX_SMSG_T_RNDZV_START] = __smsg_rndzv_start,
	[GNIX_SMSG_T_RNDZV_FIN] = __smsg_rndzv_fin
};

/*******************************************************************************
 * Generic EP recv handling
 ******************************************************************************/

ssize_t _gnix_recv(struct gnix_fid_ep *ep, uint64_t buf, size_t len,
		   void *mdesc, uint64_t src_addr, void *context,
		   uint64_t flags, uint64_t tag, uint64_t ignore)
{
	int ret = FI_SUCCESS;
	struct gnix_fid_av *av;
	struct gnix_fab_req *req = NULL;
	struct gnix_address *addr_ptr = NULL;
	struct gnix_address gnix_addr;
	fastlock_t *queue_lock = NULL;
	struct gnix_tag_storage *posted_queue = NULL;
	struct gnix_tag_storage *unexp_queue = NULL;
	uint64_t r_tag = tag, r_ignore = ignore, r_flags;
	struct gnix_fid_mem_desc *md = NULL;
	int tagged = !!(flags & GNIX_MSG_TAGGED);
	size_t addrlen = sizeof(struct gnix_address);
	void *tmp_buf;

	r_flags = flags & (FI_CLAIM | FI_DISCARD | FI_PEEK);

	/* CLAIM/DISCARD/PEEK not yet supported. */
	if (tagged && r_flags) {
		return -FI_EOPNOTSUPP;
	}

	/* Translate source address. */
	if (ep->type == FI_EP_RDM) {
		/* TODO ignore src_addr unless FI_DIRECT_RECV */
		av = ep->av;
		assert(av != NULL);
		ret = _gnix_av_lookup(av, src_addr, &gnix_addr, &addrlen);
		if (ret != FI_SUCCESS) {
			GNIX_WARN(FI_LOG_AV,
				  "_gnix_av_addr_retrieve returned %d\n",
				  ret);
			return ret;
		}
		addr_ptr = &gnix_addr;
	} else {
		assert(ep->vc != NULL);
		addr_ptr = &ep->vc->peer_addr;
	}
	assert(addr_ptr != NULL);

	__gnix_msg_queues(ep, tagged, &queue_lock, &posted_queue, &unexp_queue);

	if (!tagged) {
		r_tag = 0;
		r_ignore = ~0;
	}

	fastlock_acquire(queue_lock);

	/* Look for a matching unexpected receive request. */
	req = _gnix_match_tag(unexp_queue, r_tag, r_ignore,
			      r_flags, context, addr_ptr);
	if (req) {
		req->modes |= GNIX_FAB_RQ_M_MATCHED;

		req->addr = *addr_ptr;
		req->gnix_ep = ep;
		req->user_context = context;

		tmp_buf = (void *)req->msg.recv_addr;
		req->msg.recv_addr = (uint64_t)buf;
		req->msg.recv_len = MIN(req->msg.send_len, len);
		if (mdesc) {
			md = container_of(mdesc,
					struct gnix_fid_mem_desc,
					mr_fid);
			req->msg.recv_md = md;
		}
		req->msg.recv_flags = flags;
		req->msg.tag = r_tag;
		req->msg.ignore = r_ignore;

		if (req->msg.send_flags & GNIX_MSG_RENDEZVOUS) {
			/* Matched rendezvous request.  Start data movement. */
			GNIX_INFO(FI_LOG_EP_DATA, "matched RNDZV, req: %p\n",
				  req);

			/* TODO: prevent re-lookup of src_addr */
			ret = _gnix_ep_get_vc(ep, src_addr, &req->vc);
			if (ret) {
				GNIX_INFO(FI_LOG_EP_DATA,
					  "_gnix_ep_get_vc failed: %dn",
					  ret);
				return ret;
			}

			/* Initiate pull of source data. */
			ret = __gnix_rndzv_req(req);
			if (ret) {
				/* TODO queue TX */
				GNIX_INFO(FI_LOG_EP_DATA,
					  "__gnix_rndzv_req failed: %dn",
					  ret);
				return ret;
			}
		} else {
			/* Matched eager request.  Copy data and generate
			 * completions. */
			GNIX_INFO(FI_LOG_EP_DATA, "Matched recv, req: %p\n",
				  req);

			/* Move data from temporary buffer. */
			memcpy((void *)buf, tmp_buf, req->msg.recv_len);
			free(tmp_buf);

			__gnix_recv_completion(ep, req);
			_gnix_fr_free(ep, req);
		}
	} else {
		/* Add new posted receive request. */
		req = _gnix_fr_alloc(ep);
		if (req == NULL) {
			ret = -FI_EAGAIN;
			goto err;
		}

		GNIX_INFO(FI_LOG_EP_DATA, "New recv, req: %p\n", req);

		req->type = GNIX_FAB_RQ_RECV;

		req->addr = *addr_ptr;
		req->gnix_ep = ep;
		req->user_context = context;

		req->msg.recv_addr = (uint64_t)buf;
		req->msg.recv_len = len;
		if (mdesc) {
			md = container_of(mdesc,
					struct gnix_fid_mem_desc,
					mr_fid);
			req->msg.recv_md = md;
		}
		req->msg.recv_flags = flags;
		req->msg.tag = r_tag;
		req->msg.ignore = r_ignore;

		_gnix_insert_tag(posted_queue, r_tag, req, r_ignore);
	}

err:
	fastlock_release(queue_lock);

	return ret;
}

/*******************************************************************************
 * Generic EP send handling
 ******************************************************************************/

static int _gnix_send_req(void *arg)
{
	struct gnix_fab_req *req = (struct gnix_fab_req *)arg;
	struct gnix_nic *nic;
	struct gnix_fid_ep *ep;
	struct gnix_tx_descriptor *tdesc;
	gni_return_t status;
	int rc;
	int rendezvous = !!(req->msg.send_flags & GNIX_MSG_RENDEZVOUS);
	int hdr_len, data_len;
	void *hdr, *data;
	int tag;

	ep = req->gnix_ep;
	assert(ep != NULL);

	nic = ep->nic;
	assert(nic != NULL);

	rc = _gnix_nic_tx_alloc(nic, &tdesc);
	if (rc != FI_SUCCESS) {
		GNIX_INFO(FI_LOG_EP_DATA, "_gnix_nic_tx_alloc() failed: %d\n",
			  rc);
		return -FI_EAGAIN;
	}
	assert(rc == FI_SUCCESS);

	if (rendezvous) {
		assert(req->msg.send_md);

		tag = GNIX_SMSG_T_RNDZV_START;
		tdesc->rndzv_start_hdr.flags = req->msg.send_flags;
		tdesc->rndzv_start_hdr.imm = 0;
		tdesc->rndzv_start_hdr.msg_tag = req->msg.tag;
		tdesc->rndzv_start_hdr.mdh = req->msg.send_md->mem_hndl;
		tdesc->rndzv_start_hdr.addr = req->msg.send_addr;
		tdesc->rndzv_start_hdr.len = req->msg.send_len;
		tdesc->rndzv_start_hdr.req_addr = (uint64_t)req;

		hdr = &tdesc->rndzv_start_hdr;
		hdr_len = sizeof(tdesc->rndzv_start_hdr);
		data = NULL;
		data_len = 0;
	} else {
		tag = GNIX_SMSG_T_EGR_W_DATA;
		tdesc->eager_hdr.flags = req->msg.send_flags;
		tdesc->eager_hdr.imm = 0;
		tdesc->eager_hdr.msg_tag = req->msg.tag;
		tdesc->eager_hdr.len = req->msg.send_len;

		hdr = &tdesc->eager_hdr;
		hdr_len = sizeof(tdesc->eager_hdr);
		data = (void *)req->msg.send_addr;
		data_len = req->msg.send_len;
	}
	tdesc->req = req;
	tdesc->completer_fn = gnix_ep_smsg_completers[tag];

	fastlock_acquire(&nic->lock);

	status = GNI_SmsgSendWTag(req->vc->gni_ep,
				  hdr, hdr_len, data, data_len,
				  tdesc->id, tag);

	fastlock_release(&nic->lock);

	if (status == GNI_RC_NOT_DONE) {
		_gnix_nic_tx_free(nic, tdesc);
		GNIX_INFO(FI_LOG_EP_DATA,
			  "GNI_SmsgSendWTag returned %s\n",
			  gni_err_str[status]);
	} else if (status != GNI_RC_SUCCESS) {
		_gnix_nic_tx_free(nic, tdesc);
		GNIX_WARN(FI_LOG_EP_DATA,
			  "GNI_SmsgSendWTag returned %s\n",
			  gni_err_str[status]);
	}

	return gnixu_to_fi_errno(status);
}

ssize_t _gnix_send(struct gnix_fid_ep *ep, uint64_t loc_addr, size_t len,
		   void *mdesc, uint64_t dest_addr, void *context,
		   uint64_t flags, uint64_t data, uint64_t tag)
{
	int ret = FI_SUCCESS;
	struct gnix_vc *vc = NULL;
	struct gnix_fab_req *req;
	struct gnix_fid_mem_desc *md = NULL;
	int rendezvous;

	if (!ep) {
		return -FI_EINVAL;
	}

	if ((flags & FI_INJECT) && (len > GNIX_INJECT_SIZE)) {
		GNIX_INFO(FI_LOG_EP_DATA,
			  "Send length %d exceeds inject max size: %d\n",
			  len, GNIX_INJECT_SIZE);
		return -FI_EINVAL;
	}

	rendezvous = len >= ep->domain->params.msg_rendezvous_thresh;

	/* need a memory descriptor for large sends */
	if (rendezvous && !mdesc) {
		/* TODO auto-register source buffer */
		GNIX_INFO(FI_LOG_EP_DATA,
			  "Send of length %d requires memory descriptor\n",
			  len);
		return -FI_EINVAL;
	}

	ret = _gnix_ep_get_vc(ep, dest_addr, &vc);
	if (ret) {
		return ret;
	}

	req = _gnix_fr_alloc(ep);
	if (req == NULL)
		return -FI_EAGAIN;

	req->type = GNIX_FAB_RQ_SEND;
	req->gnix_ep = ep;
	req->vc = vc;
	req->user_context = context;
	req->send_fn = _gnix_send_req;

	req->msg.tag = tag;

	if (mdesc) {
		md = container_of(mdesc, struct gnix_fid_mem_desc, mr_fid);
	}
	req->msg.send_md = md;
	req->msg.send_len = len;
	req->msg.send_flags = flags;

	if (req->flags & FI_INJECT) {
		memcpy(req->inject_buf, (void *)loc_addr, len);
		req->msg.send_addr = (uint64_t)req->inject_buf;
	} else {
		req->msg.send_addr = loc_addr;
	}

	if (rendezvous) {
		req->msg.send_flags |= GNIX_MSG_RENDEZVOUS;
	}

	GNIX_INFO(FI_LOG_EP_DATA, "Queuing TX req: %p\n", req);

	return _gnix_vc_queue_tx_req(req);
}

