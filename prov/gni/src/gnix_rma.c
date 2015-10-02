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
#include "gnix_nic.h"
#include "gnix_vc.h"
#include "gnix_ep.h"
#include "gnix_mr.h"
#include "gnix_cm_nic.h"
#include "gnix_mbox_allocator.h"
#include "gnix_cntr.h"

#include <gni_pub.h>

static int __gnix_rma_txd_complete(void *arg)
{
	struct gnix_tx_descriptor *txd = (struct gnix_tx_descriptor *)arg;
	struct gnix_fab_req *req = txd->req;
	struct gnix_fid_ep *ep = req->gnix_ep;
	int rc;
	struct gnix_fid_cntr *cntr = NULL;

	if ((req->flags & FI_COMPLETION) && ep->send_cq) {
		rc = _gnix_cq_add_event(ep->send_cq, req->user_context,
					req->flags, req->rma.len,
					(void *)req->rma.loc_addr,
					req->rma.imm, 0);
		if (rc) {
			GNIX_WARN(FI_LOG_CQ,
				  "_gnix_cq_add_event() failed: %d\n", rc);
		}
	}

	if ((req->type == GNIX_FAB_RQ_RDMA_WRITE) &&
	    ep->write_cntr)
		cntr = ep->write_cntr;

	if ((req->type == GNIX_FAB_RQ_RDMA_READ) &&
	    ep->read_cntr)
		cntr = ep->read_cntr;


	if (cntr) {
		rc = _gnix_cntr_inc(cntr);
		if (rc)
			GNIX_WARN(FI_LOG_CQ,
				  "_gnix_cntr_inc() failed: %d\n", rc);
	}

	atomic_dec(&req->vc->outstanding_tx_reqs);
	_gnix_nic_tx_free(ep->nic, txd);

	/* We could have requests waiting for TXDs or FI_FENCE operations.
	 * Schedule this VC to push any such requests. */
	_gnix_vc_schedule_reqs(req->vc);

	_gnix_fr_free(ep, req);

	return FI_SUCCESS;
}

static gni_post_type_t __gnix_fr_post_type(int fr_type, int rdma)
{
	switch (fr_type) {
	case GNIX_FAB_RQ_RDMA_WRITE:
		return rdma ? GNI_POST_RDMA_PUT : GNI_POST_FMA_PUT;
	case GNIX_FAB_RQ_RDMA_READ:
		return rdma ? GNI_POST_RDMA_GET : GNI_POST_FMA_GET;
	default:
		break;
	}

	GNIX_WARN(FI_LOG_EP_DATA, "Unsupported post type: %d", fr_type);
	assert(0);
	return -FI_ENOSYS;
}

#define GNIX_RMA_RDMA_THRESH (8*1024)

int _gnix_rma_post_req(void *data)
{
	struct gnix_fab_req *fab_req = (struct gnix_fab_req *)data;
	struct gnix_fid_ep *ep = fab_req->gnix_ep;
	struct gnix_nic *nic = ep->nic;
	struct gnix_fid_mem_desc *loc_md;
	struct gnix_tx_descriptor *txd;
	gni_mem_handle_t mdh;
	gni_return_t status;
	int rc;
	int rdma = !!(fab_req->flags & GNIX_RMA_RDMA);

	rc = _gnix_nic_tx_alloc(nic, &txd);
	if (rc) {
		GNIX_INFO(FI_LOG_EP_DATA, "_gnix_nic_tx_alloc() failed: %d\n",
			 rc);
		return -FI_EAGAIN;
	}

	txd->completer_fn = __gnix_rma_txd_complete;
	txd->req = fab_req;

	if (rdma) {
		_gnix_convert_key_to_mhdl(
				(gnix_mr_key_t *)&fab_req->rma.rem_mr_key,
				&mdh);
	} else {
		/* Mem handle CRC is not validated during FMA operations.  Skip
		 * this costly calculation. */
		_gnix_convert_key_to_mhdl_no_crc(
				(gnix_mr_key_t *)&fab_req->rma.rem_mr_key,
				&mdh);
	}
	loc_md = (struct gnix_fid_mem_desc *)fab_req->rma.loc_md;

	txd->gni_desc.type = __gnix_fr_post_type(fab_req->type, rdma);
	txd->gni_desc.cq_mode = GNI_CQMODE_GLOBAL_EVENT; /* check flags */
	txd->gni_desc.dlvr_mode = GNI_DLVMODE_PERFORMANCE; /* check flags */
	txd->gni_desc.local_addr = (uint64_t)fab_req->rma.loc_addr;
	if (loc_md) {
		txd->gni_desc.local_mem_hndl = loc_md->mem_hndl;
	}
	txd->gni_desc.remote_addr = (uint64_t)fab_req->rma.rem_addr;
	txd->gni_desc.remote_mem_hndl = mdh;
	txd->gni_desc.length = fab_req->rma.len;
	txd->gni_desc.rdma_mode = 0; /* check flags */
	txd->gni_desc.src_cq_hndl = nic->tx_cq; /* check flags */

	{
		gni_mem_handle_t *tl_mdh = &txd->gni_desc.local_mem_hndl;
		gni_mem_handle_t *tr_mdh = &txd->gni_desc.remote_mem_hndl;
		GNIX_INFO(FI_LOG_EP_DATA, "la: %llx ra: %llx len: %d\n",
			  txd->gni_desc.local_addr, txd->gni_desc.remote_addr,
			  txd->gni_desc.length);
		GNIX_INFO(FI_LOG_EP_DATA, "lmdh: %llx:%llx rmdh: %llx:%llx key: %llx\n",
			  *(uint64_t *)tl_mdh, *(((uint64_t *)tl_mdh) + 1),
			  *(uint64_t *)tr_mdh, *(((uint64_t *)tr_mdh) + 1),
			  fab_req->rma.rem_mr_key);
	}

	fastlock_acquire(&nic->lock);

	if (rdma) {
		status = GNI_PostRdma(fab_req->vc->gni_ep, &txd->gni_desc);
	} else {
		status = GNI_PostFma(fab_req->vc->gni_ep, &txd->gni_desc);
	}

	fastlock_release(&nic->lock);

	if (status != GNI_RC_SUCCESS) {
		_gnix_nic_tx_free(nic, txd);
		GNIX_INFO(FI_LOG_EP_DATA, "GNI_Post*() failed: %s\n",
			  gni_err_str[status]);
	}

	return gnixu_to_fi_errno(status);
}

ssize_t _gnix_rma(struct gnix_fid_ep *ep, enum gnix_fab_req_type fr_type,
		  uint64_t loc_addr, size_t len, void *mdesc,
		  uint64_t dest_addr, uint64_t rem_addr, uint64_t mkey,
		  void *context, uint64_t flags, uint64_t data)
{
	struct gnix_vc *vc;
	struct gnix_fab_req *req;
	struct gnix_fid_mem_desc *md = NULL;
	int rc;
	int rdma;

	if (!ep) {
		return -FI_EINVAL;
	}

	if ((flags & FI_INJECT) && (len > GNIX_INJECT_SIZE)) {
		GNIX_INFO(FI_LOG_EP_DATA,
			  "RMA length %d exceeds inject max size: %d\n",
			  len, GNIX_INJECT_SIZE);
		return -FI_EINVAL;
	}

	rdma = len >= GNIX_RMA_RDMA_THRESH;

	/* need a memory descriptor for all RDMA and reads */
	if (!mdesc && (rdma || fr_type == GNIX_FAB_RQ_RDMA_READ)) {
		GNIX_INFO(FI_LOG_EP_DATA,
			  "RMA of length %d requires memory descriptor\n",
			  len);
		return -FI_EINVAL;
	}

	/* find VC for target */
	rc = _gnix_ep_get_vc(ep, dest_addr, &vc);
	if (rc) {
		GNIX_INFO(FI_LOG_EP_DATA,
			  "_gnix_ep_get_vc() failed, addr: %lx, rc:\n",
			  dest_addr, rc);
		return rc;
	}

	/* setup fabric request */
	req = _gnix_fr_alloc(ep);
	if (!req) {
		GNIX_INFO(FI_LOG_EP_DATA, "_gnix_fr_alloc() failed\n");
		return -FI_ENOSPC;
	}

	req->type = fr_type;
	req->gnix_ep = ep;
	req->vc = vc;
	req->user_context = context;
	req->send_fn = _gnix_rma_post_req;

	if (mdesc) {
		md = container_of(mdesc, struct gnix_fid_mem_desc, mr_fid);
	}
	req->rma.loc_md = (void *)md;

	req->rma.rem_addr = rem_addr;
	req->rma.rem_mr_key = mkey;
	req->rma.len = len;
	req->flags = flags;

	if (req->flags & FI_INJECT) {
		memcpy(req->inject_buf, (void *)loc_addr, len);
		req->rma.loc_addr = (uint64_t)req->inject_buf;
	} else {
		req->rma.loc_addr = loc_addr;
	}

	/* Inject interfaces always suppress completions.  If
	 * SELECTIVE_COMPLETION is set, honor any setting.  Otherwise, always
	 * deliver a completion. */
	if ((flags & GNIX_SUPPRESS_COMPLETION) ||
	    (ep->send_selective_completion && !(flags & FI_COMPLETION))) {
		req->flags &= ~FI_COMPLETION;
	} else {
		req->flags |= FI_COMPLETION;
	}

	if (rdma) {
		req->flags |= GNIX_RMA_RDMA;
	}

	return _gnix_vc_queue_tx_req(req);
}

