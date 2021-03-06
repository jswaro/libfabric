/*
 * Copyright (c) 2015-2018 Intel Corporation. All rights reserved.
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

#include "rxd.h"

#define RXD_EP_CAPS (FI_MSG | FI_TAGGED | FI_RMA | FI_ATOMIC | FI_SEND | FI_RECV | \
		     FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE |	\
		     FI_SOURCE | FI_DIRECTED_RECV)

struct fi_tx_attr rxd_tx_attr = {
	.caps = RXD_EP_CAPS,
	.comp_order = FI_ORDER_STRICT,
	.inject_size = RXD_MAX_MTU_SIZE - sizeof(struct rxd_base_hdr),
	.size = (1ULL << RXD_MAX_TX_BITS),
	.iov_limit = RXD_IOV_LIMIT,
	.rma_iov_limit = 0,
};

struct fi_rx_attr rxd_rx_attr = {
	.caps = RXD_EP_CAPS,
	.comp_order = FI_ORDER_STRICT,
	.total_buffered_recv = 0,
	.size = (1ULL << RXD_MAX_RX_BITS),
	.iov_limit = RXD_IOV_LIMIT
};

struct fi_ep_attr rxd_ep_attr = {
	.type = FI_EP_RDM,
	.protocol = FI_PROTO_RXD,
	.protocol_version = 1,
	.max_msg_size = SIZE_MAX,
	.tx_ctx_cnt = 1,
	.rx_ctx_cnt = 1
};

struct fi_domain_attr rxd_domain_attr = {
	.threading = FI_THREAD_SAFE,
	.control_progress = FI_PROGRESS_MANUAL,
	.data_progress = FI_PROGRESS_MANUAL,
	.resource_mgmt = FI_RM_ENABLED,
	.av_type = FI_AV_UNSPEC,
	.cq_data_size = sizeof_field(struct rxd_data_hdr, cq_data),
	.mr_key_size = sizeof(uint64_t),
	.cq_cnt = 128,
	.ep_cnt = 128,
	.tx_ctx_cnt = 1,
	.rx_ctx_cnt = 1,
	.max_ep_tx_ctx = 1,
	.max_ep_rx_ctx = 1,
	.mr_iov_limit = 1,
};

struct fi_fabric_attr rxd_fabric_attr = {
	.prov_version = FI_VERSION(RXD_MAJOR_VERSION, RXD_MINOR_VERSION),
};

struct fi_info rxd_info = {
	.caps = RXD_EP_CAPS,
	.addr_format = FI_FORMAT_UNSPEC,
	.tx_attr = &rxd_tx_attr,
	.rx_attr = &rxd_rx_attr,
	.ep_attr = &rxd_ep_attr,
	.domain_attr = &rxd_domain_attr,
	.fabric_attr = &rxd_fabric_attr
};

struct util_prov rxd_util_prov = {
	.prov = &rxd_prov,
	.info = &rxd_info,
	.flags = 0,
};
