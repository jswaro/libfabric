/*
 * Copyright (c) 2015-2016 Intel Corporation. All rights reserved.
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

#include <rdma/fi_errno.h>

#include <ofi_prov.h>
#include "rxd.h"

struct rxd_env rxd_env = {
	.spin_count	= 1000,
	.retry		= 1,
	.max_peers	= 1024,
	.max_unacked	= 128,
};

static void rxd_init_env(void)
{
	fi_param_get_int(&rxd_prov, "spin_count", &rxd_env.spin_count);
	fi_param_get_bool(&rxd_prov, "retry", &rxd_env.retry);
	fi_param_get_int(&rxd_prov, "max_peers", &rxd_env.max_peers);
	fi_param_get_int(&rxd_prov, "max_unacked", &rxd_env.max_unacked);
}

int rxd_info_to_core(uint32_t version, const struct fi_info *rxd_info,
		     struct fi_info *core_info)
{
	core_info->caps = FI_MSG;
	core_info->mode = FI_LOCAL_MR | FI_CONTEXT | FI_MSG_PREFIX;
	core_info->ep_attr->type = FI_EP_DGRAM;
	return 0;
}

int rxd_info_to_rxd(uint32_t version, const struct fi_info *core_info,
		    struct fi_info *info)
{
	info->caps = rxd_info.caps;
	info->mode = rxd_info.mode;

	*info->tx_attr = *rxd_info.tx_attr;
	info->tx_attr->inject_size = MIN(core_info->ep_attr->max_msg_size,
			RXD_MAX_MTU_SIZE) - sizeof(struct rxd_base_hdr) -
			core_info->ep_attr->msg_prefix_size;
	*info->rx_attr = *rxd_info.rx_attr;
	*info->ep_attr = *rxd_info.ep_attr;
	*info->domain_attr = *rxd_info.domain_attr;
	return 0;
}

static int rxd_getinfo(uint32_t version, const char *node, const char *service,
			uint64_t flags, const struct fi_info *hints,
			struct fi_info **info)
{
	return ofix_getinfo(version, node, service, flags, &rxd_util_prov,
			    hints, rxd_info_to_core, rxd_info_to_rxd, info);
}

static void rxd_fini(void)
{
	/* yawn */
}

struct fi_provider rxd_prov = {
	.name = OFI_UTIL_PREFIX "rxd",
	.version = FI_VERSION(RXD_MAJOR_VERSION, RXD_MINOR_VERSION),
	.fi_version = RXD_FI_VERSION,
	.getinfo = rxd_getinfo,
	.fabric = rxd_fabric,
	.cleanup = rxd_fini
};

RXD_INI
{
	fi_param_define(&rxd_prov, "spin_count", FI_PARAM_INT,
			"Number of iterations to receive packets (0 - infinite)");
	fi_param_define(&rxd_prov, "retry", FI_PARAM_BOOL,
			"Toggle packet retrying (default: yes)");
	fi_param_define(&rxd_prov, "max_peers", FI_PARAM_INT,
			"Maximum number of peers to track (default: 1024)");
	fi_param_define(&rxd_prov, "max_unacked", FI_PARAM_INT,
			"Maximum number of packets to send at once (default: 128)");

	rxd_init_env();

	return &rxd_prov;
}
