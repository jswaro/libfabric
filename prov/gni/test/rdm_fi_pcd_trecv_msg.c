/*
 * Copyright (c) 2015 Los Alamos National Security, LLC. All rights reserved.
 * Copyright (c) 2015 Cray Inc.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_tagged.h>

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "gnix_vc.h"
#include "gnix_cm_nic.h"
#include "gnix_hashtable.h"
#include "gnix_rma.h"

#include <criterion/criterion.h>

#if 0
#define dbg_printf(...)
#else
#define dbg_printf(...) \
	do { \
		fprintf(stderr, __VA_ARGS__); \
		fflush(stderr); \
	} while(0)
#endif

static struct fid_fabric *fab;
static struct fid_domain *dom;
static struct fid_ep *ep[2];
static struct fid_av *av;
static struct fi_info *hints;
static struct fi_info *fi;
void *ep_name[2];
size_t gni_addr[2];
static struct fid_cq *msg_cq[2];
static struct fi_cq_attr cq_attr;

#define BUF_SZ (8*1024)
char *target;
char *source;
struct fid_mr *rem_mr, *loc_mr;
uint64_t mr_key;

void rdm_fi_pdc_setup(void)
{
	int ret = 0;
	struct fi_av_attr attr;
	size_t addrlen = 0;

	hints = fi_allocinfo();
	cr_assert(hints, "fi_allocinfo");

	hints->domain_attr->cq_data_size = 4;
	hints->mode = ~0;

	hints->fabric_attr->name = strdup("gni");

	ret = fi_getinfo(FI_VERSION(1, 0), NULL, 0, 0, hints, &fi);
	cr_assert(!ret, "fi_getinfo");

	ret = fi_fabric(fi->fabric_attr, &fab, NULL);
	cr_assert(!ret, "fi_fabric");

	ret = fi_domain(fab, fi, &dom, NULL);
	cr_assert(!ret, "fi_domain");

	attr.type = FI_AV_MAP;
	attr.count = 16;

	ret = fi_av_open(dom, &attr, &av, NULL);
	cr_assert(!ret, "fi_av_open");

	ret = fi_endpoint(dom, fi, &ep[0], NULL);
	cr_assert(!ret, "fi_endpoint");

	cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	cq_attr.size = 1024;
	cq_attr.wait_obj = 0;

	ret = fi_cq_open(dom, &cq_attr, &msg_cq[0], 0);
	cr_assert(!ret, "fi_cq_open");

	ret = fi_cq_open(dom, &cq_attr, &msg_cq[1], 0);
	cr_assert(!ret, "fi_cq_open");

	ret = fi_ep_bind(ep[0], &msg_cq[0]->fid, FI_SEND | FI_RECV);
	cr_assert(!ret, "fi_ep_bind");

	ret = fi_getname(&ep[0]->fid, NULL, &addrlen);
	cr_assert(addrlen > 0);

	ep_name[0] = malloc(addrlen);
	cr_assert(ep_name[0] != NULL);

	ret = fi_getname(&ep[0]->fid, ep_name[0], &addrlen);
	cr_assert(ret == FI_SUCCESS);

	ret = fi_endpoint(dom, fi, &ep[1], NULL);
	cr_assert(!ret, "fi_endpoint");

	ret = fi_ep_bind(ep[1], &msg_cq[1]->fid, FI_SEND | FI_RECV);
	cr_assert(!ret, "fi_ep_bind");

	ep_name[1] = malloc(addrlen);
	cr_assert(ep_name[1] != NULL);

	ret = fi_getname(&ep[1]->fid, ep_name[1], &addrlen);
	cr_assert(ret == FI_SUCCESS);

	ret = fi_av_insert(av, ep_name[0], 1, &gni_addr[0], 0,
				NULL);
	cr_assert(ret == 1);

	ret = fi_av_insert(av, ep_name[1], 1, &gni_addr[1], 0,
				NULL);
	cr_assert(ret == 1);

	ret = fi_ep_bind(ep[0], &av->fid, 0);
	cr_assert(!ret, "fi_ep_bind");

	ret = fi_ep_bind(ep[1], &av->fid, 0);
	cr_assert(!ret, "fi_ep_bind");

	ret = fi_enable(ep[0]);
	cr_assert(!ret, "fi_ep_enable");

	ret = fi_enable(ep[1]);
	cr_assert(!ret, "fi_ep_enable");

	target = malloc(BUF_SZ);
	assert(target);

	source = malloc(BUF_SZ);
	assert(source);

	ret = fi_mr_reg(dom, target, BUF_SZ,
			FI_REMOTE_WRITE, 0, 0, 0, &rem_mr, &target);
	cr_assert_eq(ret, 0);

	ret = fi_mr_reg(dom, source, BUF_SZ,
			FI_REMOTE_WRITE, 0, 0, 0, &loc_mr, &source);
	cr_assert_eq(ret, 0);

	mr_key = fi_mr_key(rem_mr);
}

void rdm_fi_pdc_teardown(void)
{
	int ret = 0;

	fi_close(&loc_mr->fid);
	fi_close(&rem_mr->fid);

	free(target);
	free(source);

	ret = fi_close(&ep[0]->fid);
	cr_assert(!ret, "failure in closing ep.");

	ret = fi_close(&ep[1]->fid);
	cr_assert(!ret, "failure in closing ep.");

	ret = fi_close(&msg_cq[0]->fid);
	cr_assert(!ret, "failure in send cq.");

	ret = fi_close(&msg_cq[1]->fid);
	cr_assert(!ret, "failure in recv cq.");

	ret = fi_close(&av->fid);
	cr_assert(!ret, "failure in closing av.");

	ret = fi_close(&dom->fid);
	cr_assert(!ret, "failure in closing domain.");

	ret = fi_close(&fab->fid);
	cr_assert(!ret, "failure in closing fabric.");

	fi_freeinfo(fi);
	fi_freeinfo(hints);
	free(ep_name[0]);
	free(ep_name[1]);
}

void rdm_fi_pdc_init_data(char *buf, int len, char seed)
{
	int i;

	for (i = 0; i < len; i++) {
		buf[i] = seed++;
	}
}

int rdm_fi_pdc_check_data(char *buf1, char *buf2, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (buf1[i] != buf2[i]) {
			printf("data mismatch, elem: %d, exp: %x, act: %x\n",
			       i, buf1[i], buf2[i]);
			return 0;
		}
	}

	return 1;
}

void rdm_fi_pdc_xfer_for_each_size(void (*xfer)(int len), int slen, int elen)
{
	int i;

	for (i = slen; i <= elen; i *= 2) {
		xfer(i);
	}
}

/*******************************************************************************
 * Test MSG functions
 ******************************************************************************/

TestSuite(rdm_fi_pdc,
		.init = rdm_fi_pdc_setup,
		.fini = rdm_fi_pdc_teardown,
		.disabled = false);

static void __progress_cqs(struct fid_cq *mcq[2], int init_src, int init_dst)
{
	int ret;
	struct fi_cq_entry s_cqe;
	struct fi_cq_entry d_cqe;
	int source_done = init_src;
	int dest_done = init_dst;

	/* need to progress both CQs simultaneously for rendezvous */
	do {
		ret = fi_cq_read(mcq[0], &s_cqe, 1);
		if (ret == 1) {
			source_done = 1;
		}

		ret = fi_cq_read(mcq[1], &d_cqe, 1);
		if (ret == 1) {
			dest_done = 1;
		}
	} while (!(source_done && dest_done));
}
/*
ssize_t (*recvmsg)(struct fid_ep *ep, const struct fi_msg *msg,
		uint64_t flags);
 */
static void do_trecvmsg_basic(int len)
{
	int ret;
	ssize_t sz;
	int source_done = 0, dest_done = 0;
	struct fi_msg_tagged msg;
	struct iovec iov;

	rdm_fi_pdc_init_data(source, len, 0xab);
	rdm_fi_pdc_init_data(target, len, 0);

	sz = fi_tsend(ep[0], source, len, loc_mr, gni_addr[1], len, target);
	cr_assert_eq(sz, 0);

	iov.iov_base = target;
	iov.iov_len = len;

	msg.msg_iov = &iov;
	msg.desc = (void **)&rem_mr;
	msg.iov_count = 1;
	msg.addr = gni_addr[0];
	msg.context = source;
	msg.data = (uint64_t)source;
	msg.tag = len;
	msg.ignore = 0;

	sz = fi_trecvmsg(ep[1], &msg, 0);
	cr_assert_eq(sz, 0);

	__progress_cqs(msg_cq);

	dbg_printf("got context events!\n");

	cr_assert(rdm_fi_pdc_check_data(source, target, len), "Data mismatch");
}

Test(rdm_fi_pdc, trecvmsg)
{
	rdm_fi_pdc_xfer_for_each_size(do_trecvmsg_basic, 1, BUF_SZ);
}

static void do_trecvmsg_peek(int len)
{
	int ret;
	ssize_t sz;
	int source_done = 0, dest_done = 0;
	struct fi_cq_entry d_cqe;
	struct fi_msg_tagged msg;
	struct iovec iov;

	rdm_fi_pdc_init_data(source, len, 0xab);
	rdm_fi_pdc_init_data(target, len, 0);

	sz = fi_tsend(ep[0], source, len, loc_mr, gni_addr[1], len, target);
	cr_assert_eq(sz, 0);

	iov.iov_base = target;
	iov.iov_len = len;

	msg.msg_iov = &iov;
	msg.desc = (void **)&rem_mr;
	msg.iov_count = 1;
	msg.addr = gni_addr[0];
	msg.context = source;
	msg.data = (uint64_t)source;
	msg.tag = len;
	msg.ignore = 0;

	__progress_cqs(msg_cq);

	sz = fi_trecvmsg(ep[1], &msg, FI_PEEK);
	cr_assert_eq(sz, 0);

	ret = fi_cq_read(msg_cq[1], &d_cqe, 1);
	cr_assert_eq(ret, FI_SUCCESS);

	dbg_printf("got context events!\n");

	cr_assert(rdm_fi_pdc_check_data(source, target, len), "Data mismatch");
}

static void do_trecvmsg_peek(int len)
{
	int ret;
	ssize_t sz;
	int source_done = 0, dest_done = 0;
	struct fi_msg_tagged msg;
	struct iovec iov;

	rdm_fi_pdc_init_data(source, len, 0xab);
	rdm_fi_pdc_init_data(target, len, 0);

	sz = fi_tsend(ep[0], source, len, loc_mr, gni_addr[1], len, target);
	cr_assert_eq(sz, 0);

	iov.iov_base = target;
	iov.iov_len = len;

	msg.msg_iov = &iov;
	msg.desc = (void **)&rem_mr;
	msg.iov_count = 1;
	msg.addr = gni_addr[0];
	msg.context = source;
	msg.data = (uint64_t)source;
	msg.tag = len;
	msg.ignore = 0;

	/* assume the recv cq is done, we only want the send cq to get the event */
	__progress_cqs(msg_cq, 0, 1);

	sz = fi_trecvmsg(ep[1], &msg, 0);
	cr_assert_eq(sz, 0);



	__progress_cqs(msg_cq);

	dbg_printf("got context events!\n");

	cr_assert(rdm_fi_pdc_check_data(source, target, len), "Data mismatch");
}
