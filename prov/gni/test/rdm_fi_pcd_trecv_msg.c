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
#include <sys/time.h>

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

struct timeval begin, end;
struct timeval loop_start, loop_end;

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

#define BUF_SZ (64*1024)
char *target;
char *source;
struct fid_mr *rem_mr, *loc_mr;
uint64_t mr_key;
const int max_test_time = 5;

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

	cq_attr.format = FI_CQ_FORMAT_TAGGED;
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

	target = malloc(BUF_SZ*2);
	assert(target);

	source = malloc(BUF_SZ*2);
	assert(source);

	ret = fi_mr_reg(dom, target, BUF_SZ*2,
			FI_REMOTE_WRITE, 0, 0, 0, &rem_mr, &target);
	cr_assert_eq(ret, 0);

	ret = fi_mr_reg(dom, source, BUF_SZ*2,
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

void rdm_fi_pdc_init_data_range(char *buf, int start, int len, char seed)
{
	int i;

	for (i = start; i < start + len; i++) {
		buf[i] = seed;
	}
}

void rdm_fi_pdc_init_data(char *buf, int len, char seed)
{
	rdm_fi_pdc_init_data_range(buf, 0, len, seed);
}

int rdm_fi_pdc_check_data_range(char *src, char *dst, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (src[i] != dst[i]) {
			printf("data mismatch, elem: %d, exp: %x, act: %x\n",
				   i, src[i], dst[i]);
			return 0;
		}
	}

	return 1;
}

int rdm_fi_pdc_check_data_pattern(char *buf, char pattern, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (buf[i] != pattern) {
			printf("data mismatch, elem: %d, exp: %.2x, act: %.2x\n",
				   i, buf[i], pattern);
			return 0;
		}
	}

	return 1;
}

int rdm_fi_pdc_check_data(char *buf1, char *buf2, int len)
{
	return rdm_fi_pdc_check_data_range(buf1, buf2, len);
}

void rdm_fi_pdc_xfer_for_each_size(void (*xfer)(int len), int slen, int elen)
{
	int i;

	for (i = slen; i <= elen; i *= 2) {
		printf("running test on size %d bytes\n", i);
		xfer(i);
	}
}

enum send_state {
	S_STATE_SEND_MSG_1 = 0,
	S_STATE_SEND_MSG_1_WAIT_CQ,
	S_STATE_SEND_MSG_2,
	S_STATE_SEND_MSG_2_WAIT_CQ,
	S_STATE_DONE,
};

#define SHOULD_BLIND_POLL_SCQ(state) \
	((state) == S_STATE_DONE)

enum recv_state {
	R_STATE_PEEK = 0,
	R_STATE_PEEK_WAIT_CQ,
	R_STATE_PEEK_CLAIM,
	R_STATE_PEEK_CLAIM_WAIT_CQ,
	R_STATE_PEEK_DISCARD,
	R_STATE_PEEK_DISCARD_WAIT_CQ,
	R_STATE_CLAIM,
	R_STATE_CLAIM_WAIT_CQ,
	R_STATE_CLAIM_DISCARD,
	R_STATE_RECV_MSG_1,
	R_STATE_RECV_MSG_1_WAIT_CQ,
	R_STATE_RECV_MSG_2,
	R_STATE_RECV_MSG_2_WAIT_CQ,
	R_STATE_DONE,
};

#define SHOULD_BLIND_POLL_RCQ(state) \
	((state) != R_STATE_PEEK_WAIT_CQ && \
			state != R_STATE_PEEK_CLAIM_WAIT_CQ && \
			state != R_STATE_PEEK_DISCARD_WAIT_CQ && \
			state != R_STATE_CLAIM_WAIT_CQ && \
			state != R_STATE_RECV_MSG_1_WAIT_CQ && \
			state != R_STATE_RECV_MSG_2_WAIT_CQ)

/*******************************************************************************
 * Test MSG functions
 ******************************************************************************/

TestSuite(rdm_fi_pdc,
		.init = rdm_fi_pdc_setup,
		.fini = rdm_fi_pdc_teardown,
		.disabled = false);

static int elapsed_seconds(struct timeval *s, struct timeval *e)
{
	/* rough estimate... I don't care that this is accurate */
	int seconds = e->tv_sec - s->tv_sec;

	if (!seconds)
		return seconds;

	if (e->tv_usec <= s->tv_usec)
		seconds -= 1;

	return seconds;
}

static void __progress_cqs(struct fid_cq *mcq[2],
		struct fi_cq_tagged_entry *s_cqe,
		struct fi_cq_tagged_entry *d_cqe,
		int s_cqe_count,
		int d_cqe_count,
		int spin_time)
{
	int ret;
	struct fi_cq_tagged_entry *src_cqe;
	struct fi_cq_tagged_entry *dst_cqe;
	struct fi_cq_tagged_entry trash;
	int source_done = 0;
	int dest_done = 0;
	int s_cqe_left = s_cqe_count;
	int d_cqe_left = d_cqe_count;
	int elapsed;

	src_cqe = s_cqe;
	dst_cqe = d_cqe;

	gettimeofday(&begin, NULL);

	if (!src_cqe)
		src_cqe = &trash;

	if (!dst_cqe)
		dst_cqe = &trash;

	/* need to progress both CQs simultaneously for rendezvous */
	do {
		ret = fi_cq_read(mcq[0], src_cqe, 1);
		if (ret == 1 && s_cqe_left) {
			--s_cqe_left;
			if (s_cqe_left == 0) {
				source_done = 1;
				src_cqe = &trash;
			} else {
				src_cqe++;
			}
		}

		ret = fi_cq_read(mcq[1], dst_cqe, 1);
		if (ret == 1 && d_cqe_left) {
			--d_cqe_left;
			if (d_cqe_left == 0) {
				dest_done = 1;
				dst_cqe = &trash;
			} else {
				dst_cqe++;
			}
		}

		gettimeofday(&end, NULL);
		elapsed = elapsed_seconds(&begin, &end);
	} while (!(source_done && dest_done) &&
			spin_time > elapsed);

	/* all CQEs should be pulled before exiting function */
	cr_assert(d_cqe_left == 0);
	cr_assert(s_cqe_left == 0);
}

static void build_message(struct fi_msg_tagged *msg, struct iovec *iov,
		void *target, int len, void **rem_mr, size_t gni_addr, void *source,
		uint64_t tag, uint64_t ignore)
{
	iov->iov_base = target;
	iov->iov_len = len;

	msg->msg_iov = iov;
	msg->desc = rem_mr;
	msg->iov_count = 1;
	msg->addr = gni_addr;
	msg->context = source;
	msg->data = (uint64_t) source;
	msg->tag = tag;
	msg->ignore = ignore;
}

static void validate_cqe_contents(struct fi_cq_tagged_entry *entry,
		void *buf, size_t len, uint64_t tag, void *context)
{
	if (entry->buf != buf)
		printf("entry->buf=%p buf=%p\n", entry->buf, buf);
	if (entry->tag != tag) {
		printf("entry->tag=%llu tag=%llu\n", entry->tag, tag);
		*((char *) 0x0) = 128;
	}
	cr_assert_eq(entry->buf, buf);
	cr_assert_eq(entry->len, len);
	cr_assert_eq(entry->tag, tag);
	cr_assert_eq(entry->op_context, context);
}

static void validate_cqe_with_message(struct fi_cq_tagged_entry *entry,
		struct fi_msg_tagged *msg)
{
	validate_cqe_contents(entry, msg->msg_iov[0].iov_base,
			msg->msg_iov[0].iov_len, msg->tag, msg->context);
}


/*
ssize_t (*recvmsg)(struct fid_ep *ep, const struct fi_msg *msg,
		uint64_t flags);
 */
Test(rdm_fi_pdc, peek_no_event)
{
	/*
	 * This test should do nothing but peek into EP to ensure that no messages
	 * are there. This should be a simple test
	 */

	int ret;
	struct fi_msg_tagged msg;
	struct iovec iov;

	build_message(&msg, &iov, target, 128, (void *) &rem_mr, gni_addr[0],
			source, 128, 0);

	ret = fi_trecvmsg(ep[1], &msg, FI_PEEK);
	cr_assert_eq(ret, -FI_ENOMSG);
}

static void pdc_peek_event_present_buffer_provided(int len)
{
	/* for each message size (regardless of smsg or rendezvous),
	 *   send a message, wait for the send completion, then perform a peek.
	 *   If a message is present, then the test has succeeded. Otherwise, it
	 *   has failed because the message has been sent by the other endpoint.
	 *   A CQ event must be generated after the peek has been completed, so
	 *   we will check for the CQ event before posting the request after the
	 *   peek. After the CQ comes back, we should check the values of CQ for
	 *   the peek and for the post.
	 *
	 *   This is the special case where the application provides a buffer
	 *   during the peek for which some of the data can be written.
	 *
	 *   	An  application  may supply a buffer as part of the peek operation.
	 * 	   	If given, the provider may return a copy of the message data.
	 *
	 *	 Ideally, both cases should be tested, where the provider returns a
	 *	 NULL pointer indicating that no data was available yet even though
	 *	 the peek succeeded, and the case where some of the data is copied
	 *	 back. The former may be applicable to rendezvous and the latter
	 *	 applicable to smsg.
	 *
	 * The returned completion data will indicate
	 * the meta-data associated with the  message,  such  as  the  message
	 * length,  completion  flags,  available  CQ  data,  tag,  and source
	 * address.  The data available is subject  to  the  completion  entry
	 * format (e.g.  struct fi_cq_tagged_entry).
	 *
	 * this should check to see if the buf provided actually has data in it
	 * after a successful peek
	 */

	int ret;
	struct fi_msg_tagged msg;
	struct iovec iov;
	struct fi_cq_tagged_entry s_cqe;
	struct fi_cq_tagged_entry d_cqe;
	struct fi_cq_tagged_entry d_peek_cqe;
	struct fi_cq_tagged_entry trash;
	enum send_state s_state = S_STATE_SEND_MSG_1;
	enum recv_state r_state = R_STATE_PEEK;
	int elapsed;

	rdm_fi_pdc_init_data(source, len, 0xab);
	rdm_fi_pdc_init_data(target, len, 0);


	build_message(&msg, &iov, target, len, (void *) &rem_mr, gni_addr[0],
			source, len, 0);

	gettimeofday(&loop_start, NULL);
	do {
		if (SHOULD_BLIND_POLL_SCQ(s_state))
			fi_cq_read(msg_cq[0], &trash, 1);

		if (SHOULD_BLIND_POLL_RCQ(r_state))
			fi_cq_read(msg_cq[1], &trash, 1);

		switch (s_state) {
		case S_STATE_SEND_MSG_1:
			ret = fi_tsend(ep[0], source, len, loc_mr, gni_addr[1], len, target);
			cr_assert_eq(ret, FI_SUCCESS);

			s_state = S_STATE_SEND_MSG_1_WAIT_CQ;
			break;
		case S_STATE_SEND_MSG_1_WAIT_CQ:
			ret = fi_cq_read(msg_cq[0], &s_cqe, 1);
			if (ret == 1)
				s_state = S_STATE_DONE;
			break;
		case S_STATE_DONE:
			break;
		default:
			cr_assert(0 == 1, "unreachable state");
			break;
		}

		switch (r_state) {
		case R_STATE_PEEK:
			ret = fi_trecvmsg(ep[1], &msg, FI_PEEK);
			if (ret == FI_SUCCESS)
				r_state = R_STATE_PEEK_WAIT_CQ;
			break;
		case R_STATE_PEEK_WAIT_CQ:
			ret = fi_cq_read(msg_cq[1], &d_peek_cqe, 1);
			if (ret == 1)
				r_state = R_STATE_RECV_MSG_1;
			break;
		case R_STATE_RECV_MSG_1:
			ret = fi_trecvmsg(ep[1], &msg, 0);
			cr_assert_eq(ret, FI_SUCCESS);

			r_state = R_STATE_RECV_MSG_1_WAIT_CQ;
			break;
		case R_STATE_RECV_MSG_1_WAIT_CQ:
			ret = fi_cq_read(msg_cq[1], &d_cqe, 1);
			if (ret == 1)
				r_state = R_STATE_DONE;
			break;
		case R_STATE_DONE:
			break;
		default:
			cr_assert(0 == 1, "unreachable state");
			break;
		}

		gettimeofday(&loop_end, NULL);
		elapsed = elapsed_seconds(&loop_start, &loop_end);
	} while (elapsed < max_test_time &&
			!(s_state == S_STATE_DONE && r_state == R_STATE_DONE));

	cr_assert_eq(s_state, S_STATE_DONE);
	cr_assert_eq(r_state, R_STATE_DONE);

	/* validate the expected results */
	validate_cqe_contents(&s_cqe, source, len, len, target);
	validate_cqe_with_message(&d_peek_cqe, &msg);
	validate_cqe_with_message(&d_cqe, &msg);
	cr_assert(rdm_fi_pdc_check_data(source, target, len), "Data mismatch");
}

Test(rdm_fi_pdc, peek_event_present_buff_provided)
{
	rdm_fi_pdc_xfer_for_each_size(pdc_peek_event_present_buffer_provided,
			1, BUF_SZ);
}

static void pdc_peek_event_present_no_buff_provided(int len)
{
	/* for each message size (regardless of smsg or rendezvous),
	 *   send a message, wait for the send completion, then perform a peek.
	 *   If a message is present, then the test has succeeded. Otherwise, it
	 *   has failed because the message has been sent by the other endpoint.
	 *   A CQ event must be generated after the peek has been completed, so
	 *   we will check for the CQ event before posting the request after the
	 *   peek. After the CQ comes back, we should check the values of CQ for
	 *   the peek and for the post.
	 *
	 * The returned completion data will indicate
	   the meta-data associated with the  message,  such  as  the  message
	   length,  completion  flags,  available  CQ  data,  tag,  and source
	   address.  The data available is subject  to  the  completion  entry
	   format (e.g.  struct fi_cq_tagged_entry).
	 */

	int ret;
	struct fi_msg_tagged msg;
	struct iovec iov;
	struct fi_cq_tagged_entry s_cqe;
	struct fi_cq_tagged_entry d_cqe;
	struct fi_cq_tagged_entry d_peek_cqe;
	struct fi_cq_tagged_entry trash;
	enum send_state s_state = S_STATE_SEND_MSG_1;
	enum recv_state r_state = R_STATE_PEEK;
	int elapsed;

	rdm_fi_pdc_init_data(source, len, 0xab);
	rdm_fi_pdc_init_data(target, len, 0);

	ret = fi_tsend(ep[0], source, len, loc_mr, gni_addr[1], len, target);
	cr_assert_eq(ret, FI_SUCCESS);

	build_message(&msg, &iov, target, len, (void *) &rem_mr, gni_addr[0],
				source, len, 0);

	gettimeofday(&loop_start, NULL);
	do {
		if (SHOULD_BLIND_POLL_SCQ(s_state))
			fi_cq_read(msg_cq[0], &trash, 1);

		if (SHOULD_BLIND_POLL_RCQ(r_state))
			fi_cq_read(msg_cq[1], &trash, 1);

		switch (s_state) {
		case S_STATE_SEND_MSG_1:
			ret = fi_tsend(ep[0], source, len, loc_mr, gni_addr[1], len, target);
			cr_assert_eq(ret, FI_SUCCESS);

			s_state = S_STATE_SEND_MSG_1_WAIT_CQ;
			break;
		case S_STATE_SEND_MSG_1_WAIT_CQ:
			ret = fi_cq_read(msg_cq[0], &s_cqe, 1);
			if (ret == 1)
				s_state = S_STATE_DONE;
			break;
		case S_STATE_DONE:
			break;
		default:
			cr_assert(0 == 1, "unreachable state");
			break;
		}

		switch (r_state) {
		case R_STATE_PEEK:
			ret = fi_trecvmsg(ep[1], &msg, FI_PEEK);
			if (ret == FI_SUCCESS)
				r_state = R_STATE_PEEK_WAIT_CQ;
			break;
		case R_STATE_PEEK_WAIT_CQ:
			ret = fi_cq_read(msg_cq[1], &d_peek_cqe, 1);
			if (ret == 1)
				r_state = R_STATE_RECV_MSG_1;
			break;
		case R_STATE_RECV_MSG_1:
			ret = fi_trecvmsg(ep[1], &msg, 0);
			cr_assert_eq(ret, FI_SUCCESS);

			r_state = R_STATE_RECV_MSG_1_WAIT_CQ;
			break;
		case R_STATE_RECV_MSG_1_WAIT_CQ:
			ret = fi_cq_read(msg_cq[1], &d_cqe, 1);
			if (ret == 1)
				r_state = R_STATE_DONE;
			break;
		case R_STATE_DONE:
			break;
		default:
			cr_assert(0 == 1, "unreachable state");
			break;
		}

		gettimeofday(&loop_end, NULL);
		elapsed = elapsed_seconds(&loop_start, &loop_end);
	} while (elapsed < max_test_time &&
			!(s_state == S_STATE_DONE && r_state == R_STATE_DONE));

	cr_assert_eq(s_state, S_STATE_DONE);
	cr_assert_eq(r_state, R_STATE_DONE);

	/* verify test execution correctness */
	validate_cqe_contents(&s_cqe, source, len, len, target);
	validate_cqe_with_message(&d_cqe, &msg);
	validate_cqe_with_message(&d_peek_cqe, &msg);
	cr_assert(rdm_fi_pdc_check_data(source, target, len), "Data mismatch");
}

Test(rdm_fi_pdc, peek_event_present_no_buff_provided)
{
	rdm_fi_pdc_xfer_for_each_size(pdc_peek_event_present_no_buff_provided,
				1, BUF_SZ);
}

static void pdc_peek_claim_same_tag(int len)
{
	/* for each message size (regardless of smsg or rendezvous),
	 *   send two messages, each with the same tag. Call trecvmsg with distinct
	 *   parameters and FI_PEEK/FI_CLAIM flags on both messages. Correctness
	 *   will be determined by whether the CQE data matches the corresponding
	 *   parameters of the original trecvmsg calls. Additionally, the data
	 *   within the posted buffer should match the expected values of the
	 *   contents. To achieve this, the source buffer should have two sets of
	 *   values from which the sends are performed. Since the sends will
	 *   complete in order, the order in which the data is landed should
	 *   depend on the order in which trecvmsg is called.
	 */

	int ret, i, j;
	struct fi_msg_tagged msg[2];
	struct iovec iov[2];
	struct fi_cq_tagged_entry s_cqe[2];
	struct fi_cq_tagged_entry d_cqe[2];
	struct fi_cq_tagged_entry *src_cqe[2] = {NULL, NULL};
	char *src_buf[2] = {source, source + len};
	char *dst_buf[2] = {target, target + len};
	struct fi_cq_tagged_entry d_peek_cqe;
	struct fi_cq_tagged_entry trash;
	enum send_state s_state = S_STATE_SEND_MSG_1;
	enum recv_state r_state = R_STATE_PEEK_CLAIM;
	int elapsed;

	/* initialize the initial data range on the source buffer to have
	 * different data vaules for one message than for the other
	 */
	rdm_fi_pdc_init_data_range(source, 0, len, 0xa5);
	rdm_fi_pdc_init_data_range(source, len, len, 0x5a);
	rdm_fi_pdc_init_data(target, len*2 , 0);

	/* set up messages */
	for (i = 0; i < 2; i++) {
		build_message(&msg[i], &iov[i], dst_buf[i], len, (void *) &rem_mr,
				gni_addr[0], src_buf[i], len, 0);
	}

	gettimeofday(&loop_start, NULL);
	do {
		if (SHOULD_BLIND_POLL_SCQ(s_state))
			fi_cq_read(msg_cq[0], &trash, 1);

		if (SHOULD_BLIND_POLL_RCQ(r_state))
			fi_cq_read(msg_cq[1], &trash, 1);

		switch (s_state) {
		case S_STATE_SEND_MSG_1:
			ret = fi_tsend(ep[0], src_buf[0], len, loc_mr, gni_addr[1], len, dst_buf[0]);
			cr_assert_eq(ret, FI_SUCCESS);

			s_state = S_STATE_SEND_MSG_2;
			break;
		case S_STATE_SEND_MSG_2:
			ret = fi_tsend(ep[0], src_buf[1], len, loc_mr, gni_addr[1], len, dst_buf[1]);
			cr_assert_eq(ret, FI_SUCCESS);

			s_state = S_STATE_SEND_MSG_1_WAIT_CQ;
			break;
		case S_STATE_SEND_MSG_1_WAIT_CQ:
			ret = fi_cq_read(msg_cq[0], &s_cqe[0], 1);
			if (ret == 1) {
				s_state = S_STATE_SEND_MSG_2_WAIT_CQ;
			}
			break;
		case S_STATE_SEND_MSG_2_WAIT_CQ:
			ret = fi_cq_read(msg_cq[0], &s_cqe[1], 1);
			if (ret == 1) {
				s_state = S_STATE_DONE;
			}
			break;
		case S_STATE_DONE:
			break;
		default:
			cr_assert(0 == 1, "unreachable state");
			break;
		}

		switch (r_state) {
		case R_STATE_PEEK_CLAIM:
			ret = fi_trecvmsg(ep[1], &msg[0], FI_PEEK | FI_CLAIM);
			if (ret == FI_SUCCESS)
				r_state = R_STATE_PEEK_CLAIM_WAIT_CQ;
			break;
		case R_STATE_PEEK_CLAIM_WAIT_CQ:
			ret = fi_cq_read(msg_cq[1], &d_peek_cqe, 1);
			if (ret == 1) {
				r_state = R_STATE_RECV_MSG_2;
			}
			break;
		case R_STATE_RECV_MSG_2:
			ret = fi_trecvmsg(ep[1], &msg[1], 0);
			if (ret == FI_SUCCESS)
				r_state = R_STATE_RECV_MSG_2_WAIT_CQ;
			break;
		case R_STATE_RECV_MSG_2_WAIT_CQ:
			ret = fi_cq_read(msg_cq[1], &d_cqe[1], 1);
			if (ret == 1) {
				r_state = R_STATE_CLAIM;
			}
			break;
		case R_STATE_CLAIM:
			ret = fi_trecvmsg(ep[1], &msg[0], FI_CLAIM);
			if (ret == FI_SUCCESS)
				r_state = R_STATE_CLAIM_WAIT_CQ;
			break;
		case R_STATE_CLAIM_WAIT_CQ:
			ret = fi_cq_read(msg_cq[1], &d_cqe[0], 1);
			if (ret == 1) {
				r_state = R_STATE_DONE;
			}
			break;
		case R_STATE_DONE:
			break;
		default:
			cr_assert(0 == 1, "unreachable state");
			break;
		}

		gettimeofday(&loop_end, NULL);
		elapsed = elapsed_seconds(&loop_start, &loop_end);
	} while (elapsed < max_test_time &&
			!(s_state == S_STATE_DONE && r_state == R_STATE_DONE));

	cr_assert_eq(s_state, S_STATE_DONE);
	cr_assert_eq(r_state, R_STATE_DONE);

	/* map src cqes to src parameters */
	for (i = 0; i < 2; i++)
		for (j = 0; j < 2; j++)
			if (s_cqe[i].buf == src_buf[j])
				src_cqe[j] = &s_cqe[i];

	/* verify test execution correctness */
	validate_cqe_contents(src_cqe[0], src_buf[0], len, len, dst_buf[0]);
	validate_cqe_contents(src_cqe[1], src_buf[1], len, len, dst_buf[1]);
	validate_cqe_with_message(&d_peek_cqe, &msg[0]);
	validate_cqe_with_message(&d_cqe[1], &msg[1]);
	validate_cqe_with_message(&d_cqe[0], &msg[0]);

	cr_assert(rdm_fi_pdc_check_data(src_buf[0], dst_buf[0], len),
			"Data mismatch");

	cr_assert(rdm_fi_pdc_check_data(src_buf[1], dst_buf[1], len),
			"Data mismatch");
}

Test(rdm_fi_pdc, peek_claim_same_tag)
{
	rdm_fi_pdc_xfer_for_each_size(pdc_peek_claim_same_tag, 1, BUF_SZ);
}

static void pdc_peek_claim_unique_tag(int len)
{
	/* for each message size (regardless of smsg or rendezvous),
	 *   send two messages, each with a unique tag. Call trecvmsg with distinct
	 *   parameters and FI_PEEK/FI_CLAIM flags on both messages. Correctness
	 *   will be determined by whether the CQE data matches the corresponding
	 *   parameters of the original trecvmsg calls. Additionally, the data
	 *   within the posted buffer should match the expected values of the
	 *   contents. To achieve this, the source buffer should have two sets of
	 *   values from which the sends are performed. Since the sends will
	 *   complete in order, the order in which the data is landed should
	 *   depend on the order in which trecvmsg is called.
	 */

	int ret, i, j;
	struct fi_msg_tagged msg[2];
	struct iovec iov[2];
	struct fi_cq_tagged_entry s_cqe[2];
	struct fi_cq_tagged_entry d_cqe[2];
	struct fi_cq_tagged_entry *src_cqe[2] = {NULL, NULL};
	char *src_buf[2] = {source, source + len};
	char *dst_buf[2] = {target, target + len};
	struct fi_cq_tagged_entry d_peek_cqe;
	struct fi_cq_tagged_entry trash;
	enum send_state s_state = S_STATE_SEND_MSG_1;
	enum recv_state r_state = R_STATE_PEEK_CLAIM;
	int elapsed;

	/* initialize the initial data range on the source buffer to have
	 * different data vaules for one message than for the other
	 */
	rdm_fi_pdc_init_data_range(source, 0, len, 0xa5);
	rdm_fi_pdc_init_data_range(source, len, len, 0x5a);
	rdm_fi_pdc_init_data(target, len*2 , 0);

	/* set up messages */
	for (i = 0; i < 2; i++) {
		build_message(&msg[i], &iov[i], dst_buf[i], len, (void *) &rem_mr,
				gni_addr[0], src_buf[i], len + i, 0);
	}

	gettimeofday(&loop_start, NULL);
	do {
		if (SHOULD_BLIND_POLL_SCQ(s_state))
			fi_cq_read(msg_cq[0], &trash, 1);

		if (SHOULD_BLIND_POLL_RCQ(r_state))
			fi_cq_read(msg_cq[1], &trash, 1);

		switch (s_state) {
		case S_STATE_SEND_MSG_1:
			ret = fi_tsend(ep[0], src_buf[0], len, loc_mr, gni_addr[1], len, dst_buf[0]);
			cr_assert_eq(ret, FI_SUCCESS);

			s_state = S_STATE_SEND_MSG_2;
			break;
		case S_STATE_SEND_MSG_2:
			ret = fi_tsend(ep[0], src_buf[1], len, loc_mr, gni_addr[1], len + 1, dst_buf[1]);
			cr_assert_eq(ret, FI_SUCCESS);

			s_state = S_STATE_SEND_MSG_1_WAIT_CQ;
			break;
		case S_STATE_SEND_MSG_1_WAIT_CQ:
			ret = fi_cq_read(msg_cq[0], &s_cqe[0], 1);
			if (ret == 1) {
				s_state = S_STATE_SEND_MSG_2_WAIT_CQ;
			}
			break;
		case S_STATE_SEND_MSG_2_WAIT_CQ:
			ret = fi_cq_read(msg_cq[0], &s_cqe[1], 1);
			if (ret == 1) {
				s_state = S_STATE_DONE;
			}
			break;
		case S_STATE_DONE:
			break;
		default:
			cr_assert(0 == 1, "unreachable state");
			break;
		}

		switch (r_state) {
		case R_STATE_PEEK_CLAIM:
			ret = fi_trecvmsg(ep[1], &msg[0], FI_PEEK | FI_CLAIM);
			if (ret == FI_SUCCESS)
				r_state = R_STATE_PEEK_CLAIM_WAIT_CQ;
			break;
		case R_STATE_PEEK_CLAIM_WAIT_CQ:
			ret = fi_cq_read(msg_cq[1], &d_peek_cqe, 1);
			if (ret == 1)
				r_state = R_STATE_RECV_MSG_2;
			break;
		case R_STATE_RECV_MSG_2:
			ret = fi_trecvmsg(ep[1], &msg[1], 0);
			cr_assert_eq(ret, FI_SUCCESS);

			r_state = R_STATE_RECV_MSG_2_WAIT_CQ;
			break;
		case R_STATE_RECV_MSG_2_WAIT_CQ:
			ret = fi_cq_read(msg_cq[1], &d_cqe[1], 1);
			if (ret == 1)
				r_state = R_STATE_CLAIM;
			break;
		case R_STATE_CLAIM:
			ret = fi_trecvmsg(ep[1], &msg[0], FI_CLAIM);
			if (ret == FI_SUCCESS)
				r_state = R_STATE_CLAIM_WAIT_CQ;
			break;
		case R_STATE_CLAIM_WAIT_CQ:
			ret = fi_cq_read(msg_cq[1], &d_cqe[0], 1);
			if (ret == 1)
				r_state = R_STATE_DONE;
			break;
		case R_STATE_DONE:
			break;
		default:
			cr_assert(0 == 1, "unreachable state");
			break;
		}

		gettimeofday(&loop_end, NULL);
		elapsed = elapsed_seconds(&loop_start, &loop_end);
	} while (elapsed < max_test_time &&
			!(s_state == S_STATE_DONE && r_state == R_STATE_DONE));

	cr_assert_eq(s_state, S_STATE_DONE);
	cr_assert_eq(r_state, R_STATE_DONE);

	/* map src cqes to src parameters */
	for (i = 0; i < 2; i++)
		for (j = 0; j < 2; j++)
			if (s_cqe[i].buf == src_buf[j])
				src_cqe[j] = &s_cqe[i];

	/* verify test execution correctness */
	for (i = 0; i < 2; i++)
		validate_cqe_contents(src_cqe[i], src_buf[i], len, len + i, dst_buf[i]);

	validate_cqe_with_message(&d_peek_cqe, &msg[0]);
	validate_cqe_with_message(&d_cqe[1], &msg[1]);
	validate_cqe_with_message(&d_cqe[0], &msg[0]);

	cr_assert(rdm_fi_pdc_check_data(src_buf[0], dst_buf[0], len),
			"Data mismatch");
	cr_assert(rdm_fi_pdc_check_data(src_buf[1], dst_buf[1], len),
			"Data mismatch");
}

Test(rdm_fi_pdc, peek_claim_unique_tag)
{
	rdm_fi_pdc_xfer_for_each_size(pdc_peek_claim_unique_tag, 1, BUF_SZ);
}

static void pdc_peek_discard(int len)
{
	/* for each message size (regardless of smsg or rendezvous),
	 *   send one message. Wait for the send completion to arrive then perform
	 *   a peek/discard on the recv EP. If the peek/discard finds a message
	 *   and appropriately discards it, then the operation is a success.
	 *   Success can be measured by calling peek again on the EP and finding
	 *   no message.
	 */

	int ret;
	struct fi_msg_tagged msg;
	struct iovec iov;
	struct fi_cq_tagged_entry s_cqe;
	struct fi_cq_tagged_entry d_cqe;
	struct fi_cq_tagged_entry d_peek_cqe;
	struct fi_cq_tagged_entry trash;
	enum send_state s_state = S_STATE_SEND_MSG_1;
	enum recv_state r_state = R_STATE_PEEK_DISCARD;
	int elapsed;

	rdm_fi_pdc_init_data(source, len, 0xab);
	rdm_fi_pdc_init_data(target, len, 0);

	build_message(&msg, &iov, target, len, (void *) &rem_mr, gni_addr[0],
				source, len, 0);

	gettimeofday(&loop_start, NULL);
	do {
		if (SHOULD_BLIND_POLL_SCQ(s_state))
			fi_cq_read(msg_cq[0], &trash, 1);

		if (SHOULD_BLIND_POLL_RCQ(r_state))
			fi_cq_read(msg_cq[1], &trash, 1);

		switch (s_state) {
		case S_STATE_SEND_MSG_1:
			ret = fi_tsend(ep[0], source, len, loc_mr, gni_addr[1],
					len, target);
			cr_assert_eq(ret, FI_SUCCESS);

			s_state = S_STATE_SEND_MSG_1_WAIT_CQ;
			break;
		case S_STATE_SEND_MSG_1_WAIT_CQ:
			ret = fi_cq_read(msg_cq[0], &s_cqe, 1);
			if (ret == 1)
				s_state = S_STATE_DONE;
			break;
		case S_STATE_DONE:
			break;
		default:
			cr_assert(0 == 1, "unreachable state");
			break;
		}

		switch (r_state) {
		case R_STATE_PEEK_DISCARD:
			ret = fi_trecvmsg(ep[1], &msg, FI_PEEK | FI_DISCARD);
			if (ret == FI_SUCCESS)
				r_state = R_STATE_PEEK_CLAIM_WAIT_CQ;
			break;
		case R_STATE_PEEK_DISCARD_WAIT_CQ:
			ret = fi_cq_read(msg_cq[1], &d_peek_cqe, 1);
			if (ret == 1)
				r_state = R_STATE_PEEK;
			break;
		case R_STATE_PEEK:
			ret = fi_trecvmsg(ep[1], &msg, FI_PEEK);
			cr_assert_eq(ret, -FI_ENOMSG);

			r_state = R_STATE_DONE;
			break;
		case R_STATE_DONE:
			break;
		default:
			cr_assert(0 == 1, "unreachable state");
			break;
		}

		gettimeofday(&loop_end, NULL);
		elapsed = elapsed_seconds(&loop_start, &loop_end);
	} while (elapsed < max_test_time &&
			!(s_state == S_STATE_DONE && r_state == R_STATE_DONE));

	cr_assert_eq(s_state, S_STATE_DONE);
	cr_assert_eq(r_state, R_STATE_DONE);

	/* verify test execution correctness */
	validate_cqe_contents(&s_cqe, source, len, len, target);
	validate_cqe_with_message(&d_peek_cqe, &msg);
	cr_assert(rdm_fi_pdc_check_data_pattern(target, 0, len), "Data matched");
}

Test(rdm_fi_pdc, peek_discard)
{
	rdm_fi_pdc_xfer_for_each_size(pdc_peek_discard, 1, BUF_SZ);
}

static void pdc_peek_discard_unique_tags(int len)
{
	/* for each message size (regardless of smsg or rendezvous),
	 *   send two messages with unique tags. Wait for the send completion to
	 *   arrive then perform a peek/discard on the recv EP. If the
	 *   peek/discard finds a correctly tagged message and appropriately
	 *   discards it, then the operation is a success. Success can be
	 *   measured through the following steps:
	 *     - Since the messages are delivered in order, we can attempt to
	 *         discard the second message.
	 *     - Peek on the first operation's tag and find a message
	 *     - Peek on the second operation's tag and find no message
	 *     - Recv the first operation and verify the correct contents
	 */

	int ret, i, j;
	struct fi_msg_tagged msg[2];
	struct iovec iov[2];
	struct fi_cq_tagged_entry s_cqe[2];
	struct fi_cq_tagged_entry d_cqe[2];
	struct fi_cq_tagged_entry *src_cqe[2] = {NULL, NULL};
	char *src_buf[2] = {source, source + len};
	char *dst_buf[2] = {target, target + len};
	struct fi_cq_tagged_entry d_peek_cqe;
	struct fi_cq_tagged_entry trash;
	enum send_state s_state = S_STATE_SEND_MSG_1;
	enum recv_state r_state = R_STATE_PEEK_DISCARD;
	int elapsed;

	/* initialize the initial data range on the source buffer to have
	 * different data vaules for one message than for the other
	 */
	rdm_fi_pdc_init_data_range(source, 0, len, 0xa5);
	rdm_fi_pdc_init_data_range(source, len, len, 0x5a);
	rdm_fi_pdc_init_data(target, len*2 , 0);

	/* set up messages */
	for (i = 0; i < 2; i++) {
		build_message(&msg[i], &iov[i], dst_buf[i], len, (void *) &rem_mr, gni_addr[0],
				src_buf[i], len + i, 0);
	}

	gettimeofday(&loop_start, NULL);
	do {
		if (SHOULD_BLIND_POLL_SCQ(s_state))
			fi_cq_read(msg_cq[0], &trash, 1);

		if (SHOULD_BLIND_POLL_RCQ(r_state))
			fi_cq_read(msg_cq[1], &trash, 1);

		switch (s_state) {
		case S_STATE_SEND_MSG_1:
			ret = fi_tsend(ep[0], src_buf[0], len, loc_mr, gni_addr[1],
					len, dst_buf[0]);
			cr_assert_eq(ret, FI_SUCCESS);

			s_state = S_STATE_SEND_MSG_1_WAIT_CQ;
			break;
		case S_STATE_SEND_MSG_1_WAIT_CQ:
			ret = fi_cq_read(msg_cq[0], &s_cqe[0], 1);
			if (ret == 1)
				s_state = S_STATE_SEND_MSG_2;
			break;
		case S_STATE_SEND_MSG_2:
			ret = fi_tsend(ep[0], src_buf[1], len, loc_mr, gni_addr[1],
					len + 1, dst_buf[1]);
			cr_assert_eq(ret, FI_SUCCESS);

			s_state = S_STATE_SEND_MSG_2_WAIT_CQ;
			break;
		case S_STATE_SEND_MSG_2_WAIT_CQ:
			ret = fi_cq_read(msg_cq[0], &s_cqe[1], 1);
			if (ret == 1)
				s_state = S_STATE_DONE;
			break;
		case S_STATE_DONE:
			break;
		default:
			cr_assert(0 == 1, "unreachable state");
			break;
		}

		switch (r_state) {
		case R_STATE_PEEK_DISCARD:
			ret = fi_trecvmsg(ep[1], &msg[0], FI_PEEK | FI_DISCARD);
			if (ret == FI_SUCCESS)
				r_state = R_STATE_PEEK_DISCARD_WAIT_CQ;
			break;
		case R_STATE_PEEK_DISCARD_WAIT_CQ:
			ret = fi_cq_read(msg_cq[1], &d_peek_cqe, 1);
			if (ret == 1)
				r_state = R_STATE_RECV_MSG_2;
			break;
		case R_STATE_RECV_MSG_2:
			ret = fi_trecvmsg(ep[1], &msg[1], 0);
			cr_assert_eq(ret, FI_SUCCESS);

			r_state = R_STATE_RECV_MSG_2_WAIT_CQ;
			break;
		case R_STATE_RECV_MSG_2_WAIT_CQ:
			ret = fi_cq_read(msg_cq[1], &d_cqe[1], 1);
			if (ret == 1)
				r_state = R_STATE_CLAIM;
			break;
		case R_STATE_CLAIM:
			ret = fi_trecvmsg(ep[1], &msg[1], FI_CLAIM);
			if (ret == FI_SUCCESS)
				r_state = R_STATE_CLAIM_WAIT_CQ;
			break;
		case R_STATE_CLAIM_WAIT_CQ:
			ret = fi_cq_read(msg_cq[1], &d_cqe[0], 1);
			if (ret == 1)
				r_state = R_STATE_DONE;
			break;
		case R_STATE_DONE:
			break;
		default:
			cr_assert(0 == 1, "unreachable state");
			break;
		}

		gettimeofday(&loop_end, NULL);
		elapsed = elapsed_seconds(&loop_start, &loop_end);
	} while (elapsed < max_test_time &&
			!(s_state == S_STATE_DONE && r_state == R_STATE_DONE));

	cr_assert_eq(s_state, S_STATE_DONE);
	cr_assert_eq(r_state, R_STATE_DONE);

	/* map src cqes to src parameters */
	for (i = 0; i < 2; i++)
		for (j = 0; j < 2; j++)
			if (s_cqe[i].buf == src_buf[j])
				src_cqe[j] = &s_cqe[i];

	validate_cqe_contents(&s_cqe[0], src_buf[0], len, len, dst_buf[0]);
	validate_cqe_contents(&s_cqe[1], src_buf[1], len, len + 1, dst_buf[1]);
	validate_cqe_with_message(&d_peek_cqe, &msg[0]);
	validate_cqe_with_message(&d_cqe[1], &msg[1]);

	cr_assert(rdm_fi_pdc_check_data_pattern(dst_buf[0], 0, len),
			"Data mismatch");
	cr_assert(rdm_fi_pdc_check_data(src_buf[1], dst_buf[1], len),
			"Data mismatch");
}

Test(rdm_fi_pdc, peek_discard_unique_tags)
{
	rdm_fi_pdc_xfer_for_each_size(pdc_peek_discard_unique_tags, 1, BUF_SZ);
}

static void pdc_peek_claim_then_claim_discard(int len)
{
	/* for each message size (regardless of smsg or rendezvous),
	 *   send two messages with unique tags and parameters.
	 *   Wait for the send completion to arrive then perform a peek/claim
	 *   on the recv EP. Perform another trecvmsg without peek/claim to recv
	 *   the other message. Afterwards, perform the trecvmsg with CLAIM/DISCARD
	 *   to discard the first message.
	 *
	 *   From the fi_tagged man page:
	 *   	Claimed messages can only be retrieved using a subsequent,
	 *      paired receive operation with the FI_CLAIM  flag  set.
	 *
	 *      (FI_DISCARD) flag may also be used in conjunction with FI_CLAIM in
	 *      order to retrieve and discard a message previously claimed using an
	 *      FI_PEEK + FI_CLAIM request.
	 *
	 *   Success can be measured through the following steps:
	 *     - Verification of the correct CQE data
	 *     - Verification of correct buffer contents. Again, each send should
	 *       originate from a buffer with a different value set across the
	 *       buffer
	 *     - A claim on the second message should fail as nothing should have
	 *       claimed it
	 *     - a recv without claim on the first message should fail as the claim
	 *       flag was not provided
	 *     - a peek on the first message should fail after discard
	 */

	int ret, i, j;
	struct fi_msg_tagged msg[2];
	struct iovec iov[2];
	struct fi_cq_tagged_entry s_cqe[2];
	struct fi_cq_tagged_entry d_cqe[2];
	struct fi_cq_tagged_entry *src_cqe[2] = {NULL, NULL};
	char *src_buf[2] = {source, source + len};
	char *dst_buf[2] = {target, target + len};
	struct fi_cq_tagged_entry d_peek_cqe;
	struct fi_cq_tagged_entry trash;
	enum send_state s_state = S_STATE_SEND_MSG_1;
	enum recv_state r_state = R_STATE_PEEK_CLAIM;
	int elapsed;

	/* initialize the initial data range on the source buffer to have
	 * different data values for one message than for the other
	 */
	rdm_fi_pdc_init_data_range(source, 0, len, 0xa5);
	rdm_fi_pdc_init_data_range(source, len, len, 0x5a);
	rdm_fi_pdc_init_data(target, len*2 , 0);

	/* post sends */
	for (i = 0; i < 2; i++) {
		ret = fi_tsend(ep[0], src_buf[i], len, loc_mr, gni_addr[1],
				len + i, dst_buf[i]);
		cr_assert_eq(ret, FI_SUCCESS);
	}

	/* set up messages */
	for (i = 0; i < 2; i++) {
		build_message(&msg[i], &iov[i], dst_buf[i], len, (void *) &rem_mr, gni_addr[0],
				src_buf[i], len + i, 0);
	}

	/* we are looking for two s_cqes and no d_cqe, and plan to spin for
	 *   1 second after finding the s_cqe */
	__progress_cqs(msg_cq, s_cqe, NULL, 2, 0, 1);

	/* we should be claiming the first message */
	ret = fi_trecvmsg(ep[1], &msg[0], FI_PEEK | FI_CLAIM);
	cr_assert_eq(ret, FI_SUCCESS);

	/* we are looking for a single d_cqe and no s_cqe, with no spin after */
	__progress_cqs(msg_cq, NULL, d_cqe, 0, 1, 0);

	/* ensure the dest cqe has the correct information */
	validate_cqe_with_message(d_cqe, &msg[0]);
	memset(&d_cqe[0], 0x0, sizeof(struct fi_cq_tagged_entry));

	/* now lets pull the other unclaimed message */
	ret = fi_trecvmsg(ep[1], &msg[1], 0);
	cr_assert_eq(ret, FI_SUCCESS);

	/* we are looking for a single d_cqe and no s_cqe, with no spin after */
	__progress_cqs(msg_cq, NULL, d_cqe, 0, 1, 0);

	/* ensure the dest cqe has the correct information */
	validate_cqe_with_message(d_cqe, &msg[1]);
	memset(&d_cqe[0], 0x0, sizeof(struct fi_cq_tagged_entry));

	/* pull the claimed message */
	ret = fi_trecvmsg(ep[1], &msg[0], FI_CLAIM | FI_DISCARD);
	cr_assert_eq(ret, FI_SUCCESS);

	/* map src cqes to src parameters */
	for (i = 0; i < 2; i++)
		for (j = 0; j < 2; j++)
			if (s_cqe[i].buf == src_buf[j])
				src_cqe[j] = &s_cqe[i];

	for (i = 0; i < 2; i++)
		validate_cqe_contents(src_cqe[i], src_buf[i], len, len + i, dst_buf[i]);

	cr_assert(rdm_fi_pdc_check_data_pattern(dst_buf[0], 0, len),
			"Data mismatch");
	cr_assert(rdm_fi_pdc_check_data(src_buf[1], dst_buf[1], len),
			"Data mismatch");
}

Test(rdm_fi_pdc, peek_claim_then_claim_discard)
{
	rdm_fi_pdc_xfer_for_each_size(pdc_peek_claim_then_claim_discard, 1, BUF_SZ);
}
