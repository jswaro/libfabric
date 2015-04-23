/*
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <time.h>
#include <string.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "gnix_cq.h"

#ifdef assert
#undef assert
#endif

#include <criterion/criterion.h>

static struct fid_fabric *fab;
static struct fid_domain *dom;
static struct fid_cq *rcq;
static struct fi_info *hints;
static struct fi_info *fi;
static struct fi_cq_attr cq_attr;
static struct gnix_fid_cq *cq_priv;

void setup(void)
{
	int ret = 0;

	hints = fi_allocinfo();
	assert(hints, "fi_allocinfo");

	hints->domain_attr->cq_data_size = 4;
	hints->mode = ~0;

	hints->fabric_attr->name = strdup("gni");

	ret = fi_getinfo(FI_VERSION(1, 0), NULL, 0, 0, hints, &fi);
	assert(!ret, "fi_getinfo");

	ret = fi_fabric(fi->fabric_attr, &fab, NULL);
	assert(!ret, "fi_fabric");

	ret = fi_domain(fab, fi, &dom, NULL);
	assert(!ret, "fi_domain");

	cq_attr.wait_obj = FI_WAIT_NONE;
}

void teardown(void)
{
	int ret = 0;

	ret = fi_close(&dom->fid);
	assert(!ret, "failure in closing domain.");
	ret = fi_close(&fab->fid);
	assert(!ret, "failure in closing fabric.");
	fi_freeinfo(fi);
	fi_freeinfo(hints);
}

void cq_create(enum fi_cq_format format, size_t size)
{
	int ret = 0;

	cq_attr.format = format;
	cq_attr.size = size;

	ret = fi_cq_open(dom, &cq_attr, &rcq, NULL);
	assert(!ret, "fi_cq_open");

	cq_priv = container_of(rcq, struct gnix_fid_cq, cq_fid);
}

void cq_setup(void)
{
	setup();
	cq_create(FI_CQ_FORMAT_UNSPEC, 0);
}

void cq_msg_setup(void)
{
	setup();
	cq_create(FI_CQ_FORMAT_MSG, 8);
}

void cq_data_setup(void)
{
	setup();
	cq_create(FI_CQ_FORMAT_DATA, 8);
}

void cq_tagged_setup(void)
{
	setup();
	cq_create(FI_CQ_FORMAT_TAGGED, 8);
}

void cq_teardown(void)
{
	assert(!fi_close(&rcq->fid), "failure in closing cq.");
	teardown();
}

/*******************************************************************************
 * Creation Tests:
 *
 * Create the CQ with various parameters and make sure the fields are being
 * initialized correctly.
 ******************************************************************************/

TestSuite(creation, .init = setup, .fini = cq_teardown);

Test(creation, format_unspec)
{
	int ret = 0;

	cq_attr.format = FI_CQ_FORMAT_UNSPEC;

	ret = fi_cq_open(dom, &cq_attr, &rcq, NULL);
	assert(!ret, "fi_cq_open");

	cq_priv = container_of(rcq, struct gnix_fid_cq, cq_fid);
	assert(cq_priv->entry_size == sizeof(struct fi_cq_entry));
}

Test(creation, format_context)
{
	int ret = 0;

	cq_attr.format = FI_CQ_FORMAT_CONTEXT;

	ret = fi_cq_open(dom, &cq_attr, &rcq, NULL);
	assert(!ret, "fi_cq_open");

	cq_priv = container_of(rcq, struct gnix_fid_cq, cq_fid);
	assert(cq_priv->entry_size == sizeof(struct fi_cq_entry));
}

Test(creation, format_msg)
{
	int ret = 0;

	cq_attr.format = FI_CQ_FORMAT_MSG;

	ret = fi_cq_open(dom, &cq_attr, &rcq, NULL);
	assert(!ret, "fi_cq_open");

	cq_priv = container_of(rcq, struct gnix_fid_cq, cq_fid);
	assert(cq_priv->entry_size == sizeof(struct fi_cq_msg_entry));
}

Test(creation, format_data)
{
	int ret = 0;

	cq_attr.format = FI_CQ_FORMAT_DATA;

	ret = fi_cq_open(dom, &cq_attr, &rcq, NULL);
	assert(!ret, "fi_cq_open");

	cq_priv = container_of(rcq, struct gnix_fid_cq, cq_fid);
	assert(cq_priv->entry_size == sizeof(struct fi_cq_data_entry));
}

Test(creation, format_tagged)
{
	int ret = 0;

	cq_attr.format = FI_CQ_FORMAT_TAGGED;

	ret = fi_cq_open(dom, &cq_attr, &rcq, NULL);
	assert(!ret, "fi_cq_open");

	cq_priv = container_of(rcq, struct gnix_fid_cq, cq_fid);
	assert(cq_priv->entry_size == sizeof(struct fi_cq_tagged_entry));
}

TestSuite(insertion, .init = cq_setup, .fini = cq_teardown);

Test(insertion, single)
{
	int ret = 0;
	char input_ctx = 'a';
	struct fi_cq_entry entry;

	assert(!cq_priv->ev_queue.head);

	_gnix_cq_add_event(cq_priv, &input_ctx, 0, 0, 0, 0, 0);

	assert(cq_priv->ev_queue.head);
	assert_eq(cq_priv->ev_queue.head, cq_priv->ev_queue.tail);

	ret = fi_cq_read(rcq, &entry, 1);
	assert(ret == 1);
	assert(!cq_priv->ev_queue.head);

	assert_eq(*(char *) entry.op_context, input_ctx,
		  "Expected same op_context as inserted.");
}

Test(insertion, limit)
{
	int ret = 0;
	char input_ctx = 'a';
	struct fi_cq_entry entry;
	const size_t cq_size = cq_priv->attr.size;

	for (size_t i = 0; i < cq_size; i++)
		_gnix_cq_add_event(cq_priv, &input_ctx, 0, 0, 0, 0, 0);

	assert(cq_priv->ev_queue.head);
	assert(!cq_priv->ev_free.head);

	_gnix_cq_add_event(cq_priv, &input_ctx, 0, 0, 0, 0, 0);

	for (size_t i = 0; i < cq_size + 1; i++) {
		ret = fi_cq_read(rcq, &entry, 1);
		assert_eq(ret, 1);
	}

	assert(!cq_priv->ev_queue.head);
	assert(cq_priv->ev_free.head);
}

TestSuite(reading, .init = cq_setup, .fini = cq_teardown);

Test(reading, empty)
{
	int ret = 0;
	struct fi_cq_entry entry;

	ret = fi_cq_read(rcq, &entry, 1);
	assert_eq(ret, -FI_EAGAIN);
}

Test(reading, error)
{
	int ret = 0;
	struct fi_cq_entry entry;
	struct fi_cq_err_entry err_entry;

	char input_ctx = 'a';
	uint64_t flags = 0xb;
	size_t len = sizeof(input_ctx);
	void *buf = &input_ctx;
	uint64_t data = 20;
	uint64_t tag = 40;
	size_t olen = 20;
	int err = 50;
	int prov_errno = 80;

	/*
	 * By default CQ start out with no error entries and no entries
	 * in the error entry free list.
	 */
	assert(!cq_priv->err_queue.head);
	assert(!cq_priv->err_free.head);

	_gnix_cq_add_error(cq_priv, &input_ctx, flags, len, buf, data, tag,
			   olen, err, prov_errno, 0);

	assert(cq_priv->err_queue.head);

	ret = fi_cq_read(rcq, &entry, 1);
	assert_eq(ret, -FI_EAVAIL);

	assert(!cq_priv->ev_queue.head);
	assert(cq_priv->err_queue.head);

	ret = fi_cq_readerr(rcq, &err_entry, 0);
	assert_eq(ret, 1);

	/*
	 * Item should have been removed from error queue and placed on free
	 * queue.
	 */
	assert(!cq_priv->err_queue.head);
	assert(cq_priv->err_free.head);

	/*
	 * Compare structural items...
	 */
	assert_eq(*(char *) err_entry.op_context, input_ctx);
	assert_eq(err_entry.flags, flags);
	assert_eq(err_entry.len, len);
	assert_eq(err_entry.buf, buf);
	assert_eq(err_entry.data, data);
	assert_eq(err_entry.tag, tag);
	assert_eq(err_entry.olen, olen);
	assert_eq(err_entry.err, err);
	assert_eq(err_entry.prov_errno, prov_errno);
	assert_eq(err_entry.err_data, 0);
}

TestSuite(cq_msg, .init = cq_msg_setup, .fini = cq_teardown);

Test(cq_msg, single)
{
	int ret = 0;
	char input_ctx = 'a';
	struct fi_cq_msg_entry entry;

	assert(!cq_priv->ev_queue.head);

	_gnix_cq_add_event(cq_priv, &input_ctx, 2, 4, 0, 0, 0);

	assert(cq_priv->ev_queue.head);

	ret = fi_cq_read(rcq, &entry, 1);
	assert_eq(ret, 1);

	assert_eq(entry.flags, 2);
	assert_eq(*(char *) entry.op_context, input_ctx);
	assert_eq(entry.len, 4);

	assert(!cq_priv->ev_queue.head);
}

/*
 * Create up to the size events to fill it up. Check that all the properties
 * are correct, then add one more that is different. Read size items and then
 * add an error and try reading. Ensure that we get back -FI_EAVAIL. Then read
 * the last item and make sure it's the same values put in originally.
 */
Test(cq_msg, fill)
{
	struct fi_cq_msg_entry entry;
	struct fi_cq_err_entry err_entry;
	int ret = 0;
	char input_ctx = 'a';
	uint64_t flags = 2;
	size_t len = 4;
	const size_t cq_size = cq_priv->attr.size;

	assert(!cq_priv->ev_queue.head);
	assert(cq_priv->ev_free.head);

	for (size_t i = 0; i < cq_size; i++)
		_gnix_cq_add_event(cq_priv, &input_ctx, flags, len, 0, 0, 0);

	assert(cq_priv->ev_queue.head);
	assert(!cq_priv->ev_free.head);

	_gnix_cq_add_event(cq_priv, &input_ctx, flags * 2, len * 2, 0, 0, 0);

	for (size_t i = 0; i < cq_size; i++) {
		ret = fi_cq_read(rcq, &entry, 1);
		assert_eq(ret, 1);

		assert_eq(*(char *) entry.op_context, input_ctx);
		assert_eq(entry.len, len);
		assert_eq(entry.flags, flags);
	}

	/*
	 * If we insert an error it should return -FI_EAVAIL despite having
	 * something to read.
	 */
	_gnix_cq_add_error(cq_priv, &input_ctx, flags, len, 0, 0, 0, 0, 0, 0,
			   0);
	assert(cq_priv->err_queue.head);

	ret = fi_cq_read(rcq, &entry, 1);
	assert_eq(ret, -FI_EAVAIL);

	ret = fi_cq_readerr(rcq, &err_entry, 0);
	assert_eq(ret, 1);

	/*
	 * Creating an error allocs an error but it is then placed in the free
	 * list after reading.
	 */
	assert(cq_priv->err_free.head);
	assert(!cq_priv->err_queue.head);

	ret = fi_cq_read(rcq, &entry, 1);
	assert_eq(ret, 1);

	assert(cq_priv->ev_free.head);
	assert(!cq_priv->ev_queue.head);

	assert_eq(*(char *) entry.op_context, input_ctx);
	assert_eq(entry.len, (len * 2));
	assert_eq(entry.flags, (flags * 2));
}

Test(cq_msg, multi_read)
{
	int ret = 0;
	size_t count = 3;
	struct fi_cq_msg_entry entry[count];

	assert(cq_priv->ev_free.head);
	assert(!cq_priv->ev_queue.head);

	for (size_t i = 0; i < count; i++)
		_gnix_cq_add_event(cq_priv, 0, (uint64_t) i, 0, 0, 0, 0);

	assert(cq_priv->ev_queue.head);

	ret = fi_cq_read(rcq, &entry, count);
	assert_eq(ret, count);

	for (size_t j = 0; j < count; j++)
		assert_eq(entry[j].flags, (uint64_t) j);
}
