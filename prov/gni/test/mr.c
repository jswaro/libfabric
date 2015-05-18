/*
 * Copyright (c) 2015 Cray Inc. All rights reserved.
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
#include "gnix.h"

#ifdef assert
#undef assert
#endif

#include <criterion/criterion.h>

static struct fid_fabric *fab;
static struct fid_domain *dom;
static struct fid_ep *ep;
static struct fid_mr *mr;
static struct fi_info *hints;
static struct fi_info *fi;
static struct fi_cq_attr cq_attr;

#define __BUF_LEN 4096
static unsigned char *buf;
static int buf_len = __BUF_LEN * sizeof(unsigned char);
static struct gnix_fid_domain *domain;
static gnix_mr_cache_t *cache;
static int regions;

uint64_t default_access = (FI_REMOTE_READ | FI_REMOTE_WRITE
		| FI_READ | FI_WRITE);

uint64_t default_flags = 0;
uint64_t default_req_key = 0;
uint64_t default_offset = 0;

static void mr_setup(void)
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

	ret = fi_endpoint(dom, fi, &ep, NULL);
	assert(!ret, "fi_endpoint");

	cq_attr.wait_obj = FI_WAIT_NONE;

	buf = calloc(__BUF_LEN, sizeof(unsigned char));
	assert(buf, "buffer allocation");

	domain = container_of(dom, struct gnix_fid_domain, domain_fid.fid);
	cache = &domain->mr_cache;
	regions = 1024;
}

static void mr_teardown(void)
{
	int ret = 0;

	ret = fi_close(&ep->fid);
	assert(!ret, "failure in closing ep.");
	ret = fi_close(&dom->fid);
	assert(!ret, "failure in closing domain.");
	ret = fi_close(&fab->fid);
	assert(!ret, "failure in closing fabric.");
	fi_freeinfo(fi);
	fi_freeinfo(hints);

	domain = NULL;
	cache = NULL;

	free(buf);
}

TestSuite(memory_registration_bare, .init = mr_setup, .fini = mr_teardown);

TestSuite(memory_registration_cache, .init = mr_setup, .fini = mr_teardown);

/* Test simple init, register and deregister */
Test(memory_registration_bare, basic_init)
{
	int ret;

	ret = fi_mr_reg(dom, (void *) buf, buf_len, default_access,
			default_offset, default_req_key,
			default_flags, &mr, NULL);
	assert(ret == FI_SUCCESS);

	ret = fi_close(&mr->fid);
	assert(ret == FI_SUCCESS);
}

/* Test invalid flags to fi_mr_reg */
Test(memory_registration_bare, invalid_flags)
{
	int ret;

	ret = fi_mr_reg(dom, (void *) buf, buf_len, default_access,
			default_offset, default_req_key,
			~0, &mr, NULL);
	assert(ret == -FI_EBADFLAGS);
}

/* Test invalid access param to fi_mr_reg */
Test(memory_registration_bare, invalid_access)
{
	int ret;

	ret = fi_mr_reg(dom, (void *) buf, buf_len, 0,
			default_offset, default_req_key,
			default_flags, &mr, NULL);
	assert(ret == -FI_EINVAL);
}

/* Test invalid offset param to fi_mr_reg */
Test(memory_registration_bare, invalid_offset)
{
	int ret;

	ret = fi_mr_reg(dom, (void *) buf, buf_len, default_access,
			~0, default_req_key, default_flags,
			&mr, NULL);
	assert(ret == -FI_EINVAL);
}

/* Test invalid requested key param to fi_mr_reg */
Test(memory_registration_bare, invalid_requested_key)
{
	int ret;

	ret = fi_mr_reg(dom, (void *) buf, buf_len, default_access,
			default_offset, ~0, default_flags,
			&mr, NULL);
	assert(ret == -FI_EKEYREJECTED);
}

/* Test invalid buf param to fi_mr_reg */
Test(memory_registration_bare, invalid_buf)
{
	int ret;

	ret = fi_mr_reg(dom, NULL, buf_len, default_access,
			default_offset, default_req_key, default_flags,
			&mr, NULL);
	assert(ret == -FI_EINVAL);
}

/* Test invalid mr_o param to fi_mr_reg */
Test(memory_registration_bare, invalid_mr_ptr)
{
	int ret;

	ret = fi_mr_reg(dom, (void *) buf, buf_len, default_access,
			default_offset, default_req_key, default_flags,
			NULL, NULL);
	assert(ret == -FI_EINVAL);
}

/* Test invalid fid param to fi_mr_reg */
Test(memory_registration_bare, invalid_fid_class)
{
	int ret;
	size_t old_class = dom->fid.fclass;

	dom->fid.fclass = FI_CLASS_UNSPEC;

	ret = fi_mr_reg(dom, (void *) buf, buf_len, default_access,
			default_offset, default_req_key, default_flags,
			&mr, NULL);
	assert(ret == -FI_EINVAL);

	/* restore old fclass for teardown */
	dom->fid.fclass = old_class;
}

/* Test simple cache initialization */
Test(memory_registration_cache, basic_init)
{
	int ret;

	assert(cache->state == GNIX_MRC_STATE_READY);

	ret = fi_mr_reg(dom, (void *) buf, buf_len, default_access,
			default_offset, default_req_key,
			default_flags, &mr, NULL);
	assert(ret == FI_SUCCESS);

	assert(atomic_get(&cache->inuse_elements) == 1);
	assert(atomic_get(&cache->stale_elements) == 0);

	ret = fi_close(&mr->fid);
	assert(ret == FI_SUCCESS);

	assert(atomic_get(&cache->inuse_elements) == 0);
	assert(atomic_get(&cache->stale_elements) == 1);
}

/* Test duplicate registration. Since this is a valid operation, we
 *   provide a unique fid_mr but internally, a second reference to the same
 *   entry is provided to prevent expensive calls to GNI_MemRegister
 */
Test(memory_registration_cache, duplicate_registration)
{
	int ret;
	struct fid_mr *f_mr;


	assert(cache->state == GNIX_MRC_STATE_READY);

	ret = fi_mr_reg(dom, (void *) buf, buf_len, default_access,
			default_offset, default_req_key,
			default_flags, &mr, NULL);
	assert(ret == FI_SUCCESS);

	assert(atomic_get(&cache->inuse_elements) == 1);
	assert(atomic_get(&cache->stale_elements) == 0);

	ret = fi_mr_reg(dom, (void *) buf, buf_len, default_access,
			default_offset, default_req_key,
			default_flags, &f_mr, NULL);
	assert(ret == FI_SUCCESS);

	assert(atomic_get(&cache->inuse_elements) == 1);
	assert(atomic_get(&cache->stale_elements) == 0);

	ret = fi_close(&mr->fid);
	assert(ret == FI_SUCCESS);

	ret = fi_close(&f_mr->fid);
	assert(ret == FI_SUCCESS);

	assert(atomic_get(&cache->inuse_elements) == 0);
	assert(atomic_get(&cache->stale_elements) == 1);
}

/* Test registration of 1024 elements, all distinct. Cache element counts
 *   should meet expected values
 */
Test(memory_registration_cache, register_1024_distinct_regions)
{
	int ret;
	uint64_t **buffers;
	struct fid_mr **mr_arr;
	int i;

	mr_arr = calloc(regions, sizeof(struct fid_mr *));
	assert(mr_arr);

	buffers = calloc(regions, sizeof(uint64_t *));
	assert(buffers, "failed to allocate array of buffers");

	for (i = 0; i < regions; ++i) {
		buffers[i] = calloc(__BUF_LEN, sizeof(uint64_t));
		assert(buffers[i]);
	}

	for (i = 0; i < regions; ++i) {
		ret = fi_mr_reg(dom, (void *) buffers[i], __BUF_LEN, default_access,
				default_offset, default_req_key,
				default_flags, &mr_arr[i], NULL);
		assert(ret == FI_SUCCESS);
	}

	assert(atomic_get(&cache->inuse_elements) == regions);
	assert(atomic_get(&cache->stale_elements) == 0);

	for (i = 0; i < regions; ++i) {
		ret = fi_close(&mr_arr[i]->fid);
		assert(ret == FI_SUCCESS);
	}

	for (i = 0; i < regions; ++i) {
		free(buffers[i]);
		buffers[i] = NULL;
	}

	free(buffers);
	buffers = NULL;

	free(mr_arr);
	mr_arr = NULL;

	assert(atomic_get(&cache->inuse_elements) == 0);
	assert(atomic_get(&cache->stale_elements) >= 0);
}

/* Test registration of 1024 registrations backed by the same initial
 *   registration. There should only be a single registration in the cache
 */
Test(memory_registration_cache, register_1024_non_unique_regions)
{
	int ret;
	char *hugepage;
	struct fid_mr *hugepage_mr;
	char **buffers;
	struct fid_mr **mr_arr;
	int i;

	mr_arr = calloc(regions, sizeof(struct fid_mr *));
	assert(mr_arr);

	buffers = calloc(regions, sizeof(uint64_t *));
	assert(buffers, "failed to allocate array of buffers");

	hugepage = calloc(regions * regions, sizeof(char));
	assert(hugepage);

	for (i = 0; i < regions; ++i) {
		buffers[i] = &hugepage[i * regions];
		assert(buffers[i]);
	}

	ret = fi_mr_reg(dom, (void *) hugepage, regions * regions * sizeof(char),
			default_access, default_offset, default_req_key,
			default_flags, &hugepage_mr, NULL);
	assert(ret == FI_SUCCESS);

	for (i = 0; i < regions; ++i) {
		ret = fi_mr_reg(dom, (void *) buffers[i], regions, default_access,
				default_offset, default_req_key,
				default_flags, &mr_arr[i], NULL);
		assert(ret == FI_SUCCESS);
	}

	assert(atomic_get(&cache->inuse_elements) == 1);
	assert(atomic_get(&cache->stale_elements) == 0);

	for (i = 0; i < regions; ++i) {
		ret = fi_close(&mr_arr[i]->fid);
		assert(ret == FI_SUCCESS);
	}

	ret = fi_close(&hugepage_mr->fid);
	assert(ret == FI_SUCCESS);

	free(buffers);
	buffers = NULL;

	free(mr_arr);
	mr_arr = NULL;

	assert(atomic_get(&cache->inuse_elements) == 0);
	assert(atomic_get(&cache->stale_elements) > 0);
}

/* Test registration of 128 regions that will be cycled in and out of the
 *   inuse and stale trees. inuse + stale should never exceed 128
 */
Test(memory_registration_cache, cyclic_register_128_distinct_regions)
{
	int ret;
	char **buffers;
	struct fid_mr **mr_arr;
	int i;
	int buf_size = __BUF_LEN * sizeof(char);

	regions = 128;
	mr_arr = calloc(regions, sizeof(struct fid_mr *));
	assert(mr_arr);

	buffers = calloc(regions, sizeof(char *));
	assert(buffers, "failed to allocate array of buffers");

	for (i = 0; i < regions; ++i) {
		buffers[i] = calloc(__BUF_LEN, sizeof(char));
		assert(buffers[i]);
	}

	/* create the initial memory registrations */
	for (i = 0; i < regions; ++i) {
		ret = fi_mr_reg(dom, (void *) buffers[i], buf_size, default_access,
				default_offset, default_req_key,
				default_flags, &mr_arr[i], NULL);
		assert(ret == FI_SUCCESS);
	}

	/* all registrations should now be 'in-use' */
	assert(atomic_get(&cache->inuse_elements) == regions);
	assert(atomic_get(&cache->stale_elements) == 0);

	for (i = 0; i < regions; ++i) {
		ret = fi_close(&mr_arr[i]->fid);
		assert(ret == FI_SUCCESS);
	}

	/* all registrations should now be 'stale' */
	assert(atomic_get(&cache->inuse_elements) == 0);
	assert(atomic_get(&cache->stale_elements) >= 0);

	for (i = 0; i < regions; ++i) {
		ret = fi_mr_reg(dom, (void *) buffers[i], buf_size, default_access,
				default_offset, default_req_key,
				default_flags, &mr_arr[i], NULL);
		assert(ret == FI_SUCCESS);
	}

	/* all registrations should have been moved from 'stale' to 'in-use' */
	assert(atomic_get(&cache->inuse_elements) == regions);
	assert(atomic_get(&cache->stale_elements) == 0);

	for (i = 0; i < regions; ++i) {
		ret = fi_close(&mr_arr[i]->fid);
		assert(ret == FI_SUCCESS);
	}

	/* all registrations should now be 'stale' */
	assert(atomic_get(&cache->inuse_elements) == 0);
	assert(atomic_get(&cache->stale_elements) >= 0);

	for (i = 0; i < regions; ++i) {
		free(buffers[i]);
		buffers[i] = NULL;
	}

	free(buffers);
	buffers = NULL;

	free(mr_arr);
	mr_arr = NULL;
}
