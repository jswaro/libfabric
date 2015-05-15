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

#ifndef GNIX_MR_H_
#define GNIX_MR_H_

#include "rdma/fi_domain.h"
#include "gnix_util.h"
#include "ccan/list.h"
#include "common/rbtree.h"

#define GNIX_MR_PAGE_SHIFT 12
#define GNIX_MR_PFN_BITS 37
#define GNIX_MR_MDD_BITS 12
#define GNIX_MR_FMT_BITS 1
#define GNIX_MR_FLAG_BITS 1
#define GNIX_MR_VA_BITS (GNIX_MR_PFN_BITS + GNIX_MR_PAGE_SHIFT)
#define GNIX_MR_KEY_BITS (GNIX_MR_PFN_BITS + GNIX_MR_MDD_BITS)
#define GNIX_MR_RESERVED_BITS \
	(GNIX_MR_KEY_BITS + GNIX_MR_FLAG_BITS + GNIX_MR_FMT_BITS)
#define GNIX_MR_PADDING_LENGTH (64 - GNIX_MR_RESERVED_BITS)

enum {
	GNIX_MR_FLAG_READONLY = 1 << 0
};

typedef struct gnix_mr_cache_key {
	uint64_t address;
	uint64_t length;
} gnix_mr_cache_key_t;

struct gnix_fid_domain;
struct gnix_nic;
struct gnix_fid_mem_desc {
	struct fid_mr mr_fid;
	struct gnix_fid_domain *domain;
	gni_mem_handle_t mem_hndl;
	struct gnix_nic *nic;
	gnix_mr_cache_key_t key;
};

typedef struct gnix_mr_key {
	union {
		struct {
			struct {
				uint64_t pfn: GNIX_MR_PFN_BITS;
				uint64_t mdd: GNIX_MR_MDD_BITS;
			};
			uint64_t format : GNIX_MR_FMT_BITS;
			uint64_t flags : GNIX_MR_FLAG_BITS;
			uint64_t padding: GNIX_MR_PADDING_LENGTH;
		};
		uint64_t value;
	};
} gnix_mr_key_t;

typedef struct gnix_mr_cache_attr {
	int soft_reg_limit;
	int hard_reg_limit;
	int hard_stale_limit;
	int lazy_deregistration;
} gnix_mr_cache_attr_t;

typedef enum {
	GNIX_MRC_STATE_UNINITIALIZED = 0,
	GNIX_MRC_STATE_READY,
	GNIX_MRC_STATE_DEAD,
} gnix_mrc_state_e;

typedef struct gnix_mr_cache {
	gnix_mrc_state_e state;
	gnix_mr_cache_attr_t attr;
	RbtHandle inuse;
	RbtHandle stale;
	atomic_t inuse_elements;
	atomic_t stale_elements;
} gnix_mr_cache_t;

void gnix_convert_key_to_mhdl(
		IN    gnix_mr_key_t    *key,
		INOUT gni_mem_handle_t *mhdl);

void gnix_convert_mhdl_to_key(
		IN    gni_mem_handle_t *mhdl,
		INOUT gnix_mr_key_t    *key);

int gnix_mr_cache_init(
		IN gnix_mr_cache_t      *cache,
		IN gnix_mr_cache_attr_t *attr);

int gnix_mr_cache_destroy(
		IN gnix_mr_cache_t *cache);

int gnix_mr_cache_flush(
		IN gnix_mr_cache_t *cache);

#endif /* GNIX_MR_H_ */
