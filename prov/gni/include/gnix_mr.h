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

/**
 * @brief structure for containing the fields relevant to the memory cache key
 *
 * @var   address  base address of the memory region
 * @var   address  length of the memory region
 */
typedef struct gnix_mr_cache_key {
	uint64_t address;
	uint64_t length;
} gnix_mr_cache_key_t;

/* forward declarations */
struct gnix_fid_domain;
struct gnix_nic;

/**
 * @brief gnix memory descriptor object for use with fi_mr_reg
 *
 * @var   mr_fid    libfabric memory region descriptor
 * @var   domain    gnix domain associated with this memory region
 * @var   mem_hndl  gni memory handle for the memory region
 * @var   nic       gnix nic associated with this memory region
 * @var   key       gnix memory cache key associated with this memory region
 */
struct gnix_fid_mem_desc {
	struct fid_mr mr_fid;
	struct gnix_fid_domain *domain;
	gni_mem_handle_t mem_hndl;
	struct gnix_nic *nic;
	gnix_mr_cache_key_t key;
};

/**
 * @brief gnix memory region key
 *
 * @var   pfn      prefix of the virtual address
 * @var   mdd      index for the mdd
 * @var   format   flag for determining whether new mdd format is used
 * @var   flags    set of bits for passing flags such as read-only
 * @var   padding  reserved bits, unused for now
 */
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

/**
 * @brief gnix memory registration cache attributes
 *
 * @var   soft_reg_limit       unused currently, imposes a soft limit for which
 *                             a flush can be called during register to
 *                             drain any stale registrations
 * @var   hard_reg_limit       limit to the number of memory registrations
 *                             in the cache
 * @var   hard_stale_limit     limit to the number of stale memory
 *                             registrations in the cache. If the number is
 *                             exceeded during deregistration,
 *                             gnix_mr_cache_flush will be called to flush
 *                             the stale entries.
 * @var   lazy_deregistration  if non-zero, allows registrations to linger
 *                             until the hard_stale_limit is exceeded. This
 *                             prevents unnecessary re-registration of memory
 *                             regions that may be reused frequently. Larger
 *                             values for hard_stale_limit may reduce the
 *                             frequency of flushes.
 */
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

/**
 * @brief  gnix memory registration cache object
 *
 * @var    state           state of the cache
 * @var    attr            cache attributes, @see gnix_mr_cache_attr_t
 * @var    inuse           red-black tree containing in-use memory registrations
 * @var    stale           reb-black tree containing stale memory registrations
 * @var    inuse_elements  count of in-use memory registrations
 * @var    stale_elements  count of stale memory registrations
 */
typedef struct gnix_mr_cache {
	gnix_mrc_state_e state;
	gnix_mr_cache_attr_t attr;
	RbtHandle inuse;
	RbtHandle stale;
	atomic_t inuse_elements;
	atomic_t stale_elements;
} gnix_mr_cache_t;

/**
 * Converts a libfabric key to a gni memory handle
 *
 * @param key   libfabric memory region key
 * @param mhdl  gni memory handle
 */
void gnix_convert_key_to_mhdl(
		IN    gnix_mr_key_t    *key,
		INOUT gni_mem_handle_t *mhdl);

/**
 * Converts a gni memory handle to a libfabric key
 *
 * @param mhdl  gni memory handle
 * @param key   libfabric memory region key
 */
void gnix_convert_mhdl_to_key(
		IN    gni_mem_handle_t *mhdl,
		INOUT gnix_mr_key_t    *key);

/**
 * Initializes a gnix memory registration cache
 *
 * @param cache  a gnix memory registration cache
 * @param attr   a set of attributes to apply to the cache
 *
 * @return       FI_SUCCESS on success
 *               -FI_EINVAL if an invalid cache pointer, or invalid set of
 *                 attributes has been passed into the function
 *               -FI_ENOMEM if there wasn't sufficient memory to allocate
 *                 internal data structures
 */
int gnix_mr_cache_init(
		IN gnix_mr_cache_t      *cache,
		IN gnix_mr_cache_attr_t *attr);

/**
 * Destroys a gnix memory registration cache. Flushes stale memory
 *   registrations if the hard limit for stale registrations has been exceeded
 *
 * @param cache  a gnix memory registration cache
 *
 * @return       FI_SUCCESS on success
 *               -FI_EINVAL if an invalid cache pointer has been passed into
 *                 the function
 *               -FI_EAGAIN if the cache still contains memory registrations
 *                 that have not yet been deregistered
 */
int gnix_mr_cache_destroy(
		IN gnix_mr_cache_t *cache);

/**
 * Flushes stale memory registrations from a memory registration cache.
 *
 * @param cache  a gnix memory registration cache
 *
 * @return       FI_SUCCESS on success
 *               -FI_EINVAL if an invalid cache pointer has been passed into
 *                 the function
 */
int gnix_mr_cache_flush(
		IN gnix_mr_cache_t *cache);

#endif /* GNIX_MR_H_ */
