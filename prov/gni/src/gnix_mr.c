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

//
// memory registration common code
//
#include <stdlib.h>
#include <string.h>

#include "gnix.h"
#include "gnix_util.h"
#include "gnix_mr.h"
#include "gnix_priv.h"

#define PAGE_SHIFT 12

static int fi_gnix_mr_close(fid_t fid);

static struct fi_ops fi_gnix_mr_ops = {
	.size = sizeof(struct fi_ops),
	.close = fi_gnix_mr_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static inline int64_t __sign_extend(uint64_t val, int len)
{
	int64_t m = 1UL << (len - 1);
	int64_t r = (val ^ m) - m;

	return r;
}

<<<<<<< HEAD
void gnix_convert_key_to_mhdl(
		IN    gnix_mr_key_t *key,
		INOUT gni_mem_handle_t *mhdl)
{
	uint64_t va = (uint64_t) __sign_extend(key->pfn << PAGE_SHIFT,
			GNIX_MR_VA_BITS);
	uint8_t flags = 0;

	if (key->flags & GNIX_MR_FLAG_READONLY)
		flags |= GNI_MEMHNDL_ATTR_READONLY;

	GNI_MEMHNDL_INIT((*mhdl));
	if (key->format)
		GNI_MEMHNDL_SET_FLAGS((*mhdl), GNI_MEMHNDL_FLAG_NEW_FRMT);
	GNI_MEMHNDL_SET_VA((*mhdl), va);
	GNI_MEMHNDL_SET_MDH((*mhdl), key->mdd);
	GNI_MEMHNDL_SET_NPAGES((*mhdl), GNI_MEMHNDL_NPGS_MASK);
	GNI_MEMHNDL_SET_FLAGS((*mhdl), flags);
	GNI_MEMHNDL_SET_PAGESIZE((*mhdl), PAGE_SHIFT);
	GNI_MEMHNDL_SET_CRC((*mhdl));
}

void gnix_convert_mhdl_to_key(
		IN    gni_mem_handle_t *mhdl,
		INOUT gnix_mr_key_t *key)
{
	key->pfn = GNI_MEMHNDL_GET_VA((*mhdl)) >> PAGE_SHIFT;
	key->mdd = GNI_MEMHNDL_GET_MDH((*mhdl));
	key->format = GNI_MEMHNDL_NEW_FRMT((*mhdl));
	key->flags = 0;

	if (GNI_MEMHNDL_GET_FLAGS((*mhdl)) & GNI_MEMHNDL_FLAG_READONLY)
		key->flags |= GNIX_MR_FLAG_READONLY;
}

int gnix_mr_reg(struct fid *fid, const void *buf, size_t len,
		uint64_t access, uint64_t offset, uint64_t requested_key,
		uint64_t flags, struct fid_mr **mr_o, void *context)
{
	struct gnix_fid_mem_desc *mr;
	int fi_gnix_access = 0;
	struct gnix_fid_domain *domain;
	struct gnix_nic *nic;
	gni_return_t grc = GNI_RC_INVALID_PARAM;
	int rc;

	if (flags)
		return -FI_EBADFLAGS;

	/* The offset parameter is reserved for future use and must be 0. */
	if (offset || !buf || !mr_o || !access ||
			(access & ~(FI_READ | FI_WRITE | FI_RECV | FI_SEND |
						FI_REMOTE_READ |
						FI_REMOTE_WRITE)) ||
			(fid->fclass != FI_CLASS_DOMAIN))

		return -FI_EINVAL;

	/* requested key is not permitted at this point */
	if (requested_key)
		return -FI_EKEYREJECTED;

	if (fid->fclass != FI_CLASS_DOMAIN)
		return -FI_EINVAL;

	domain = container_of(fid, struct gnix_fid_domain, domain_fid.fid);

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return -FI_ENOMEM;

	/* If network would be able to write to this buffer, use read-write */
	if (access & (FI_RECV | FI_READ | FI_REMOTE_WRITE))
		fi_gnix_access |= GNI_MEM_READWRITE;
	else
		fi_gnix_access |= GNI_MEM_READ_ONLY;

	/* If the nic list is empty, create a nic */
	if (list_empty(&domain->nic_list)) {
		rc = gnix_nic_alloc(domain, &nic);
		if (rc) {
			GNIX_WARN(FI_LOG_MR, "could not allocate nic to do mr_reg,"
					" ret=%i", rc);

			return rc;
		}
	}

	list_for_each(&domain->nic_list, nic, list)
	{
		grc = GNI_MemRegister(nic->gni_nic_hndl, (uintptr_t) buf, len,
					NULL, fi_gnix_access,
					-1, &mr->mem_hndl);
		if (grc == GNI_RC_SUCCESS)
			break;
	}

	if (grc != GNI_RC_SUCCESS)
		goto err;

	/* md.domain */
	mr->domain = domain;
	atomic_inc(&domain->ref_cnt); /* take reference on domain */

	/* md.mr_fid */
	mr->mr_fid.fid.fclass = FI_CLASS_MR;
	mr->mr_fid.fid.context = context;
	mr->mr_fid.fid.ops = &fi_gnix_mr_ops;

	/* nic */
	mr->nic = nic;
	atomic_inc(&nic->ref_cnt); /* take reference on nic */

	/* setup internal key structure */
	gnix_convert_mhdl_to_key(&mr->mem_hndl,
			(gnix_mr_key_t *) &mr->mr_fid.key);

	*mr_o = &mr->mr_fid;


	return FI_SUCCESS;

err:
	free(mr);
	GNIX_INFO(FI_LOG_MR, "failed to register memory with uGNI, ret=%s",
			gni_err_str[grc]);
	return -gnixu_to_fi_errno(grc);
}

static int fi_gnix_mr_close(fid_t fid)
{
	struct gnix_fid_mem_desc *mr;
	gni_return_t ret;

	if (fid->fclass != FI_CLASS_MR)
		return -FI_EINVAL;

	mr = container_of(fid, struct gnix_fid_mem_desc, mr_fid.fid);

	ret = GNI_MemDeregister(mr->nic->gni_nic_hndl, &mr->mem_hndl);
	if (ret == GNI_RC_SUCCESS) {
		atomic_dec(&mr->domain->ref_cnt);
		atomic_dec(&mr->nic->ref_cnt);

		/* Change the fid class to prevent user from calling into
		 *   close again on a dead atomic.
		 */
		mr->mr_fid.fid.fclass = FI_CLASS_UNSPEC;

		free(mr);
	} else {
		GNIX_WARN(FI_LOG_MR, "failed to deregister memory"
				" region, mr=%p ret=%i", mr, ret);
	}

	return gnixu_to_fi_errno(ret);
}


