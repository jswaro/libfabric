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

#ifndef GNIX_HASHTABLE_H_
#define GNIX_HASHTABLE_H_

#include <stdint.h>
#include <pthread.h>

#include "fi.h"
#include "prov/gni/ccan/list.h"

#if HAVE_ATOMICS
static inline int atomic_add(atomic_t *atomic, int val)
{
	ATOMIC_IS_INITIALIZED(atomic);
	return atomic_fetch_add_explicit(&atomic->val,
			val, memory_order_acq_rel) + 1;
}

static inline int atomic_sub(atomic_t *atomic, int val)
{
	ATOMIC_IS_INITIALIZED(atomic);
	return atomic_fetch_sub_explicit(&atomic->val,
			val, memory_order_acq_rel) - 1;
}
#else
static inline int atomic_add(atomic_t *atomic, int val)
{
	int v;

	ATOMIC_IS_INITIALIZED(atomic);
	fastlock_acquire(&atomic->lock);
	atomic->val += val;
	v = atomic->val;
	fastlock_release(&atomic->lock);
	return v;
}

static inline int atomic_sub(atomic_t *atomic, int val)
{
	int v;

	ATOMIC_IS_INITIALIZED(atomic);
	fastlock_acquire(&atomic->lock);
	atomic->val += val;
	v = atomic->val;
	fastlock_release(&atomic->lock);
	return v;
}
#endif


#define __GNIX_HT_INITIAL_SIZE 128
#define __GNIX_HT_MAXIMUM_SIZE 1024
#define __GNIX_HT_INCREASE_STEP __GNIX_HT_INITIAL_SIZE

#define COLLISION_RESIZE_RATIO 20

typedef uint64_t gnix_ht_key_t;

typedef enum gnix_ht_state {
	GNIX_HT_STATE_UNINITIALIZED = 0,
	GNIX_HT_STATE_READY,
	GNIX_HT_STATE_DEAD,
} gnix_ht_state_e;

typedef struct gnix_ht_entry {
	struct list_node entry;
	gnix_ht_key_t key;
	void *value;
} gnix_ht_entry_t;

typedef struct gnix_ht_list_head {
	pthread_rwlock_t lh_lock;
	struct list_head bucket_list;
} gnix_ht_list_head_t;

typedef struct gnix_hashtable {
	pthread_rwlock_t ht_lock;
	gnix_ht_state_e ht_state;
	atomic_t ht_elements;
	atomic_t ht_collisions;
	atomic_t ht_ops;
	int ht_size;
	gnix_ht_list_head_t *ht_tbl;
} gnix_hashtable_t;

int gnix_ht_init(gnix_hashtable_t *ht);
int gnix_ht_destroy(gnix_hashtable_t *ht);

int gnix_ht_insert(gnix_hashtable_t *ht, gnix_ht_key_t key, void *entry);
int gnix_ht_remove(gnix_hashtable_t *ht, gnix_ht_key_t key);
void *gnix_ht_lookup(gnix_hashtable_t *ht, gnix_ht_key_t key);

int gnix_ht_empty(gnix_hashtable_t *ht);

#endif /* GNIX_HASHTABLE_H_ */
