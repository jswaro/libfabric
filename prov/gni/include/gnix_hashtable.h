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

enum gnix_ht_increase {
	GNIX_HT_INCREASE_ADD = 0,
	GNIX_HT_INCREASE_MULT
};

/**
 * Set of attributes that can be passed to the gnix_ht_init.
 *
 * @var ht_initial_size      initial number of buckets allocated
 * @var ht_maximum_size      maximum number of buckets to allocate on resize
 * @var ht_increase_step     additive or multiplicative factor to increase by.
 *                           If additive, the new_size = (old_size + increase)
 *                           If multiplicative, the new size = (old_size *
 *                           increase)
 * @var ht_increase_type     based on the gnix_ht_increase enum, this
 *                           influences whether the increase of the bucket
 *                           count is additive or multiplicative
 * @var ht_collision_thresh  threshold for resizing based on insertion
 *                           collisions. The threshold is based on the
 *                           average number of collisions per insertion,
 *                           multiplied by 100. If you want an average bucket
 *                           depth of 4, you would want to see 3-4 collisions
 *                           on average, so the appropriate threshold would be
 *                           ~400.
 * @var ht_hash_seed		 seed value that affects how items are hashed
 *                           internally. Using the same seed value and the same
 *                           insertion pattern will allow for repeatable
 *                           results.
 */
typedef struct gnix_hashtable_attr {
	int ht_initial_size;
	int ht_maximum_size;
	int ht_increase_step;
	int ht_increase_type;
	int ht_collision_thresh;
	uint64_t ht_hash_seed;
} gnix_hashtable_attr_t;

/**
 * Hashtable structure
 *
 * @var ht_lock        reader/writer lock for protecting internal structures
 *                     during a resize
 * @var ht_state       internal state mechanism for detecting valid state
 *                     transitions
 * @var ht_attr        attributes for the hash map to follow after init
 * @var ht_elements    number of items in the hash map
 * @var ht_collisions  number of insertion collisions since the last resize
 * @var ht_ops         number of insertions since the last resize
 * @var ht_size        number of hash buckets
 * @var ht_tbl         array of hash buckets
 */
typedef struct gnix_hashtable {
	pthread_rwlock_t ht_lock;
	gnix_ht_state_e ht_state;
	gnix_hashtable_attr_t ht_attr;
	atomic_t ht_elements;
	atomic_t ht_collisions;
	atomic_t ht_ops;
	int ht_size;
	gnix_ht_list_head_t *ht_tbl;
} gnix_hashtable_t;

/**
 * Initializes the hash table with provided attributes, if any
 *
 * @param ht      pointer to the hash table structure
 * @param attr    pointer to the hash table attributes to initialize with
 * @return        0 on success, -EINVAL on initialization error, or -ENOMEM
 *                if allocation of the bucket array fails
 */
int gnix_ht_init(gnix_hashtable_t *ht, gnix_hashtable_attr_t *attr);

/**
 * Destroys the hash table
 *
 * @param ht      pointer to the hash table structure
 * @return        0 on success, -EINVAL upon passing an uninitialized or dead
 *                structure
 */
int gnix_ht_destroy(gnix_hashtable_t *ht);

/**
 * Inserts an entry into the map with the provided key
 *
 * @param ht      pointer to the hash table structure
 * @param key     key used to hash the entry
 * @param entry   entry to be stored
 * @return        0 on success, -ENOSPC when another entry with the same key
 *                exists in the hashtable, or -EINVAL when called on a dead or
 *                uninitialized hash table
 */
int gnix_ht_insert(gnix_hashtable_t *ht, gnix_ht_key_t key, void *entry);

/**
 * Removes an entry from the map with the provided key
 *
 * @param ht      pointer to the hash table structure
 * @param key     key used to hash the entry
 * @return        0 on success, -ENOENT when the key doesn't exist in the hash
 *                table, or -EINVAL when called on a dead or uninitialized hash
 *                table
 */
int gnix_ht_remove(gnix_hashtable_t *ht, gnix_ht_key_t key);

/**
 * Looks up an entry in the hash table using key
 *
 * @param ht      pointer to the hash table structure
 * @param key     key used to hash the entry
 * @return        NULL if the key did not exist in the hash table, or the
 *                entry if the key exists in the hash table
 */
void *gnix_ht_lookup(gnix_hashtable_t *ht, gnix_ht_key_t key);

/**
 * Tests to see if the hash table is empty
 *
 * @param ht      pointer to the hash table structure
 * @return        true if the hash table is empty, false if not
 */
int gnix_ht_empty(gnix_hashtable_t *ht);

#endif /* GNIX_HASHTABLE_H_ */
