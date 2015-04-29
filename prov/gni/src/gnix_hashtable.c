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

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#include <gnix_hashtable.h>
#include <prov/gni/fasthash/fasthash.h>

static inline void __gnix_ht_delete_entry(gnix_ht_entry_t *ht_entry)
{
	list_del(&ht_entry->entry);

	ht_entry->value = NULL;
	ht_entry->key = 0;
	free(ht_entry);
}

static inline void __gnix_ht_init_list_head(gnix_ht_list_head_t *lh)
{
	list_head_init(&lh->bucket_list);
	pthread_rwlock_init(&lh->lh_lock, NULL);
}

static inline gnix_ht_key_t gnix_hash_func(
		gnix_hashtable_t *ht,
		gnix_ht_key_t key)
{
	return fasthash64(&key, sizeof(gnix_ht_key_t), 0) % ht->ht_size;
}

static inline gnix_ht_entry_t *__gnix_ht_lookup_key(
		gnix_ht_list_head_t *lh,
		gnix_ht_key_t key,
		uint64_t *collision_count)
{
	gnix_ht_entry_t *ht_entry;


	if (list_empty(&lh->bucket_list))
		return NULL;


	list_for_each(&lh->bucket_list, ht_entry, entry) {
		if (ht_entry->key == key)
			return ht_entry;

		if (collision_count)
			*collision_count += 1;
	}

	return NULL;
}

static inline void *gnix_ht_lookup_key(
		gnix_ht_list_head_t *lh,
		gnix_ht_key_t key)
{
	gnix_ht_entry_t *ht_entry = NULL;

	pthread_rwlock_rdlock(&lh->lh_lock);
	ht_entry = __gnix_ht_lookup_key(lh, key, NULL);
	pthread_rwlock_unlock(&lh->lh_lock);

	if (!ht_entry)
		return NULL;

	return ht_entry->value;
}

static inline void __gnix_ht_destroy_list(
		gnix_hashtable_t *ht,
		gnix_ht_list_head_t *lh)
{
	gnix_ht_entry_t *ht_entry, *iter;
	int entries_freed = 0;

	list_for_each_safe(&lh->bucket_list, ht_entry, iter, entry) {
		__gnix_ht_delete_entry(ht_entry);

		++entries_freed;
	}

	atomic_sub(&ht->ht_elements, entries_freed);
}

static inline int __gnix_ht_insert_list(
		gnix_ht_list_head_t *lh,
		gnix_ht_entry_t *ht_entry,
		uint64_t *collisions)
{
	gnix_ht_entry_t *found;

	found = __gnix_ht_lookup_key(lh, ht_entry->key, collisions);
	if (!found) {
		list_add_tail(&lh->bucket_list, &ht_entry->entry);
	} else {
		return -ENOSPC;
	}

	return 0;
}

static inline int __gnix_ht_insert_list_locked(
		gnix_ht_list_head_t *lh,
		gnix_ht_entry_t *ht_entry,
		uint64_t *collisions)
{
	int ret;

	pthread_rwlock_wrlock(&lh->lh_lock);
	ret = __gnix_ht_insert_list(lh, ht_entry, collisions);
	pthread_rwlock_unlock(&lh->lh_lock);

	return ret;
}

static inline int __gnix_ht_remove_list(
		gnix_ht_list_head_t *lh,
		gnix_ht_key_t key)
{
	gnix_ht_entry_t *ht_entry;

	pthread_rwlock_wrlock(&lh->lh_lock);

	ht_entry = __gnix_ht_lookup_key(lh, key, NULL);
	if (!ht_entry) {
		pthread_rwlock_unlock(&lh->lh_lock);
		return -ENOENT;
	}
	__gnix_ht_delete_entry(ht_entry);

	pthread_rwlock_unlock(&lh->lh_lock);

	return 0;
}

static inline void __gnix_ht_rehash_list(
		gnix_hashtable_t *ht,
		gnix_ht_list_head_t *list)
{
	gnix_ht_entry_t *ht_entry, *tmp;
	gnix_ht_key_t bucket;
	int ret;

	if (list_empty(&list->bucket_list))
		return;

	list_for_each_safe(&list->bucket_list, ht_entry, tmp, entry) {
		bucket = gnix_hash_func(ht, ht_entry->key);

		list_del(&ht_entry->entry);

		ret = __gnix_ht_insert_list(&ht->ht_tbl[bucket],
				ht_entry, NULL);
	}
}

static inline void __gnix_ht_rehash_table(
		gnix_hashtable_t *ht,
		gnix_ht_list_head_t *ht_tbl,
		int old_length)
{
	int i;

	for (i = 0; i < old_length; ++i) {
		__gnix_ht_rehash_list(ht, &ht_tbl[i]);
	}
}

static inline void __gnix_ht_resize_hashtable(gnix_hashtable_t *ht)
{
	int old_size = ht->ht_size;
	int new_size = ht->ht_size + __GNIX_HT_INCREASE_STEP;
	int i;
	gnix_ht_list_head_t *new_table = NULL, *old_table = NULL;


	/* race to resize... let one of them resize the hash table and the rest
	 * can just release after the first is done.
	 */
	pthread_rwlock_wrlock(&ht->ht_lock);
	if (ht->ht_size != old_size) {
		pthread_rwlock_unlock(&ht->ht_lock);
		return;
	}

	new_table = calloc(new_size, sizeof(gnix_ht_list_head_t));
	if (!new_table) {
		pthread_rwlock_unlock(&ht->ht_lock);
		return;
	}

	fprintf(stderr, "resizing table from %i to %i\n", old_size, new_size);

	for (i = 0; i < new_size; ++i) {
		__gnix_ht_init_list_head(&new_table[i]);
	}

	old_table = ht->ht_tbl;
	ht->ht_tbl = new_table;
	ht->ht_size = new_size;

	__gnix_ht_rehash_table(ht, old_table, old_size);

	pthread_rwlock_unlock(&ht->ht_lock);
}

int gnix_ht_init(gnix_hashtable_t *ht)
{
	int i;

	if (ht->ht_state == GNIX_HT_STATE_READY)
		return -EINVAL;

	if (ht->ht_state != GNIX_HT_STATE_DEAD)
		pthread_rwlock_init(&ht->ht_lock, NULL);

	pthread_rwlock_wrlock(&ht->ht_lock);

	ht->ht_size = __GNIX_HT_INITIAL_SIZE;
	ht->ht_tbl = calloc(ht->ht_size, sizeof(gnix_ht_list_head_t));
	if (!ht->ht_tbl) {
		pthread_rwlock_unlock(&ht->ht_lock);
		ht->ht_size = 0;
		return -ENOMEM;
	}

	for (i = 0; i < ht->ht_size; ++i)
		__gnix_ht_init_list_head(&ht->ht_tbl[i]);

	if (ht->ht_state == GNIX_HT_STATE_UNINITIALIZED) {
		atomic_initialize(&ht->ht_elements, 0);
		atomic_initialize(&ht->ht_collisions, 0);
		atomic_initialize(&ht->ht_ops, 0);
	} else {
		atomic_set(&ht->ht_elements, 0);
		atomic_set(&ht->ht_collisions, 0);
		atomic_set(&ht->ht_ops, 0);
	}

	ht->ht_state = GNIX_HT_STATE_READY;

	pthread_rwlock_unlock(&ht->ht_lock);
	return 0;
}

int gnix_ht_destroy(gnix_hashtable_t *ht)
{
	int i;

	if (ht->ht_state != GNIX_HT_STATE_READY)
		return -EINVAL;

	pthread_rwlock_wrlock(&ht->ht_lock);

	for (i = 0; i < ht->ht_size; ++i) {
		__gnix_ht_destroy_list(ht, &ht->ht_tbl[i]);
	}

	free(ht->ht_tbl);
	ht->ht_tbl = NULL;

	fprintf(stderr, "table size at destruction, size=%i\n", ht->ht_size);
	fprintf(stderr, "collisions=%i ops=%i\n", atomic_get(&ht->ht_collisions),
			atomic_get(&ht->ht_ops));

	ht->ht_size = 0;
	atomic_set(&ht->ht_collisions, 0);
	atomic_set(&ht->ht_ops, 0);
	atomic_set(&ht->ht_elements, 0);
	ht->ht_state = GNIX_HT_STATE_DEAD;

	pthread_rwlock_unlock(&ht->ht_lock);

	return 0;
}

int gnix_ht_insert(gnix_hashtable_t *ht, gnix_ht_key_t key, void *entry)
{
	int bucket;
	int ret;
	int collisions, ops;
	uint64_t hits = 0;

	gnix_ht_entry_t *list_entry;

	if (ht->ht_state != GNIX_HT_STATE_READY)
		return -EINVAL;

	list_entry = calloc(1, sizeof(gnix_ht_entry_t));
	if (!list_entry)
		return -ENOMEM;

	list_entry->value = entry;
	list_entry->key = key;

	pthread_rwlock_rdlock(&ht->ht_lock);
	bucket = gnix_hash_func(ht, key);
	ret = __gnix_ht_insert_list_locked(&ht->ht_tbl[bucket],
			list_entry, &hits);
	pthread_rwlock_unlock(&ht->ht_lock);

	if (ht->ht_size < __GNIX_HT_MAXIMUM_SIZE) {
		collisions = atomic_add(&ht->ht_collisions, hits);
		ops = atomic_inc(&ht->ht_ops);
		if (ops > 10 &&
				((collisions * 100) / ops)
				> COLLISION_RESIZE_RATIO) {

			fprintf(stderr, "collisions=%i ops=%i elements=%i\n",
					collisions, ops, atomic_get(&ht->ht_elements));
			atomic_set(&ht->ht_collisions, 0);
			atomic_set(&ht->ht_ops, 0);

			__gnix_ht_resize_hashtable(ht);
		}
	}

	if (ret == 0)
		atomic_inc(&ht->ht_elements);

	return ret;
}

int gnix_ht_remove(gnix_hashtable_t *ht, gnix_ht_key_t key)
{
	int bucket;
	int ret;

	if (ht->ht_state != GNIX_HT_STATE_READY)
		return -EINVAL;

	pthread_rwlock_rdlock(&ht->ht_lock);

	bucket = gnix_hash_func(ht, key);
	ret = __gnix_ht_remove_list(&ht->ht_tbl[bucket], key);

	pthread_rwlock_unlock(&ht->ht_lock);

	if (ret == 0)
		atomic_dec(&ht->ht_elements);

	return ret;
}

void *gnix_ht_lookup(gnix_hashtable_t *ht, gnix_ht_key_t key)
{
	int bucket;
	void *ret;

	if (ht->ht_state != GNIX_HT_STATE_READY)
		return NULL;

	pthread_rwlock_rdlock(&ht->ht_lock);
	bucket = gnix_hash_func(ht, key);

	ret = gnix_ht_lookup_key(&ht->ht_tbl[bucket], key);
	pthread_rwlock_unlock(&ht->ht_lock);

	return ret;
}

int gnix_ht_empty(gnix_hashtable_t *ht)
{
	return atomic_get(&ht->ht_elements) == 0;
}
