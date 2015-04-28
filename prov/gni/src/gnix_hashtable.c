/*
 * Copyright 2015 Cray Inc. All rights reserved.
 *
 *  Created on: Apr 27, 2015
 *      Author: jswaro
 */

#include <stdlib.h>
#include <errno.h>

#include <gnix_hashtable.h>


static inline gnix_ht_key_t gnix_hash_func(
		gnix_hashtable_t *ht,
		gnix_ht_key_t key)
{
	return key % ht->ht_size;
}

static inline void __gnix_ht_lookup_key(
		gnix_ht_list_head_t *lh,
		gnix_ht_key_t key,
		gnix_ht_entry_t **prev,
		gnix_ht_entry_t **entry)
{
	gnix_ht_entry_t *iter;

	iter = lh->head;
	prev = NULL;

	while (iter) {
		if (iter->key == key) {
			*entry = iter;
			return;
		}

		*prev = iter;
		iter = iter->next;
	}
}

static inline void *gnix_ht_lookup_key(gnix_ht_list_head_t *lh,
		gnix_ht_key_t key)
{
	gnix_ht_entry_t *prev, *iter;

	pthread_rwlock_rdlock(&lh->lh_lock);
	__gnix_ht_lookup_key(lh, key, &prev, &iter);
	pthread_rwlock_unlock(&lh->lh_lock);

	if (!iter)
		return NULL;

	return iter->entry;
}

static inline void __gnix_ht_destroy_list(gnix_hashtable_t *ht,
		gnix_ht_list_head_t *lh)
{
	gnix_ht_entry_t *iter, *next;
	int entries_freed = 0;

	iter = lh->head;
	lh->head = NULL;

	while (iter) {
		next = iter->next;

		iter->next = NULL;
		iter->entry = NULL;
		free(iter);

		++entries_freed;
	}

	atomic_sub(&ht->ht_elements, entries_freed);
}



static inline int __gnix_ht_insert_list(
		gnix_ht_list_head_t *lh,
		gnix_ht_entry_t *entry,
		int *collisions)
{
	gnix_ht_entry_t *iter;
	int hits = 0;

	iter = lh->head;

	if (!lh->head) {
		lh->head = entry;
		return 0;
	}

	while (iter) {
		if (iter->key == entry->key) {
			*collisions = hits;

			return -EINVAL;
		}

		++hits;

		if (iter->next) {
			iter = iter->next;
			continue;
		}

		break;
	}

	iter->next = entry;
	*collisions = hits;

	return 0;
}

static inline int __gnix_ht_insert_list_locked(
		gnix_ht_list_head_t *lh,
		gnix_ht_entry_t *entry,
		int *collisions)
{
	int ret;

	pthread_rwlock_wrlock(&lh->lh_lock);
	ret = __gnix_ht_insert_list(lh, entry, collisions);
	pthread_rwlock_unlock(&lh->lh_lock);

	return ret;
}

static inline int __gnix_ht_remove_list(
		gnix_ht_list_head_t *lh,
		gnix_ht_key_t key)
{
	gnix_ht_entry_t *iter, *prev;

	pthread_rwlock_wrlock(&lh->lh_lock);
	__gnix_ht_lookup_key(lh, key, &prev, &iter);

	if (iter && prev) {
		prev->next = iter->next;
	} else if (iter && !prev) {
		lh->head = iter->next;
	} else {
		pthread_rwlock_unlock(&lh->lh_lock);
		return -ENOENT;
	}
	pthread_rwlock_unlock(&lh->lh_lock);

	iter->entry = NULL;
	iter->key = 0;
	iter->next = NULL;

	free(iter);

	return 0;
}

static inline void __gnix_ht_rehash_list(gnix_hashtable_t *ht,
		gnix_ht_list_head_t *list)
{
	gnix_ht_entry_t *iter, *current;
	gnix_ht_key_t bucket;
	int collisions = 0;
	int ret;

	iter = list->head;
	list->head = NULL;

	if (!iter)
		return;

	while (iter) {
		current = iter;
		iter = current->next;

		bucket = gnix_hash_func(ht, current->key);

		current->next = NULL;

		ret = __gnix_ht_insert_list(&ht->ht_tbl[bucket],
				current, &collisions);
	}
}

static inline void __gnix_ht_rehash_table(gnix_hashtable_t *ht,
		gnix_ht_list_head_t *ht_tbl, int old_length)
{
	int i;

	for (i = 0; i < old_length; ++i) {
		__gnix_ht_rehash_list(ht, &ht_tbl[i]);
	}
}

static inline void __gnix_ht_resize_hashtable(gnix_hashtable_t *ht)
{
	int old_size = ht->ht_size;
	int new_size = old_size + __GNIX_HT_INCREASE_STEP;
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

	for (i = 0; i < new_size; ++i) {
		pthread_rwlock_init(&ht->ht_tbl[i].lh_lock, NULL);
		ht->ht_tbl[i].head = NULL;
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

	if (ht->ht_state == GNIX_HT_STATE_UNINITIALIZED)
		return -EINVAL;

	if (ht->ht_state != GNIX_HT_STATE_DEAD)
		pthread_rwlock_init(&ht->ht_lock, NULL);

	pthread_rwlock_wrlock(&ht->ht_lock);

	ht->ht_size = __GNIX_HT_INITIAL_SIZE;
	ht->ht_tbl = calloc(ht->ht_size, sizeof(gnix_ht_list_head_t *));
	if (!ht->ht_tbl) {
		pthread_rwlock_unlock(&ht->ht_lock);
		ht->ht_size = 0;
		return -ENOMEM;
	}

	for (i = 0; i < ht->ht_size; ++i) {
		pthread_rwlock_init(&ht->ht_tbl[i].lh_lock, NULL);
		ht->ht_tbl[i].head = NULL;
	}

	if (ht->ht_state == GNIX_HT_STATE_UNINITIALIZED) {
		atomic_initialize(&ht->ht_elements, 0);
	} else {
		atomic_set(&ht->ht_elements, 0);
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

	ht->ht_size = 0;
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
	int hits = 0;

	gnix_ht_entry_t *list_entry;

	if (ht->ht_state != GNIX_HT_STATE_READY)
		return -EINVAL;

	list_entry = calloc(1, sizeof(gnix_ht_entry_t));
	if (!list_entry)
		return -ENOMEM;

	list_entry->entry = entry;
	list_entry->key = key;
	list_entry->next = NULL;

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
