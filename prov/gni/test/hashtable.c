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
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#include <errno.h>
#include <gnix_hashtable.h>
#include <gnix_bitmap.h>

#ifdef assert
#undef assert
#endif

#include <criterion/criterion.h>

#define __GNIX_MAGIC_VALUE 0xDEADBEEF

typedef struct gnix_test_element {
	uint64_t val;
	uint64_t key;
	uint64_t magic;
} gnix_test_element_t;

#define GNIX_TEST_ELEMENT_INIT(_val, _key) \
	{ .val = (_val), .key = (_key), .magic = (__GNIX_MAGIC_VALUE) }

gnix_test_element_t elements[4] = {
	GNIX_TEST_ELEMENT_INIT(1, 100),
	GNIX_TEST_ELEMENT_INIT(2, 200),
	GNIX_TEST_ELEMENT_INIT(10, 300),
	GNIX_TEST_ELEMENT_INIT(777, 500000)
};

gnix_test_element_t *simple_element = &elements[0];
gnix_hashtable_t *test_ht = NULL;

void __gnix_hashtable_test_uninitialized(void)
{
	assert(test_ht->ht_state == GNIX_HT_STATE_UNINITIALIZED);
	assert(test_ht->ht_size == 0);
	assert(test_ht->ht_tbl == NULL);
}

void __gnix_hashtable_test_setup_bare(void)
{
	assert(test_ht == NULL);
	test_ht = (gnix_hashtable_t *) calloc(1, sizeof(gnix_hashtable_t));
	assert(test_ht != NULL);

	__gnix_hashtable_test_uninitialized();
}


void __gnix_hashtable_test_teardown_bare(void)
{
	assert(test_ht != NULL);
	free(test_ht);
	test_ht = NULL;
}

void __gnix_hashtable_test_initialized(void)
{
	assert(test_ht->ht_state == GNIX_HT_STATE_READY);
	assert(atomic_get(&test_ht->ht_elements) == 0);
	assert(test_ht->ht_size == __GNIX_HT_INITIAL_SIZE);
	assert(test_ht->ht_tbl != NULL);
}

void __gnix_hashtable_test_destroyed_clean(void)
{
	assert(test_ht->ht_state == GNIX_HT_STATE_DEAD);
	assert(atomic_get(&test_ht->ht_elements) == 0);
	assert(test_ht->ht_size == 0);
	assert(test_ht->ht_tbl == NULL);
}

void __gnix_hashtable_destroy(void)
{
	int ret = gnix_ht_destroy(test_ht);
	assert(ret == 0);
	__gnix_hashtable_test_destroyed_clean();
}

void __gnix_hashtable_initialize(void)
{
	int ret;

	ret = gnix_ht_init(test_ht);
	assert(ret == 0);

	__gnix_hashtable_test_initialized();
}

void __gnix_hashtable_test_setup(void)
{
	__gnix_hashtable_test_setup_bare();

	__gnix_hashtable_test_uninitialized();

	__gnix_hashtable_initialize();
}

void __gnix_hashtable_test_teardown(void)
{
	__gnix_hashtable_destroy();

	__gnix_hashtable_test_teardown_bare();
}

/*
 * Basic functionality tests for the gnix_hashtable_t object
 */

TestSuite(gnix_hashtable_basic,
		.init = __gnix_hashtable_test_setup_bare,
		.fini = __gnix_hashtable_test_teardown_bare);

TestSuite(gnix_hashtable_advanced,
		.init = __gnix_hashtable_test_setup,
		.fini = __gnix_hashtable_test_teardown);


Test(gnix_hashtable_basic, uninitialized)
{
	__gnix_hashtable_test_uninitialized();
}


Test(gnix_hashtable_basic, initialize_ht)
{
	__gnix_hashtable_initialize();
}

Test(gnix_hashtable_basic, err_initialize_twice)
{
	int ret;

	__gnix_hashtable_initialize();

	ret = gnix_ht_init(test_ht);
	assert(ret == -EINVAL);
	__gnix_hashtable_test_initialized();
}

Test(gnix_hashtable_basic, err_destroy_uninitialized)
{
	int ret;

	ret = gnix_ht_destroy(test_ht);
	assert(ret == -EINVAL);

	__gnix_hashtable_test_uninitialized();
}

Test(gnix_hashtable_basic, destroy)
{
	__gnix_hashtable_initialize();

	__gnix_hashtable_destroy();
}

Test(gnix_hashtable_basic, destroy_twice)
{
	int ret;

	__gnix_hashtable_initialize();

	__gnix_hashtable_destroy();

	ret = gnix_ht_destroy(test_ht);
	assert(ret == -EINVAL);
	__gnix_hashtable_test_destroyed_clean();
}

Test(gnix_hashtable_advanced, insert_1)
{
	int ret;

	ret = gnix_ht_insert(test_ht, simple_element->key, simple_element);
	assert(ret == 0);

	assert(atomic_get(&test_ht->ht_elements) == 1);
}

Test(gnix_hashtable_advanced, insert_duplicate)
{
	int ret;

	ret = gnix_ht_insert(test_ht, simple_element->key, simple_element);
	assert(ret == 0);

	assert(atomic_get(&test_ht->ht_elements) == 1);

	ret = gnix_ht_insert(test_ht, simple_element->key, simple_element);
	assert(ret == -ENOSPC);

	assert(atomic_get(&test_ht->ht_elements) == 1);
}

Test(gnix_hashtable_advanced, insert_1_remove_1)
{
	int ret;

	srand(time(NULL));

	ret = gnix_ht_insert(test_ht, simple_element->key, simple_element);
	assert(ret == 0);

	assert(atomic_get(&test_ht->ht_elements) == 1);

	ret = gnix_ht_remove(test_ht, simple_element->key);
	assert(ret == 0);

	assert(atomic_get(&test_ht->ht_elements) == 0);
}


Test(gnix_hashtable_advanced, insert_1024)
{
	int ret, i;

	gnix_test_element_t test_elements[1024];

	srand(time(NULL));

	for (i = 0; i < 1024; ++i) {
		test_elements[i].key = rand();
		test_elements[i].val = rand() % (1024 * 1024);
		test_elements[i].magic = __GNIX_MAGIC_VALUE;
	}

	for (i = 0; i < 1024; ++i) {
		ret = gnix_ht_insert(test_ht,
				test_elements[i].key, &test_elements[i]);
		assert(ret == 0);
		assert(atomic_get(&test_ht->ht_elements) == (i + 1));
	}

	assert(atomic_get(&test_ht->ht_elements) == 1024);
}


Test(gnix_hashtable_advanced, insert_1024_remove_1024)
{
	int ret, i;

	gnix_test_element_t test_elements[1024];
	gnix_test_element_t *item;

	srand(time(NULL));

	for (i = 0; i < 1024; ++i) {
		item = &test_elements[i];
		item->key = i;
		item->val = rand() % (1024 * 1024);
		item->magic = __GNIX_MAGIC_VALUE;
	}

	for (i = 0; i < 1024; ++i) {
		item = &test_elements[i];
		ret = gnix_ht_insert(test_ht,
				item->key, item);
		assert(ret == 0);
		assert(atomic_get(&test_ht->ht_elements) == (i + 1));
	}

	for (i = 1023; i >= 0; --i) {
		item = &test_elements[i];
		assert(i == item->key);

		ret = gnix_ht_remove(test_ht,
				item->key);
		assert(ret == 0);
		assert(atomic_get(&test_ht->ht_elements) == i);
	}

	assert(atomic_get(&test_ht->ht_elements) == 0);
}


Test(gnix_hashtable_advanced, insert_1_lookup_pass)
{
	int ret;
	gnix_test_element_t *found = NULL;

	ret = gnix_ht_insert(test_ht,
			simple_element->key, simple_element);
	assert(ret == 0);

	assert(atomic_get(&test_ht->ht_elements) == 1);

	found = gnix_ht_lookup(test_ht, simple_element->key);
	assert(found == simple_element);
	assert(found->magic == __GNIX_MAGIC_VALUE);
}

Test(gnix_hashtable_advanced, insert_1_lookup_fail)
{
	int ret;
	gnix_test_element_t *found = NULL;

	ret = gnix_ht_insert(test_ht,
			simple_element->key, simple_element);
	assert(ret == 0);

	assert(atomic_get(&test_ht->ht_elements) == 1);

	found = gnix_ht_lookup(test_ht, simple_element->key - 1);
	assert(found != simple_element);
	assert(found == NULL);
}

Test(gnix_hashtable_advanced, insert_1024_lookup_all)
{
	int ret, i;
	gnix_test_element_t test_elements[1024];
	gnix_test_element_t *item;
	gnix_test_element_t *found = NULL;

	srand(time(NULL));

	for (i = 0; i < 1024; ++i) {
		item = &test_elements[i];

		item->key = i;
		item->val = rand() % (1024 * 1024);
		item->magic = __GNIX_MAGIC_VALUE;
	}

	for (i = 0; i < 1024; ++i) {
		item = &test_elements[i];

		ret = gnix_ht_insert(test_ht,
				item->key, item);
		assert(ret == 0);
		assert(atomic_get(&test_ht->ht_elements) == (i + 1));
	}

	assert(atomic_get(&test_ht->ht_elements) == 1024);

	for (i = 0; i < 1024; ++i) {
		found = gnix_ht_lookup(test_ht, test_elements[i].key);
		assert(found != NULL);
		assert(found == &test_elements[i]);
		assert(found->magic == __GNIX_MAGIC_VALUE);
	}
}

Test(gnix_hashtable_advanced, insert_1024_lookup_random)
{
	int ret, i;
	gnix_test_element_t test_elements[1024];
	gnix_test_element_t *found = NULL, *to_find = NULL;
	gnix_test_element_t *item;

	srand(time(NULL));

	for (i = 0; i < 1024; ++i) {
		item = &test_elements[i];

		item->key = i;
		item->val = rand() % (1024 * 1024);
		item->magic = __GNIX_MAGIC_VALUE;
	}

	for (i = 0; i < 1024; ++i) {
		item = &test_elements[i];

		ret = gnix_ht_insert(test_ht,
				item->key, item);
		assert(ret == 0);
		assert(atomic_get(&test_ht->ht_elements) == (i + 1));
	}

	assert(atomic_get(&test_ht->ht_elements) == 1024);

	for (i = 0; i < 1024; ++i) {
		to_find = &test_elements[rand() % 1024];
		found = gnix_ht_lookup(test_ht, to_find->key);
		assert(found != NULL);
		assert(found == to_find);
		assert(found->magic == __GNIX_MAGIC_VALUE);
	}
}

Test(gnix_hashtable_advanced, insert_8K_lookup_1M_random)
{
	int ret, i, index;
	gnix_test_element_t *test_elements;
	gnix_test_element_t *found = NULL, *to_find = NULL;
	gnix_test_element_t *item;
	gnix_bitmap_t allocated;
	int test_size = 8 * 1024;
	int bitmap_size = 64 * test_size;

	test_elements = calloc(test_size, sizeof(gnix_test_element_t));
	assert(test_elements != NULL);

	ret = alloc_bitmap(&allocated, bitmap_size);
	assert(ret == 0);

	srand(time(NULL));

	for (i = 0; i < test_size; ++i) {
		do {
			index = rand() % bitmap_size;
		} while (test_and_set_bit(&allocated, index));

		item = &test_elements[i];

		item->key = index;
		item->val = rand() % (1024 * 1024);
		item->magic = __GNIX_MAGIC_VALUE;
	}

	for (i = 0; i < test_size; ++i) {
		item = &test_elements[i];

		ret = gnix_ht_insert(test_ht,
				item->key, item);
		assert(ret == 0);
		assert(atomic_get(&test_ht->ht_elements) == (i + 1));
	}

	assert(atomic_get(&test_ht->ht_elements) == test_size);

	for (i = 0; i < 1024 * 1024; ++i) {
		to_find = &test_elements[rand() % test_size];
		found = gnix_ht_lookup(test_ht, to_find->key);
		assert(found != NULL);
		assert(found == to_find);
		assert(found->magic == __GNIX_MAGIC_VALUE);
	}

	ret = free_bitmap(&allocated);
	expect(ret == 0);

	free(test_elements);
}

