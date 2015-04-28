/*
 * Copyright (c) 2015 Cray Inc. All rights reserved.
 *
 *  Created on: Apr 27, 2015
 *      Author: jswaro
 */

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#include <errno.h>
#include <gnix_hashtable.h>

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

void __gnix_hashtable_test_setup_bare(void)
{
	assert(test_ht == NULL);
	test_ht = (gnix_hashtable_t *) calloc(1, sizeof(gnix_hashtable_t));
	assert(test_ht != NULL);
}


void __gnix_hashtable_test_teardown_bare(void)
{
	assert(test_ht != NULL);
	free(test_ht);
	test_ht = NULL;
}

void __gnix_hashtable_test_uninitialized(void)
{
	assert(test_ht->ht_state == GNIX_HT_STATE_UNINITIALIZED);
	assert(test_ht->ht_size == 0);
	assert(test_ht->ht_tbl == NULL);
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
/*
Test(gnix_hashtable, destroy_twice,
		.init = __gnix_hashtable_test_setup_bare,
		.fini = __gnix_hashtable_test_teardown_bare)
{
	int ret;

	__gnix_hashtable_initialize();

	__gnix_hashtable_destroy();

	ret = gnix_ht_destroy(test_ht);
	assert(ret == -EINVAL);
	__gnix_hashtable_test_destroyed_clean();
}
*/

/* from this point on in the testing, init functions will already set up the
 *   hash maps and then destroy them at the end of the tests.
 */

/*
Test(gnix_hashtable, insert_1)
{
	int ret;

	ret = gnix_ht_insert(test_ht, simple_element->key, simple_element);
	assert(ret == 0);

	assert(atomic_get(&test_ht->ht_elements) == 1);
}

Test(gnix_hashtable, insert_1_remove_1)
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

Test(gnix_hashtable, insert_1024)
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

Test(gnix_hashtable, insert_1024_remove_1024)
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

	for (i = 1024; i >= 0; --i) {
		ret = gnix_ht_remove(test_ht,
				test_elements[i].key);
		assert(ret == 0);
		assert(atomic_get(&test_ht->ht_elements) == (i - 1));
	}

	assert(atomic_get(&test_ht->ht_elements) == 0);
}

Test(gnix_hashtable, insert_1_lookup_pass)
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

Test(gnix_hashtable, insert_1_lookup_fail)
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

Test(gnix_hashtable, insert_1024_lookup_all)
{
	int ret, i;
	gnix_test_element_t test_elements[1024];
	gnix_test_element_t *found = NULL;

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

	for (i = 0; i < 1024; ++i) {
		found = gnix_ht_lookup(test_ht, test_elements[i].key);
		assert(found != NULL);
		assert(found == &test_elements[i]);
		assert(found->magic == __GNIX_MAGIC_VALUE);
	}
}

Test(gnix_hashtable, insert_1024_lookup_random)
{
	int ret, i;
	gnix_test_element_t test_elements[1024];
	gnix_test_element_t *found = NULL, *to_find = NULL;

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

	for (i = 0; i < 1024; ++i) {
		to_find = &test_elements[rand() % 1024];
		found = gnix_ht_lookup(test_ht, to_find->key);
		assert(found != NULL);
		assert(found == to_find);
		assert(found->magic == __GNIX_MAGIC_VALUE);
	}
}
*/


