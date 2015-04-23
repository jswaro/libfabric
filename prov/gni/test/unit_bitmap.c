/*
 * Copyright 2015 Cray Inc. All rights reserved.
 *
 *  Created on: Apr 23, 2015
 *      Author: jswaro
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

#include <criterion/criterion.h>

#include <bitmap.h>

gnix_bitmap_t *test_bitmap = NULL;

int call_free_bitmap = 0;

void __gnix_bitmap_test_setup(void)
{
	assert(test_bitmap == NULL);
	test_bitmap = (gnix_bitmap_t *) calloc(1, sizeof(test_bitmap));
	memset(test_bitmap, 0, sizeof(gnix_bitmap_t));
	assert(test_bitmap != NULL);

	call_free_bitmap = 1;
}

void __gnix_bitmap_test_teardown(void)
{
	if (call_free_bitmap) {
		free_bitmap(test_bitmap);
	} else if (test_bitmap && test_bitmap->arr) {
		free(test_bitmap->arr);
	}

	assert(test_bitmap != NULL);
	free(test_bitmap);
	test_bitmap = NULL;
}


#define __test_clean_bitmap_state(bitmap, _length, _state) \
	do { \
		assert((bitmap)->arr != NULL); \
		assert((bitmap)->length == (_length)); \
		assert((bitmap)->state == (_state)); \
	} while (0)

#define __test_initialize_bitmap(bitmap, bits) \
	do { \
		int __ret; \
		__ret = alloc_bitmap(bitmap, bits); \
		assert(__ret == 0); \
		__test_clean_bitmap_state(bitmap, bits, \
				GNIX_BITMAP_STATE_READY); \
	} while (0)

#define __test_initialize_bitmap_clean(bitmap, bits) \
	do { \
		__test_initialize_bitmap(bitmap, bits); \
		assert(bitmap_empty(bitmap)); \
	} while (0)

#define __test_realloc_bitmap(bitmap, bits) \
	do { \
		int __ret; \
		__ret = realloc_bitmap(bitmap, bits); \
		assert(__ret == 0); \
		__test_clean_bitmap_state(bitmap, bits, \
				GNIX_BITMAP_STATE_READY); \
	} while (0)

#define __test_realloc_bitmap_clean(bitmap, initial, next) \
	do { \
		__test_initialize_bitmap(bitmap, initial); \
		__test_realloc_bitmap(bitmap, next); \
		assert(bitmap_empty(test_bitmap)); \
	} while (0)

#define __test_free_bitmap_clean(bitmap) \
	do { \
		assert(free_bitmap(bitmap) == 0); \
		assert((bitmap)->arr == NULL); \
		assert((bitmap)->length == 0); \
		assert((bitmap)->state == GNIX_BITMAP_STATE_FREE); \
	} while (0)

/*
 *
 */

TestSuite(gnix_bitmap,
		.init = __gnix_bitmap_test_setup,
		.fini = __gnix_bitmap_test_teardown);

Test(gnix_bitmap, uninitialized)
{
	assert(test_bitmap->arr == NULL);
	assert(test_bitmap->length == 0);
	assert(test_bitmap->state == GNIX_BITMAP_STATE_UNINITIALIZED);

	call_free_bitmap = 0;
}

Test(gnix_bitmap, initialize_128)
{
	__test_initialize_bitmap(test_bitmap, 128);

	call_free_bitmap = 0;
}

Test(gnix_bitmap, initialize_1)
{
	__test_initialize_bitmap(test_bitmap, 1);

	call_free_bitmap = 0;
}

Test(gnix_bitmap, initialize_0)
{
	int ret;

	ret = alloc_bitmap(test_bitmap, 0);
	assert(ret == -EINVAL);

	call_free_bitmap = 0;
}

Test(gnix_bitmap, already_initialized)
{
	int ret;

	__test_initialize_bitmap(test_bitmap, 128);

	ret = alloc_bitmap(test_bitmap, 128);
	assert(ret == -EINVAL);

	call_free_bitmap = 0;
}

Test(gnix_bitmap, destroy_bitmap)
{
	__test_initialize_bitmap(test_bitmap, 128);

	__test_free_bitmap_clean(test_bitmap);
}

Test(gnix_bitmap, destroy_bitmap_uninitialized)
{
	int ret;

	ret = free_bitmap(test_bitmap);
	assert(ret == -EINVAL);
	expect(test_bitmap->arr == NULL);
	expect(test_bitmap->length == 0);
	expect(test_bitmap->state == GNIX_BITMAP_STATE_UNINITIALIZED);
}

Test(gnix_bitmap, destroy_bitmap_already_freed)
{
	int ret;

	__test_initialize_bitmap(test_bitmap, 128);

	__test_free_bitmap_clean(test_bitmap);

	ret = free_bitmap(test_bitmap);
	assert(ret == -EINVAL);
	expect(test_bitmap->arr == NULL);
	expect(test_bitmap->length == 0);
	expect(test_bitmap->state == GNIX_BITMAP_STATE_FREE);
}

Test(gnix_bitmap, realloc_63)
{
	__test_realloc_bitmap_clean(test_bitmap, 128, 63);
}

Test(gnix_bitmap, realloc_64)
{
	__test_realloc_bitmap_clean(test_bitmap, 128, 64);
}

Test(gnix_bitmap, realloc_65)
{
	__test_realloc_bitmap_clean(test_bitmap, 128, 65);
}

Test(gnix_bitmap, realloc_255)
{
	__test_realloc_bitmap_clean(test_bitmap, 128, 255);
}

Test(gnix_bitmap, realloc_256)
{
	__test_realloc_bitmap_clean(test_bitmap, 128, 256);
}

Test(gnix_bitmap, realloc_257)
{
	__test_realloc_bitmap_clean(test_bitmap, 128, 257);
}

Test(gnix_bitmap, realloc_63_check_bits)
{
	__test_realloc_bitmap_clean(test_bitmap, 128, 63);
}

Test(gnix_bitmap, realloc_64_check_bits)
{
	__test_realloc_bitmap_clean(test_bitmap, 128, 64);
}

Test(gnix_bitmap, realloc_65_check_bits)
{
	__test_realloc_bitmap_clean(test_bitmap, 128, 65);
}

Test(gnix_bitmap, realloc_255_check_bits)
{
	__test_realloc_bitmap_clean(test_bitmap, 128, 255);
}

Test(gnix_bitmap, realloc_256_check_bits)
{
	__test_realloc_bitmap_clean(test_bitmap, 128, 256);
}

Test(gnix_bitmap, realloc_257_check_bits)
{
	__test_realloc_bitmap_clean(test_bitmap, 128, 257);
}

Test(gnix_bitmap, bit_set_test_pass)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	set_bit(test_bitmap, 1);

	assert(test_bit(test_bitmap, 1));
}

Test(gnix_bitmap, bit_set_test_fail)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	set_bit(test_bitmap, 1);

	assert(test_bit(test_bitmap, 0));
}

Test(gnix_bitmap, bit_set_clear)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	set_bit(test_bitmap, 1);

	assert(test_bit(test_bitmap, 1));

	clear_bit(test_bitmap, 1);

	assert(!test_bit(test_bitmap, 1));
}

Test(gnix_bitmap, bit_clear)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	clear_bit(test_bitmap, 1);

	assert(!test_bit(test_bitmap, 1));
}

Test(gnix_bitmap, bit_set)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	set_bit(test_bitmap, 1);
}

Test(gnix_bitmap, bit_test_and_set_unset)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	assert(!test_and_set_bit(test_bitmap, 1));
}

Test(gnix_bitmap, bit_test_and_set_already_set)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	set_bit(test_bitmap, 1);
	assert(test_bit(test_bitmap, 1));

	assert(test_and_set_bit(test_bitmap, 1));
}

Test(gnix_bitmap, bit_test_and_clear_unset)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	assert(!test_and_clear_bit(test_bitmap, 1));
}

Test(gnix_bitmap, bit_test_and_clear_already_set)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	set_bit(test_bitmap, 1);
	assert(test_bit(test_bitmap, 1));

	assert(test_and_clear_bit(test_bitmap, 1));
}

Test(gnix_bitmap, ffs_clean_bitmap)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	assert(find_first_set_bit(bitmap) == test_bitmap->length);
}

Test(gnix_bitmap, ffs_first_bit_set)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	set_bit(test_bitmap, 0);

	assert(find_first_set_bit(bitmap) == 0);
}

Test(gnix_bitmap, ffs_seventeen_set)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	set_bit(test_bitmap, 17);

	assert(find_first_set_bit(bitmap) == 17);
}

Test(gnix_bitmap, ffz_clean_bitmap)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	assert(find_first_set_bit(bitmap) == 0);
}

Test(gnix_bitmap, ffz_full_bitmap)
{
	int i;

	__test_initialize_bitmap_clean(test_bitmap, 64);

	for (i = 0; i < test_bitmap->length; ++i) {
		set_bit(test_bitmap, i);
		assert(test_bit(test_bitmap, i));
	}

	assert(find_first_set_bit(bitmap) == test_bitmap->length);
}

Test(gnix_bitmap, ffz_last_half_set)
{
	int i;

	__test_initialize_bitmap_clean(test_bitmap, 64);

	for (i = (test_bitmap->length >> 1); i < test_bitmap->length ; ++i) {
		set_bit(test_bitmap, i);
		assert(test_bit(test_bitmap, i));
	}

	assert(find_first_set_bit(bitmap) == (test_bitmap->length >> 1));
}

Test(gnix_bitmap, map_fill_0)
{
	int i;

	__test_initialize_bitmap_clean(test_bitmap, 64);

	for (i = 0; i < test_bitmap->length; ++i) {
		set_bit(test_bitmap, i);
		assert(test_bit(test_bitmap, i));
	}

	assert(bitmap_full(test_bitmap));

	fill_bitmap(test_bitmap, 0);

	assert(bitmap_empty(test_bitmap));
}

Test(gnix_bitmap, map_fill_1)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	fill_bitmap(test_bitmap, 1);

	assert(bitmap_full(test_bitmap));
}
