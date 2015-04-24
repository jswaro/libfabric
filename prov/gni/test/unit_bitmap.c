/*
 * Copyright (c) 2015 Cray Inc. All rights reserved.
 *
 *  Created on: Apr 23, 2015
 *      Author: jswaro
 */

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#include <errno.h>
#include <bitmap.h>

#ifdef assert
#undef assert
#endif

#include <criterion/criterion.h>

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


static void __test_clean_bitmap_state(gnix_bitmap_t *bitmap,
		int _length, gnix_bitmap_state_e _state)
{
	assert(bitmap->arr != NULL);
	assert(bitmap->length == _length);
	assert(bitmap->state == _state);
}

static void __test_initialize_bitmap(gnix_bitmap_t *bitmap, int bits)
{
	int ret = alloc_bitmap(bitmap, bits);

	assert(ret == 0);
	__test_clean_bitmap_state(bitmap, bits, GNIX_BITMAP_STATE_READY);
}

static void __test_initialize_bitmap_clean(gnix_bitmap_t *bitmap, int bits)
{
	__test_initialize_bitmap(bitmap, bits);
	assert(bitmap_empty(bitmap));
}

static void __test_realloc_bitmap(gnix_bitmap_t *bitmap, int bits)
{
	int ret = realloc_bitmap(bitmap, bits);

	assert(ret == 0);
	__test_clean_bitmap_state(bitmap, bits,	GNIX_BITMAP_STATE_READY);
}

static void __test_realloc_bitmap_clean(gnix_bitmap_t *bitmap, int initial,
		int next)
{
	__test_initialize_bitmap(bitmap, initial);
	__test_realloc_bitmap(bitmap, next);
	assert(bitmap_empty(bitmap));
}

static void __test_free_bitmap_clean(gnix_bitmap_t *bitmap)
{
	int ret = free_bitmap(bitmap);

	assert(ret == 0);
	assert(bitmap->arr == NULL);
	assert(bitmap->length == 0);
	assert(bitmap->state == GNIX_BITMAP_STATE_FREE);
}

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

	assert(!test_bit(test_bitmap, 0));
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

	assert(find_first_set_bit(test_bitmap) == test_bitmap->length);
}

Test(gnix_bitmap, ffs_first_bit_set)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	set_bit(test_bitmap, 0);

	assert(find_first_set_bit(test_bitmap) == 0);
}

Test(gnix_bitmap, ffs_seventeen_set)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	set_bit(test_bitmap, 17);

	assert(find_first_set_bit(test_bitmap) == 17);
}

Test(gnix_bitmap, ffz_clean_bitmap)
{
	__test_initialize_bitmap_clean(test_bitmap, 64);

	assert(find_first_zero_bit(test_bitmap) == 0);
}

Test(gnix_bitmap, ffz_full_bitmap)
{
	int i;

	__test_initialize_bitmap_clean(test_bitmap, 64);

	for (i = 0; i < test_bitmap->length; ++i) {
		set_bit(test_bitmap, i);
		assert(test_bit(test_bitmap, i));
	}

	assert(find_first_zero_bit(test_bitmap) == test_bitmap->length);
}

Test(gnix_bitmap, ffz_first_half_set)
{
	int i;
	__test_initialize_bitmap_clean(test_bitmap, 64);

	for (i = 0; i < 32 ; ++i) {
		set_bit(test_bitmap, i);
		assert(test_bit(test_bitmap, i));
	}

	expect(test_bitmap->length == 64);
	expect(i == 32);
	assert(find_first_zero_bit(test_bitmap) == i);
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

Test(gnix_bitmap, bitmap_load)
{
	gnix_bitmap_value_t expected = ~0;

	__test_initialize_bitmap_clean(test_bitmap, 64);

	fill_bitmap(test_bitmap, 1);

	assert(expected == __gnix_load_block(test_bitmap, 0));
}

Test(gnix_bitmap, bitmap_set)
{
	gnix_bitmap_value_t expected = ~0;

	__test_initialize_bitmap_clean(test_bitmap, 64);

	__gnix_set_block(test_bitmap, 0, expected);

	assert(__gnix_load_block(test_bitmap, 0) == expected);
}
