/*
 * Copyright 2015 Cray Inc. All rights reserved.
 *
 *  Created on: Apr 16, 2015
 *      Author: jswaro
 */

#include "bitmap.h"

static inline int __find_first_zero_bit(uint8_t val)
{
	int i;
	uint8_t j;

	for (i = 0, j = 1; i < 8; ++i, j <<= 1) {
		if (!(val & j))
			break;
	}

	return i;
}

static inline int __find_first_zero_byte(gnix_bitmap_value_t *val)
{
	int i, pos, ret;
	uint8_t *iter = (uint8_t *) val;
	uint8_t full_value = ~0;

	for (i = 0, pos = 0;
			i < sizeof(gnix_bitmap_value_t);
			++i, pos += 8) {

		if (iter[i] != full_value) {
			pos += __find_first_zero_bit(iter[i]);
			break;
		}
	}

	return pos;
}

int find_first_zero_bit(gnix_bitmap_t *bitmap)
{
	int i, pos;
	gnix_bitmap_block_t *block;
	gnix_bitmap_value_t full_value = ~0;
	gnix_bitmap_value_t value;

	for (i = 0, pos = 0; i < BITMAP_BLOCKS(bitmap->length);
			++i, pos += GNIX_BITMAP_BUCKET_LENGTH) {
		block = &bitmap->arr[i];
		value = __gnix_load_block(bitmap, i);
		if (value != full_value) {
			pos += __find_first_zero_byte(&value);

			return pos;
		}
	}

	return bitmap->length;
}

static inline int __find_first_set_bit(gnix_bitmap_value_t val)
{

	int i;
	uint8_t j;

	for (i = 0, j = 1; i < 8; ++i, j <<= 1) {
		if (val & j)
			break;
	}

	return i;
}


static inline int __find_first_set_byte(gnix_bitmap_value_t *val)
{
	int i, pos, ret;
	uint8_t *iter = (uint8_t *) val;

	for (i = 0, pos = 0;
			i < sizeof(gnix_bitmap_value_t);
			++i, pos += 8) {

		if ((iter[i] != 0)) {
			pos += __find_first_set_bit(iter[i]);
			break;
		}
	}

	return pos;
}

int find_first_set_bit(gnx_bitmap_t *bitmap)
{
	int i, pos;
	gnix_bitmap_block_t *block;
	gnix_bitmap_value_t full_value = ~0;
	gnix_bitmap_value_t value;

	for (i = 0, pos = 0; i < BITMAP_BLOCKS(bitmap->length);
			++i, pos += GNIX_BITMAP_BUCKET_LENGTH) {
		block = &bitmap->arr[i];
		value = __gnix_load_block(bitmap, i);
		if (value != 0) {
			pos += __find_first_set_byte(&value);

			return pos;
		}
	}

	return bitmap->length;
}

void fill_bitmap(gnix_bitmap_t *bitmap, int value)
{
	int i;
	gnix_bitmap_value_t fill_value = (value != 0) ? ~0 : 0;

	GNIX_BITMAP_LOCK_ACQUIRE(bitmap);

	for (i = 0; i < BITMAP_BLOCKS(bitmap->length); ++i) {
		__gnix_set_block(bitmap, index, fill_value);
	}

	GNIX_BITMAP_LOCK_RELEASE(bitmap);
}

int alloc_bitmap(gnix_bitmap_t *bitmap, uint32_t nbits)
{
	int i;

	if (bitmap->state == GNIX_BITMAP_STATE_READY)
		return -EINVAL;

	if (bitmap->state == GNIX_BITMAP_STATE_UNINITIALIZED) {
		GNIX_BITMAP_LOCK_INIT(bitmap);
	}

	GNIX_BITMAP_LOCK_ACQUIRE(bitmap);

	if (bitmap->length != 0 || nbits == 0) {
		GNIX_BITMAP_LOCK_RELEASE(bitmap);
		return -EINVAL;
	}

	bitmap->length = nbits;
	bitmap->arr = calloc(BITMAP_BLOCKS(nbits), sizeof(uint64_t));
	if (!bitmap->arr) {
		GNIX_BITMAP_LOCK_RELEASE(bitmap);
		return -ENOMEM;
	}

	for (i = 0; i < BITMAP_BLOCKS(bitmap->length); ++i)
		__gnix_init_block(&bitmap->arr[i]);

	bitmap->state = GNIX_BITMAP_STATE_READY;

	GNIX_BITMAP_LOCK_RELEASE(bitmap);

	return 0;
}

int realloc_bitmap(gnix_bitmap_t *bitmap, uint32_t nbits)
{
	gnix_bitmap_block_t *new_allocation;
	int blocks_to_allocate = BITMAP_BLOCKS(nbits);

	if (bitmap->state != GNIX_BITMAP_STATE_READY)
		return -EINVAL;

	GNIX_BITMAP_LOCK_ACQUIRE(bitmap);

	if (nbits == 0 && bitmap->arr) {
		free(bitmap->arr);
		bitmap->arr = NULL;
	} else {
		new_allocation = realloc(bitmap->arr,
				(blocks_to_allocate *
						sizeof(gnix_bitmap_block_t)));

		if (!new_allocation) {
			GNIX_BITMAP_LOCK_RELEASE(bitmap);
			return -ENOMEM;
		}

		bitmap->arr = new_allocation;
		bitmap->length = nbits;
	}

	GNIX_BITMAP_LOCK_RELEASE(bitmap);

	return 0;
}

void free_bitmap(gnix_bitmap_t *bitmap)
{
	if (bitmap->state != GNIX_BITMAP_STATE_READY)
		return;

	GNIX_BITMAP_LOCK_ACQUIRE(bitmap);

	bitmap->length = 0;
	if (bitmap->arr) {
		free(bitmap->arr);
		bitmap->arr = NULL;
	}

	bitmap->state = GNIX_BITMAP_STATE_FREE;

	GNIX_BITMAP_LOCK_RELEASE(bitmap);
}

