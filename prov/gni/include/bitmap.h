/*
 * Copyright (c) 2015 Cray Inc. All rights reserved.
 *
 *  Created on: Apr 16, 2015
 *      Author: jswaro
 */

#ifndef BITMAP_H_
#define BITMAP_H_

#include <stdint.h>
#include <pthread.h>
#include "fi.h"


#define GNIX_BITMAP_BUCKET_BITS 6
#define GNIX_BITMAP_BUCKET_LENGTH (1ULL << GNIX_BITMAP_BUCKET_BITS)
#define GNIX_BUCKET_INDEX(index) ((index) >> GNIX_BITMAP_BUCKET_BITS)
#define GNIX_BIT_INDEX(index) ((index) % GNIX_BITMAP_BUCKET_LENGTH)
#define GNIX_BIT_VALUE(index) (1ULL << GNIX_BIT_INDEX(index))

#define __PARTIAL_BLOCKS(nbits) (((nbits) % GNIX_BITMAP_BUCKET_LENGTH) ? 1 : 0)
#define __FULL_BLOCKS(nbits) ((nbits) >> GNIX_BITMAP_BUCKET_BITS)
#define GNIX_BITMAP_BLOCKS(nbits) \
	(__FULL_BLOCKS(nbits) + __PARTIAL_BLOCKS(nbits))

typedef uint64_t gnix_bitmap_value_t;

#if HAVE_ATOMICS
#include <stdatomic.h>

typedef atomic_uint_fast64_t gnix_bitmap_block_t;
#else
typedef struct atomic_uint64_t {
	fastlock_t lock;
	gnix_bitmap_value_t val;
} gnix_bitmap_block_t;
#endif

typedef enum gnix_bitmap_state {
	GNIX_BITMAP_STATE_UNINITIALIZED = 0,
	GNIX_BITMAP_STATE_READY,
	GNIX_BITMAP_STATE_FREE,
} gnix_bitmap_state_e;

typedef struct gnix_bitmap {
	gnix_bitmap_state_e state;
	uint32_t length;
	gnix_bitmap_block_t *arr;
} gnix_bitmap_t;

#if HAVE_ATOMICS

#define __gnix_init_block(block) atomic_init(block, 0)
#define __gnix_set_block(bitmap, index, value) \
	atomic_store(&(bitmap)->arr[(index)], (value))
#define __gnix_load_block(bitmap, index) atomic_load(&(bitmap->arr[(index)]))
#define __gnix_set_bit(bitmap, bit) \
	atomic_fetch_or(&(bitmap)->arr[GNIX_BUCKET_INDEX(bit)], \
			GNIX_BIT_VALUE(bit))
#define __gnix_clear_bit(bitmap, bit) \
	atomic_fetch_and(&(bitmap)->arr[GNIX_BUCKET_INDEX(bit)], \
			~GNIX_BIT_VALUE(bit))
#define __gnix_test_bit(bitmap, bit) \
	((atomic_load(&(bitmap)->arr[GNIX_BUCKET_INDEX(bit)]) \
			& GNIX_BIT_VALUE(bit)) != 0)
#else

static inline void __gnix_init_block(gnix_bitmap_block_t *block)
{
	fastlock_init(&block->lock);
	block->val = 0llu;
}

static inline void __gnix_set_block(gnix_bitmap_t *bitmap, int index,
		uint64_t value)
{
	gnix_bitmap_block_t *block = &bitmap->arr[index];

	fastlock_acquire(&block->lock);
	block->val = value;
	fastlock_release(&block->lock);
}

static inline uint64_t __gnix_load_block(gnix_bitmap_t *bitmap, int index)
{
	gnix_bitmap_block_t *block = &bitmap->arr[index];
	uint64_t ret;

	fastlock_acquire(&block->lock);
	ret = block->val;
	fastlock_release(&block->lock);

	return ret;
}

static inline uint64_t __gnix_set_bit(gnix_bitmap_t *bitmap, int bit)
{
	gnix_bitmap_block_t *block = &bitmap->arr[GNIX_BUCKET_INDEX(bit)];
	uint64_t ret;

	fastlock_acquire(&block->lock);
	ret = block->val;
	block->val |= GNIX_BIT_VALUE(bit);
	fastlock_release(&block->lock);

	return ret;
}

static inline uint64_t __gnix_clear_bit(gnix_bitmap_t *bitmap, int bit)
{
	gnix_bitmap_block_t *block = &bitmap->arr[GNIX_BUCKET_INDEX(bit)];
	uint64_t ret;

	fastlock_acquire(&block->lock);
	ret = block->val;
	block->val &= ~GNIX_BIT_VALUE(bit);
	fastlock_release(&block->lock);

	return ret;
}

static inline int __gnix_test_bit(gnix_bitmap_t *bitmap, int bit)
{
	gnix_bitmap_block_t *block = &bitmap->arr[GNIX_BUCKET_INDEX(bit)];
	int ret;

	fastlock_acquire(&block->lock);
	ret = (block->val & GNIX_BIT_VALUE(bit)) != 0;
	fastlock_release(&block->lock);

	return ret;
}
#endif

static inline int test_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	return __gnix_test_bit(bitmap, index);
}

static inline void set_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	__gnix_set_bit(bitmap, index);
}

static inline void clear_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	__gnix_clear_bit(bitmap, index);
}

static inline int test_and_set_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	return (__gnix_set_bit(bitmap, index) & GNIX_BIT_VALUE(index)) != 0;
}

static inline int test_and_clear_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	return (__gnix_clear_bit(bitmap, index) & GNIX_BIT_VALUE(index)) != 0;
}

int alloc_bitmap(gnix_bitmap_t *bitmap, uint32_t nbits);
int realloc_bitmap(gnix_bitmap_t *bitmap, uint32_t nbits);
int free_bitmap(gnix_bitmap_t *bitmap);
void fill_bitmap(gnix_bitmap_t *bitmap, uint64_t value);

int find_first_zero_bit(gnix_bitmap_t *bitmap);
int find_first_set_bit(gnix_bitmap_t *bitmap);

static inline int bitmap_full(gnix_bitmap_t *bitmap)
{
	return find_first_zero_bit(bitmap) == bitmap->length;
}

static inline int bitmap_empty(gnix_bitmap_t *bitmap)
{
	return find_first_set_bit(bitmap) == bitmap->length;
}

#endif /* BITMAP_H_ */
