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
#include <errno.h>
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

/**
 * Tests to see if a bit has been set in the bit.
 *
 * @param   bitmap  a gnix_bitmap pointer to the bitmap struct
 * @param   index   index of the bit in the map to test
 * @return  0 if the bit is not set, 1 if the bit is set
 */
static inline int test_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	return __gnix_test_bit(bitmap, index);
}

/**
 * Sets a bit in the bitmap
 *
 * @param   bitmap  a gnix_bitmap pointer to the bitmap struct
 * @param   index   index of the bit in the map to set
 */
static inline void set_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	__gnix_set_bit(bitmap, index);
}

/**
 * Clears a bit in the bitmap
 *
 * @param   bitmap  a gnix_bitmap pointer to the bitmap struct
 * @param   index   index of the bit in the map to clear
 */
static inline void clear_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	__gnix_clear_bit(bitmap, index);
}

/**
 * Tests to see if a bit is set, then sets the bit in the bitmap
 *
 * @param   bitmap  a gnix_bitmap pointer to the bitmap struct
 * @param   index   index of the bit in the map to test and set
 * @return  0 if the bit was not set, 1 if the bit was already set
 */
static inline int test_and_set_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	return (__gnix_set_bit(bitmap, index) & GNIX_BIT_VALUE(index)) != 0;
}

/**
 * Tests to see if a bit is set, the clears the bit in the bitmap
 *
 * @param   bitmap  a gnix_bitmap pointer to the bitmap struct
 * @param   index   index of the bit in the map to test and set
 * @return  0 if the bit was not set, 1 if the bit was already set
 */
static inline int test_and_clear_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	return (__gnix_clear_bit(bitmap, index) & GNIX_BIT_VALUE(index)) != 0;
}

/**
 * Takes a gnix_bitmap and allocates the internal structures and performs
 *   generic setup based on the number of bits requested
 *
 * @param   bitmap  a gnix_bitmap pointer to the bitmap struct
 * @param   nbits   number of bits to request space for
 * @return  0       on success
 * @return  -EINVAL if bitmap is already initialized, or 0 is given as nbits
 * @return  -ENOMEM if there isn't sufficient memory available to create bitmap
 */
int alloc_bitmap(gnix_bitmap_t *bitmap, uint32_t nbits);

/**
 * Takes a gnix_bitmap and reallocates the internal structures to the requested
 *   size given in bits
 *
 * @note    On return of a ENOMEM error code, the bitmap will not be
 *          resized and will still be a valid and operable bitmap.
 *          The ENOMEM error only serves to indication that resources
 *          are	limited.
 *
 * @param   bitmap  a gnix_bitmap pointer to the bitmap struct
 * @param   nbits   number of bits to resize the bitmap to
 * @return  0       on success
 * @return  -EINVAL if the bitmap hasn't been allocated yet or nbits == 0
 * @return  -ENOMEM if there wasn't sufficient memory to expand the bitmap.
 */
int realloc_bitmap(gnix_bitmap_t *bitmap, uint32_t nbits);

/**
 * Frees the internal structures of gnix_bitmap
 *
 * @param   bitmap  a gnix_bitmap pointer to the bitmap struct
 * @return  0       on success
 * @return  -EINVAL if the internal resources are uninitialized or already free
 */
int free_bitmap(gnix_bitmap_t *bitmap);

/**
 * Sets every bit in the bitmap with (value != 0)
 *
 * @param   bitmap  a gnix_bitmap pointer to the bitmap struct
 * @param   value   an integer value to be compared with 0 to set bits to
 */
void fill_bitmap(gnix_bitmap_t *bitmap, uint64_t value);

/**
 * Finds the bit index of the first zero bit in the bitmap
 *
 * @param   bitmap	a gnix_bitmap pointer to the bitmap struct
 * @return  index	on success, returns an index s.t.
 *                    0 <= index < bitmap->length
 * @return  -EAGAIN on failure to find a zero bit
 */
int find_first_zero_bit(gnix_bitmap_t *bitmap);

/**
 * Finds the bit index of the first set bit in the bitmap
 *
 * @param   bitmap  a gnix_bitmap pointer to the bitmap struct
 * @return  index   on success, returns a index s.t.
 *                    0 <= index < bitmap->length
 * @return  -EAGAIN on failure to find a set bit
 */
int find_first_set_bit(gnix_bitmap_t *bitmap);

/**
 * Tests to verify that the bitmap is full
 *
 * @param   bitmap  a gnix_bitmap pointer to the bitmap struct
 * @return  0 if the bitmap has cleared bits, 1 if the bitmap is fully set
 */
static inline int bitmap_full(gnix_bitmap_t *bitmap)
{
	return find_first_zero_bit(bitmap) == -EAGAIN;
}

/**
 * Tests to verify that the bitmap is empty
 *
 * @param   bitmap  a gnix_bitmap pointer to the bitmap struct
 * @return  0 if the bitmap has set bits, 1 if the bitmap is fully cleared
 */
static inline int bitmap_empty(gnix_bitmap_t *bitmap)
{
	return find_first_set_bit(bitmap) == -EAGAIN;
}

#endif /* BITMAP_H_ */
