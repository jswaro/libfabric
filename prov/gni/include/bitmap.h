/*
 * Copyright 2015 Cray Inc. All rights reserved.
 *
 *  Created on: Apr 16, 2015
 *      Author: jswaro
 */

#ifndef BITMAP_H_
#define BITMAP_H_

#include "fi.h"

#define GNIX_BITMAP_BUCKET_BITS 6
#define GNIX_BITMAP_BUCKET_LENGTH (1 << GNIX_BITMAP_BITS)

#define GNIX_BUCKET_INDEX(index) (index >> GNIX_BITMAP_BUCKET_BITS)
#define GNIX_BIT_INDEX(index) (index % GNIX_BITMAP_BUCKET_LENGTH)
#define GNIX_BIT_VALUE(index) (1 << GNIX_BIT_INDEX(index))

#define __PARTIAL_BLOCKS(nbits) (((nbits) % GNIX_BITMAP_BUCKET_LENGTH) ? 1 : 0)
#define __FULL_BLOCKS(nbits) ((nbits) >> GNIX_BITMAP_BUCKET_BITS)
#define BITMAP_BLOCKS(nbits) (__FULL_BLOCKS(nbits) + __PARTIAL_BLOCKS(nbits))

#define __GNIX_USE_BITMAP_LOCKS 0

#if __STDC_NO_ATOMICS__

#undef __GNIX_USE_BITMAP_LOCKS
#define __GNIX_USE_BITMAP_LOCKS 1

typedef uint64_t gnix_bitmap_block_t;
typedef uint64_t gnix_bitmap_value_t;

#define __gnix_init_block(block) (*(block) = 0)
#define __gnix_set_block(bitmap, index, value) \
	((bitmap)->arr[(index)] = (value))
#define __gnix_load_block(bitmap, index) ((bitmap)->arr[(index)])
#define __gnix_set_bit(bitmap, bit) \
	((bitmap)->arr[GNIX_BUCKET_INDEX(bit)] |= GNIX_BIT_VALUE(bit))
#define __gnix_clear_bit(bitmap, bit) \
	((bitmap)->arr[GNIX_BUCKET_INDEX(bit)] &= ~GNIX_BIT_VALUE(bit))
#define __gnix_test_bit(bitmap, bit) \
	((bitmap)->arr[(GNIX_BUCKET_INDEX(bit))] & (GNIX_BIT_VALUE(bit)) != 0)

static inline int __gnix_locked_block_cas(gnix_bitmap_block_t *block,
		gnix_bitmap_value_t old, gnix_bitmap_value_t new) {
	int rc = (*block == old);

	*block = new;
	return rc;
}

#define __gnix_atomic_block_cas(block, old, new) \
	__gnix_locked_block_cas(block, old, new)

#else

typedef atomic_uint_fast64_t gnix_bitmap_block_t;
typedef uint64_t gnix_bitmap_value_t;

#define __gnix_init_block(block) atomic_store(block, 0)
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
	((atomic_load(&(bitmap)->arr[GNIX_BUCKET_INDEX(index)]) \
			& GNIX_BIT_VALUE(index)) != 0)
#define __gnix_atomic_block_cas(block, old, new) \
	atomic_compare_exchange_strong(block, old, new)
#endif

#if __GNIX_USE_BITMAP_LOCKS
#define GNIX_BITMAP_LOCK_INIT(bitmap) fastlock_init(&(bitmap)->lock)
#define GNIX_BITMAP_LOCK_ACQUIRE(bitmap) fastlock_acquire(&(bitmap)->lock)
#define GNIX_BITMAP_LOCK_RELEASE(bitmap) fastlock_release(&(bitmap)->lock)
#else
#define GNIX_BITMAP_LOCK_INIT(bitmap) do {} while (0)
#define GNIX_BITMAP_LOCK_ACQUIRE(bitmap) do {} while (0)
#define GNIX_BITMAP_LOCK_RELEASE(bitmap) do {} while (0)
#endif

typedef enum gnix_bitmap_state {
	GNIX_BITMAP_STATE_UNINITIALIZED = 0,
	GNIX_BITMAP_STATE_READY,
	GNIX_BITMAP_STATE_FREE,
} gnix_bitmap_state_e;

typedef struct gnix_bitmap {
#if __GNIX_USE_BITMAP_LOCKS
	fastlock_t lock;
#endif
	gnix_bitmap_state_e state;
	uint32_t length;
	gnix_bitmap_block_t *arr;
} gnix_bitmap_t;

static inline int test_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	int rc;

	GNIX_BITMAP_LOCK_ACQUIRE(bitmap);
	rc = __gnix_test_bit(bitmap, index);
	GNIX_BITMAP_LOCK_RELEASE(bitmap);

	return rc;
}

static inline void set_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	GNIX_BITMAP_LOCK_ACQUIRE(bitmap);
	__gnix_set_bit(bitmap, index);
	GNIX_BITMAP_LOCK_RELEASE(bitmap);
}

static inline void clear_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	GNIX_BITMAP_LOCK_ACQUIRE(bitmap);
	__gnix_clear_bit(bitmap, index);
	GNIX_BITMAP_LOCK_RELEASE(bitmap);
}

static inline int test_and_set_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	int rc;

	GNIX_BITMAP_LOCK_ACQUIRE(bitmap);
	rc = __gnix_test_and_set_bit(bitmap, bit);
	GNIX_BITMAP_LOCK_RELEASE(bitmap);

	return rc;
}

static inline int test_and_clear_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	int rc;

	GNIX_BITMAP_LOCK_ACQUIRE(bitmap);
	rc = __gnix_test_and_clear_bit(bitmap, bit);
	GNIX_BITMAP_LOCK_RELEASE(bitmap);

	return rc;
}

static inline int __gnix_test_and_set_bit(gnix_bitmap_t *bitmap, uint32_t bit)
{
	gnix_bitmap_block_t *block = &bitmap->arr[GNIX_BUCKET_INDEX(bit)];
	int rc = __gnix_test_bit(bitmap, bit);
	gnix_bitmap_value_t old_value = __gnix_load_block(bitmap,
			GNIX_BUCKET_INDEX(bit));
	gnix_bitmap_value_t bit_to_set = GNIX_BIT_VALUE(bit);

	while (!__gnix_atomic_block_cas(block, old_value,
			(old_value | bit_to_set))) {
		old_value = __gnix_load_block(bitmap, GNIX_BUCKET_INDEX(bit));
	}

	return __rc;
}

static inline int __gnix_test_and_clear_bit(gnix_bitmap_t *bitmap, uint32_t bit)
{
	gnix_bitmap_block_t *block = &bitmap->arr[GNIX_BUCKET_INDEX(bit)];
	int rc = __gnix_test_bit(bitmap, bit);
	gnix_bitmap_value_t old_value = __gnix_load_block(bitmap,
			GNIX_BUCKET_INDEX(bit));
	gnix_bitmap_value_t bit_to_set = GNIX_BIT_VALUE(bit);

	while (!__gnix_atomic_block_cas(block, old_value,
			(old_value & ~bit_to_set))) {
		old_value = __gnix_load_block(bitmap, GNIX_BUCKET_INDEX(bit));
	}

	return __rc;
}

int alloc_bitmap(gnix_bitmap_t *bitmap, uint32_t nbits);
int realloc_bitmap(gnix_bitmap_t *bitmap, uint32_t nbits);
void free_bitmap(gnix_bitmap_t *bitmap);

int fill_bitmap(gnix_bitmap_t *bitmap, int value);

#endif /* BITMAP_H_ */
