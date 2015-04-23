/*
 * Copyright 2015 Cray Inc. All rights reserved.
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
#define GNIX_BITMAP_BUCKET_LENGTH (1 << GNIX_BITMAP_BUCKET_BITS)
#define GNIX_BUCKET_INDEX(index) (index >> GNIX_BITMAP_BUCKET_BITS)
#define GNIX_BIT_INDEX(index) (index % GNIX_BITMAP_BUCKET_LENGTH)
#define GNIX_BIT_VALUE(index) (1 << GNIX_BIT_INDEX(index))

#define __PARTIAL_BLOCKS(nbits) (((nbits) % GNIX_BITMAP_BUCKET_LENGTH) ? 1 : 0)
#define __FULL_BLOCKS(nbits) ((nbits) >> GNIX_BITMAP_BUCKET_BITS)
#define GNIX_BITMAP_BLOCKS(nbits) \
	(__FULL_BLOCKS(nbits) + __PARTIAL_BLOCKS(nbits))

#if HAVE_ATOMICS
#include <stdatomic.h>

typedef atomic_uint_fast64_t gnix_bitmap_block_t;
typedef uint64_t gnix_bitmap_value_t;
#else
typedef struct atomic_uint64_t {
	fastlock_t lock;
	uint64_t val;
} gnix_bitmap_block_t;

typedef uint64_t gnix_bitmap_value_t;
#endif

typedef enum gnix_bitmap_state {
	GNIX_BITMAP_STATE_UNINITIALIZED = 0,
	GNIX_BITMAP_STATE_READY,
	GNIX_BITMAP_STATE_FREE,
} gnix_bitmap_state_e;

#define GNIX_LOCKLESS_BITMAP 1

#if GNIX_LOCKLESS_BITMAP
#define GNIX_BITMAP_LOCK_INIT(bitmap) do {} while (0)
#define GNIX_BITMAP_READ_ACQUIRE(bitmap) do {} while (0)
#define GNIX_BITMAP_READ_RELEASE(bitmap) do {} while (0)
#define GNIX_BITMAP_WRITE_ACQUIRE(bitmap) do {} while (0)
#define GNIX_BITMAP_WRITE_RELEASE(bitmap) do {} while (0)
#else
#define GNIX_BITMAP_LOCK_INIT(bitmap) \
	pthread_rwlock_init(&(bitmap)->lock, NULL)
#define GNIX_BITMAP_READ_ACQUIRE(bitmap) pthread_rwlock_rdlock(&(bitmap)->lock)
#define GNIX_BITMAP_READ_RELEASE(bitmap) pthread_rwlock_unlock(&(bitmap)->lock)
#define GNIX_BITMAP_WRITE_ACQUIRE(bitmap) pthread_rwlock_wrlock(&(bitmap)->lock)
#define GNIX_BITMAP_WRITE_RELEASE(bitmap) pthread_rwlock_unlock(&(bitmap)->lock)
#endif

typedef struct gnix_bitmap {
#if !GNIX_LOCKLESS_BITMAP
	pthread_rwlock_t lock;
#endif
	gnix_bitmap_state_e state;
	uint32_t length;
	gnix_bitmap_block_t *arr;
} gnix_bitmap_t;

#define READ_SAFE_RETURN(bitmap, expr) \
	({ \
		int __ret; \
		GNIX_BITMAP_READ_ACQUIRE(bitmap); \
		__ret = (expr); \
		GNIX_BITMAP_READ_RELEASE(bitmap); \
		__ret; \
	})

#define READ_SAFE_EXEC(bitmap, func) \
	do { \
		GNIX_BITMAP_READ_ACQUIRE(bitmap); \
		func; \
		GNIX_BITMAP_READ_RELEASE(bitmap); \
	} while (0)


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
	((atomic_load(&(bitmap)->arr[GNIX_BUCKET_INDEX(index)]) \
			& GNIX_BIT_VALUE(index)) != 0)
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
	uint64_t ret;

	fastlock_acquire(&block->lock);
	ret = (block->val & GNIX_BIT_VALUE(bit)) != 0;
	fastlock_release(&block->lock);

	return ret;
}
#endif

static inline int test_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	return READ_SAFE_RETURN(bitmap, __gnix_test_bit(bitmap, index));
}

static inline void set_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	READ_SAFE_EXEC(bitmap, __gnix_set_bit(bitmap, index));
}

static inline void clear_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	READ_SAFE_EXEC(bitmap, __gnix_clear_bit(bitmap, index));
}

static inline int test_and_set_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	return READ_SAFE_RETURN(bitmap,
			(__gnix_set_bit(bitmap, index) & GNIX_BIT_VALUE(index)) != 0);
}

static inline int test_and_clear_bit(gnix_bitmap_t *bitmap, uint32_t index)
{
	return READ_SAFE_RETURN(bitmap,
			(__gnix_clear_bit(bitmap, index) & GNIX_BIT_VALUE(index)) != 0);
}

int alloc_bitmap(gnix_bitmap_t *bitmap, uint32_t nbits);
int realloc_bitmap(gnix_bitmap_t *bitmap, uint32_t nbits);
void free_bitmap(gnix_bitmap_t *bitmap);
void fill_bitmap(gnix_bitmap_t *bitmap, uint64_t value);

#endif /* BITMAP_H_ */
