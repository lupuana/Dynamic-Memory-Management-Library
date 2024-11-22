// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"

#define MMAP_THRESHOLD (128 * 1024) // 128 KB
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define SIZE_T_ALG (ALIGN(sizeof(size_t)))
#define META_SIZE_ALG ALIGN(sizeof(struct block_meta))
#define ERROR ((void *)-1)

// to create a list for the heap blocks
struct block_meta *first_in_heap;

int is_calloc;

// used after every free
struct block_meta *coalesce_blocks(struct block_meta *block)
{
    // checking if the block is not the last in the heap
    if (block->next != NULL && block->next->status == STATUS_FREE) {
        struct block_meta *next_block = block->next;
        block->size += next_block->size + META_SIZE_ALG;
        block->size = ALIGN(block->size);

        // relinking to skip over the next_block
        block->next = next_block->next;
        if (next_block->next != NULL) {
            next_block->next->prev = block;
        }
        block->status = STATUS_FREE;
    }

    // checking if the block is not the first in the heap
    if (block->prev != NULL && block->prev->status == STATUS_FREE) {
        struct block_meta *prev_block = block->prev;
        prev_block->size += block->size + META_SIZE_ALG;
		prev_block->size = ALIGN(prev_block->size);

        // relinking to skip over the current block
        prev_block->next = block->next;
        if (block->next != NULL) {
            block->next->prev = prev_block;
        }

		// updating first_in_heap if necessary
		if (prev_block->prev == NULL) {
			first_in_heap = prev_block;
		}
		block = prev_block;
		block->status = STATUS_FREE;
    }
	return block;
}

struct block_meta *split_block(struct block_meta *block, size_t size)
{
    size = ALIGN(size);
	if (block == NULL || size > block->size) {
        return NULL;
    }

	// the split can only happen if the unused space is big enough
	size_t min_split_size = META_SIZE_ALG + ALIGNMENT;
	min_split_size = ALIGN(min_split_size);

    // no need for a split
    if (block->size < size + META_SIZE_ALG + min_split_size) {
        block->status = STATUS_ALLOC;
        return block;
    } else if (block->size >= size + META_SIZE_ALG + min_split_size) {
        if (block == first_in_heap) {
            first_in_heap = block;
        }

		// redefining the original block
		size_t unused_size = block->size - size - META_SIZE_ALG;
		unused_size = ALIGN(unused_size);
		block->size = size;
        block->status = STATUS_ALLOC;

		// defining the unused block
		struct block_meta *unused_block = (struct block_meta *)
			((char *)block + size + META_SIZE_ALG);
        unused_block->size = unused_size;
        unused_block->status = STATUS_FREE;

		if ((void *)unused_block < (void *)block || unused_block == NULL) {
            return block;
        }

		// relinking the 2 blocks together
		unused_block->prev = block;
        unused_block->next = block->next;
		// only relink if there is a block after
		if (block->next != NULL) {
			block->next->prev = unused_block;
		}
        block->next = unused_block;
        coalesce_blocks(unused_block);
	}
	return block;
}

struct block_meta *find_best_fit(size_t size)
{
	size = ALIGN(size);

	struct block_meta *current = first_in_heap;
	struct block_meta *best_fit = NULL;
	size_t dif_min;
	size_t difference;

	// for the first search for best_fit, so there is
	//a starting point for dif_min
	while (best_fit == NULL && current != NULL) {
		if (current->status == STATUS_FREE) {
			difference = current->size - size;
			// searching the heap for a free block
			//bigger than the required size
			if(difference >= 0) {
				dif_min = difference;
				best_fit = current;
			}
		}
		current = current->next;
	}
	// there is no need to search again if there
	//aren't any free blocks bigger
	if (best_fit == NULL) return NULL;

	while (current != NULL) {
		if (current->status == STATUS_FREE) {
			difference = current->size - size;
			// searching for the smallest positive difference
			if(difference >= 0 && difference < dif_min) {
				dif_min = difference;
				best_fit = current;
			}
		}
		current = current->next;
	}

	if (best_fit == NULL) {
		return NULL;
	} else {
		best_fit = split_block(best_fit, size);
        return best_fit;
	}
}

void *preallocate()
{
	if (first_in_heap == NULL) {
        first_in_heap = (struct block_meta *)sbrk(MMAP_THRESHOLD);
        DIE(first_in_heap == ERROR, "Error from preallocation with sbrk\n");

		// creating the first block
        first_in_heap->size = MMAP_THRESHOLD - META_SIZE_ALG;
        first_in_heap->status = STATUS_FREE;
        first_in_heap->next = NULL;
    }
	return (void *)(char *)(first_in_heap) + META_SIZE_ALG;
}

// to find a block from its address
struct block_meta *search_from_address(void *ptr)
{
	return (struct block_meta *) (((char *) ptr) - META_SIZE_ALG);
}

void *os_malloc(size_t size)
{
    if (size == 0) {
        return NULL;
    }

    size = ALIGN(size);

    if (is_calloc == 1) {
        struct block_meta *block;
        if (size + META_SIZE_ALG >= 4096) {
        block = mmap(NULL, size + META_SIZE_ALG,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x20, -1, 0);
        DIE(block == ERROR, "Error from mmap in os_malloc\n");

        block->size = size;
        block->status = STATUS_MAPPED;
        block->next = NULL;
        block->prev = NULL;
        memset((void *)((char *)block + META_SIZE_ALG), 0, size);
        return (void *)((char *)block + META_SIZE_ALG);
    }
    }

    // using mmap for large allocations
    if (size + META_SIZE_ALG >= MMAP_THRESHOLD) {
        struct block_meta *block = mmap(NULL, size + META_SIZE_ALG,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        DIE(block == ERROR, "Error from mmap in os_malloc\n");
        block->size = size;
        block->status = STATUS_MAPPED;
        block->next = NULL;
        block->prev = NULL;
        return (void *)((char *)block + META_SIZE_ALG);
    }

    // initializing heap for first allocation
    if (first_in_heap == NULL) {
        preallocate();
    }

    // searching the heap for a free block
    struct block_meta *block = find_best_fit(size);
    if (block) {
        block->status = STATUS_ALLOC;
        return (void *)((char *)block + META_SIZE_ALG);
    }

    // there is no free block, so the heap needs to be extended
    struct block_meta *last_block = first_in_heap;
    while (last_block && last_block->next) {
        last_block = last_block->next;
    }

    // calculating needed size
    size_t extend_size = size + META_SIZE_ALG;
    // if the last block is free, we can extend it
    //and only extend the heap with the needed size
    if (last_block != NULL && last_block->status == STATUS_FREE) {
        extend_size = size - last_block->size;
        if (extend_size <= 0) {
            // existing block is large enough
            last_block->status = STATUS_ALLOC;
            return (void *)((char *)last_block + META_SIZE_ALG);
        }
    }

    // extending heap
    struct block_meta *new_block = sbrk(extend_size);
    DIE(new_block == ERROR, "Error from extension with sbrk in os_malloc\n");

    if (last_block && last_block->status == STATUS_FREE) {
        // extending existing free block
        new_block->next = NULL;
        new_block->prev = last_block;
        last_block->next = new_block;
        new_block->status = STATUS_FREE;
        new_block->size = extend_size;
        last_block = coalesce_blocks(new_block);
        last_block->status = STATUS_ALLOC;
        return (void *)((char *)last_block + META_SIZE_ALG);
    } else {
        // creating new block
        new_block->size = size;
        new_block->status = STATUS_ALLOC;
        new_block->next = NULL;
        new_block->prev = last_block;
        if (last_block != NULL) {
            last_block->next = new_block;
        } else {
            first_in_heap = new_block;
        }
        return (void *)((char *)new_block + META_SIZE_ALG);
    }
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (ptr == NULL) return;

	struct block_meta *block = search_from_address(ptr);
    DIE(block == NULL, "Error: Invalid pointer or memory block not found\n");

	struct block_meta *current = block;
	if (current->status == STATUS_ALLOC) { // sbrk
		current->status = STATUS_FREE;
		current = coalesce_blocks(current);
	} else if (current->status == STATUS_MAPPED) { // mmap
		size_t total_size = block->size + META_SIZE_ALG;
        munmap((void *)block, total_size);
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
    if (nmemb == 0 || size == 0) {
        return NULL;
    }

    is_calloc = 1;
    void *ptr = os_malloc(nmemb * size);
    is_calloc = 0;
    if (ptr == NULL) {
        return NULL;
    }
    memset(ptr, 0, nmemb * size);
    return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
    if (ptr == NULL)
        return os_malloc(size);
    if (size == 0) {
        os_free(ptr);
        return NULL;
    }

    struct block_meta *start_block = search_from_address(ptr);
    size = ALIGN(size);

    if (start_block->status == STATUS_FREE) {
        return NULL;
    }

    if (size + META_SIZE_ALG >= MMAP_THRESHOLD || start_block->status == STATUS_MAPPED) {
        void *new_ptr = os_malloc(size);
        if (new_ptr == NULL)
            return NULL;
        size_t copy_size;
        if (start_block->size < size) {
        copy_size = start_block->size;
        } else {
        copy_size = size;
        }
        memcpy(new_ptr, ptr, copy_size);
        os_free(ptr);
        return new_ptr;
    }

    struct block_meta *new_block = NULL;

    if (start_block->size >= size) {
        new_block = split_block(start_block, size);
        return (void *)((char *)new_block + META_SIZE_ALG);
    } else if (start_block->size < size) {
        void *new_ptr = os_malloc(size);
        if (new_ptr == NULL)
            return NULL;
        memcpy(new_ptr, ptr, start_block->size);
        os_free(ptr);
        return new_ptr;
    }

    return (void *)((char *)new_block + META_SIZE_ALG);
}
