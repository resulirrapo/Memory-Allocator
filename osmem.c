// SPDX-License-Identifier: BSD-3-Clause

#include "block_meta.h"
#include "osmem.h"
#include <unistd.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <string.h>
#define MMAP_THRESHOLD 131072
#define page_size 4096

struct block_meta *global_base;

static void split(struct block_meta *block, size_t size)
{
	if (!block || block->size <= size + sizeof(struct block_meta))
		return;

    //calculating the new block size
	size_t new_block_size = block->size - size - sizeof(struct block_meta);
	struct block_meta *new_block = (struct block_meta *)((char *)block + sizeof(struct block_meta) + size);

	new_block->size = new_block_size;
	new_block->status = STATUS_FREE;
	new_block->next = block->next;
	new_block->prev = block;

	if (new_block->next)
		new_block->next->prev = new_block;

	block->size = size;
	block->next = new_block;
}

struct block_meta *coalesce(struct block_meta *block)
{
	if (!block)
		return NULL;

    //checks if the next block status is free and if yes it merges the current block with the next one
	if (block->next && block->next->status == STATUS_FREE) {
		block->size += sizeof(struct block_meta) + block->next->size;
		block->next = block->next->next;
		if (block->next)
			block->next->prev = block;
	}

    //checks if the prev block status is free and if yes it merges the current block with the prev one
	if (block->prev && block->prev->status == STATUS_FREE) {
		block->prev->size += sizeof(struct block_meta) + block->size;
		block->prev->next = block->next;
		if (block->next)
			block->next->prev = block->prev;
		block = block->prev;
	}

	return block;
}

struct block_meta *find_free_block(struct block_meta **last, size_t size)
{
	struct block_meta *current = global_base;

	while (current && !(current->status == STATUS_FREE && current->size >= size)) {
		*last = current;
		current = current->next;
	}
	return current;
}

size_t align_size(size_t size)
{
	return (size + (8 - 1)) & ~(8 - 1);
}

struct block_meta *request_space(struct block_meta *last, size_t size)
{
	struct block_meta *block;
	size_t allocation_size;

	// Determine the allocation size
	if (!global_base)
		allocation_size = MMAP_THRESHOLD;
	else
		allocation_size = size + sizeof(struct block_meta);

// increasing the program data space by allocation_size
void *request = sbrk(allocation_size);

	if (request == (void *)-1)
		return NULL;

	block = request;
	block->size = size;
	block->status = STATUS_ALLOC;
	block->next = NULL;
	block->prev = last;

	if (last)
		last->next = block;
	return block;
}

bool expand_block(struct block_meta *block, size_t new_size)
{
	if (block->status != STATUS_FREE)
		return false;

	size_t current_size = block->size;
	size_t needed_size = new_size - current_size;

	if (needed_size <= 0)
		return true;

	void *request = sbrk(needed_size);

	if (request == (void *)-1)
		return false;

	// Update block size and status
	block->size = new_size;
	block->status = STATUS_ALLOC;

	return true;
}


void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;

	size = align_size(size);
	struct block_meta *block;

	if (size >= MMAP_THRESHOLD) {
        block = mmap(NULL, size + sizeof(struct block_meta), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (block == MAP_FAILED)
			return NULL;
		block->size = size;
		block->status = STATUS_MAPPED;
		block->next = NULL;
		block->prev = NULL;
		return (block + 1); // Return a pointer to the payload, not the block_meta
	}

	if (!global_base) {
		block = request_space(NULL, size);
		if (!block)
			return NULL;
		global_base = block;
	} else {
		struct block_meta *last = global_base;

		block = find_free_block(&last, size);
		if (!block) {
			struct block_meta *it = global_base;

			while (it->next != NULL)
				it = it->next;
			block = it;
			if (!expand_block(it, size))
				block = request_space(last, size);
			if (!block)
				return NULL;
		} else {
			// Split the block if it's significantly larger than the requested size.
			split(block, size);
		}
	}

	block->status = STATUS_ALLOC;
	return (block + 1);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	// Get the block_meta structure corresponding to the given pointer.
	struct block_meta *block_ptr = (struct block_meta *)ptr - 1;

	if (block_ptr->status == STATUS_MAPPED) {
		munmap(block_ptr, block_ptr->size + sizeof(struct block_meta));
		return;
	}

	block_ptr->status = STATUS_FREE;

	// Coalesce with free blocks to reduce fragmentation.
	coalesce(block_ptr);
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0)
		return NULL;

	size_t total_size = nmemb * size;

	size_t aligned_size = align_size(total_size);

	aligned_size += sizeof(struct block_meta);
	// Check for overflow in size calculation
	if (total_size / size != nmemb)
		return NULL;

	struct block_meta *ptr = NULL;

    // Handle large allocations with mmap
	if (aligned_size > page_size) {
		ptr = (struct block_meta *)mmap(NULL, aligned_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		ptr->status = STATUS_MAPPED;
		ptr->size = aligned_size - sizeof(struct block_meta);

		if (ptr == MAP_FAILED)
			return NULL;

		return ptr + 1;
	}

		ptr = os_malloc(total_size);
		if (!ptr)
			return NULL;

	// Initialize allocated memory to zero
	memset(ptr, 0, total_size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block_ptr = (struct block_meta *)ptr - 1;

	if (block_ptr->size >= size)
		return ptr;

// Allocate a new block with malloc
void *new_ptr = os_malloc(size);

		if (!new_ptr)
			return NULL;
		memcpy(new_ptr, ptr, block_ptr->size);
		os_free(ptr);

		return new_ptr;
}
