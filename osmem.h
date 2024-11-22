/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include "printf.h"
#include <string.h>

struct block_meta *coalesce_blocks(struct block_meta *block);
struct block_meta *split_block(struct block_meta *block, size_t size);
struct block_meta *find_best_fit(size_t size);
void *preallocate(void);
struct block_meta *search_from_address(void *ptr);

void *os_malloc(size_t size);
void os_free(void *ptr);
void *os_calloc(size_t nmemb, size_t size);
void *os_realloc(void *ptr, size_t size);