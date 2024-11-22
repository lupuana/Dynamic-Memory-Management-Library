# Dynamic Memory Management Library

This repository contains a custom **Dynamic Memory Management Library** developed as part of an assignment for the course **Operating Systems**. The project was created to explore low-level memory allocation techniques, working with dynamic memory, and implementing custom versions of commonly used memory management functions `malloc`, `free`, `calloc`, and `realloc`.

---

## Functionality

The library provides the following features:

### 1. **Dynamic Memory Allocation**
- Implements a custom version of `malloc` (**`os_malloc`**) for dynamic memory allocation.
- Allocates memory using two methods:
  - **`sbrk`**: For small allocations, extending the program's heap.
  - **`mmap`**: For large allocations (above 128 KB), mapping memory directly from the operating system.
- Ensures memory alignment to 8 bytes for compatibility with 64-bit systems.

### 2. **Memory Freeing**
- Custom `free` implementation (**`os_free`**) that:
  - Releases memory back to the heap for `sbrk`-allocated blocks.
  - Unmaps memory for `mmap`-allocated blocks using `munmap`.
- Supports block coalescing to merge adjacent free blocks, reducing fragmentation.

### 3. **Memory Zeroing and Allocation**
- Implements `calloc` (**`os_calloc`**) for allocating and initializing memory to zero.
- Combines zeroing functionality with the `os_malloc` mechanism.

### 4. **Memory Reallocation**
- Custom `realloc` (**`os_realloc`**) implementation that:
  - Allocates new memory if the requested size exceeds the current block size or moves to larger memory blocks when necessary.
  - Splits blocks for better memory utilization when shrinking allocations.

### 5. **Heap Management**
- Pre-allocates a chunk of memory for the heap on the first allocation.
- Maintains a doubly linked list of memory blocks for managing allocated and free regions.

### Key Constants and Structures:
- **Alignment:** All memory and metadata are aligned to 8 bytes.
- **Metadata:** Each memory block is preceded by a `block_meta` structure, storing information like size, status, and links to adjacent blocks.
- **Threshold:** Memory allocations larger than 128 KB are handled by `mmap` for efficiency.

---

## Challenges and Limitations

This project was both a learning experience and an opportunity to understand the intricacies of memory management in low-level programming. As a beginner in this domain, several challenges were encountered:
- Ensuring correct memory alignment and handling edge cases with block splitting and coalescing.
- Debugging and managing interactions between `sbrk` and `mmap`-allocated memory.
- Optimizing block searches for performance, balancing between simplicity and efficiency.

While the library provides functional implementations, it is not yet perfect or optimized for production use. This project represents a step in my learning journey and an exploration of operating system concepts. Feedback and contributions are welcome!
