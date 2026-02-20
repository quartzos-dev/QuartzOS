#include <lib/string.h>
#include <memory/heap.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <stdint.h>

#define HEAP_BASE 0xffffc10000000000ULL
#define HEAP_INITIAL_PAGES 32
#define HEAP_GROW_PAGES 16
#define HEAP_POISON_ALLOC 0xA5
#define HEAP_POISON_FREE 0xDD

typedef struct block {
    size_t size;
    int free;
    struct block *next;
} block_t;

static block_t *heap_head;
static uint64_t heap_end;
static volatile uint32_t heap_lock;

static void heap_lock_acquire(void) {
    while (__atomic_test_and_set(&heap_lock, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause");
    }
}

static void heap_lock_release(void) {
    __atomic_clear(&heap_lock, __ATOMIC_RELEASE);
}

static size_t align_up(size_t value, size_t align) {
    if (align == 0) {
        return value;
    }
    if (value > ((size_t)-1) - (align - 1)) {
        return 0;
    }
    return (value + align - 1) & ~(align - 1);
}

static int heap_grow(size_t pages) {
    for (size_t i = 0; i < pages; i++) {
        uint64_t phys = pmm_alloc_page();
        if (!phys) {
            return 0;
        }
        vmm_map_page(heap_end, phys, VMM_PRESENT | VMM_WRITE | VMM_NX);
        heap_end += PAGE_SIZE;
    }
    return 1;
}

void heap_init(void) {
    heap_lock = 0;
    heap_end = HEAP_BASE;
    if (!heap_grow(HEAP_INITIAL_PAGES)) {
        heap_head = 0;
        return;
    }

    heap_head = (block_t *)HEAP_BASE;
    heap_head->size = HEAP_INITIAL_PAGES * PAGE_SIZE - sizeof(block_t);
    heap_head->free = 1;
    heap_head->next = 0;
}

static void split_block(block_t *block, size_t size) {
    if (block->size <= size + sizeof(block_t) + 16) {
        return;
    }
    block_t *next = (block_t *)((uint8_t *)block + sizeof(block_t) + size);
    next->size = block->size - size - sizeof(block_t);
    next->free = 1;
    next->next = block->next;
    block->size = size;
    block->next = next;
}

void *kmalloc(size_t size) {
    if (!size) {
        return 0;
    }
    size = align_up(size, 16);
    if (size == 0) {
        return 0;
    }
    heap_lock_acquire();
    if (!heap_head) {
        heap_lock_release();
        return 0;
    }

    for (;;) {
        block_t *block = heap_head;
        while (block) {
            if (block->free && block->size >= size) {
                split_block(block, size);
                block->free = 0;
                void *ptr = (uint8_t *)block + sizeof(block_t);
                memset(ptr, HEAP_POISON_ALLOC, block->size);
                heap_lock_release();
                return ptr;
            }
            block = block->next;
        }

        if (size > ((size_t)-1) - sizeof(block_t)) {
            heap_lock_release();
            return 0;
        }
        size_t needed = size + sizeof(block_t);
        size_t needed_aligned = align_up(needed, PAGE_SIZE);
        if (needed_aligned == 0) {
            heap_lock_release();
            return 0;
        }
        size_t pages = needed_aligned / PAGE_SIZE;
        if (pages < HEAP_GROW_PAGES) {
            pages = HEAP_GROW_PAGES;
        }

        uint64_t old_heap_end = heap_end;
        if (!heap_grow(pages)) {
            heap_lock_release();
            return 0;
        }

        block_t *new_block = (block_t *)old_heap_end;
        new_block->size = pages * PAGE_SIZE - sizeof(block_t);
        new_block->free = 1;
        new_block->next = 0;

        block_t *tail = heap_head;
        while (tail->next) {
            tail = tail->next;
        }
        tail->next = new_block;
    }
}

void *kcalloc(size_t count, size_t size) {
    if (count != 0 && size > ((size_t)-1) / count) {
        return 0;
    }
    size_t total = count * size;
    void *ptr = kmalloc(total);
    if (ptr) {
        memset(ptr, 0, total);
    }
    return ptr;
}

static void coalesce(void) {
    block_t *block = heap_head;
    while (block && block->next) {
        if (block->free && block->next->free) {
            block->size += sizeof(block_t) + block->next->size;
            block->next = block->next->next;
            continue;
        }
        block = block->next;
    }
}

void kfree(void *ptr) {
    if (!ptr) {
        return;
    }
    heap_lock_acquire();
    if (!heap_head) {
        heap_lock_release();
        return;
    }
    block_t *block = (block_t *)((uint8_t *)ptr - sizeof(block_t));
    uint64_t addr = (uint64_t)block;
    if (addr >= HEAP_BASE && addr < heap_end) {
        memset(ptr, HEAP_POISON_FREE, block->size);
        block->free = 1;
        coalesce();
    }
    heap_lock_release();
}
