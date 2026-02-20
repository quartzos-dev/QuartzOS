#include <kernel/log.h>
#include <lib/string.h>
#include <memory/pmm.h>

#define PMM_MAX_PAGES (1ULL << 22) /* 16 GiB tracked at 4 KiB pages */

static uint8_t bitmap[PMM_MAX_PAGES / 8];
static size_t total_pages_count;
static size_t used_pages_count;
static size_t alloc_hint;
static volatile uint32_t pmm_lock;

static void pmm_lock_acquire(void) {
    while (__atomic_test_and_set(&pmm_lock, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause");
    }
}

static void pmm_lock_release(void) {
    __atomic_clear(&pmm_lock, __ATOMIC_RELEASE);
}

static inline void bit_set(size_t page) {
    bitmap[page / 8] |= (uint8_t)(1U << (page % 8));
}

static inline void bit_clear(size_t page) {
    bitmap[page / 8] &= (uint8_t)~(1U << (page % 8));
}

static inline int bit_test(size_t page) {
    return (bitmap[page / 8] >> (page % 8)) & 1U;
}

void pmm_init(struct limine_memmap_response *memmap, uint64_t hhdm_offset) {
    (void)hhdm_offset;
    pmm_lock = 0;
    memset(bitmap, 0xFF, sizeof(bitmap));

    uint64_t highest = 0;
    for (uint64_t i = 0; i < memmap->entry_count; i++) {
        struct limine_memmap_entry *entry = memmap->entries[i];
        uint64_t end = entry->base;
        if (entry->length > (uint64_t)-1 - entry->base) {
            end = (uint64_t)-1;
        } else {
            end = entry->base + entry->length;
        }
        if (end > highest) {
            highest = end;
        }
    }

    total_pages_count = (size_t)(highest / 4096ULL + ((highest % 4096ULL) ? 1ULL : 0ULL));
    if (total_pages_count > PMM_MAX_PAGES) {
        total_pages_count = PMM_MAX_PAGES;
    }
    used_pages_count = total_pages_count;

    for (uint64_t i = 0; i < memmap->entry_count; i++) {
        struct limine_memmap_entry *entry = memmap->entries[i];
        if (entry->type != LIMINE_MEMMAP_USABLE) {
            continue;
        }

        uint64_t start = entry->base / 4096ULL;
        uint64_t pages = entry->length / 4096ULL;
        for (uint64_t p = 0; p < pages; p++) {
            uint64_t page = start + p;
            if (page >= total_pages_count || page == 0) {
                continue;
            }
            if (bit_test((size_t)page)) {
                bit_clear((size_t)page);
                used_pages_count--;
            }
        }
    }

    alloc_hint = 1;
    kprintf("PMM: total=%u pages used=%u pages\n", (unsigned)total_pages_count, (unsigned)used_pages_count);
}

uint64_t pmm_alloc_page(void) {
    pmm_lock_acquire();
    for (size_t i = alloc_hint; i < total_pages_count; i++) {
        if (!bit_test(i)) {
            bit_set(i);
            used_pages_count++;
            alloc_hint = i + 1;
            pmm_lock_release();
            return (uint64_t)i * 4096ULL;
        }
    }
    for (size_t i = 1; i < alloc_hint; i++) {
        if (!bit_test(i)) {
            bit_set(i);
            used_pages_count++;
            alloc_hint = i + 1;
            pmm_lock_release();
            return (uint64_t)i * 4096ULL;
        }
    }
    pmm_lock_release();
    return 0;
}

void pmm_free_page(uint64_t phys) {
    pmm_lock_acquire();
    size_t page = (size_t)(phys / 4096ULL);
    if (page == 0 || page >= total_pages_count) {
        pmm_lock_release();
        return;
    }
    if (bit_test(page)) {
        bit_clear(page);
        used_pages_count--;
        if (page < alloc_hint) {
            alloc_hint = page;
        }
    }
    pmm_lock_release();
}

size_t pmm_total_pages(void) {
    return total_pages_count;
}

size_t pmm_used_pages(void) {
    return used_pages_count;
}
