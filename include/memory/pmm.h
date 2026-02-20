#ifndef MEMORY_PMM_H
#define MEMORY_PMM_H

#include <stddef.h>
#include <stdint.h>
#include <kernel/limine.h>

void pmm_init(struct limine_memmap_response *memmap, uint64_t hhdm_offset);
uint64_t pmm_alloc_page(void);
void pmm_free_page(uint64_t phys);
size_t pmm_total_pages(void);
size_t pmm_used_pages(void);

#endif
