#ifndef MEMORY_VMM_H
#define MEMORY_VMM_H

#include <stddef.h>
#include <stdint.h>

#define PAGE_SIZE 4096ULL

#define VMM_PRESENT  (1ULL << 0)
#define VMM_WRITE    (1ULL << 1)
#define VMM_USER     (1ULL << 2)
#define VMM_NX       (1ULL << 63)

void vmm_init(uint64_t hhdm_offset);
void vmm_map_page(uint64_t virt, uint64_t phys, uint64_t flags);
void vmm_unmap_page(uint64_t virt);
uint64_t vmm_translate(uint64_t virt);
void vmm_map_range(uint64_t virt, uint64_t phys, size_t size, uint64_t flags);
uint64_t vmm_hhdm_offset(void);

#endif
