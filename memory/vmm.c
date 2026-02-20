#include <lib/string.h>
#include <memory/pmm.h>
#include <memory/vmm.h>

static uint64_t hhdm;
static uint64_t *kernel_pml4;
static volatile uint32_t vmm_lock;

static void vmm_lock_acquire(void) {
    while (__atomic_test_and_set(&vmm_lock, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause");
    }
}

static void vmm_lock_release(void) {
    __atomic_clear(&vmm_lock, __ATOMIC_RELEASE);
}

static inline uint64_t *phys_to_virt(uint64_t phys) {
    return (uint64_t *)(phys + hhdm);
}

void vmm_init(uint64_t hhdm_offset) {
    hhdm = hhdm_offset;
    vmm_lock = 0;
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    kernel_pml4 = phys_to_virt(cr3 & ~0xFFFULL);
}

static uint64_t *get_or_create(uint64_t *table, uint16_t index, uint64_t flags) {
    if (!(table[index] & 1)) {
        uint64_t phys = pmm_alloc_page();
        if (!phys) {
            return (uint64_t *)0;
        }
        uint64_t *next = phys_to_virt(phys);
        memset(next, 0, PAGE_SIZE);
        table[index] = phys | (flags & 0xFFFULL) | VMM_PRESENT;
    }
    return phys_to_virt(table[index] & ~0xFFFULL);
}

void vmm_map_page(uint64_t virt, uint64_t phys, uint64_t flags) {
    vmm_lock_acquire();
    uint16_t pml4_i = (virt >> 39) & 0x1FF;
    uint16_t pdpt_i = (virt >> 30) & 0x1FF;
    uint16_t pd_i = (virt >> 21) & 0x1FF;
    uint16_t pt_i = (virt >> 12) & 0x1FF;

    uint64_t *pdpt = get_or_create(kernel_pml4, pml4_i, VMM_WRITE | VMM_USER);
    if (!pdpt) {
        vmm_lock_release();
        return;
    }
    uint64_t *pd = get_or_create(pdpt, pdpt_i, VMM_WRITE | VMM_USER);
    if (!pd) {
        vmm_lock_release();
        return;
    }
    uint64_t *pt = get_or_create(pd, pd_i, VMM_WRITE | VMM_USER);
    if (!pt) {
        vmm_lock_release();
        return;
    }

    uint64_t entry = (phys & ~0xFFFULL) | (flags & (0xFFFULL | VMM_NX)) | VMM_PRESENT;
    pt[pt_i] = entry;
    __asm__ volatile("invlpg (%0)" : : "r"((void *)virt) : "memory");
    vmm_lock_release();
}

void vmm_unmap_page(uint64_t virt) {
    vmm_lock_acquire();
    uint16_t pml4_i = (virt >> 39) & 0x1FF;
    uint16_t pdpt_i = (virt >> 30) & 0x1FF;
    uint16_t pd_i = (virt >> 21) & 0x1FF;
    uint16_t pt_i = (virt >> 12) & 0x1FF;

    if (!(kernel_pml4[pml4_i] & 1)) {
        vmm_lock_release();
        return;
    }
    uint64_t *pdpt = phys_to_virt(kernel_pml4[pml4_i] & ~0xFFFULL);
    if (!(pdpt[pdpt_i] & 1)) {
        vmm_lock_release();
        return;
    }
    uint64_t *pd = phys_to_virt(pdpt[pdpt_i] & ~0xFFFULL);
    if (!(pd[pd_i] & 1)) {
        vmm_lock_release();
        return;
    }
    uint64_t *pt = phys_to_virt(pd[pd_i] & ~0xFFFULL);
    pt[pt_i] = 0;
    __asm__ volatile("invlpg (%0)" : : "r"((void *)virt) : "memory");
    vmm_lock_release();
}

uint64_t vmm_translate(uint64_t virt) {
    vmm_lock_acquire();
    uint16_t pml4_i = (virt >> 39) & 0x1FF;
    uint16_t pdpt_i = (virt >> 30) & 0x1FF;
    uint16_t pd_i = (virt >> 21) & 0x1FF;
    uint16_t pt_i = (virt >> 12) & 0x1FF;

    if (!(kernel_pml4[pml4_i] & 1)) {
        vmm_lock_release();
        return 0;
    }
    uint64_t *pdpt = phys_to_virt(kernel_pml4[pml4_i] & ~0xFFFULL);
    if (!(pdpt[pdpt_i] & 1)) {
        vmm_lock_release();
        return 0;
    }
    uint64_t *pd = phys_to_virt(pdpt[pdpt_i] & ~0xFFFULL);
    if (!(pd[pd_i] & 1)) {
        vmm_lock_release();
        return 0;
    }
    uint64_t *pt = phys_to_virt(pd[pd_i] & ~0xFFFULL);
    if (!(pt[pt_i] & 1)) {
        vmm_lock_release();
        return 0;
    }

    uint64_t phys = (pt[pt_i] & ~0xFFFULL) | (virt & 0xFFFULL);
    vmm_lock_release();
    return phys;
}

void vmm_map_range(uint64_t virt, uint64_t phys, size_t size, uint64_t flags) {
    size_t pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    for (size_t i = 0; i < pages; i++) {
        vmm_map_page(virt + i * PAGE_SIZE, phys + i * PAGE_SIZE, flags);
    }
}

uint64_t vmm_hhdm_offset(void) {
    return hhdm;
}
