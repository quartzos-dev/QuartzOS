#include <drivers/pit.h>
#include <kernel/gdt.h>
#include <kernel/interrupts.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <process/task.h>
#include <process/user.h>
#include <stdint.h>

#define ELF_MAGIC 0x464c457fU
#define PT_LOAD 1
#define PF_X 0x1u
#define PF_W 0x2u
#define ELFCLASS64 2u
#define ELFDATA2LSB 1u
#define EV_CURRENT 1u
#define ET_EXEC 2u
#define EM_X86_64 0x3Eu
#define USER_STACK_TOP 0x0000007000000000ULL
#define USER_STACK_PAGES 16
#define USER_STACK_GUARD_LOW_PAGES 1
#define USER_STACK_GUARD_HIGH_PAGES 1
#define USER_STACK_RANDOM_PAGES 64
#define USER_STACK_REGION_PAGES \
    (USER_STACK_PAGES + USER_STACK_GUARD_LOW_PAGES + USER_STACK_GUARD_HIGH_PAGES + USER_STACK_RANDOM_PAGES)
#define USER_IMAGE_MIN 0x0000000000001000ULL
#define USER_IMAGE_MAX (USER_STACK_TOP - USER_STACK_REGION_PAGES * PAGE_SIZE)
#define USER_MAX_MAPPED_PAGES 8192
#define USER_MAX_PHDRS 256
#define USER_MAX_LOAD_SEGMENTS 64

typedef struct elf64_ehdr {
    uint32_t e_magic;
    uint8_t e_ident_rest[12];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed)) elf64_ehdr_t;

typedef struct elf64_phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed)) elf64_phdr_t;

extern void user_enter_ring3(uint64_t entry, uint64_t user_stack);
extern void user_return_from_syscall(void) __attribute__((noreturn));

uint64_t g_user_saved_rsp;
static volatile int g_user_active;
static volatile int g_user_in_ring3;

typedef struct mapped_page {
    uint64_t virt;
    uint64_t phys;
    uint64_t final_flags;
} mapped_page_t;

static mapped_page_t g_user_pages[USER_MAX_MAPPED_PAGES];
static size_t g_user_page_count;

static void user_unmap_all_pages(void) {
    for (size_t i = 0; i < g_user_page_count; i++) {
        vmm_unmap_page(g_user_pages[i].virt);
        pmm_free_page(g_user_pages[i].phys);
    }
    g_user_page_count = 0;
}

static mapped_page_t *find_user_page(uint64_t virt) {
    for (size_t i = 0; i < g_user_page_count; i++) {
        if (g_user_pages[i].virt == virt) {
            return &g_user_pages[i];
        }
    }
    return 0;
}

static int track_user_page(uint64_t virt, uint64_t phys, uint64_t final_flags) {
    mapped_page_t *existing = find_user_page(virt);
    if (existing) {
        if (existing->phys != phys) {
            return 0;
        }
        existing->final_flags |= (final_flags & (0xFFFULL | VMM_NX));
        if ((existing->final_flags & VMM_WRITE) != 0) {
            existing->final_flags |= VMM_NX;
        }
        return 1;
    }

    if (g_user_page_count >= USER_MAX_MAPPED_PAGES) {
        return 0;
    }
    g_user_pages[g_user_page_count].virt = virt;
    g_user_pages[g_user_page_count].phys = phys;
    g_user_pages[g_user_page_count].final_flags = final_flags & (0xFFFULL | VMM_NX);
    if ((g_user_pages[g_user_page_count].final_flags & VMM_WRITE) != 0) {
        g_user_pages[g_user_page_count].final_flags |= VMM_NX;
    }
    g_user_page_count++;
    return 1;
}

static uint64_t final_flags_from_program(uint32_t prog_flags) {
    uint64_t map = VMM_PRESENT | VMM_USER;
    if ((prog_flags & PF_W) != 0) {
        map |= VMM_WRITE;
    }
    if ((prog_flags & PF_X) == 0) {
        map |= VMM_NX;
    }
    if ((map & VMM_WRITE) != 0) {
        map |= VMM_NX;
    }
    return map;
}

static int apply_user_page_permissions(void) {
    for (size_t i = 0; i < g_user_page_count; i++) {
        mapped_page_t *page = &g_user_pages[i];
        uint64_t phys = vmm_translate(page->virt);
        if (phys == 0 || (phys & ~0xFFFULL) != page->phys) {
            return 0;
        }
        uint64_t final = page->final_flags | VMM_PRESENT | VMM_USER;
        if ((final & VMM_WRITE) != 0) {
            final |= VMM_NX;
        }
        vmm_map_page(page->virt, page->phys, final);
    }
    return 1;
}

static int map_segment(uint64_t vaddr, const uint8_t *src, uint64_t filesz, uint64_t memsz, uint32_t flags) {
    if (memsz < filesz || memsz == 0) {
        return 0;
    }
    if (vaddr < USER_IMAGE_MIN || vaddr >= USER_IMAGE_MAX) {
        return 0;
    }
    if (vaddr + memsz < vaddr || vaddr + memsz > USER_IMAGE_MAX) {
        return 0;
    }

    uint64_t start = vaddr & ~(PAGE_SIZE - 1);
    uint64_t end = (vaddr + memsz + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    if (end < start || end > USER_IMAGE_MAX) {
        return 0;
    }
    uint64_t final_flags = final_flags_from_program(flags);

    for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
        mapped_page_t *existing = find_user_page(addr);
        if (existing) {
            if (!track_user_page(addr, existing->phys, final_flags)) {
                return 0;
            }
            continue;
        }
        if (vmm_translate(addr) != 0) {
            return 0;
        }

        uint64_t phys = pmm_alloc_page();
        if (!phys) {
            return 0;
        }

        uint64_t map_flags = final_flags | VMM_WRITE | VMM_NX;

        vmm_map_page(addr, phys, map_flags);
        if (!track_user_page(addr, phys, final_flags)) {
            vmm_unmap_page(addr);
            pmm_free_page(phys);
            return 0;
        }
    }

    uint8_t *dst = (uint8_t *)vaddr;
    for (uint64_t i = 0; i < filesz; i++) {
        dst[i] = src[i];
    }
    for (uint64_t i = filesz; i < memsz; i++) {
        dst[i] = 0;
    }

    return 1;
}

static uint64_t stack_random_pages(const void *image, size_t size, uint64_t entry) {
    uint64_t seed = pit_ticks();
    seed ^= (uint64_t)(uintptr_t)image;
    seed ^= (uint64_t)size << 7;
    seed ^= entry << 11;
    seed ^= (seed << 13);
    seed ^= (seed >> 7);
    seed ^= (seed << 17);
    return seed % (USER_STACK_RANDOM_PAGES + 1ULL);
}

static int map_user_stack(const void *image, size_t size, uint64_t entry, uint64_t *user_sp_out) {
    if (!user_sp_out) {
        return 0;
    }

    uint64_t random_pages = stack_random_pages(image, size, entry);
    uint64_t region_base = USER_STACK_TOP - USER_STACK_REGION_PAGES * PAGE_SIZE;
    uint64_t guard_low = region_base + random_pages * PAGE_SIZE;
    uint64_t start = guard_low + USER_STACK_GUARD_LOW_PAGES * PAGE_SIZE;
    uint64_t top = start + USER_STACK_PAGES * PAGE_SIZE;
    uint64_t guard_high_end = top + USER_STACK_GUARD_HIGH_PAGES * PAGE_SIZE;

    if (guard_high_end > USER_STACK_TOP) {
        return 0;
    }

    for (uint64_t addr = start; addr < top; addr += PAGE_SIZE) {
        if (vmm_translate(addr) != 0) {
            return 0;
        }
        uint64_t phys = pmm_alloc_page();
        if (!phys) {
            return 0;
        }
        vmm_map_page(addr, phys, VMM_PRESENT | VMM_WRITE | VMM_USER | VMM_NX);
        if (!track_user_page(addr, phys, VMM_PRESENT | VMM_WRITE | VMM_USER | VMM_NX)) {
            vmm_unmap_page(addr);
            pmm_free_page(phys);
            return 0;
        }
    }
    *user_sp_out = top - 16u;
    return 1;
}

bool user_run_elf(const void *image, size_t size) {
    if (!image || size < sizeof(elf64_ehdr_t) || g_user_active) {
        return false;
    }

    const elf64_ehdr_t *eh = (const elf64_ehdr_t *)image;
    if (eh->e_magic != ELF_MAGIC || eh->e_phoff == 0 || eh->e_phnum == 0 ||
        eh->e_phentsize < sizeof(elf64_phdr_t)) {
        return false;
    }
    if (eh->e_ident_rest[0] != ELFCLASS64 ||
        eh->e_ident_rest[1] != ELFDATA2LSB ||
        eh->e_ident_rest[2] != EV_CURRENT) {
        return false;
    }
    if (eh->e_type != ET_EXEC || eh->e_machine != EM_X86_64 || eh->e_version != EV_CURRENT) {
        return false;
    }
    if (eh->e_ehsize < sizeof(elf64_ehdr_t) || eh->e_phnum > USER_MAX_PHDRS) {
        return false;
    }
    if (eh->e_phoff >= size) {
        return false;
    }
    uint64_t phdr_bytes = (uint64_t)eh->e_phentsize * eh->e_phnum;
    if (phdr_bytes > size || eh->e_phoff + phdr_bytes > size || eh->e_phoff + phdr_bytes < eh->e_phoff) {
        return false;
    }
    if (eh->e_entry < USER_IMAGE_MIN || eh->e_entry >= USER_IMAGE_MAX) {
        return false;
    }

    g_user_page_count = 0;
    const uint8_t *base = (const uint8_t *)image;
    int has_load = 0;
    uint16_t load_segments = 0;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        uint64_t off = eh->e_phoff + (uint64_t)i * eh->e_phentsize;
        if (off + sizeof(elf64_phdr_t) > size) {
            user_unmap_all_pages();
            return false;
        }

        const elf64_phdr_t *ph = (const elf64_phdr_t *)(base + off);
        if (ph->p_type != PT_LOAD) {
            continue;
        }
        has_load = 1;
        load_segments++;
        if (load_segments > USER_MAX_LOAD_SEGMENTS) {
            user_unmap_all_pages();
            return false;
        }
        if ((ph->p_flags & (PF_W | PF_X)) == (PF_W | PF_X)) {
            user_unmap_all_pages();
            return false;
        }
        if (ph->p_memsz == 0 || ph->p_memsz < ph->p_filesz) {
            user_unmap_all_pages();
            return false;
        }
        if (ph->p_align != 0 && (ph->p_align & (ph->p_align - 1u)) != 0) {
            user_unmap_all_pages();
            return false;
        }
        if (ph->p_align > PAGE_SIZE) {
            user_unmap_all_pages();
            return false;
        }
        if (ph->p_align != 0 &&
            ((ph->p_vaddr & (ph->p_align - 1u)) != (ph->p_offset & (ph->p_align - 1u)))) {
            user_unmap_all_pages();
            return false;
        }
        if (ph->p_vaddr % PAGE_SIZE != ph->p_offset % PAGE_SIZE) {
            user_unmap_all_pages();
            return false;
        }

        if (ph->p_offset > size || ph->p_filesz > size - ph->p_offset) {
            user_unmap_all_pages();
            return false;
        }

        if (!map_segment(ph->p_vaddr, base + ph->p_offset, ph->p_filesz, ph->p_memsz, ph->p_flags)) {
            user_unmap_all_pages();
            return false;
        }
    }

    uint64_t user_stack = 0;
    if (!map_user_stack(image, size, eh->e_entry, &user_stack)) {
        user_unmap_all_pages();
        return false;
    }
    if (!has_load || !apply_user_page_permissions()) {
        user_unmap_all_pages();
        return false;
    }

    uint64_t rsp;
    __asm__ volatile("mov %%rsp, %0" : "=r"(rsp));
    tss_set_rsp0(rsp - 8);

    g_user_active = 1;
    g_user_in_ring3 = 1;
    user_enter_ring3(eh->e_entry, user_stack);

    interrupts_enable();
    g_user_in_ring3 = 0;
    g_user_active = 0;
    user_unmap_all_pages();
    return true;
}

bool user_active(void) {
    return g_user_active != 0;
}

bool user_pointer_readable(const void *ptr, size_t len) {
    if (!ptr) {
        return false;
    }
    if (len == 0) {
        return true;
    }

    uint64_t start = (uint64_t)(uintptr_t)ptr;
    if (start < USER_IMAGE_MIN || start >= USER_STACK_TOP) {
        return false;
    }
    uint64_t last = start + (uint64_t)len - 1u;
    if (last < start || last >= USER_STACK_TOP) {
        return false;
    }

    uint64_t page = start & ~(PAGE_SIZE - 1ULL);
    uint64_t end_page = last & ~(PAGE_SIZE - 1ULL);
    while (1) {
        uint64_t flags = 0;
        if (!vmm_query_page(page, 0, &flags)) {
            return false;
        }
        if ((flags & (VMM_PRESENT | VMM_USER)) != (VMM_PRESENT | VMM_USER)) {
            return false;
        }
        if (page == end_page) {
            break;
        }
        page += PAGE_SIZE;
    }
    return true;
}

void user_exit_current(void) {
    if (g_user_in_ring3) {
        g_user_in_ring3 = 0;
        g_user_active = 0;
        user_return_from_syscall();
    }
    g_user_active = 0;
    task_exit();
}
