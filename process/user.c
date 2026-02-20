#include <kernel/gdt.h>
#include <kernel/interrupts.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <process/task.h>
#include <process/user.h>
#include <stdint.h>

#define ELF_MAGIC 0x464c457fU
#define PT_LOAD 1
#define USER_STACK_TOP 0x0000007000000000ULL
#define USER_STACK_PAGES 16
#define USER_IMAGE_MIN 0x0000000000001000ULL
#define USER_IMAGE_MAX (USER_STACK_TOP - USER_STACK_PAGES * PAGE_SIZE)
#define USER_MAX_MAPPED_PAGES 8192

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

static int track_user_page(uint64_t virt, uint64_t phys) {
    if (g_user_page_count >= USER_MAX_MAPPED_PAGES) {
        return 0;
    }
    g_user_pages[g_user_page_count].virt = virt;
    g_user_pages[g_user_page_count].phys = phys;
    g_user_page_count++;
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

    for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
        if (vmm_translate(addr) != 0) {
            continue;
        }

        uint64_t phys = pmm_alloc_page();
        if (!phys) {
            return 0;
        }

        uint64_t map_flags = VMM_PRESENT | VMM_USER | VMM_WRITE;
        if ((flags & 1) == 0) {
            map_flags |= VMM_NX;
        }

        vmm_map_page(addr, phys, map_flags);
        if (!track_user_page(addr, phys)) {
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

static int map_user_stack(void) {
    uint64_t start = USER_STACK_TOP - USER_STACK_PAGES * PAGE_SIZE;
    for (uint64_t addr = start; addr < USER_STACK_TOP; addr += PAGE_SIZE) {
        if (vmm_translate(addr) != 0) {
            continue;
        }
        uint64_t phys = pmm_alloc_page();
        if (!phys) {
            return 0;
        }
        vmm_map_page(addr, phys, VMM_PRESENT | VMM_WRITE | VMM_USER | VMM_NX);
        if (!track_user_page(addr, phys)) {
            vmm_unmap_page(addr);
            pmm_free_page(phys);
            return 0;
        }
    }
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

        if (ph->p_offset + ph->p_filesz > size) {
            user_unmap_all_pages();
            return false;
        }

        if (!map_segment(ph->p_vaddr, base + ph->p_offset, ph->p_filesz, ph->p_memsz, ph->p_flags)) {
            user_unmap_all_pages();
            return false;
        }
    }

    if (!map_user_stack()) {
        user_unmap_all_pages();
        return false;
    }

    uint64_t rsp;
    __asm__ volatile("mov %%rsp, %0" : "=r"(rsp));
    tss_set_rsp0(rsp - 8);

    g_user_active = 1;
    g_user_in_ring3 = 1;
    user_enter_ring3(eh->e_entry, USER_STACK_TOP - 16);

    interrupts_enable();
    g_user_in_ring3 = 0;
    g_user_active = 0;
    user_unmap_all_pages();
    return true;
}

bool user_active(void) {
    return g_user_active != 0;
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
