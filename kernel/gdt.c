#include <kernel/gdt.h>
#include <lib/string.h>

struct gdt_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_mid;
    uint8_t access;
    uint8_t granularity;
    uint8_t base_high;
} __attribute__((packed));

struct gdt_tss_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_mid;
    uint8_t access;
    uint8_t granularity;
    uint8_t base_high;
    uint32_t base_upper;
    uint32_t reserved;
} __attribute__((packed));

struct gdtr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

struct tss {
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iopb;
} __attribute__((packed));

static struct {
    struct gdt_entry entries[5];
    struct gdt_tss_entry tss;
} __attribute__((packed)) gdt;

static struct tss kernel_tss;

static void gdt_set_entry(int idx, uint32_t base, uint32_t limit, uint8_t access, uint8_t gran) {
    gdt.entries[idx].base_low = base & 0xFFFF;
    gdt.entries[idx].base_mid = (base >> 16) & 0xFF;
    gdt.entries[idx].base_high = (base >> 24) & 0xFF;

    gdt.entries[idx].limit_low = limit & 0xFFFF;
    gdt.entries[idx].granularity = ((limit >> 16) & 0x0F) | (gran & 0xF0);
    gdt.entries[idx].access = access;
}

static void gdt_set_tss(uint64_t base, uint32_t limit) {
    gdt.tss.limit_low = limit & 0xFFFF;
    gdt.tss.base_low = base & 0xFFFF;
    gdt.tss.base_mid = (base >> 16) & 0xFF;
    gdt.tss.access = 0x89;
    gdt.tss.granularity = (limit >> 16) & 0x0F;
    gdt.tss.base_high = (base >> 24) & 0xFF;
    gdt.tss.base_upper = (uint32_t)(base >> 32);
    gdt.tss.reserved = 0;
}

void tss_set_rsp0(uint64_t rsp0) {
    kernel_tss.rsp0 = rsp0;
}

void gdt_init(void) {
    memset(&gdt, 0, sizeof(gdt));
    memset(&kernel_tss, 0, sizeof(kernel_tss));

    gdt_set_entry(0, 0, 0, 0, 0);
    gdt_set_entry(1, 0, 0xFFFFF, 0x9A, 0xA0);
    gdt_set_entry(2, 0, 0xFFFFF, 0x92, 0xA0);
    gdt_set_entry(3, 0, 0xFFFFF, 0xFA, 0xA0);
    gdt_set_entry(4, 0, 0xFFFFF, 0xF2, 0xA0);

    kernel_tss.iopb = sizeof(kernel_tss);
    gdt_set_tss((uint64_t)&kernel_tss, sizeof(kernel_tss) - 1);

    struct gdtr gdtr = {
        .limit = sizeof(gdt) - 1,
        .base = (uint64_t)&gdt,
    };

    __asm__ volatile("lgdt %0" : : "m"(gdtr));

    __asm__ volatile(
        "movw $0x10, %%ax\n"
        "movw %%ax, %%ds\n"
        "movw %%ax, %%es\n"
        "movw %%ax, %%fs\n"
        "movw %%ax, %%gs\n"
        "movw %%ax, %%ss\n"
        "pushq $0x08\n"
        "leaq 1f(%%rip), %%rax\n"
        "pushq %%rax\n"
        "lretq\n"
        "1:\n"
        :
        :
        : "rax", "memory");

    uint16_t tss_selector = 5 * 8;
    __asm__ volatile("ltr %0" : : "r"(tss_selector));
}
