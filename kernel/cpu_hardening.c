#include <kernel/cpu_hardening.h>
#include <stdint.h>

#define CPUID_EXT_FEATURES 7u
#define CPUID_EXT_SUBLEAF 0u
#define CPUID7_EBX_SMEP (1u << 7)
#define CPUID7_EBX_SMAP (1u << 20)
#define CR4_SMEP (1ull << 20)
#define CR4_SMAP (1ull << 21)

static bool g_smep_enabled;
static bool g_smap_enabled;

static void cpuid(uint32_t leaf, uint32_t subleaf,
                  uint32_t *eax, uint32_t *ebx,
                  uint32_t *ecx, uint32_t *edx) {
    uint32_t a = 0;
    uint32_t b = 0;
    uint32_t c = 0;
    uint32_t d = 0;
    __asm__ volatile("cpuid"
                     : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                     : "a"(leaf), "c"(subleaf));
    if (eax) {
        *eax = a;
    }
    if (ebx) {
        *ebx = b;
    }
    if (ecx) {
        *ecx = c;
    }
    if (edx) {
        *edx = d;
    }
}

static uint64_t read_cr4(void) {
    uint64_t value = 0;
    __asm__ volatile("mov %%cr4, %0" : "=r"(value));
    return value;
}

static void write_cr4(uint64_t value) {
    __asm__ volatile("mov %0, %%cr4" : : "r"(value) : "memory");
}

void cpu_hardening_init(void) {
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;
    cpuid(CPUID_EXT_FEATURES, CPUID_EXT_SUBLEAF, &eax, &ebx, &ecx, &edx);
    (void)eax;
    (void)ecx;
    (void)edx;

    uint64_t cr4 = read_cr4();
    if ((ebx & CPUID7_EBX_SMEP) != 0u) {
        cr4 |= CR4_SMEP;
        g_smep_enabled = true;
    }
    if ((ebx & CPUID7_EBX_SMAP) != 0u) {
        cr4 |= CR4_SMAP;
        g_smap_enabled = true;
    }
    write_cr4(cr4);
}

bool cpu_hardening_smep_enabled(void) {
    return g_smep_enabled;
}

bool cpu_hardening_smap_enabled(void) {
    return g_smap_enabled;
}

void cpu_user_access_begin(void) {
    if (g_smap_enabled) {
        __asm__ volatile("stac" : : : "memory");
    }
}

void cpu_user_access_end(void) {
    if (g_smap_enabled) {
        __asm__ volatile("clac" : : : "memory");
    }
}
