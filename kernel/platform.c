#include <kernel/platform.h>
#include <kernel/log.h>
#include <lib/string.h>
#include <stdint.h>

static int g_is_vm;
static char g_vm_vendor[13] = "bare-metal";
static int g_host_license_request_emitted;

static void cpuid_query(uint32_t leaf, uint32_t subleaf,
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

static char printable_or_unknown(uint8_t c) {
    if (c >= 32u && c <= 126u) {
        return (char)c;
    }
    return '?';
}

void platform_detect(void) {
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;

    g_is_vm = 0;
    strcpy(g_vm_vendor, "bare-metal");
    g_host_license_request_emitted = 0;

    cpuid_query(1u, 0u, &eax, &ebx, &ecx, &edx);
    if ((ecx & (1u << 31)) == 0u) {
        return;
    }

    g_is_vm = 1;
    cpuid_query(0x40000000u, 0u, &eax, &ebx, &ecx, &edx);

    uint8_t raw[12];
    memcpy(raw + 0, &ebx, sizeof(ebx));
    memcpy(raw + 4, &ecx, sizeof(ecx));
    memcpy(raw + 8, &edx, sizeof(edx));

    for (size_t i = 0; i < 12; i++) {
        g_vm_vendor[i] = printable_or_unknown(raw[i]);
    }
    g_vm_vendor[12] = '\0';
}

bool platform_is_virtual_machine(void) {
    return g_is_vm != 0;
}

const char *platform_vm_vendor(void) {
    return g_vm_vendor;
}

void platform_request_host_license_activation(void) {
    if (!g_is_vm || g_host_license_request_emitted) {
        return;
    }
    g_host_license_request_emitted = 1;
    kprintf("HOST_LICENSE_ACTIVATION_REQUIRED vendor=%s\n", g_vm_vendor);
}

void platform_clear_host_license_activation_request(void) {
    g_host_license_request_emitted = 0;
}
