#include "../common/runtime.h"

static uint32_t fnv1a(const char *text) {
    uint32_t h = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        h ^= (uint32_t)(*p);
        h *= 16777619u;
    }
    return h;
}

int main(void) {
    static const char *samples[] = {
        "QuartzOS",
        "Security-first kernel",
        "license-lock",
        "compat-wrapper",
        "failsafe-integrity",
        "failsafe-intrusion"
    };

    app_begin("hashlab", "FNV-1a hash lab for deterministic test vectors");

    for (uint32_t i = 0; i < (uint32_t)(sizeof(samples) / sizeof(samples[0])); i++) {
        uint32_t h = fnv1a(samples[i]);
        app_write("sample ");
        app_write_u32(i + 1u);
        app_write(": ");
        app_write(samples[i]);
        app_write(" -> 0x");
        app_write_hex32(h);
        app_newline();
        app_yield();
    }

    app_end("hashlab");
    app_exit();
    return 0;
}
