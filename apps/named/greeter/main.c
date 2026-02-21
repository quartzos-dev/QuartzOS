#include "../common/runtime.h"

static uint32_t fnv1a32(const char *s) {
    uint32_t h = 2166136261u;
    while (s && *s) {
        h ^= (uint8_t)*s++;
        h *= 16777619u;
    }
    return h;
}

void _start(void) {
    static const char *services[] = {
        "kernel", "scheduler", "memory", "filesystem", "desktop", "shell", "network"
    };

    uint32_t signature = 0;
    app_begin("greeter", "QuartzOS interactive startup report");

    app_write_line("welcome: quartz desktop session");
    app_write_line("boot phases:");
    for (uint32_t i = 0; i < 5; i++) {
        app_write("  phase ");
        app_write_u32(i + 1);
        app_write(": ");
        app_write_bar(i + 1, 5, 18, '#', '.');
        app_newline();
        app_yield_n(1);
    }

    app_write_line("service health:");
    for (uint32_t i = 0; i < (sizeof(services) / sizeof(services[0])); i++) {
        uint32_t hash = fnv1a32(services[i]);
        signature ^= hash;
        app_write("  ");
        app_write(services[i]);
        app_write("  state=online  id=0x");
        app_write_hex32(hash);
        app_newline();
        app_yield_n(1);
    }

    app_write("session signature: 0x");
    app_write_hex32(signature);
    app_newline();

    app_end("greeter");
    app_exit();
}
