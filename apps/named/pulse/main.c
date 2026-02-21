#include "../common/runtime.h"

static uint32_t triangle(uint32_t t, uint32_t period, uint32_t peak) {
    uint32_t x = t % period;
    uint32_t half = period / 2u;
    if (x <= half) {
        return (x * peak) / half;
    }
    return ((period - x) * peak) / half;
}

void _start(void) {
    app_begin("pulse", "Dual-envelope pulse generator");

    for (uint32_t t = 0; t < 40; t++) {
        uint32_t env1 = triangle(t, 20u, 24u);
        uint32_t env2 = triangle(t + 7u, 28u, 16u);
        uint32_t amp = env1 + env2;

        app_write("frame ");
        app_write_padded_u32(t, 2);
        app_write(" amp=");
        app_write_padded_u32(amp, 2);
        app_write(" ");
        app_write_bar(amp, 40u, 28u, '#', '.');
        app_newline();

        app_yield();
    }

    app_end("pulse");
    app_exit();
}
