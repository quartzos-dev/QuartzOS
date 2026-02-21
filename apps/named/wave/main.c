#include "../common/runtime.h"

static const uint8_t sin16[16] = {
    8, 11, 14, 15, 14, 11, 8, 5,
    2, 1, 0, 1, 2, 5, 8, 11
};

void _start(void) {
    uint32_t energy = 0;

    app_begin("wave", "Multi-oscillator waveform scope");

    for (uint32_t t = 0; t < 48; t++) {
        uint32_t a = sin16[t & 15u];
        uint32_t b = sin16[(t * 3u) & 15u];
        uint32_t c = sin16[(t * 5u) & 15u];
        uint32_t mixed = (a * 3u + b * 2u + c) / 6u;
        energy += mixed * mixed;

        app_write("t=");
        app_write_padded_u32(t, 2);
        app_write(" amp=");
        app_write_padded_u32(mixed, 2);
        app_write(" ");
        app_spaces(16u - mixed);
        app_write_ch('|');
        app_repeat('*', mixed);
        app_newline();

        app_yield();
    }

    app_write("energy=");
    app_write_u32(energy);
    app_newline();

    app_end("wave");
    app_exit();
}
