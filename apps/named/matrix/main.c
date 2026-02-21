#include "../common/runtime.h"

void _start(void) {
    app_rng_t rng;
    uint32_t checksum = 0;

    app_rng_seed(&rng, 0xC0DEC0DEu);
    app_begin("matrix", "Pseudo matrix-rain renderer with deterministic seed");

    for (uint32_t row = 0; row < 18; row++) {
        for (uint32_t col = 0; col < 42; col++) {
            uint32_t r = app_rng_next(&rng);
            uint8_t value = (uint8_t)((r >> 16) & 0x7Fu);
            checksum ^= ((uint32_t)value << (col & 7u));

            if ((r & 31u) == 0u) {
                app_write_ch('#');
            } else if ((r & 15u) < 8u) {
                app_write_ch((char)('A' + (value % 26u)));
            } else {
                app_write_ch((char)('0' + (value % 10u)));
            }
        }
        app_newline();
        app_yield();
    }

    app_write("checksum=0x");
    app_write_hex32(checksum);
    app_newline();

    app_end("matrix");
    app_exit();
}
