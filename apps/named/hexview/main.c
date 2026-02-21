#include "../common/runtime.h"

void _start(void) {
    uint8_t buf[128];
    app_rng_t rng;
    uint32_t checksum = 0;

    app_rng_seed(&rng, 0x1EAFCAFEu);
    for (uint32_t i = 0; i < sizeof(buf); i++) {
        buf[i] = (uint8_t)(app_rng_next(&rng) >> 24);
        checksum += buf[i];
    }

    app_begin("hexview", "Hex dump with ASCII pane and rolling checksum");

    for (uint32_t row = 0; row < sizeof(buf) / 16u; row++) {
        uint32_t off = row * 16u;
        app_write("0x");
        app_write_hex16((uint16_t)off);
        app_write(": ");

        for (uint32_t i = 0; i < 16; i++) {
            app_write_hex8(buf[off + i]);
            app_write_ch(' ');
        }

        app_write(" | ");
        for (uint32_t i = 0; i < 16; i++) {
            uint8_t ch = buf[off + i];
            if (ch < 32u || ch > 126u) {
                app_write_ch('.');
            } else {
                app_write_ch((char)ch);
            }
        }

        app_newline();
        app_yield();
    }

    app_write("checksum(8-bit sum)=0x");
    app_write_hex32(checksum);
    app_newline();

    app_end("hexview");
    app_exit();
}
