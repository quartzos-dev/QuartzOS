#include "../common/runtime.h"

void _start(void) {
    uint32_t dark = 0;
    uint32_t light = 0;

    app_begin("checker", "Checkerboard pattern engine with occupancy stats");
    app_write_line("   0123456789ABCDEF");

    for (uint32_t row = 0; row < 8; row++) {
        app_write("r");
        app_write_u32(row);
        app_write(" ");

        for (uint32_t col = 0; col < 16; col++) {
            char cell;
            if (((row + col) & 1u) == 0u) {
                cell = '#';
                dark++;
            } else {
                cell = '.';
                light++;
            }

            if (row == (col >> 1)) {
                cell = 'X';
            }

            app_write_ch(cell);
        }

        app_newline();
        app_yield();
    }

    app_write("dark=");
    app_write_u32(dark);
    app_write(" light=");
    app_write_u32(light);
    app_newline();

    app_end("checker");
    app_exit();
}
