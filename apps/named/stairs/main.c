#include "../common/runtime.h"

void _start(void) {
    uint32_t area = 0;

    app_begin("stairs", "Staircase blueprint with cumulative footprint metrics");

    for (uint32_t step = 1; step <= 12; step++) {
        area += step;
        app_write("step ");
        app_write_padded_u32(step, 2);
        app_write(" rise=");
        app_write_padded_u32(step * 18u, 3);
        app_write("mm run=");
        app_write_padded_u32(step * 24u, 3);
        app_write("  ");
        app_repeat(' ', 12u - step);
        app_repeat('=', step);
        app_newline();
        app_yield();
    }

    app_write("triangular footprint=");
    app_write_u32(area);
    app_write_line(" units");

    app_end("stairs");
    app_exit();
}
