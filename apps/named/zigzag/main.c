#include "../common/runtime.h"

void _start(void) {
    int32_t x = 0;
    int32_t y = 0;
    int32_t dx = 1;
    int32_t dy = 1;

    app_begin("zigzag", "2D zigzag path tracer with edge reflections");

    for (uint32_t step = 0; step < 34; step++) {
        app_write("step ");
        app_write_padded_u32(step, 2);
        app_write(" pos=(");
        app_write_i32(x);
        app_write(",");
        app_write_i32(y);
        app_write(") ");

        app_spaces((uint32_t)x);
        app_write_ch('*');
        app_newline();

        x += dx;
        y += dy;

        if (x <= 0 || x >= 24) {
            dx = -dx;
        }
        if (y <= 0 || y >= 8) {
            dy = -dy;
        }

        app_yield();
    }

    app_end("zigzag");
    app_exit();
}
