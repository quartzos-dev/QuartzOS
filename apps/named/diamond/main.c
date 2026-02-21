#include "../common/runtime.h"

static void draw_diamond(uint32_t radius, int hollow) {
    for (int32_t y = -(int32_t)radius; y <= (int32_t)radius; y++) {
        int32_t ay = y < 0 ? -y : y;
        int32_t span = (int32_t)radius - ay;

        app_spaces((uint32_t)ay + 1u);
        for (int32_t x = -span; x <= span; x++) {
            int32_t ax = x < 0 ? -x : x;
            if (hollow && ax != span && y != -(int32_t)radius && y != (int32_t)radius) {
                app_write_ch(' ');
            } else {
                app_write_ch('*');
            }
        }
        app_newline();
    }
}

void _start(void) {
    app_begin("diamond", "Filled and wireframe diamond renderer");

    app_write_line("filled:");
    draw_diamond(6u, 0);
    app_yield_n(4);

    app_write_line("wireframe:");
    draw_diamond(6u, 1);
    app_yield_n(4);

    app_end("diamond");
    app_exit();
}
