#include "../common/runtime.h"

void _start(void) {
    static const char lane_a[] = {'|', '/', '-', '\\'};
    static const char lane_b[] = {'<', '^', '>', 'v'};
    static const char lane_c[] = {'.', 'o', 'O', 'o'};

    app_begin("spinner", "Triple-lane spinner animation with phase offsets");

    for (uint32_t t = 0; t < 36; t++) {
        uint32_t load_x10 = (t * 37u) % 1000u;
        app_write("t=");
        app_write_padded_u32(t, 2);
        app_write("  ");
        app_write_ch(lane_a[t & 3u]);
        app_write("  ");
        app_write_ch(lane_b[(t + 1u) & 3u]);
        app_write("  ");
        app_write_ch(lane_c[(t + 2u) & 3u]);
        app_write("  load=");
        app_write_percent_x10(load_x10);
        app_write(" ");
        app_write_bar(load_x10, 1000u, 18, '#', '.');
        app_newline();
        app_yield();
    }

    app_end("spinner");
    app_exit();
}
