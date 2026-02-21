#include "../common/runtime.h"

void _start(void) {
    app_begin("table", "12x12 multiplication matrix with row and column totals");

    app_write("    | ");
    for (uint32_t c = 1; c <= 12; c++) {
        app_write_padded_u32(c, 4);
    }
    app_newline();
    app_write("----+-");
    app_repeat('-', 48);
    app_newline();

    for (uint32_t r = 1; r <= 12; r++) {
        uint32_t row_sum = 0;
        app_write_padded_u32(r, 3);
        app_write(" | ");
        for (uint32_t c = 1; c <= 12; c++) {
            uint32_t v = r * c;
            row_sum += v;
            app_write_padded_u32(v, 4);
        }
        app_write("  row=");
        app_write_u32(row_sum);
        app_newline();
        app_yield();
    }

    app_write("col-sum:");
    for (uint32_t c = 1; c <= 12; c++) {
        uint32_t col_sum = c * (12u * 13u / 2u);
        app_write(" ");
        app_write_u32(col_sum);
    }
    app_newline();

    app_end("table");
    app_exit();
}
