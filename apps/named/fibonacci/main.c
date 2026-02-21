#include "../common/runtime.h"

void _start(void) {
    uint64_t a = 0;
    uint64_t b = 1;

    app_begin("fibonacci", "Sequence generator with ratio convergence tracking");
    app_write_line("idx   value                 ratio(next/current)");

    for (uint32_t i = 0; i < 32; i++) {
        uint64_t next = a + b;
        app_write_padded_u32(i, 2);
        app_write("  ");
        app_write_u64(a);

        app_write("    ");
        if (a == 0) {
            app_write_line("n/a");
        } else {
            uint32_t scaled = (uint32_t)((next * 1000ull) / a);
            app_write_fixed3(scaled);
            app_newline();
        }

        a = b;
        b = next;
        app_yield();
    }

    app_write("gcd(last pair)=");
    app_write_u32(app_gcd_u32((uint32_t)a, (uint32_t)b));
    app_newline();

    app_end("fibonacci");
    app_exit();
}
