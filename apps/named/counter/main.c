#include "../common/runtime.h"

void _start(void) {
    uint32_t total = 0;
    uint32_t odd = 0;
    uint32_t even = 0;
    int32_t signed_accum = 0;

    app_begin("counter", "Multi-track counter with parity and drift analysis");

    app_write_line("forward pass:");
    for (uint32_t i = 1; i <= 24; i++) {
        total += i;
        if (i & 1u) {
            odd += i;
        } else {
            even += i;
        }
        signed_accum += (i & 1u) ? (int32_t)i : -(int32_t)i;

        app_write("  tick ");
        app_write_padded_u32(i, 2);
        app_write(" total=");
        app_write_padded_u32(total, 4);
        app_write(" drift=");
        app_write_i32(signed_accum);
        app_newline();
        app_yield();
    }

    app_write_line("reverse diagnostics:");
    for (int32_t i = 12; i >= 0; i--) {
        app_write("  rewind ");
        app_write_padded_u32((uint32_t)i, 2);
        app_write(" marker=");
        app_write_u32((uint32_t)(i * i));
        app_newline();
        app_yield();
    }

    app_write("parity ratio odd/even = ");
    app_write_u32(odd);
    app_write("/");
    app_write_u32(even);
    app_newline();

    app_write("checksum=0x");
    app_write_hex32(total ^ odd ^ even ^ (uint32_t)signed_accum);
    app_newline();

    app_end("counter");
    app_exit();
}
