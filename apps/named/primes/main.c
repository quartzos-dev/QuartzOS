#include "../common/runtime.h"

void _start(void) {
    uint32_t prev = 0;
    uint32_t found = 0;
    uint32_t twin_pairs = 0;
    uint32_t max_gap = 0;

    app_begin("primes", "Prime stream with gap analysis and twin-pair detection");

    for (uint32_t n = 2; found < 48; n++) {
        if (!app_is_prime_u32(n)) {
            continue;
        }

        uint32_t gap = (found == 0) ? 0 : (n - prev);
        if (gap > max_gap) {
            max_gap = gap;
        }
        if (gap == 2u) {
            twin_pairs++;
        }

        app_write("p[");
        app_write_padded_u32(found, 2);
        app_write("] = ");
        app_write_padded_u32(n, 4);
        app_write("  gap=");
        app_write_padded_u32(gap, 2);
        app_newline();

        prev = n;
        found++;
        app_yield();
    }

    app_write("largest gap: ");
    app_write_u32(max_gap);
    app_newline();

    app_write("twin prime pairs: ");
    app_write_u32(twin_pairs);
    app_newline();

    app_end("primes");
    app_exit();
}
