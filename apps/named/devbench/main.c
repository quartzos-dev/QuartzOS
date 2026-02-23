#include "../common/runtime.h"

int main(void) {
    app_begin("devbench", "Integer pipeline micro-benchmark for scheduler tuning");

    uint64_t acc = 0x9e3779b97f4a7c15ull;
    for (uint32_t round = 0; round < 12; round++) {
        for (uint32_t i = 0; i < 25000; i++) {
            acc ^= (acc << 7) + (acc >> 3) + (uint64_t)i + (uint64_t)round * 17ull;
            acc = (acc << 9) | (acc >> (64 - 9));
            acc += 0x100000001b3ull;
        }
        app_write("round ");
        app_write_u32(round + 1u);
        app_write(" checksum=0x");
        app_write_hex32((uint32_t)(acc >> 32));
        app_write_hex32((uint32_t)acc);
        app_newline();
        app_yield();
    }

    app_write("final checksum=0x");
    app_write_hex32((uint32_t)(acc >> 32));
    app_write_hex32((uint32_t)acc);
    app_newline();

    app_end("devbench");
    app_exit();
    return 0;
}
