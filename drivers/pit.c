#include <arch/x86_64/io.h>
#include <drivers/pit.h>

static volatile uint64_t g_ticks;

void pit_init(uint32_t freq_hz) {
    if (freq_hz == 0) {
        freq_hz = 100;
    }
    uint32_t divisor = 1193182u / freq_hz;

    outb(0x43, 0x36);
    outb(0x40, divisor & 0xFF);
    outb(0x40, (divisor >> 8) & 0xFF);

    g_ticks = 0;
}

void pit_handle_tick(void) {
    g_ticks++;
}

uint64_t pit_ticks(void) {
    return g_ticks;
}
