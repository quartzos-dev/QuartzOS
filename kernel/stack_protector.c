#include <drivers/pit.h>
#include <kernel/panic.h>
#include <kernel/stack_protector.h>
#include <stdint.h>

uintptr_t __stack_chk_guard = (uintptr_t)0x3C6EF372A54FF53Aull;

static uint64_t read_tsc(void) {
    uint32_t lo = 0;
    uint32_t hi = 0;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

void stack_protector_seed(void) {
    uint64_t seed = read_tsc();
    seed ^= pit_ticks();
    seed ^= (uint64_t)(uintptr_t)&seed;
    seed ^= 0x9E3779B97F4A7C15ull;
    if (seed == 0) {
        seed = 0xA5A5A5A55A5A5A5Aull;
    }
    __stack_chk_guard = (uintptr_t)seed;
}

__attribute__((noreturn)) void __stack_chk_fail(void) {
    panic("Kernel stack canary corruption detected");
}

__attribute__((noreturn)) void __stack_chk_fail_local(void) {
    __stack_chk_fail();
}
