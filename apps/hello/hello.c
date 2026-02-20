#include <stddef.h>
#include <stdint.h>

static inline uint64_t sys_call3(uint64_t id, uint64_t a0, uint64_t a1, uint64_t a2) {
    uint64_t ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(id), "b"(a0), "c"(a1), "d"(a2)
        : "memory");
    return ret;
}

static size_t cstrlen(const char *s) {
    size_t n = 0;
    while (s[n]) {
        n++;
    }
    return n;
}

void _start(void) {
    const char *msg = "hello from /bin/hello\n";
    sys_call3(1, (uint64_t)msg, cstrlen(msg), 0);

    for (int i = 0; i < 50; i++) {
        sys_call3(3, 0, 0, 0);
    }

    sys_call3(2, 0, 0, 0);
    for (;;) {
        __asm__ volatile("pause");
    }
}
