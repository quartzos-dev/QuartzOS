#include <stddef.h>
#include <stdint.h>

#ifndef APP_NAME
#define APP_NAME "app"
#endif

#ifndef APP_KIND
#define APP_KIND 0
#endif

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

static void app_write_len(const char *s, size_t n) {
    if (!s || n == 0) {
        return;
    }
    sys_call3(1, (uint64_t)s, (uint64_t)n, 0);
}

static void app_write(const char *s) {
    app_write_len(s, cstrlen(s));
}

static void app_write_ch(char c) {
    app_write_len(&c, 1);
}

static void app_newline(void) {
    app_write_ch('\n');
}

static void app_yield_n(uint32_t count) {
    for (uint32_t i = 0; i < count; i++) {
        sys_call3(3, 0, 0, 0);
    }
}

static void app_write_u32(uint32_t value) {
    char buf[10];
    size_t n = 0;

    if (value == 0) {
        app_write_ch('0');
        return;
    }

    while (value > 0 && n < sizeof(buf)) {
        buf[n++] = (char)('0' + (value % 10));
        value /= 10;
    }

    while (n > 0) {
        n--;
        app_write_ch(buf[n]);
    }
}

static void app_write_hex8(uint8_t value) {
    static const char hex[] = "0123456789ABCDEF";
    char out[2];
    out[0] = hex[(value >> 4) & 0x0F];
    out[1] = hex[value & 0x0F];
    app_write_len(out, 2);
}

static void app_write_repeat(char ch, uint32_t count) {
    for (uint32_t i = 0; i < count; i++) {
        app_write_ch(ch);
    }
}

static void app_write_spaces(uint32_t count) {
    app_write_repeat(' ', count);
}

static void app_write_line(const char *s) {
    app_write(s);
    app_newline();
}

static void run_greeter(void) {
    app_write_line("Hello from QuartzOS user space.");
    app_write_line("This app confirms system calls are operational.");
    app_yield_n(6);
}

static void run_banner(void) {
    app_write_line("+----------------------+");
    app_write_line("|      QUARTZOS        |");
    app_write_line("|   NAMED APP DEMO     |");
    app_write_line("+----------------------+");
    app_yield_n(6);
}

static void run_counter(void) {
    for (uint32_t i = 1; i <= 12; i++) {
        app_write("count: ");
        app_write_u32(i);
        app_newline();
        app_yield_n(2);
    }
}

static void run_fibonacci(void) {
    uint32_t a = 0;
    uint32_t b = 1;

    for (uint32_t i = 0; i < 12; i++) {
        uint32_t next = a + b;
        app_write("fib[");
        app_write_u32(i);
        app_write("] = ");
        app_write_u32(a);
        app_newline();
        a = b;
        b = next;
        app_yield_n(2);
    }
}

static void run_primes(void) {
    uint32_t found = 0;
    uint32_t n = 2;

    while (found < 12) {
        int prime = 1;
        for (uint32_t d = 2; d * d <= n; d++) {
            if ((n % d) == 0) {
                prime = 0;
                break;
            }
        }

        if (prime) {
            app_write("prime[");
            app_write_u32(found);
            app_write("] = ");
            app_write_u32(n);
            app_newline();
            found++;
            app_yield_n(2);
        }
        n++;
    }
}

static void run_table(void) {
    for (uint32_t r = 1; r <= 10; r++) {
        app_write_u32(7);
        app_write(" x ");
        app_write_u32(r);
        app_write(" = ");
        app_write_u32(7 * r);
        app_newline();
        app_yield_n(1);
    }
}

static void run_spinner(void) {
    static const char frames[4] = {'|', '/', '-', '\\'};

    for (uint32_t i = 0; i < 24; i++) {
        app_write("spinner ");
        app_write_ch(frames[i & 3]);
        app_newline();
        app_yield_n(1);
    }
}

static void run_pulse(void) {
    for (uint32_t width = 1; width <= 10; width++) {
        app_write("pulse ");
        app_write_repeat('#', width);
        app_newline();
        app_yield_n(1);
    }
    for (int32_t width = 9; width >= 1; width--) {
        app_write("pulse ");
        app_write_repeat('#', (uint32_t)width);
        app_newline();
        app_yield_n(1);
    }
}

static void run_progress(void) {
    for (uint32_t pct = 0; pct <= 100; pct += 10) {
        uint32_t done = pct / 10;
        app_write("[");
        app_write_repeat('#', done);
        app_write_repeat('.', 10 - done);
        app_write("] ");
        app_write_u32(pct);
        app_write("%");
        app_newline();
        app_yield_n(1);
    }
}

static void run_matrix(void) {
    uint32_t seed = 0xC0FFEEU;

    for (uint32_t row = 0; row < 12; row++) {
        for (uint32_t col = 0; col < 24; col++) {
            seed = seed * 1664525U + 1013904223U;
            app_write_ch((char)('A' + ((seed >> 16) % 26U)));
        }
        app_newline();
        app_yield_n(1);
    }
}

static void run_zigzag(void) {
    int32_t pos = 0;
    int32_t dir = 1;

    for (uint32_t step = 0; step < 26; step++) {
        app_write_spaces((uint32_t)pos);
        app_write_line("*");
        pos += dir;
        if (pos == 0 || pos == 12) {
            dir = -dir;
        }
        app_yield_n(1);
    }
}

static void run_checker(void) {
    for (uint32_t row = 0; row < 8; row++) {
        for (uint32_t col = 0; col < 16; col++) {
            app_write_ch(((row + col) & 1U) ? '.' : '#');
        }
        app_newline();
        app_yield_n(1);
    }
}

static void run_stairs(void) {
    for (uint32_t step = 0; step < 10; step++) {
        app_write_spaces(step);
        app_write_line("[]");
        app_yield_n(1);
    }
}

static void run_diamond(void) {
    for (int32_t i = 0; i < 7; i++) {
        app_write_spaces((uint32_t)(6 - i));
        app_write_repeat('*', (uint32_t)(2 * i + 1));
        app_newline();
        app_yield_n(1);
    }
    for (int32_t i = 5; i >= 0; i--) {
        app_write_spaces((uint32_t)(6 - i));
        app_write_repeat('*', (uint32_t)(2 * i + 1));
        app_newline();
        app_yield_n(1);
    }
}

static void run_quotes(void) {
    static const char *quotes[] = {
        "Systems work when invariants are explicit.",
        "Simple kernels are easier to debug than clever kernels.",
        "Measure first, optimize second.",
        "Correctness is a feature."
    };

    for (uint32_t i = 0; i < (sizeof(quotes) / sizeof(quotes[0])); i++) {
        app_write("quote ");
        app_write_u32(i + 1);
        app_write(": ");
        app_write_line(quotes[i]);
        app_yield_n(2);
    }
}

static void run_weekdays(void) {
    static const char *days[] = {
        "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"
    };

    for (uint32_t i = 0; i < (sizeof(days) / sizeof(days[0])); i++) {
        app_write_u32(i + 1);
        app_write(". ");
        app_write_line(days[i]);
        app_yield_n(1);
    }
}

static void run_stats(void) {
    static const uint32_t sample[] = {12, 7, 22, 5, 18, 31, 11, 9};
    uint32_t min = sample[0];
    uint32_t max = sample[0];
    uint32_t sum = 0;

    for (uint32_t i = 0; i < (sizeof(sample) / sizeof(sample[0])); i++) {
        uint32_t v = sample[i];
        sum += v;
        if (v < min) {
            min = v;
        }
        if (v > max) {
            max = v;
        }
    }

    app_write("samples: ");
    app_write_u32((uint32_t)(sizeof(sample) / sizeof(sample[0])));
    app_newline();

    app_write("sum: ");
    app_write_u32(sum);
    app_newline();

    app_write("min: ");
    app_write_u32(min);
    app_newline();

    app_write("max: ");
    app_write_u32(max);
    app_newline();

    app_write("avg: ");
    app_write_u32(sum / (uint32_t)(sizeof(sample) / sizeof(sample[0])));
    app_write(".");
    app_write_u32(((sum % (uint32_t)(sizeof(sample) / sizeof(sample[0]))) * 10U) /
                  (uint32_t)(sizeof(sample) / sizeof(sample[0])));
    app_newline();

    app_yield_n(6);
}

static void run_hexview(void) {
    for (uint32_t row = 0; row < 4; row++) {
        app_write("0x");
        app_write_u32(row * 8);
        app_write(": ");
        for (uint32_t col = 0; col < 8; col++) {
            uint8_t value = (uint8_t)(row * 8 + col * 3);
            app_write_hex8(value);
            if (col != 7) {
                app_write_ch(' ');
            }
        }
        app_newline();
        app_yield_n(1);
    }
}

static void run_wave(void) {
    static const uint8_t levels[] = {4, 6, 8, 10, 11, 10, 8, 6, 4, 2, 1, 2, 4, 6, 8, 10};

    for (uint32_t i = 0; i < (sizeof(levels) / sizeof(levels[0])); i++) {
        uint32_t spaces = 12U - levels[i];
        app_write_spaces(spaces);
        app_write_line("*");
        app_yield_n(1);
    }
}

static void run_heartbeat(void) {
    static const char *frames[] = {
        "   .   ",
        "  .#.  ",
        " .###. ",
        ".#####.",
        " .###. ",
        "  .#.  ",
        "   .   "
    };

    for (uint32_t cycle = 0; cycle < 3; cycle++) {
        for (uint32_t i = 0; i < (sizeof(frames) / sizeof(frames[0])); i++) {
            app_write_line(frames[i]);
            app_yield_n(1);
        }
        app_write_line("-------");
    }
}

void _start(void) {
    app_write("[");
    app_write(APP_NAME);
    app_write_line("] starting");

    switch (APP_KIND) {
        case 1: run_greeter(); break;
        case 2: run_banner(); break;
        case 3: run_counter(); break;
        case 4: run_fibonacci(); break;
        case 5: run_primes(); break;
        case 6: run_table(); break;
        case 7: run_spinner(); break;
        case 8: run_pulse(); break;
        case 9: run_progress(); break;
        case 10: run_matrix(); break;
        case 11: run_zigzag(); break;
        case 12: run_checker(); break;
        case 13: run_stairs(); break;
        case 14: run_diamond(); break;
        case 15: run_quotes(); break;
        case 16: run_weekdays(); break;
        case 17: run_stats(); break;
        case 18: run_hexview(); break;
        case 19: run_wave(); break;
        case 20: run_heartbeat(); break;
        default:
            app_write_line("No behavior configured for this app.");
            break;
    }

    app_write("[");
    app_write(APP_NAME);
    app_write_line("] done");

    sys_call3(2, 0, 0, 0);
    for (;;) {
        __asm__ volatile("pause");
    }
}
