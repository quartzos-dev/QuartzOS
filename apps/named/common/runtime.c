#include "runtime.h"

static inline uint64_t sys_call3(uint64_t id, uint64_t a0, uint64_t a1, uint64_t a2) {
    uint64_t ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(id), "b"(a0), "c"(a1), "d"(a2)
        : "memory");
    return ret;
}

size_t app_strlen(const char *s) {
    size_t n = 0;
    if (!s) {
        return 0;
    }
    while (s[n]) {
        n++;
    }
    return n;
}

void app_write_len(const char *s, size_t n) {
    if (!s || n == 0) {
        return;
    }
    (void)sys_call3(1, (uint64_t)s, (uint64_t)n, 0);
}

void app_write(const char *s) {
    app_write_len(s, app_strlen(s));
}

void app_write_ch(char c) {
    app_write_len(&c, 1);
}

void app_newline(void) {
    app_write_ch('\n');
}

void app_write_line(const char *s) {
    app_write(s);
    app_newline();
}

void app_spaces(uint32_t count) {
    for (uint32_t i = 0; i < count; i++) {
        app_write_ch(' ');
    }
}

void app_repeat(char ch, uint32_t count) {
    for (uint32_t i = 0; i < count; i++) {
        app_write_ch(ch);
    }
}

void app_write_u32(uint32_t value) {
    char buf[10];
    size_t n = 0;

    if (value == 0) {
        app_write_ch('0');
        return;
    }

    while (value > 0 && n < sizeof(buf)) {
        buf[n++] = (char)('0' + (value % 10u));
        value /= 10u;
    }

    while (n > 0) {
        n--;
        app_write_ch(buf[n]);
    }
}

void app_write_u64(uint64_t value) {
    char buf[20];
    size_t n = 0;

    if (value == 0) {
        app_write_ch('0');
        return;
    }

    while (value > 0 && n < sizeof(buf)) {
        buf[n++] = (char)('0' + (value % 10u));
        value /= 10u;
    }

    while (n > 0) {
        n--;
        app_write_ch(buf[n]);
    }
}

void app_write_i32(int32_t value) {
    if (value < 0) {
        app_write_ch('-');
        app_write_u32((uint32_t)(-(int64_t)value));
    } else {
        app_write_u32((uint32_t)value);
    }
}

void app_write_hex8(uint8_t value) {
    static const char hex[] = "0123456789ABCDEF";
    char out[2];
    out[0] = hex[(value >> 4) & 0x0Fu];
    out[1] = hex[value & 0x0Fu];
    app_write_len(out, 2);
}

void app_write_hex16(uint16_t value) {
    app_write_hex8((uint8_t)(value >> 8));
    app_write_hex8((uint8_t)value);
}

void app_write_hex32(uint32_t value) {
    app_write_hex16((uint16_t)(value >> 16));
    app_write_hex16((uint16_t)value);
}

void app_write_percent_x10(uint32_t value_x10) {
    app_write_u32(value_x10 / 10u);
    app_write_ch('.');
    app_write_u32(value_x10 % 10u);
    app_write_ch('%');
}

void app_write_fixed3(uint32_t scaled) {
    app_write_u32(scaled / 1000u);
    app_write_ch('.');

    uint32_t frac = scaled % 1000u;
    app_write_ch((char)('0' + ((frac / 100u) % 10u)));
    app_write_ch((char)('0' + ((frac / 10u) % 10u)));
    app_write_ch((char)('0' + (frac % 10u)));
}

void app_write_padded_u32(uint32_t value, uint32_t width) {
    char buf[10];
    size_t n = 0;

    if (value == 0) {
        buf[n++] = '0';
    } else {
        while (value > 0 && n < sizeof(buf)) {
            buf[n++] = (char)('0' + (value % 10u));
            value /= 10u;
        }
    }

    while (width > n) {
        app_write_ch(' ');
        width--;
    }

    while (n > 0) {
        n--;
        app_write_ch(buf[n]);
    }
}

void app_write_bar(uint32_t done, uint32_t total, uint32_t width, char fill, char empty) {
    if (width == 0) {
        return;
    }

    if (total == 0) {
        total = 1;
    }
    if (done > total) {
        done = total;
    }

    uint32_t filled = (done * width) / total;
    app_write_ch('[');
    app_repeat(fill, filled);
    app_repeat(empty, width - filled);
    app_write_ch(']');
}

void app_write_wrapped(const char *text, uint32_t width) {
    uint32_t col = 0;
    const char *cursor = text;

    if (!cursor || !*cursor) {
        app_newline();
        return;
    }

    if (width < 24u) {
        width = 24u;
    }

    while (*cursor) {
        const char *word = cursor;
        uint32_t word_len = 0;

        while (*cursor && *cursor != ' ' && *cursor != '\n') {
            cursor++;
            word_len++;
        }

        if (word_len > 0) {
            if (col != 0 && (col + 1u + word_len) > width) {
                app_newline();
                col = 0;
            }
            if (col != 0) {
                app_write_ch(' ');
                col++;
            }
            app_write_len(word, word_len);
            col += word_len;
        }

        if (*cursor == '\n') {
            app_newline();
            col = 0;
            cursor++;
        } else if (*cursor == ' ') {
            cursor++;
        }
    }

    if (col != 0) {
        app_newline();
    }
}

void app_rng_seed(app_rng_t *rng, uint32_t seed) {
    if (!rng) {
        return;
    }
    rng->state = seed ? seed : 0xA5A5F00Du;
}

uint32_t app_rng_next(app_rng_t *rng) {
    if (!rng) {
        return 0;
    }
    rng->state = rng->state * 1664525u + 1013904223u;
    return rng->state;
}

uint32_t app_rng_range(app_rng_t *rng, uint32_t bound) {
    if (bound == 0u) {
        return 0u;
    }
    return app_rng_next(rng) % bound;
}

uint32_t app_u32_sqrt(uint32_t value) {
    uint32_t x = value;
    uint32_t y = (x + 1u) / 2u;

    if (value == 0u) {
        return 0u;
    }

    while (y < x) {
        x = y;
        y = (x + value / x) / 2u;
    }

    return x;
}

uint32_t app_gcd_u32(uint32_t a, uint32_t b) {
    while (b != 0u) {
        uint32_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

int app_is_prime_u32(uint32_t value) {
    if (value < 2u) {
        return 0;
    }
    if ((value & 1u) == 0u) {
        return value == 2u;
    }

    for (uint32_t d = 3u; d * d <= value; d += 2u) {
        if ((value % d) == 0u) {
            return 0;
        }
    }

    return 1;
}

void app_yield(void) {
    (void)sys_call3(3, 0, 0, 0);
}

void app_yield_n(uint32_t count) {
    for (uint32_t i = 0; i < count; i++) {
        app_yield();
    }
}

void app_begin(const char *name, const char *summary) {
    app_write("[");
    app_write(name);
    app_write_line("] starting");
    if (summary && summary[0]) {
        app_write("about: ");
        app_write_line(summary);
    }
}

void app_end(const char *name) {
    app_write("[");
    app_write(name);
    app_write_line("] done");
}

void app_exit(void) {
    (void)sys_call3(2, 0, 0, 0);
    for (;;) {
        __asm__ volatile("pause");
    }
}
