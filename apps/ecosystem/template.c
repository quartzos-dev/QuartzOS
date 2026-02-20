#include <stddef.h>
#include <stdint.h>

#ifndef APP_ID
#define APP_ID 0
#endif

#ifndef APP_SLUG
#define APP_SLUG "ecosystem_app"
#endif

#ifndef APP_TITLE
#define APP_TITLE "QuartzOS Ecosystem App"
#endif

#ifndef APP_PROFILE
#define APP_PROFILE "QuartzOS profile"
#endif

#ifndef APP_SUMMARY
#define APP_SUMMARY "No summary available."
#endif

#ifndef APP_CAPABILITIES
#define APP_CAPABILITIES "No capabilities listed."
#endif

#ifndef APP_TECH
#define APP_TECH "QuartzOS native stack."
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
    (void)sys_call3(1, (uint64_t)s, (uint64_t)n, 0);
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

static void app_write_line(const char *s) {
    app_write(s);
    app_newline();
}

static void app_write_u32(uint32_t value) {
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

static void app_yield_n(uint32_t count) {
    for (uint32_t i = 0; i < count; i++) {
        (void)sys_call3(3, 0, 0, 0);
    }
}

static void app_write_wrapped(const char *text, uint32_t width) {
    if (!text || !*text) {
        app_newline();
        return;
    }
    if (width < 24) {
        width = 24;
    }

    uint32_t col = 0;
    while (*text) {
        char ch = *text++;
        if (ch == '\n') {
            app_newline();
            col = 0;
            continue;
        }
        if (col >= width && ch == ' ') {
            app_newline();
            col = 0;
            continue;
        }
        if (col >= width) {
            app_newline();
            col = 0;
        }
        app_write_ch(ch);
        col++;
    }
    if (col != 0) {
        app_newline();
    }
}

void _start(void) {
    app_write("[");
    app_write(APP_SLUG);
    app_write_line("] starting");

    app_write("id: ");
    app_write_u32((uint32_t)APP_ID);
    app_newline();

    app_write("title: ");
    app_write_line(APP_TITLE);

    app_write("profile: ");
    app_write_line(APP_PROFILE);

    app_write_line("summary:");
    app_write_wrapped(APP_SUMMARY, 78);

    app_write_line("capabilities:");
    app_write_wrapped(APP_CAPABILITIES, 78);

    app_write_line("integration:");
    app_write_wrapped(APP_TECH, 78);

    app_yield_n(8);

    app_write("[");
    app_write(APP_SLUG);
    app_write_line("] done");

    (void)sys_call3(2, 0, 0, 0);
    for (;;) {
        __asm__ volatile("pause");
    }
}
