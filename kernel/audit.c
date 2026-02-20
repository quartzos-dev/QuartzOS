#include <drivers/pit.h>
#include <kernel/audit.h>
#include <lib/string.h>

#define AUDIT_MAX_ENTRIES 256
#define AUDIT_ENTRY_LEN 128

static char g_entries[AUDIT_MAX_ENTRIES][AUDIT_ENTRY_LEN];
static unsigned int g_next;
static unsigned int g_count;
static volatile unsigned int g_lock;

static void lock_acquire(void) {
    while (__atomic_test_and_set(&g_lock, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause");
    }
}

static void lock_release(void) {
    __atomic_clear(&g_lock, __ATOMIC_RELEASE);
}

static void u64_to_dec(uint64_t value, char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return;
    }
    char tmp[32];
    size_t idx = 0;
    do {
        tmp[idx++] = (char)('0' + (value % 10u));
        value /= 10u;
    } while (value != 0u && idx < sizeof(tmp));

    size_t n = idx;
    if (n >= out_len) {
        n = out_len - 1;
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = tmp[n - 1 - i];
    }
    out[n] = '\0';
}

void audit_init(void) {
    g_next = 0;
    g_count = 0;
    g_lock = 0;
    memset(g_entries, 0, sizeof(g_entries));
}

void audit_log(const char *event, const char *detail) {
    if (!event) {
        return;
    }

    char line[AUDIT_ENTRY_LEN];
    char tick_buf[32];
    u64_to_dec(pit_ticks(), tick_buf, sizeof(tick_buf));

    line[0] = '\0';
    strncat(line, "[", sizeof(line) - strlen(line) - 1);
    strncat(line, tick_buf, sizeof(line) - strlen(line) - 1);
    strncat(line, "] ", sizeof(line) - strlen(line) - 1);
    strncat(line, event, sizeof(line) - strlen(line) - 1);
    if (detail && *detail) {
        strncat(line, " ", sizeof(line) - strlen(line) - 1);
        strncat(line, detail, sizeof(line) - strlen(line) - 1);
    }

    lock_acquire();
    strncpy(g_entries[g_next], line, AUDIT_ENTRY_LEN - 1);
    g_entries[g_next][AUDIT_ENTRY_LEN - 1] = '\0';
    g_next = (g_next + 1u) % AUDIT_MAX_ENTRIES;
    if (g_count < AUDIT_MAX_ENTRIES) {
        g_count++;
    }
    lock_release();
}

size_t audit_dump(char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return 0;
    }

    lock_acquire();
    out[0] = '\0';
    size_t written = 0;

    unsigned int start = 0;
    if (g_count == AUDIT_MAX_ENTRIES) {
        start = g_next;
    }

    for (unsigned int i = 0; i < g_count; i++) {
        unsigned int idx = (start + i) % AUDIT_MAX_ENTRIES;
        size_t len = strlen(g_entries[idx]);
        if (len == 0) {
            continue;
        }
        if (written + len + 1 >= out_len) {
            break;
        }
        memcpy(out + written, g_entries[idx], len);
        written += len;
        out[written++] = '\n';
    }

    if (written < out_len) {
        out[written] = '\0';
    } else {
        out[out_len - 1] = '\0';
    }
    lock_release();
    return written;
}

void audit_clear(void) {
    lock_acquire();
    memset(g_entries, 0, sizeof(g_entries));
    g_next = 0;
    g_count = 0;
    lock_release();
}
