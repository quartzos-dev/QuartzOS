#include <drivers/pit.h>
#include <kernel/slog.h>
#include <lib/string.h>

#define SLOG_MAX_ENTRIES 256
#define SLOG_COMPONENT_LEN 23
#define SLOG_MESSAGE_LEN 95

typedef struct slog_entry {
    uint64_t tick;
    uint8_t level;
    char component[SLOG_COMPONENT_LEN + 1];
    char message[SLOG_MESSAGE_LEN + 1];
} slog_entry_t;

static slog_entry_t g_entries[SLOG_MAX_ENTRIES];
static uint32_t g_next;
static uint32_t g_count;
static volatile unsigned int g_lock;
static slog_level_t g_min_level = SLOG_LEVEL_DEBUG;

static void lock_acquire(void) {
    while (__atomic_test_and_set(&g_lock, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause");
    }
}

static void lock_release(void) {
    __atomic_clear(&g_lock, __ATOMIC_RELEASE);
}

static void append_text(char *out, size_t out_len, const char *text) {
    if (!out || out_len == 0 || !text) {
        return;
    }
    strncat(out, text, out_len - strlen(out) - 1);
}

static void append_u64_dec(char *out, size_t out_len, uint64_t value) {
    char tmp[32];
    size_t idx = 0;
    do {
        tmp[idx++] = (char)('0' + (value % 10u));
        value /= 10u;
    } while (value != 0u && idx < sizeof(tmp));
    while (idx > 0) {
        char c[2];
        c[0] = tmp[idx - 1];
        c[1] = '\0';
        append_text(out, out_len, c);
        idx--;
    }
}

const char *slog_level_name(slog_level_t level) {
    switch (level) {
        case SLOG_LEVEL_DEBUG: return "debug";
        case SLOG_LEVEL_INFO: return "info";
        case SLOG_LEVEL_WARN: return "warn";
        case SLOG_LEVEL_ERROR: return "error";
        default: return "unknown";
    }
}

int slog_level_from_text(const char *text, slog_level_t *out_level) {
    if (!text || !out_level) {
        return 0;
    }
    if (strcmp(text, "debug") == 0) {
        *out_level = SLOG_LEVEL_DEBUG;
        return 1;
    }
    if (strcmp(text, "info") == 0) {
        *out_level = SLOG_LEVEL_INFO;
        return 1;
    }
    if (strcmp(text, "warn") == 0) {
        *out_level = SLOG_LEVEL_WARN;
        return 1;
    }
    if (strcmp(text, "error") == 0) {
        *out_level = SLOG_LEVEL_ERROR;
        return 1;
    }
    return 0;
}

void slog_init(void) {
    g_lock = 0;
    memset(g_entries, 0, sizeof(g_entries));
    g_next = 0;
    g_count = 0;
    g_min_level = SLOG_LEVEL_DEBUG;
}

void slog_set_min_level(slog_level_t level) {
    if (level < SLOG_LEVEL_DEBUG) {
        level = SLOG_LEVEL_DEBUG;
    }
    if (level > SLOG_LEVEL_ERROR) {
        level = SLOG_LEVEL_ERROR;
    }
    lock_acquire();
    g_min_level = level;
    lock_release();
}

slog_level_t slog_min_level(void) {
    lock_acquire();
    slog_level_t lvl = g_min_level;
    lock_release();
    return lvl;
}

void slog_log(slog_level_t level, const char *component, const char *message) {
    if (level < SLOG_LEVEL_DEBUG || level > SLOG_LEVEL_ERROR) {
        return;
    }

    lock_acquire();
    if (level < g_min_level) {
        lock_release();
        return;
    }

    slog_entry_t *ent = &g_entries[g_next];
    ent->tick = pit_ticks();
    ent->level = (uint8_t)level;
    strncpy(ent->component, component && *component ? component : "kernel", SLOG_COMPONENT_LEN);
    ent->component[SLOG_COMPONENT_LEN] = '\0';
    strncpy(ent->message, message && *message ? message : "-", SLOG_MESSAGE_LEN);
    ent->message[SLOG_MESSAGE_LEN] = '\0';

    g_next = (g_next + 1u) % SLOG_MAX_ENTRIES;
    if (g_count < SLOG_MAX_ENTRIES) {
        g_count++;
    }
    lock_release();
}

size_t slog_dump(char *out, size_t out_len, slog_level_t min_level) {
    if (!out || out_len == 0) {
        return 0;
    }
    if (min_level < SLOG_LEVEL_DEBUG) {
        min_level = SLOG_LEVEL_DEBUG;
    }
    if (min_level > SLOG_LEVEL_ERROR) {
        min_level = SLOG_LEVEL_ERROR;
    }

    lock_acquire();
    out[0] = '\0';

    uint32_t start = (g_count == SLOG_MAX_ENTRIES) ? g_next : 0;
    for (uint32_t i = 0; i < g_count; i++) {
        const slog_entry_t *ent = &g_entries[(start + i) % SLOG_MAX_ENTRIES];
        if (ent->level < min_level) {
            continue;
        }
        append_text(out, out_len, "[");
        append_u64_dec(out, out_len, ent->tick);
        append_text(out, out_len, "] ");
        append_text(out, out_len, slog_level_name((slog_level_t)ent->level));
        append_text(out, out_len, " ");
        append_text(out, out_len, ent->component);
        append_text(out, out_len, ": ");
        append_text(out, out_len, ent->message);
        append_text(out, out_len, "\n");
    }

    size_t written = strlen(out);
    lock_release();
    return written;
}

void slog_clear(void) {
    lock_acquire();
    memset(g_entries, 0, sizeof(g_entries));
    g_next = 0;
    g_count = 0;
    lock_release();
}
