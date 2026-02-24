#include <drivers/pit.h>
#include <filesystem/sfs.h>
#include <kernel/audit.h>
#include <kernel/cron.h>
#include <kernel/license.h>
#include <kernel/secure_store.h>
#include <kernel/slog.h>
#include <kernel/trace.h>
#include <lib/string.h>

#define CRON_CFG_PATH "/etc/cron.cfg"
#define CRON_MAX_JOBS 32
#define PIT_HZ 100u

typedef enum cron_action {
    CRON_ACTION_SYNC = 1,
    CRON_ACTION_FSCK = 2,
    CRON_ACTION_AUDIT_CLEAR = 3,
    CRON_ACTION_TRACE_CLEAR = 4,
    CRON_ACTION_LICENSE_RELOAD = 5
} cron_action_t;

typedef struct cron_job {
    uint32_t id;
    cron_action_t action;
    uint32_t interval_ticks;
    uint64_t next_tick;
    uint32_t run_count;
    uint32_t fail_count;
    uint64_t last_run_tick;
    uint8_t last_ok;
    uint8_t enabled;
} cron_job_t;

static cron_job_t g_jobs[CRON_MAX_JOBS];
static uint32_t g_next_job_id = 1;
static volatile unsigned int g_lock;

static void lock_acquire(void) {
    while (__atomic_test_and_set(&g_lock, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause");
    }
}

static void lock_release(void) {
    __atomic_clear(&g_lock, __ATOMIC_RELEASE);
}

static const char *action_name(cron_action_t action) {
    switch (action) {
        case CRON_ACTION_SYNC: return "sync";
        case CRON_ACTION_FSCK: return "fsck";
        case CRON_ACTION_AUDIT_CLEAR: return "audit_clear";
        case CRON_ACTION_TRACE_CLEAR: return "trace_clear";
        case CRON_ACTION_LICENSE_RELOAD: return "license_reload";
        default: return "unknown";
    }
}

static int parse_action(const char *name, cron_action_t *out) {
    if (!name || !out) {
        return 0;
    }
    if (strcmp(name, "sync") == 0) {
        *out = CRON_ACTION_SYNC;
        return 1;
    }
    if (strcmp(name, "fsck") == 0) {
        *out = CRON_ACTION_FSCK;
        return 1;
    }
    if (strcmp(name, "audit_clear") == 0) {
        *out = CRON_ACTION_AUDIT_CLEAR;
        return 1;
    }
    if (strcmp(name, "trace_clear") == 0) {
        *out = CRON_ACTION_TRACE_CLEAR;
        return 1;
    }
    if (strcmp(name, "license_reload") == 0) {
        *out = CRON_ACTION_LICENSE_RELOAD;
        return 1;
    }
    return 0;
}

static int parse_u32_dec(const char *text, uint32_t *out) {
    if (!text || !*text || !out) {
        return 0;
    }
    uint32_t value = 0;
    for (const char *p = text; *p; p++) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
        uint32_t digit = (uint32_t)(*p - '0');
        if (value > (0xFFFFFFFFu - digit) / 10u) {
            return 0;
        }
        value = value * 10u + digit;
    }
    *out = value;
    return 1;
}

static void append_text(char *out, size_t out_len, const char *text) {
    if (!out || out_len == 0 || !text) {
        return;
    }
    size_t used = 0;
    while (used < out_len && out[used] != '\0') {
        used++;
    }
    if (used >= out_len - 1u) {
        out[out_len - 1u] = '\0';
        return;
    }
    strncat(out, text, out_len - used - 1u);
}

static void append_u32(char *out, size_t out_len, uint32_t value) {
    char tmp[16];
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

static cron_job_t *find_job(uint32_t id) {
    for (size_t i = 0; i < CRON_MAX_JOBS; i++) {
        if (g_jobs[i].id == id) {
            return &g_jobs[i];
        }
    }
    return 0;
}

static cron_job_t *alloc_job_slot(void) {
    for (size_t i = 0; i < CRON_MAX_JOBS; i++) {
        if (g_jobs[i].id == 0) {
            return &g_jobs[i];
        }
    }
    return 0;
}

static uint32_t seconds_to_ticks(uint32_t seconds) {
    uint64_t ticks64 = (uint64_t)seconds * PIT_HZ;
    if (ticks64 == 0) {
        ticks64 = PIT_HZ;
    }
    if (ticks64 > 0xFFFFFFFFu) {
        ticks64 = 0xFFFFFFFFu;
    }
    return (uint32_t)ticks64;
}

static bool run_job_action(const cron_job_t *job) {
    if (!job) {
        return false;
    }

    if (job->action == CRON_ACTION_SYNC) {
        return sfs_persistence_enabled() ? sfs_sync() : true;
    }
    if (job->action == CRON_ACTION_FSCK) {
        char report[512];
        return sfs_check(report, sizeof(report));
    }
    if (job->action == CRON_ACTION_AUDIT_CLEAR) {
        audit_clear();
        return true;
    }
    if (job->action == CRON_ACTION_TRACE_CLEAR) {
        trace_clear();
        return true;
    }
    if (job->action == CRON_ACTION_LICENSE_RELOAD) {
        license_reload();
        return true;
    }
    return false;
}

void cron_init(void) {
    memset(g_jobs, 0, sizeof(g_jobs));
    g_next_job_id = 1;
    g_lock = 0;
}

bool cron_add(const char *action_name_text, uint32_t seconds, uint32_t *out_id) {
    cron_action_t action = 0;
    if (!parse_action(action_name_text, &action) || seconds == 0) {
        return false;
    }

    lock_acquire();
    cron_job_t *job = alloc_job_slot();
    if (!job) {
        lock_release();
        return false;
    }

    memset(job, 0, sizeof(*job));
    job->id = g_next_job_id++;
    job->action = action;
    job->interval_ticks = seconds_to_ticks(seconds);
    job->next_tick = pit_ticks() + job->interval_ticks;
    job->run_count = 0;
    job->fail_count = 0;
    job->last_run_tick = 0;
    job->last_ok = 0;
    job->enabled = 1;

    if (out_id) {
        *out_id = job->id;
    }
    lock_release();

    audit_log("CRON_ADD", action_name(action));
    slog_log(SLOG_LEVEL_INFO, "cron", "job added");
    return true;
}

bool cron_remove(uint32_t id) {
    lock_acquire();
    for (size_t i = 0; i < CRON_MAX_JOBS; i++) {
        if (g_jobs[i].id != id) {
            continue;
        }
        memset(&g_jobs[i], 0, sizeof(g_jobs[i]));
        lock_release();
        audit_log("CRON_REMOVE", "job removed");
        slog_log(SLOG_LEVEL_INFO, "cron", "job removed");
        return true;
    }
    lock_release();
    return false;
}

bool cron_set_enabled(uint32_t id, bool enabled) {
    lock_acquire();
    cron_job_t *job = find_job(id);
    if (!job) {
        lock_release();
        return false;
    }
    job->enabled = enabled ? 1 : 0;
    if (enabled) {
        job->next_tick = pit_ticks() + job->interval_ticks;
    }
    lock_release();
    return true;
}

bool cron_run(uint32_t id) {
    lock_acquire();
    cron_job_t *job = find_job(id);
    if (!job) {
        lock_release();
        return false;
    }
    cron_job_t snapshot = *job;
    lock_release();

    bool ok = run_job_action(&snapshot);

    lock_acquire();
    job = find_job(id);
    if (!job) {
        lock_release();
        return false;
    }
    job->run_count++;
    job->last_run_tick = pit_ticks();
    job->last_ok = ok ? 1 : 0;
    if (!ok) {
        job->fail_count++;
    }
    job->next_tick = pit_ticks() + job->interval_ticks;
    lock_release();

    audit_log(ok ? "CRON_OK" : "CRON_FAIL", action_name(snapshot.action));
    slog_log(ok ? SLOG_LEVEL_INFO : SLOG_LEVEL_WARN, "cron", ok ? "job run ok" : "job run failed");
    return true;
}

size_t cron_list(char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return 0;
    }

    lock_acquire();
    out[0] = '\0';
    append_text(out, out_len, "id action interval_s enabled runs fails\n");
    for (size_t i = 0; i < CRON_MAX_JOBS; i++) {
        if (g_jobs[i].id == 0) {
            continue;
        }
        append_u32(out, out_len, g_jobs[i].id);
        append_text(out, out_len, " ");
        append_text(out, out_len, action_name(g_jobs[i].action));
        append_text(out, out_len, " ");
        append_u32(out, out_len, g_jobs[i].interval_ticks / PIT_HZ);
        append_text(out, out_len, " ");
        append_text(out, out_len, g_jobs[i].enabled ? "on" : "off");
        append_text(out, out_len, " ");
        append_u32(out, out_len, g_jobs[i].run_count);
        append_text(out, out_len, " ");
        append_u32(out, out_len, g_jobs[i].fail_count);
        append_text(out, out_len, "\n");
    }
    size_t written = strlen(out);
    lock_release();
    return written;
}

size_t cron_actions(char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return 0;
    }
    out[0] = '\0';
    append_text(out, out_len, "sync\n");
    append_text(out, out_len, "fsck\n");
    append_text(out, out_len, "audit_clear\n");
    append_text(out, out_len, "trace_clear\n");
    append_text(out, out_len, "license_reload\n");
    return strlen(out);
}

bool cron_save(void) {
    char out[2048];
    out[0] = '\0';

    lock_acquire();
    for (size_t i = 0; i < CRON_MAX_JOBS; i++) {
        if (g_jobs[i].id == 0) {
            continue;
        }
        append_text(out, sizeof(out), action_name(g_jobs[i].action));
        append_text(out, sizeof(out), " ");
        append_u32(out, sizeof(out), g_jobs[i].interval_ticks / PIT_HZ);
        append_text(out, sizeof(out), " ");
        append_text(out, sizeof(out), g_jobs[i].enabled ? "1" : "0");
        append_text(out, sizeof(out), "\n");
    }
    lock_release();

    if (!secure_store_write_text(CRON_CFG_PATH, out, strlen(out), sfs_persistence_enabled())) {
        return false;
    }
    return true;
}

bool cron_load(void) {
    char buf[2048];
    size_t read = 0;
    if (!secure_store_read_text(CRON_CFG_PATH, buf, sizeof(buf), &read)) {
        return false;
    }
    buf[read] = '\0';

    lock_acquire();
    memset(g_jobs, 0, sizeof(g_jobs));
    g_next_job_id = 1;
    lock_release();

    size_t pos = 0;
    while (pos < read) {
        size_t start = pos;
        while (pos < read && buf[pos] != '\n') {
            pos++;
        }
        size_t end = pos;
        if (pos < read && buf[pos] == '\n') {
            pos++;
        }
        if (end <= start) {
            continue;
        }

        char line[128];
        size_t len = end - start;
        if (len >= sizeof(line)) {
            continue;
        }
        memcpy(line, &buf[start], len);
        line[len] = '\0';
        if (line[0] == '#') {
            continue;
        }

        char *action = line;
        while (*action == ' ' || *action == '\t') {
            action++;
        }
        if (!*action) {
            continue;
        }
        char *p = action;
        while (*p && *p != ' ' && *p != '\t') {
            p++;
        }
        if (!*p) {
            continue;
        }
        *p++ = '\0';

        while (*p == ' ' || *p == '\t') {
            p++;
        }
        char *sec = p;
        while (*p && *p != ' ' && *p != '\t') {
            p++;
        }
        if (!*p) {
            continue;
        }
        *p++ = '\0';

        while (*p == ' ' || *p == '\t') {
            p++;
        }
        char *enabled = p;
        while (*p && *p != ' ' && *p != '\t') {
            p++;
        }
        *p = '\0';

        uint32_t seconds = 0;
        if (!parse_u32_dec(sec, &seconds) || seconds == 0) {
            continue;
        }
        uint32_t id = 0;
        if (!cron_add(action, seconds, &id)) {
            continue;
        }
        if (enabled[0] == '0') {
            (void)cron_set_enabled(id, false);
        }
    }

    return true;
}

void cron_tick(void) {
    uint64_t now = pit_ticks();

    for (size_t i = 0; i < CRON_MAX_JOBS; i++) {
        lock_acquire();
        cron_job_t *job = &g_jobs[i];
        if (job->id == 0 || !job->enabled || now < job->next_tick) {
            lock_release();
            continue;
        }
        cron_job_t snapshot = *job;
        lock_release();

        bool ok = run_job_action(&snapshot);

        lock_acquire();
        job = &g_jobs[i];
        if (job->id != snapshot.id || !job->enabled) {
            lock_release();
            continue;
        }
        job->run_count++;
        job->last_run_tick = now;
        job->last_ok = ok ? 1 : 0;
        if (!ok) {
            job->fail_count++;
        }
        job->next_tick = now + job->interval_ticks;
        lock_release();

        audit_log(ok ? "CRON_OK" : "CRON_FAIL", action_name(snapshot.action));
        slog_log(ok ? SLOG_LEVEL_INFO : SLOG_LEVEL_WARN, "cron", ok ? "job tick ok" : "job tick failed");
    }
}
