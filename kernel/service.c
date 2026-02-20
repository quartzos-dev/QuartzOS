#include <drivers/pit.h>
#include <kernel/audit.h>
#include <kernel/service.h>
#include <kernel/slog.h>
#include <lib/string.h>

#define MAX_SERVICES 16
#define PIT_HZ 100u
#define DEFAULT_MAX_RESTARTS 5u
#define DEFAULT_WINDOW_TICKS (30u * PIT_HZ)
#define DEFAULT_BACKOFF_TICKS (5u * PIT_HZ)

typedef struct service_entry {
    char name[24];
    service_spawn_fn spawn;
    void *arg;
    service_policy_t policy;
    uint64_t task_id;
    uint32_t restarts_total;
    uint32_t crashes_total;
    uint32_t max_restarts;
    uint32_t restart_window_ticks;
    uint32_t backoff_ticks;
    uint32_t restarts_in_window;
    uint64_t window_start_tick;
    uint64_t backoff_until_tick;
    uint64_t last_start_tick;
    uint64_t last_stop_tick;
    uint8_t active;
    uint8_t admin_stop;
} service_entry_t;

static service_entry_t g_services[MAX_SERVICES];
static size_t g_service_count;
static volatile unsigned int g_lock;

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

static service_entry_t *find_service(const char *name) {
    if (!name) {
        return 0;
    }
    for (size_t i = 0; i < g_service_count; i++) {
        if (strcmp(g_services[i].name, name) == 0) {
            return &g_services[i];
        }
    }
    return 0;
}

static const char *policy_name(service_policy_t policy) {
    return policy == SERVICE_POLICY_ALWAYS ? "always" : "manual";
}

static const char *service_state(const service_entry_t *svc, uint64_t now) {
    if (!svc) {
        return "invalid";
    }
    if (svc->task_id != 0 && task_exists(svc->task_id)) {
        return "online";
    }
    if (svc->admin_stop) {
        return "stopped";
    }
    if (svc->backoff_until_tick > now) {
        return "backoff";
    }
    return "offline";
}

static void service_bump_window(service_entry_t *svc, uint64_t now_tick) {
    if (!svc) {
        return;
    }
    if (svc->window_start_tick == 0 ||
        now_tick - svc->window_start_tick >= svc->restart_window_ticks) {
        svc->window_start_tick = now_tick;
        svc->restarts_in_window = 0;
    }
    svc->restarts_in_window++;
}

static int service_should_backoff(service_entry_t *svc, uint64_t now_tick) {
    if (!svc) {
        return 1;
    }
    if (svc->max_restarts == 0) {
        return 0;
    }

    if (svc->window_start_tick == 0 ||
        now_tick - svc->window_start_tick >= svc->restart_window_ticks) {
        svc->window_start_tick = now_tick;
        svc->restarts_in_window = 0;
    }

    if (svc->restarts_in_window >= svc->max_restarts) {
        svc->backoff_until_tick = now_tick + svc->backoff_ticks;
        return 1;
    }
    return 0;
}

static bool spawn_service_task(service_entry_t *svc, int is_restart) {
    if (!svc || !svc->spawn) {
        return false;
    }

    task_t *task = svc->spawn(svc->arg);
    if (!task) {
        audit_log("SERVICE_SPAWN_FAIL", svc->name);
        slog_log(SLOG_LEVEL_ERROR, "service", "spawn failed");
        return false;
    }

    uint64_t now_tick = pit_ticks();
    svc->task_id = task->id;
    svc->last_start_tick = now_tick;
    svc->backoff_until_tick = 0;
    svc->admin_stop = 0;

    if (is_restart) {
        svc->restarts_total++;
        service_bump_window(svc, now_tick);
        audit_log("SERVICE_RESTART", svc->name);
        slog_log(SLOG_LEVEL_WARN, "service", "service restarted");
    } else {
        audit_log("SERVICE_START", svc->name);
        slog_log(SLOG_LEVEL_INFO, "service", "service started");
    }
    return true;
}

void service_init(void) {
    memset(g_services, 0, sizeof(g_services));
    g_service_count = 0;
    g_lock = 0;
}

bool service_register(const char *name, service_spawn_fn spawn, void *arg, service_policy_t policy) {
    if (!name || !*name || !spawn) {
        return false;
    }

    lock_acquire();
    if (find_service(name)) {
        lock_release();
        return false;
    }
    if (g_service_count >= MAX_SERVICES) {
        lock_release();
        return false;
    }

    service_entry_t *svc = &g_services[g_service_count++];
    memset(svc, 0, sizeof(*svc));
    strncpy(svc->name, name, sizeof(svc->name) - 1);
    svc->spawn = spawn;
    svc->arg = arg;
    svc->policy = policy;
    svc->task_id = 0;
    svc->restarts_total = 0;
    svc->crashes_total = 0;
    svc->max_restarts = DEFAULT_MAX_RESTARTS;
    svc->restart_window_ticks = DEFAULT_WINDOW_TICKS;
    svc->backoff_ticks = DEFAULT_BACKOFF_TICKS;
    svc->restarts_in_window = 0;
    svc->window_start_tick = 0;
    svc->backoff_until_tick = 0;
    svc->last_start_tick = 0;
    svc->last_stop_tick = 0;
    svc->active = 1;
    svc->admin_stop = 0;
    lock_release();
    return true;
}

bool service_bind_task(const char *name, uint64_t task_id) {
    lock_acquire();
    service_entry_t *svc = find_service(name);
    if (!svc) {
        lock_release();
        return false;
    }
    svc->task_id = task_id;
    svc->last_start_tick = pit_ticks();
    svc->admin_stop = 0;
    lock_release();
    return true;
}

bool service_start(const char *name) {
    lock_acquire();
    service_entry_t *svc = find_service(name);
    if (!svc) {
        lock_release();
        return false;
    }

    svc->admin_stop = 0;
    if (svc->task_id != 0 && task_exists(svc->task_id)) {
        lock_release();
        return true;
    }
    svc->task_id = 0;
    bool ok = spawn_service_task(svc, 0);
    lock_release();
    return ok;
}

bool service_stop(const char *name) {
    lock_acquire();
    service_entry_t *svc = find_service(name);
    if (!svc) {
        lock_release();
        return false;
    }

    uint8_t previous_admin_stop = svc->admin_stop;
    svc->admin_stop = 1;
    svc->backoff_until_tick = 0;
    uint64_t id = svc->task_id;
    if (id != 0 && task_exists(id)) {
        if (!task_kill(id)) {
            svc->admin_stop = previous_admin_stop;
            lock_release();
            return false;
        }
    }
    svc->task_id = 0;
    svc->last_stop_tick = pit_ticks();
    audit_log("SERVICE_STOP", svc->name);
    slog_log(SLOG_LEVEL_INFO, "service", "service stopped");
    lock_release();
    return true;
}

bool service_restart(const char *name) {
    lock_acquire();
    service_entry_t *svc = find_service(name);
    if (!svc) {
        lock_release();
        return false;
    }

    uint64_t id = svc->task_id;
    if (id != 0 && task_exists(id)) {
        if (!task_kill(id)) {
            lock_release();
            return false;
        }
    }
    svc->task_id = 0;
    svc->admin_stop = 0;
    bool ok = spawn_service_task(svc, 1);
    lock_release();
    return ok;
}

bool service_set_policy(const char *name, service_policy_t policy) {
    lock_acquire();
    service_entry_t *svc = find_service(name);
    if (!svc) {
        lock_release();
        return false;
    }
    svc->policy = policy;
    lock_release();
    return true;
}

bool service_set_restart_limits(const char *name, uint32_t max_restarts,
                                uint32_t window_seconds, uint32_t backoff_seconds) {
    if (window_seconds == 0 || backoff_seconds == 0) {
        return false;
    }

    lock_acquire();
    service_entry_t *svc = find_service(name);
    if (!svc) {
        lock_release();
        return false;
    }

    svc->max_restarts = max_restarts;
    svc->restart_window_ticks = window_seconds * PIT_HZ;
    svc->backoff_ticks = backoff_seconds * PIT_HZ;
    if (svc->restart_window_ticks == 0) {
        svc->restart_window_ticks = PIT_HZ;
    }
    if (svc->backoff_ticks == 0) {
        svc->backoff_ticks = PIT_HZ;
    }
    svc->window_start_tick = 0;
    svc->restarts_in_window = 0;
    lock_release();
    return true;
}

uint64_t service_task_id(const char *name) {
    lock_acquire();
    service_entry_t *svc = find_service(name);
    uint64_t id = svc ? svc->task_id : 0;
    lock_release();
    return id;
}

service_policy_t service_policy(const char *name) {
    lock_acquire();
    service_entry_t *svc = find_service(name);
    service_policy_t out = svc ? svc->policy : SERVICE_POLICY_MANUAL;
    lock_release();
    return out;
}

void service_tick(void) {
    uint64_t now_tick = pit_ticks();

    lock_acquire();
    for (size_t i = 0; i < g_service_count; i++) {
        service_entry_t *svc = &g_services[i];
        if (!svc->active) {
            continue;
        }

        if (svc->task_id != 0 && !task_exists(svc->task_id)) {
            svc->task_id = 0;
            svc->last_stop_tick = now_tick;
            if (!svc->admin_stop) {
                svc->crashes_total++;
                audit_log("SERVICE_CRASH", svc->name);
                slog_log(SLOG_LEVEL_WARN, "service", "service crashed");
            }
        }

        if (svc->task_id != 0) {
            continue;
        }
        if (svc->admin_stop) {
            continue;
        }
        if (svc->policy != SERVICE_POLICY_ALWAYS) {
            continue;
        }
        if (svc->backoff_until_tick > now_tick) {
            continue;
        }
        if (service_should_backoff(svc, now_tick)) {
            audit_log("SERVICE_BACKOFF", svc->name);
            slog_log(SLOG_LEVEL_WARN, "service", "service backoff");
            continue;
        }

        if (!spawn_service_task(svc, 1)) {
            svc->backoff_until_tick = now_tick + svc->backoff_ticks;
        }
    }
    lock_release();
}

size_t service_dump(char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return 0;
    }

    lock_acquire();
    out[0] = '\0';
    append_text(out, out_len, "name task policy restarts crashes state\n");
    uint64_t now_tick = pit_ticks();
    for (size_t i = 0; i < g_service_count; i++) {
        service_entry_t *svc = &g_services[i];
        append_text(out, out_len, svc->name);
        append_text(out, out_len, " ");
        append_u32(out, out_len, (uint32_t)svc->task_id);
        append_text(out, out_len, " ");
        append_text(out, out_len, policy_name(svc->policy));
        append_text(out, out_len, " ");
        append_u32(out, out_len, svc->restarts_total);
        append_text(out, out_len, " ");
        append_u32(out, out_len, svc->crashes_total);
        append_text(out, out_len, " ");
        append_text(out, out_len, service_state(svc, now_tick));
        append_text(out, out_len, "\n");
    }
    size_t written = strlen(out);
    lock_release();
    return written;
}
