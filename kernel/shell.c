#include <drivers/ata.h>
#include <drivers/keyboard.h>
#include <drivers/mouse.h>
#include <drivers/pit.h>
#include <filesystem/sfs.h>
#include <gui/gui.h>
#include <kernel/app_runtime.h>
#include <kernel/audit.h>
#include <kernel/console.h>
#include <kernel/config.h>
#include <kernel/cron.h>
#include <kernel/license.h>
#include <kernel/log.h>
#include <kernel/mp.h>
#include <kernel/security.h>
#include <kernel/shell.h>
#include <kernel/slog.h>
#include <kernel/service.h>
#include <kernel/trace.h>
#include <lib/string.h>
#include <memory/heap.h>
#include <net/net.h>
#include <process/mutex.h>
#include <process/task.h>
#include <process/user.h>

static char cwd[256] = "/";
static char line[256];
static size_t line_len;
static int g_license_lock_mode;
static int g_security_lock_mode;
static int g_license_setup_active;
static uint32_t g_license_setup_attempts;

#define SERVER_FEATURE_COUNT 900u
#define SERVER_USE_CASE_COUNT 5000u
#define SERVER_FEATURES_PATH "/etc/server.features"
#define SERVER_EXPORT_DIR "/server"
#define SERVER_DEFAULT_IDEA_EXPORT "/server/SERVER_USE_CASES_5000.txt"
#define SERVER_DEFAULT_FEATURE_EXPORT "/server/SERVER_FEATURES_900.txt"

static uint8_t g_server_features[SERVER_FEATURE_COUNT];
static uint32_t g_server_feature_enabled_count;
static int g_server_endpoint_ready;
static uint32_t g_server_ip;
static uint16_t g_server_port;

static void print_hex_byte(uint8_t value) {
    static const char digits[] = "0123456789abcdef";
    char out[2];
    out[0] = digits[(value >> 4) & 0x0F];
    out[1] = digits[value & 0x0F];
    console_write_len(out, 2);
}

static int parse_u8(const char *s, size_t len, uint8_t *out) {
    if (!s || len == 0 || len > 3) {
        return 0;
    }
    int value = 0;
    for (size_t i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return 0;
        }
        value = value * 10 + (s[i] - '0');
    }
    if (value < 0 || value > 255) {
        return 0;
    }
    *out = (uint8_t)value;
    return 1;
}

static int parse_u32_text(const char *s, uint32_t *out) {
    if (!s || !*s || !out) {
        return 0;
    }
    uint32_t value = 0;
    for (const char *p = s; *p; p++) {
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

static int parse_u64_text(const char *s, uint64_t *out) {
    if (!s || !*s || !out) {
        return 0;
    }
    uint64_t value = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
        uint64_t digit = (uint64_t)(*p - '0');
        if (value > (0xFFFFFFFFFFFFFFFFull - digit) / 10ull) {
            return 0;
        }
        value = value * 10ull + digit;
    }
    *out = value;
    return 1;
}

static int parse_i32_text(const char *s, int *out) {
    if (!s || !*s || !out) {
        return 0;
    }
    int sign = 1;
    if (*s == '-') {
        sign = -1;
        s++;
    }
    if (!*s) {
        return 0;
    }
    uint32_t value = 0;
    uint32_t limit = (sign > 0) ? 2147483647u : 2147483648u;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
        uint32_t digit = (uint32_t)(*p - '0');
        if (value > (limit - digit) / 10u) {
            return 0;
        }
        value = value * 10u + digit;
    }
    if (sign > 0) {
        *out = (int)value;
        return 1;
    }
    if (value == 2147483648u) {
        *out = (-2147483647 - 1);
    } else {
        *out = -(int)value;
    }
    return 1;
}

static int parse_on_off(const char *text, int *out_on) {
    if (!text || !out_on) {
        return 0;
    }
    if (strcmp(text, "on") == 0 || strcmp(text, "1") == 0) {
        *out_on = 1;
        return 1;
    }
    if (strcmp(text, "off") == 0 || strcmp(text, "0") == 0) {
        *out_on = 0;
        return 1;
    }
    return 0;
}

static char ascii_lower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return (char)(c + ('a' - 'A'));
    }
    return c;
}

static int text_contains_ci(const char *text, const char *needle) {
    if (!text || !needle) {
        return 0;
    }
    if (*needle == '\0') {
        return 1;
    }

    for (const char *t = text; *t; t++) {
        const char *a = t;
        const char *b = needle;
        while (*a && *b && ascii_lower(*a) == ascii_lower(*b)) {
            a++;
            b++;
        }
        if (*b == '\0') {
            return 1;
        }
    }
    return 0;
}

static int apply_profile_runtime(const char *profile_name) {
    if (!service_start("gui") || !service_start("shell")) {
        return 0;
    }
    uint64_t gui_id = service_task_id("gui");
    uint64_t shell_id = service_task_id("shell");
    if (gui_id == 0 || shell_id == 0) {
        return 0;
    }

    if (!profile_name || strcmp(profile_name, "normal") == 0) {
        service_set_policy("net", SERVICE_POLICY_ALWAYS);
        if (!service_start("net")) {
            return 0;
        }
        uint64_t net_id = service_task_id("net");
        if (net_id == 0) {
            return 0;
        }
        task_set_quantum_ticks(10);
        task_set_priority(gui_id, 14);
        task_set_priority(shell_id, 20);
        task_set_realtime(shell_id, true);
        task_set_priority(net_id, 12);
        return 1;
    }
    if (strcmp(profile_name, "safe") == 0) {
        uint64_t net_id = service_task_id("net");
        if (net_id == 0 && !service_start("net")) {
            return 0;
        }
        net_id = service_task_id("net");
        if (net_id == 0) {
            return 0;
        }
        task_set_quantum_ticks(18);
        task_set_priority(gui_id, 10);
        task_set_priority(shell_id, 22);
        task_set_realtime(shell_id, false);
        task_set_priority(net_id, 8);
        service_set_policy("net", SERVICE_POLICY_MANUAL);
        if (!service_stop("net")) {
            return 0;
        }
        return 1;
    }
    if (strcmp(profile_name, "perf") == 0) {
        service_set_policy("net", SERVICE_POLICY_ALWAYS);
        if (!service_start("net")) {
            return 0;
        }
        uint64_t net_id = service_task_id("net");
        if (net_id == 0) {
            return 0;
        }
        task_set_quantum_ticks(4);
        task_set_priority(gui_id, 18);
        task_set_priority(shell_id, 20);
        task_set_realtime(shell_id, true);
        task_set_priority(net_id, 20);
        return 1;
    }
    return 0;
}

static void sync_license_lock_mode(void) {
    int should_lock = license_usage_allowed() ? 0 : 1;
    if (should_lock == g_license_lock_mode) {
        return;
    }
    g_license_lock_mode = should_lock;
    if (g_license_lock_mode) {
        (void)service_stop("gui");
        (void)service_stop("net");
        (void)service_set_policy("net", SERVICE_POLICY_MANUAL);
        kprintf("license: enforcement lock enabled (consumer monthly license required)\n");
        audit_log("LICENSE_LOCK_MODE", "enabled");
    } else {
        kprintf("license: verification passed, full access enabled\n");
        audit_log("LICENSE_LOCK_MODE", "disabled");
    }
}

static void sync_security_lock_mode(void) {
    int should_lock = security_lockdown_active() ? 1 : 0;
    if (should_lock == g_security_lock_mode) {
        return;
    }
    g_security_lock_mode = should_lock;
    if (g_security_lock_mode) {
        kprintf("security: lockdown enabled (failsafe active)\n");
        audit_log("SECURITY_LOCK_MODE", "enabled");
    } else {
        kprintf("security: lockdown cleared\n");
        audit_log("SECURITY_LOCK_MODE", "disabled");
    }
}

static int system_access_locked(void) {
    return g_license_lock_mode || g_security_lock_mode;
}

static int command_allowed_in_lock_mode(int argc, char **argv) {
    if (argc <= 0 || !argv || !argv[0]) {
        return 1;
    }
    if (strcmp(argv[0], "help") == 0 || strcmp(argv[0], "clear") == 0) {
        return 1;
    }
    if (strcmp(argv[0], "license") == 0) {
        if (argc == 1) {
            return 1;
        }
        if (strcmp(argv[1], "status") == 0 ||
            strcmp(argv[1], "terms") == 0 ||
            strcmp(argv[1], "accept") == 0 ||
            strcmp(argv[1], "reject") == 0 ||
            strcmp(argv[1], "setup") == 0 ||
            strcmp(argv[1], "verify") == 0 ||
            strcmp(argv[1], "activate") == 0 ||
            strcmp(argv[1], "deactivate") == 0 ||
            strcmp(argv[1], "reload") == 0 ||
            strcmp(argv[1], "unlock") == 0) {
            return 1;
        }
    }
    if (strcmp(argv[0], "security") == 0) {
        if (g_security_lock_mode && !g_license_lock_mode) {
            return 1;
        }
        return 0;
    }
    if (strcmp(argv[0], "server") == 0) {
        return 0;
    }
    return 0;
}

static int parse_ipv4(const char *text, uint32_t *out_ip) {
    if (!text || !out_ip) {
        return 0;
    }

    uint8_t oct[4] = {0};
    int idx = 0;
    const char *part = text;
    const char *p = text;

    while (1) {
        if (*p == '.' || *p == '\0') {
            if (idx >= 4) {
                return 0;
            }
            if (!parse_u8(part, (size_t)(p - part), &oct[idx])) {
                return 0;
            }
            idx++;
            if (*p == '\0') {
                break;
            }
            part = p + 1;
        }
        p++;
    }

    if (idx != 4) {
        return 0;
    }

    *out_ip = ((uint32_t)oct[0] << 24) |
              ((uint32_t)oct[1] << 16) |
              ((uint32_t)oct[2] << 8) |
              (uint32_t)oct[3];
    return 1;
}

static void buf_append_text(char *out, size_t out_len, const char *text) {
    if (!out || out_len == 0 || !text) {
        return;
    }
    size_t cur = strlen(out);
    if (cur >= out_len - 1u) {
        return;
    }
    strncat(out, text, out_len - cur - 1u);
}

static void buf_append_u32(char *out, size_t out_len, uint32_t value) {
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
        buf_append_text(out, out_len, c);
        idx--;
    }
}

static void format_ipv4_text(uint32_t ip, char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return;
    }
    out[0] = '\0';
    buf_append_u32(out, out_len, (ip >> 24) & 0xFFu);
    buf_append_text(out, out_len, ".");
    buf_append_u32(out, out_len, (ip >> 16) & 0xFFu);
    buf_append_text(out, out_len, ".");
    buf_append_u32(out, out_len, (ip >> 8) & 0xFFu);
    buf_append_text(out, out_len, ".");
    buf_append_u32(out, out_len, ip & 0xFFu);
}

static void server_feature_name(uint32_t index, char *out, size_t out_len) {
    static const char *groups[] = {
        "Ingest", "Backup", "Observability", "Routing", "Security", "Identity", "Storage",
        "Automation", "Build", "Monitoring", "Compliance", "Analytics", "Recovery",
        "Replication", "Optimization"
    };
    static const char *verbs[] = {
        "Adaptive", "Secure", "Predictive", "Distributed", "Elastic", "Verified",
        "RealTime", "Policy", "Snapshot", "Smart", "Isolated", "Resilient"
    };
    static const char *nouns[] = {
        "Pipeline", "Gateway", "Collector", "Scheduler", "Queue", "Mirror", "Archive",
        "Guard", "Reporter", "Balancer", "Proxy", "Ledger"
    };
    if (!out || out_len == 0) {
        return;
    }
    out[0] = '\0';
    uint32_t g = index / 60u;
    uint32_t local = index % 60u;
    const char *group = groups[g % (sizeof(groups) / sizeof(groups[0]))];
    const char *verb = verbs[(local * 7u + g) % (sizeof(verbs) / sizeof(verbs[0]))];
    const char *noun = nouns[(local * 11u + g * 3u) % (sizeof(nouns) / sizeof(nouns[0]))];
    buf_append_text(out, out_len, group);
    buf_append_text(out, out_len, " ");
    buf_append_text(out, out_len, verb);
    buf_append_text(out, out_len, " ");
    buf_append_text(out, out_len, noun);
}

static void server_use_case_text(uint32_t index, char *out, size_t out_len) {
    static const char *domains[] = {
        "CI/CD", "Security", "Backups", "Telemetry", "Assets", "Licensing", "Compliance",
        "Analytics", "Ops", "DR", "Updates", "Automation", "QA", "Incident", "Monitoring",
        "Support", "Logs", "Orchestration", "Data", "Build Farm"
    };
    static const char *verbs[] = {
        "stream", "replicate", "archive", "verify", "index", "compress", "score", "snapshot",
        "audit", "schedule", "triage", "throttle", "sign", "track", "dispatch", "validate",
        "publish", "route", "inspect", "restore"
    };
    static const char *targets[] = {
        "build artifacts", "license events", "security alerts", "GUI metrics", "kernel traces",
        "app manifests", "backup blocks", "release bundles", "telemetry frames", "service states",
        "task snapshots", "network sessions", "cron actions", "config deltas", "integrity reports",
        "support payloads", "runtime flags", "storage journals", "audit logs", "crash dumps"
    };
    static const char *modes[] = {"nightly", "realtime", "staged", "isolated", "read-only"};
    static const char *outcomes[] = {
        "faster recovery", "stronger integrity", "lower downtime", "fewer incidents", "stable scaling",
        "easier audits", "deterministic builds", "improved visibility", "safer rollout", "lower cost"
    };

    if (!out || out_len == 0) {
        return;
    }

    out[0] = '\0';
    const char *domain = domains[(index * 13u + 7u) % (sizeof(domains) / sizeof(domains[0]))];
    const char *verb = verbs[(index * 17u + 3u) % (sizeof(verbs) / sizeof(verbs[0]))];
    const char *target = targets[(index * 19u + 11u) % (sizeof(targets) / sizeof(targets[0]))];
    const char *mode = modes[(index * 5u + 2u) % (sizeof(modes) / sizeof(modes[0]))];
    const char *outcome = outcomes[(index * 7u + 1u) % (sizeof(outcomes) / sizeof(outcomes[0]))];

    buf_append_u32(out, out_len, index + 1u);
    buf_append_text(out, out_len, ". ");
    buf_append_text(out, out_len, "Use server to ");
    buf_append_text(out, out_len, verb);
    buf_append_text(out, out_len, " ");
    buf_append_text(out, out_len, target);
    buf_append_text(out, out_len, " for ");
    buf_append_text(out, out_len, domain);
    buf_append_text(out, out_len, " in ");
    buf_append_text(out, out_len, mode);
    buf_append_text(out, out_len, " mode (");
    buf_append_text(out, out_len, outcome);
    buf_append_text(out, out_len, ")");
}

static void server_recount_enabled(void) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < SERVER_FEATURE_COUNT; i++) {
        if (g_server_features[i]) {
            count++;
        }
    }
    g_server_feature_enabled_count = count;
}

static void server_reset_features_defaults(void) {
    for (uint32_t i = 0; i < SERVER_FEATURE_COUNT; i++) {
        g_server_features[i] = ((i % 4u) == 0u || (i % 9u) == 0u) ? 1u : 0u;
    }
    server_recount_enabled();
}

static bool server_save_features(void) {
    char out[SERVER_FEATURE_COUNT + 2];
    for (uint32_t i = 0; i < SERVER_FEATURE_COUNT; i++) {
        out[i] = g_server_features[i] ? '1' : '0';
    }
    out[SERVER_FEATURE_COUNT] = '\n';
    out[SERVER_FEATURE_COUNT + 1] = '\0';
    return sfs_write_file(SERVER_FEATURES_PATH, out, SERVER_FEATURE_COUNT + 1u);
}

static void server_load_features(void) {
    char in[SERVER_FEATURE_COUNT + 8];
    size_t read = 0;
    if (!sfs_read_file(SERVER_FEATURES_PATH, in, sizeof(in), &read) || read < SERVER_FEATURE_COUNT) {
        server_reset_features_defaults();
        return;
    }
    for (uint32_t i = 0; i < SERVER_FEATURE_COUNT; i++) {
        g_server_features[i] = (in[i] == '1') ? 1u : 0u;
    }
    server_recount_enabled();
}

static void server_load_endpoint(void) {
    const char *ip_text = config_get("server.endpoint_ip");
    const char *port_text = config_get("server.endpoint_port");
    uint32_t ip = 0;
    uint32_t port_u32 = 0;

    g_server_endpoint_ready = 0;
    g_server_ip = 0;
    g_server_port = 0;
    if (!ip_text || !port_text) {
        return;
    }
    if (!parse_ipv4(ip_text, &ip) || !parse_u32_text(port_text, &port_u32)) {
        return;
    }
    if (port_u32 == 0 || port_u32 > 65535u) {
        return;
    }
    g_server_ip = ip;
    g_server_port = (uint16_t)port_u32;
    g_server_endpoint_ready = 1;
}

static bool server_save_endpoint(void) {
    if (!g_server_endpoint_ready) {
        (void)config_unset("server.endpoint_ip");
        (void)config_unset("server.endpoint_port");
        return config_save();
    }

    char ip_text[24];
    char port_text[8];
    ip_text[0] = '\0';
    port_text[0] = '\0';
    format_ipv4_text(g_server_ip, ip_text, sizeof(ip_text));
    buf_append_u32(port_text, sizeof(port_text), (uint32_t)g_server_port);

    if (!config_set("server.endpoint_ip", ip_text) ||
        !config_set("server.endpoint_port", port_text)) {
        return false;
    }
    return config_save();
}

static bool server_send_payload(const char *payload, char *reason, size_t reason_len) {
    if (reason && reason_len > 0) {
        reason[0] = '\0';
    }
    if (!payload || !payload[0]) {
        if (reason && reason_len > 0) {
            buf_append_text(reason, reason_len, "empty payload");
        }
        return false;
    }
    if (!g_server_endpoint_ready) {
        if (reason && reason_len > 0) {
            buf_append_text(reason, reason_len, "endpoint not configured");
        }
        return false;
    }
    if (!security_allow_server_payload(strlen(payload), reason, reason_len)) {
        return false;
    }
    if (!net_available()) {
        if (reason && reason_len > 0) {
            buf_append_text(reason, reason_len, "network unavailable");
        }
        return false;
    }
    return net_tcp_send_text(g_server_ip, g_server_port, payload);
}

static bool server_export_catalog(const char *path, int ideas_mode) {
    const char *dst = path && path[0] ? path : (ideas_mode ? SERVER_DEFAULT_IDEA_EXPORT : SERVER_DEFAULT_FEATURE_EXPORT);
    if (!dst || dst[0] != '/') {
        return false;
    }

    if (!sfs_exists(SERVER_EXPORT_DIR)) {
        (void)sfs_make_dir(SERVER_EXPORT_DIR);
    }

    size_t max_lines = ideas_mode ? (size_t)SERVER_USE_CASE_COUNT : (size_t)SERVER_FEATURE_COUNT;
    size_t cap = ideas_mode ? (size_t)SERVER_USE_CASE_COUNT * 144u : (size_t)SERVER_FEATURE_COUNT * 96u;
    if (cap < 4096u) {
        cap = 4096u;
    }
    char *blob = (char *)kmalloc(cap);
    if (!blob) {
        return false;
    }
    blob[0] = '\0';
    size_t used = 0;

    for (size_t i = 0; i < max_lines; i++) {
        char line_buf[192];
        line_buf[0] = '\0';
        if (ideas_mode) {
            server_use_case_text((uint32_t)i, line_buf, sizeof(line_buf));
        } else {
            char name[96];
            name[0] = '\0';
            server_feature_name((uint32_t)i, name, sizeof(name));
            buf_append_u32(line_buf, sizeof(line_buf), (uint32_t)(i + 1u));
            buf_append_text(line_buf, sizeof(line_buf), ". ");
            buf_append_text(line_buf, sizeof(line_buf), name);
            buf_append_text(line_buf, sizeof(line_buf), " : ");
            buf_append_text(line_buf, sizeof(line_buf), g_server_features[i] ? "on" : "off");
        }
        size_t line_len = strlen(line_buf);
        if (used + line_len + 1u >= cap) {
            kfree(blob);
            return false;
        }
        memcpy(blob + used, line_buf, line_len);
        used += line_len;
        blob[used++] = '\n';
        blob[used] = '\0';
    }

    bool ok = sfs_write_file(dst, blob, used);
    kfree(blob);
    return ok;
}

static void print_prompt(void) {
    console_set_prompt(cwd);
    kprintf("\n%s$ ", cwd);
}

static char *trim_spaces(char *text) {
    if (!text) {
        return text;
    }
    while (*text == ' ' || *text == '\t') {
        text++;
    }
    size_t len = strlen(text);
    while (len > 0 && (text[len - 1] == ' ' || text[len - 1] == '\t')) {
        text[--len] = '\0';
    }
    return text;
}

static void print_license_setup_prompt(void) {
    console_set_prompt("license-setup");
    kprintf("\nlicense-key> ");
}

static int license_unlock_runtime(void) {
    if (!license_usage_allowed()) {
        kprintf("license: unlock denied. requires verified consumer monthly license and accepted terms.\n");
        return 0;
    }
    if (security_lockdown_active()) {
        kprintf("license: unlock denied. security lockdown active; clear failsafe first.\n");
        return 0;
    }
    const char *profile = config_get("boot.profile");
    if (!profile) {
        profile = "normal";
    }
    if (!apply_profile_runtime(profile)) {
        kprintf("license: unlock failed to start desktop services\n");
        return 0;
    }
    g_license_lock_mode = 0;
    sync_security_lock_mode();
    kprintf("license: system unlocked (profile=%s)\n", profile);
    return 1;
}

static int license_setup_activate_and_unlock(const char *key) {
    if (!key || !key[0]) {
        kprintf("license setup: key cannot be empty\n");
        return 0;
    }
    if (!license_terms_accepted()) {
        if (!license_accept_terms()) {
            kprintf("license setup: cannot accept terms (missing or invalid terms file)\n");
            return 0;
        }
        kprintf("license setup: terms accepted\n");
    }
    if (!license_activate(key)) {
        uint32_t lock_left = license_lockout_remaining_seconds();
        kprintf("license setup: activation failed (%s",
                license_error_text(license_last_error()));
        if (lock_left > 0) {
            kprintf(", lock=%us", (unsigned)lock_left);
        }
        kprintf(")\n");
        return 0;
    }
    kprintf("license setup: key activated\n");
    return license_unlock_runtime();
}

static void start_license_setup_app(int auto_started) {
    g_license_setup_active = 1;
    g_license_setup_attempts = 0;

    kprintf("\n=== QuartzOS License Setup ===\n");
    if (auto_started) {
        kprintf("System is in license lock mode.\n");
    }
    kprintf("Paste a QOS3 consumer key and press Enter.\n");
    kprintf("Commands: 'skip' keeps manual mode, 'status' shows license state.\n");
    print_license_setup_prompt();
}

static void handle_license_setup_line(char *raw_input) {
    char *input = trim_spaces(raw_input);
    if (!input || input[0] == '\0') {
        kprintf("license setup: enter a key or type 'skip'\n");
        print_license_setup_prompt();
        return;
    }

    if (strcmp(input, "skip") == 0 || strcmp(input, "cancel") == 0) {
        g_license_setup_active = 0;
        kprintf("license setup: skipped (manual commands remain available)\n");
        print_prompt();
        return;
    }

    if (strcmp(input, "status") == 0) {
        char active[LICENSE_MAX_KEY_TEXT + 1];
        const char *tier = license_active_tier_name();
        license_active_key(active, sizeof(active));
        kprintf("license setup: active=%s usage=%s key=%s tier=%s terms=%s last=%s\n",
                license_is_active() ? "yes" : "no",
                license_usage_allowed() ? "allowed" : "blocked",
                active,
                license_is_active() && tier ? tier : "none",
                license_terms_accepted() ? "accepted" : (license_terms_available() ? "pending" : "missing"),
                license_error_text(license_last_error()));
        print_license_setup_prompt();
        return;
    }

    g_license_setup_attempts++;
    if (license_setup_activate_and_unlock(input)) {
        g_license_setup_active = 0;
        print_prompt();
        return;
    }

    kprintf("license setup: try again or type 'skip' (attempt %u)\n",
            (unsigned)g_license_setup_attempts);
    print_license_setup_prompt();
}

static int path_resolve(const char *input, char *out, size_t out_len) {
    if (!out || out_len < 2) {
        return 0;
    }

    char raw[256];
    if (!input || !*input) {
        strncpy(raw, cwd, sizeof(raw) - 1);
        raw[sizeof(raw) - 1] = '\0';
    } else if (input[0] == '/') {
        strncpy(raw, input, sizeof(raw) - 1);
        raw[sizeof(raw) - 1] = '\0';
    } else {
        raw[0] = '\0';
        strncpy(raw, cwd, sizeof(raw) - 1);
        raw[sizeof(raw) - 1] = '\0';
        if (strcmp(raw, "/") != 0) {
            strncat(raw, "/", sizeof(raw) - strlen(raw) - 1);
        }
        strncat(raw, input, sizeof(raw) - strlen(raw) - 1);
    }

    if (raw[0] != '/') {
        return 0;
    }

    char norm[256];
    size_t nlen = 1;
    norm[0] = '/';
    norm[1] = '\0';

    const char *p = raw;
    while (*p == '/') {
        p++;
    }

    while (*p) {
        char comp[96];
        size_t clen = 0;
        while (*p && *p != '/') {
            unsigned char ch = (unsigned char)*p;
            if (ch < 32u || ch == 127u) {
                return 0;
            }
            if (clen + 1 >= sizeof(comp)) {
                return 0;
            }
            comp[clen++] = *p++;
        }
        comp[clen] = '\0';

        while (*p == '/') {
            p++;
        }

        if (clen == 0 || strcmp(comp, ".") == 0) {
            continue;
        }

        if (strcmp(comp, "..") == 0) {
            if (nlen > 1) {
                while (nlen > 1 && norm[nlen - 1] == '/') {
                    nlen--;
                }
                while (nlen > 1 && norm[nlen - 1] != '/') {
                    nlen--;
                }
                if (nlen > 1) {
                    nlen--;
                }
                norm[nlen] = '\0';
            }
            continue;
        }

        if (strchr(comp, '\\')) {
            return 0;
        }

        if (nlen > 1) {
            if (nlen + 1 >= sizeof(norm)) {
                return 0;
            }
            norm[nlen++] = '/';
        }
        if (nlen + clen >= sizeof(norm)) {
            return 0;
        }
        memcpy(norm + nlen, comp, clen);
        nlen += clen;
        norm[nlen] = '\0';
    }

    strncpy(out, norm, out_len - 1);
    out[out_len - 1] = '\0';
    return 1;
}

static int path_has_prefix(const char *path, const char *prefix) {
    if (!path || !prefix) {
        return 0;
    }
    size_t plen = strlen(prefix);
    if (plen == 0) {
        return 0;
    }
    if (strncmp(path, prefix, plen) != 0) {
        return 0;
    }
    return path[plen] == '\0' || path[plen] == '/';
}

static int path_equals(const char *a, const char *b) {
    return a && b && strcmp(a, b) == 0;
}

static int config_key_is_server_restricted(const char *key) {
    if (!key) {
        return 0;
    }
    return strncmp(key, "server.", 7) == 0 ||
           strncmp(key, "license.server.", 15) == 0 ||
           strncmp(key, "security.server.", 16) == 0;
}

static int path_is_security_protected(const char *path) {
    if (!path || path[0] != '/') {
        return 0;
    }

    if (path_has_prefix(path, "/bin") || path_has_prefix(path, "/boot")) {
        return 1;
    }

    if (path_has_prefix(path, "/etc/licenses")) {
        return 1;
    }
    if (path_equals(path, SERVER_FEATURES_PATH)) {
        return 1;
    }

    if (path_equals(path, "/etc/licenses.db") ||
        path_equals(path, "/etc/licenses.revoked") ||
        path_equals(path, "/etc/license.state") ||
        path_equals(path, "/etc/license.accept") ||
        path_equals(path, "/etc/license.hardware") ||
        path_equals(path, "/etc/licenses_integrity.json") ||
        path_equals(path, "/etc/licenses_audit.csv") ||
        path_equals(path, "/etc/licenses_meta.csv") ||
        path_equals(path, "/etc/licenses_tracking.csv") ||
        path_equals(path, "/etc/system.cfg") ||
        path_equals(path, "/etc/security.cfg") ||
        path_equals(path, "/etc/security.cfg.sig") ||
        path_equals(path, "/etc/security_manifest.txt") ||
        path_equals(path, "/etc/security_manifest.sig") ||
        path_equals(path, "/etc/security_failsafe.log") ||
        path_equals(path, "/etc/cron.cfg") ||
        path_equals(path, "/etc/LICENSE.txt") ||
        path_equals(path, "/etc/license_notice.txt")) {
        return 1;
    }

    return 0;
}

static int path_is_sensitive_read(const char *path) {
    if (!path || path[0] != '/') {
        return 0;
    }
    if (path_has_prefix(path, "/etc/licenses")) {
        return 1;
    }
    if (path_equals(path, SERVER_FEATURES_PATH)) {
        return 1;
    }
    return path_equals(path, "/etc/license.state") ||
           path_equals(path, "/etc/license.accept") ||
           path_equals(path, "/etc/license.hardware") ||
           path_equals(path, "/etc/licenses.db") ||
           path_equals(path, "/etc/licenses.revoked") ||
           path_equals(path, "/etc/licenses_tracking.csv") ||
           path_equals(path, "/etc/security.cfg") ||
           path_equals(path, "/etc/security.cfg.sig") ||
           path_equals(path, "/etc/security_manifest.txt") ||
           path_equals(path, "/etc/security_manifest.sig") ||
           path_equals(path, "/etc/security_failsafe.log");
}

static int command_is_privileged(const char *cmd) {
    if (!cmd) {
        return 0;
    }
    return strcmp(cmd, "sched") == 0 ||
           strcmp(cmd, "svc") == 0 ||
           strcmp(cmd, "cron") == 0 ||
           strcmp(cmd, "config") == 0 ||
           strcmp(cmd, "license") == 0 ||
           strcmp(cmd, "trace") == 0 ||
           strcmp(cmd, "audit") == 0 ||
           strcmp(cmd, "log") == 0 ||
           strcmp(cmd, "boot") == 0 ||
           strcmp(cmd, "security") == 0 ||
           strcmp(cmd, "server") == 0 ||
           strcmp(cmd, "diskread") == 0;
}

static int tokenize(char *input, char **argv, int max) {
    int argc = 0;
    char *p = input;

    while (*p && argc < max) {
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (!*p) {
            break;
        }
        argv[argc++] = p;
        while (*p && *p != ' ' && *p != '\t') {
            p++;
        }
        if (*p) {
            *p++ = '\0';
        }
    }
    return argc;
}

static int resolve_bin_app_path(const char *input, char *out, size_t out_len) {
    if (!input || !*input || !out || out_len < 2) {
        return 0;
    }

    if (!strchr(input, '/')) {
        char raw[256];
        raw[0] = '\0';
        strncat(raw, "/bin/", sizeof(raw) - strlen(raw) - 1);
        strncat(raw, input, sizeof(raw) - strlen(raw) - 1);
        if (!path_resolve(raw, out, out_len)) {
            return 0;
        }
    } else {
        if (!path_resolve(input, out, out_len)) {
            return 0;
        }
    }

    if (!path_has_prefix(out, "/bin")) {
        return 0;
    }
    return 1;
}

static int load_app_image(const char *path, void **out_image, size_t *out_size) {
    if (!path || !out_image || !out_size) {
        return 0;
    }
    *out_image = 0;
    *out_size = 0;

    size_t cap = 4 * 1024 * 1024;
    void *image = kmalloc(cap);
    if (!image) {
        return 0;
    }
    size_t read = 0;
    if (!sfs_read_file(path, image, cap, &read)) {
        kfree(image);
        return 0;
    }

    *out_image = image;
    *out_size = read;
    return 1;
}

static void cmd_help(void) {
    if (system_access_locked()) {
        if (g_license_lock_mode) {
            kprintf("System is in LICENSE LOCK mode.\n");
            kprintf("Minimum required: verified QOS3 consumer monthly license.\n");
        }
        if (g_security_lock_mode) {
            kprintf("System is in SECURITY LOCKDOWN mode.\n");
            kprintf("Trigger: integrity/intrusion failsafe.\n");
        }
        kprintf("Allowed commands:\n");
        kprintf("  help               Show this message\n");
        kprintf("  clear              Clear console\n");
        kprintf("  license status     Show license state\n");
        kprintf("  license terms      View terms\n");
        kprintf("  license accept     Accept terms\n");
        kprintf("  license reject     Reject terms\n");
        kprintf("  license setup      Start guided license activation\n");
        kprintf("  license verify <key>    Validate key signature/state\n");
        kprintf("  license activate <key>  Activate key\n");
        kprintf("  license reload     Reload key databases\n");
        kprintf("  license unlock     Unlock GUI/network after verification\n");
        kprintf("  security status    Show security posture\n");
        kprintf("  security verify    Re-run integrity checks\n");
        kprintf("  security failsafe ...  Inspect/reset failsafes\n");
        kprintf("  server ...         Kernel-only (user access disabled)\n");
        return;
    }

    kprintf("Commands:\n");
    kprintf("  help               Show help\n");
    kprintf("  ls [path]          List directory\n");
    kprintf("  cd <path|..>       Change directory\n");
    kprintf("  cat <file>         Print file\n");
    kprintf("  write <f> <text>   Write text file\n");
    kprintf("  mkdir <path>       Create directory\n");
    kprintf("  apps [find <txt>]  List installed apps\n");
    kprintf("  run <name|/bin/x>  Run custom/Linux/Windows/macOS app payload from /bin\n");
    kprintf("  compat ...         Probe and run compatibility wrappers\n");
    kprintf("  sync               Flush filesystem to disk\n");
    kprintf("  cpuinfo            Show SMP status\n");
    kprintf("  ps                 Show scheduler task table\n");
    kprintf("  sched ...          Scheduler controls/status\n");
    kprintf("  netinfo            Show network config\n");
    kprintf("  ifconfig           Alias for netinfo\n");
    kprintf("  ping <ip>          Send ICMP echo request\n");
    kprintf("  tcplisten <port>   Set TCP echo listen port\n");
    kprintf("  tcpsend <ip> <port> <text>  Send text over TCP\n");
    kprintf("  clear              Clear console\n");
    kprintf("  gui                Toggle console overlay\n");
    kprintf("  fsck               Filesystem consistency check\n");
    kprintf("  license ...        License management\n");
    kprintf("  trace ...          Kernel trace buffer tools\n");
    kprintf("  audit ...          Security audit log tools\n");
    kprintf("  log ...            Structured system log tools\n");
    kprintf("  svc ...            Service manager controls\n");
    kprintf("  cron ...           Cron scheduler controls\n");
    kprintf("  config ...         Configuration database tools\n");
    kprintf("  security ...       Security policy, features, and failsafes\n");
    kprintf("  server ...         Kernel-only (user access disabled)\n");
    kprintf("  boot ...           Boot profile controls\n");
    kprintf("  mutex stats        Mutex contention statistics\n");
    kprintf("  mouse ...          Mouse settings/status\n");
    kprintf("  diskread           Read ATA sector 0\n");
}

static void execute_line(char *input) {
    char *argv[16];
    int argc = tokenize(input, argv, 16);
    if (argc == 0) {
        return;
    }

    sync_license_lock_mode();
    sync_security_lock_mode();
    if (system_access_locked() && !command_allowed_in_lock_mode(argc, argv)) {
        if (g_license_lock_mode) {
            audit_log("CMD_BLOCKED", "license-lock");
            security_note_event(SECURITY_EVENT_LICENSE_BLOCKED, "license-lock");
            kprintf("system locked: command blocked until verified consumer monthly license is active.\n");
            kprintf("use: license setup | license status | license terms | license accept | license activate <key> | license unlock\n");
        } else {
            audit_log("CMD_BLOCKED", "security-lock");
            security_note_event(SECURITY_EVENT_CMD_BLOCKED, "security-lock");
            kprintf("security lockdown: command blocked while failsafe is active.\n");
            kprintf("use: security status | security verify | security failsafe reset all\n");
        }
        return;
    }
    if (command_is_privileged(argv[0])) {
        audit_log("CMD_PRIVILEGED", argv[0]);
    }

    if (strcmp(argv[0], "server") == 0) {
        security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "user-server-cmd");
        kprintf("server: access denied. kernel-managed security channel.\n");
        return;
    }

    if (strcmp(argv[0], "help") == 0) {
        cmd_help();
        return;
    }

    if (strcmp(argv[0], "clear") == 0) {
        console_clear();
        return;
    }

    if (strcmp(argv[0], "gui") == 0) {
        gui_set_console_overlay(!gui_console_overlay());
        kprintf("console overlay: %s\n", gui_console_overlay() ? "on" : "off");
        return;
    }

    if (strcmp(argv[0], "mouse") == 0) {
        if (argc == 1 || strcmp(argv[1], "status") == 0) {
            mouse_state_t m = mouse_get_state();
            kprintf("mouse: x=%d y=%d invertx=%s inverty=%s\n",
                    m.x, m.y, mouse_invert_x() ? "on" : "off", mouse_invert_y() ? "on" : "off");
            return;
        }
        if (argc >= 3 && strcmp(argv[1], "invertx") == 0) {
            if (strcmp(argv[2], "on") == 0) {
                mouse_set_invert_x(true);
            } else if (strcmp(argv[2], "off") == 0) {
                mouse_set_invert_x(false);
            } else {
                kprintf("mouse: usage mouse invertx <on|off>\n");
                return;
            }
            kprintf("mouse invertx: %s\n", mouse_invert_x() ? "on" : "off");
            return;
        }
        if (argc >= 3 && strcmp(argv[1], "inverty") == 0) {
            if (strcmp(argv[2], "on") == 0) {
                mouse_set_invert_y(true);
            } else if (strcmp(argv[2], "off") == 0) {
                mouse_set_invert_y(false);
            } else {
                kprintf("mouse: usage mouse inverty <on|off>\n");
                return;
            }
            kprintf("mouse inverty: %s\n", mouse_invert_y() ? "on" : "off");
            return;
        }
        if (strcmp(argv[1], "center") == 0) {
            mouse_center();
            kprintf("mouse: centered\n");
            return;
        }
        kprintf("mouse commands:\n");
        kprintf("  mouse status\n");
        kprintf("  mouse invertx <on|off>\n");
        kprintf("  mouse inverty <on|off>\n");
        kprintf("  mouse center\n");
        return;
    }

    if (strcmp(argv[0], "security") == 0) {
        if (argc == 1 || strcmp(argv[1], "status") == 0) {
            kprintf("security: mode=%s lockdown=%s intrusion=%s integrity=%s features=%u/%u threshold=%u events=%u checked=%u failures=%u\n",
                    security_mode_name(security_mode()),
                    security_lockdown_active() ? "on" : "off",
                    security_intrusion_failsafe_active() ? "on" : "off",
                    security_integrity_failsafe_active() ? "on" : "off",
                    (unsigned)security_feature_enabled_count(),
                    (unsigned)security_feature_count(),
                    (unsigned)security_intrusion_threshold(),
                    (unsigned)security_recent_suspicious_events(),
                    (unsigned)security_integrity_checked_entries(),
                    (unsigned)security_integrity_failure_count());
            kprintf("security: server control=%s send=%s export=%s private-endpoint=%s sandbox=%s\n",
                    security_feature_enabled(SECURITY_FEATURE_ALLOW_SERVER_CONTROL) ? "on" : "off",
                    security_feature_enabled(SECURITY_FEATURE_ALLOW_SERVER_SEND) ? "on" : "off",
                    security_feature_enabled(SECURITY_FEATURE_ALLOW_SERVER_EXPORT) ? "on" : "off",
                    security_feature_enabled(SECURITY_FEATURE_SERVER_REQUIRE_PRIVATE_ENDPOINT) ? "on" : "off",
                    security_feature_enabled(SECURITY_FEATURE_SERVER_EXPORT_SANDBOX) ? "on" : "off");
            return;
        }

        if (strcmp(argv[1], "verify") == 0) {
            char report[160];
            if (security_verify_integrity_now(report, sizeof(report))) {
                kprintf("security: integrity ok (%s)\n", report);
            } else {
                kprintf("security: integrity failure (%s)\n", report);
            }
            sync_security_lock_mode();
            return;
        }

        if (strcmp(argv[1], "features") == 0) {
            uint32_t page = 1;
            if (argc >= 3 && !parse_u32_text(argv[2], &page)) {
                kprintf("security: usage security features [page]\n");
                return;
            }
            if (page == 0) {
                page = 1;
            }
            uint32_t per_page = 20;
            uint32_t total = (uint32_t)security_feature_count();
            uint32_t pages = (total + per_page - 1u) / per_page;
            if (page > pages) {
                page = pages;
            }
            uint32_t start = (page - 1u) * per_page;
            uint32_t end = start + per_page;
            if (end > total) {
                end = total;
            }
            kprintf("security features page %u/%u:\n", (unsigned)page, (unsigned)pages);
            for (uint32_t i = start; i < end; i++) {
                char name[96];
                security_feature_name(i, name, sizeof(name));
                kprintf("  %u [%s] %s\n",
                        (unsigned)i,
                        security_feature_enabled(i) ? "on " : "off",
                        name);
            }
            return;
        }

        if (argc >= 4 && strcmp(argv[1], "feature") == 0) {
            uint32_t index = 0;
            int on = 0;
            if (!parse_u32_text(argv[2], &index) || !parse_on_off(argv[3], &on)) {
                kprintf("security: usage security feature <id> <on|off>\n");
                return;
            }
            if (!security_feature_set(index, on != 0)) {
                kprintf("security: invalid feature id\n");
                return;
            }
            kprintf("security: feature %u=%s\n", (unsigned)index, on ? "on" : "off");
            return;
        }

        if (argc >= 3 && strcmp(argv[1], "mode") == 0) {
            security_mode_t mode = SECURITY_MODE_HARDENED;
            if (strcmp(argv[2], "normal") == 0) {
                mode = SECURITY_MODE_NORMAL;
            } else if (strcmp(argv[2], "hardened") == 0) {
                mode = SECURITY_MODE_HARDENED;
            } else if (strcmp(argv[2], "lockdown") == 0) {
                mode = SECURITY_MODE_LOCKDOWN;
            } else {
                kprintf("security: usage security mode <normal|hardened|lockdown>\n");
                return;
            }
            if (!security_set_mode(mode)) {
                kprintf("security: mode update failed\n");
                return;
            }
            sync_security_lock_mode();
            kprintf("security: mode=%s\n", security_mode_name(security_mode()));
            return;
        }

        if (strcmp(argv[1], "failsafe") == 0) {
            if (argc == 2 || strcmp(argv[2], "status") == 0) {
                kprintf("security failsafe: intrusion=%s integrity=%s lockdown=%s\n",
                        security_intrusion_failsafe_active() ? "on" : "off",
                        security_integrity_failsafe_active() ? "on" : "off",
                        security_lockdown_active() ? "on" : "off");
                return;
            }
            if (argc >= 4 && strcmp(argv[2], "reset") == 0) {
                if (!security_feature_enabled(SECURITY_FEATURE_ALLOW_FAILSAFE_RESET)) {
                    kprintf("security: failsafe reset disabled by policy\n");
                    return;
                }
                if (!license_usage_allowed()) {
                    kprintf("security: reset requires active verified license\n");
                    return;
                }
                if (strcmp(argv[3], "intrusion") == 0) {
                    security_reset_failsafes(true, false);
                } else if (strcmp(argv[3], "integrity") == 0) {
                    security_reset_failsafes(false, true);
                } else if (strcmp(argv[3], "all") == 0) {
                    security_reset_failsafes(true, true);
                } else {
                    kprintf("security: usage security failsafe reset <intrusion|integrity|all>\n");
                    return;
                }
                sync_security_lock_mode();
                kprintf("security: failsafe reset applied\n");
                return;
            }
            kprintf("security failsafe commands:\n");
            kprintf("  security failsafe status\n");
            kprintf("  security failsafe reset <intrusion|integrity|all>\n");
            return;
        }

        if (argc >= 3 && strcmp(argv[1], "threshold") == 0) {
            uint32_t value = 0;
            if (!parse_u32_text(argv[2], &value) || !security_set_intrusion_threshold(value)) {
                kprintf("security: usage security threshold <1..10000>\n");
                return;
            }
            kprintf("security: intrusion threshold=%u\n", (unsigned)security_intrusion_threshold());
            return;
        }

        if (strcmp(argv[1], "save") == 0) {
            if (!security_save()) {
                kprintf("security: save failed\n");
                return;
            }
            kprintf("security: saved\n");
            return;
        }

        if (strcmp(argv[1], "load") == 0) {
            if (!security_load()) {
                kprintf("security: load failed or no policy file\n");
                return;
            }
            sync_security_lock_mode();
            kprintf("security: loaded\n");
            return;
        }

        kprintf("security commands:\n");
        kprintf("  security status\n");
        kprintf("  security verify\n");
        kprintf("  security features [page]\n");
        kprintf("  security feature <id> <on|off>\n");
        kprintf("  security mode <normal|hardened|lockdown>\n");
        kprintf("  security threshold <1..10000>\n");
        kprintf("  security failsafe status\n");
        kprintf("  security failsafe reset <intrusion|integrity|all>\n");
        kprintf("  security save\n");
        kprintf("  security load\n");
        return;
    }

    if (strcmp(argv[0], "license") == 0) {
        if (argc == 1 || strcmp(argv[1], "status") == 0) {
            char active[LICENSE_MAX_KEY_TEXT + 1];
            char terms_hash[65];
            int active_now = license_is_active() ? 1 : 0;
            int usage_ok = license_usage_allowed() ? 1 : 0;
            uint8_t policy = license_active_policy_bits();
            const char *tier = license_active_tier_name();
            license_active_key(active, sizeof(active));
            uint32_t lock_left = license_lockout_remaining_seconds();
            if (!license_terms_hash(terms_hash, sizeof(terms_hash))) {
                strncpy(terms_hash, "none", sizeof(terms_hash) - 1);
                terms_hash[sizeof(terms_hash) - 1] = '\0';
            }
            kprintf("license: active=%s usage=%s key=%s tier=%s policy=0x%x terms=%s hash=%s issued=%u revoked=%u failed=%u lock=%us last=%s\n",
                    active_now ? "yes" : "no",
                    usage_ok ? "allowed" : "blocked",
                    active,
                    (active_now && tier) ? tier : "none",
                    (unsigned)policy,
                    license_terms_accepted() ? "accepted" : (license_terms_available() ? "pending" : "missing"),
                    terms_hash,
                    (unsigned)license_registered_count(),
                    (unsigned)license_revoked_count(),
                    (unsigned)license_failed_attempts(),
                    (unsigned)lock_left,
                    license_error_text(license_last_error()));
            return;
        }

        if (strcmp(argv[1], "terms") == 0) {
            size_t cap = 128 * 1024;
            char *buf = (char *)kmalloc(cap);
            if (!buf) {
                kprintf("license: out of memory\n");
                return;
            }
            size_t read = 0;
            if (!license_read_terms(buf, cap, &read)) {
                kprintf("license: terms file unavailable\n");
                kfree(buf);
                return;
            }
            buf[read < cap ? read : (cap - 1)] = '\0';
            kprintf("%s\n", buf);
            kfree(buf);
            return;
        }

        if (strcmp(argv[1], "accept") == 0) {
            if (!license_accept_terms()) {
                kprintf("license: cannot accept terms (missing or invalid terms file)\n");
                return;
            }
            kprintf("license: terms accepted\n");
            return;
        }

        if (strcmp(argv[1], "reject") == 0) {
            if (!license_reject_terms()) {
                kprintf("license: cannot reject terms\n");
                return;
            }
            kprintf("license: terms set to pending\n");
            return;
        }

        if (strcmp(argv[1], "setup") == 0) {
            if (license_usage_allowed()) {
                kprintf("license setup: already unlocked\n");
                return;
            }
            start_license_setup_app(0);
            return;
        }

        if (strcmp(argv[1], "reload") == 0) {
            license_reload();
            kprintf("license: registry reloaded, issued=%u revoked=%u\n",
                    (unsigned)license_registered_count(),
                    (unsigned)license_revoked_count());
            return;
        }

        if (strcmp(argv[1], "deactivate") == 0) {
            license_deactivate();
            kprintf("license: deactivated\n");
            return;
        }

        if (argc >= 3 && strcmp(argv[1], "verify") == 0) {
            int sig_ok = license_signature_valid(argv[2]) ? 1 : 0;
            int reg_ok = license_registered(argv[2]) ? 1 : 0;
            int revoked = license_key_revoked(argv[2]) ? 1 : 0;
            kprintf("license: signature=%s registered=%s revoked=%s\n",
                    sig_ok ? "valid" : "invalid",
                    reg_ok ? "yes" : "no",
                    revoked ? "yes" : "no");
            return;
        }

        if (argc >= 3 && strcmp(argv[1], "activate") == 0) {
            if (!license_activate(argv[2])) {
                uint32_t lock_left = license_lockout_remaining_seconds();
                kprintf("license: activation failed (%s",
                        license_error_text(license_last_error()));
                if (lock_left > 0) {
                    kprintf(", lock=%us", (unsigned)lock_left);
                }
                kprintf(")\n");
                return;
            }
            kprintf("license: activated\n");
            return;
        }

        if (strcmp(argv[1], "unlock") == 0) {
            if (!license_unlock_runtime()) {
                return;
            }
            return;
        }

        kprintf("license commands:\n");
        kprintf("  license status\n");
        kprintf("  license terms\n");
        kprintf("  license accept\n");
        kprintf("  license reject\n");
        kprintf("  license setup\n");
        kprintf("  license verify <key>\n");
        kprintf("  license activate <key>\n");
        kprintf("  license deactivate\n");
        kprintf("  license reload\n");
        kprintf("  license unlock\n");
        return;
    }

    if (strcmp(argv[0], "ps") == 0) {
        task_debug_dump();
        return;
    }

    if (strcmp(argv[0], "sched") == 0) {
        if (argc == 1 || strcmp(argv[1], "status") == 0) {
            kprintf("sched: quantum=%u ticks=%u switches=%u\n",
                    (unsigned)task_quantum_ticks(),
                    (unsigned)task_tick_count(),
                    (unsigned)task_switch_count());
            return;
        }
        if (argc >= 3 && strcmp(argv[1], "quantum") == 0) {
            uint32_t q = 0;
            if (!parse_u32_text(argv[2], &q) || q == 0) {
                kprintf("sched: usage sched quantum <ticks>\n");
                return;
            }
            task_set_quantum_ticks(q);
            kprintf("sched: quantum=%u\n", (unsigned)task_quantum_ticks());
            return;
        }
        if (strcmp(argv[1], "save") == 0) {
            char qtext[16];
            qtext[0] = '\0';
            uint32_t q = task_quantum_ticks();
            char rev[16];
            size_t idx = 0;
            do {
                rev[idx++] = (char)('0' + (q % 10u));
                q /= 10u;
            } while (q != 0u && idx < sizeof(rev));
            while (idx > 0) {
                char c[2];
                c[0] = rev[idx - 1];
                c[1] = '\0';
                strncat(qtext, c, sizeof(qtext) - strlen(qtext) - 1);
                idx--;
            }
            if (!config_set("sched.quantum", qtext) || !config_save()) {
                kprintf("sched: failed to persist quantum\n");
                return;
            }
            kprintf("sched: persisted quantum=%s\n", qtext);
            return;
        }
        if (argc >= 4 && strcmp(argv[1], "prio") == 0) {
            uint64_t id = 0;
            int prio = 0;
            if (!parse_u64_text(argv[2], &id) || !parse_i32_text(argv[3], &prio)) {
                kprintf("sched: usage sched prio <id> <0..31>\n");
                return;
            }
            if (!task_set_priority(id, prio)) {
                kprintf("sched: task id not found\n");
                return;
            }
            kprintf("sched: updated priority for task %u\n", (unsigned)id);
            return;
        }
        if (argc >= 4 && strcmp(argv[1], "rt") == 0) {
            uint64_t id = 0;
            if (!parse_u64_text(argv[2], &id)) {
                kprintf("sched: usage sched rt <id> <on|off>\n");
                return;
            }
            int on = 0;
            if (strcmp(argv[3], "on") == 0) {
                on = 1;
            } else if (strcmp(argv[3], "off") == 0) {
                on = 0;
            } else {
                kprintf("sched: usage sched rt <id> <on|off>\n");
                return;
            }
            if (!task_set_realtime(id, on != 0)) {
                kprintf("sched: task id not found\n");
                return;
            }
            kprintf("sched: task %u class=%s\n", (unsigned)id, on ? "rt" : "normal");
            return;
        }
        kprintf("sched commands:\n");
        kprintf("  sched status\n");
        kprintf("  sched quantum <ticks>\n");
        kprintf("  sched save\n");
        kprintf("  sched prio <id> <0..31>\n");
        kprintf("  sched rt <id> <on|off>\n");
        return;
    }

    if (strcmp(argv[0], "trace") == 0) {
        if (argc == 1 || strcmp(argv[1], "status") == 0) {
            kprintf("trace: bytes=%u\n", (unsigned)trace_size());
            return;
        }
        if (strcmp(argv[1], "clear") == 0) {
            trace_clear();
            kprintf("trace: cleared\n");
            return;
        }
        if (strcmp(argv[1], "dump") == 0) {
            size_t cap = 8192;
            char *buf = (char *)kmalloc(cap);
            if (!buf) {
                kprintf("trace: out of memory\n");
                return;
            }
            size_t n = trace_copy(buf, cap);
            if (n == 0) {
                kprintf("trace: empty\n");
            } else {
                kprintf("%s", buf);
            }
            kfree(buf);
            return;
        }
        kprintf("trace commands:\n");
        kprintf("  trace status\n");
        kprintf("  trace dump\n");
        kprintf("  trace clear\n");
        return;
    }

    if (strcmp(argv[0], "mutex") == 0) {
        if (argc == 2 && strcmp(argv[1], "stats") == 0) {
            kprintf("mutex: locks=%u contentions=%u\n",
                    (unsigned)kmutex_global_locks(),
                    (unsigned)kmutex_global_contentions());
            return;
        }
        kprintf("mutex commands:\n");
        kprintf("  mutex stats\n");
        return;
    }

    if (strcmp(argv[0], "audit") == 0) {
        if (argc == 1 || strcmp(argv[1], "show") == 0) {
            size_t cap = 8192;
            char *buf = (char *)kmalloc(cap);
            if (!buf) {
                kprintf("audit: out of memory\n");
                return;
            }
            size_t n = audit_dump(buf, cap);
            if (n == 0) {
                kprintf("audit: empty\n");
            } else {
                kprintf("%s", buf);
            }
            kfree(buf);
            return;
        }
        if (strcmp(argv[1], "clear") == 0) {
            audit_clear();
            kprintf("audit: cleared\n");
            return;
        }
        kprintf("audit commands:\n");
        kprintf("  audit show\n");
        kprintf("  audit clear\n");
        return;
    }

    if (strcmp(argv[0], "log") == 0) {
        if (argc == 1 || strcmp(argv[1], "list") == 0 || strcmp(argv[1], "show") == 0) {
            slog_level_t min_level = SLOG_LEVEL_DEBUG;
            if (argc >= 3 && !slog_level_from_text(argv[2], &min_level)) {
                kprintf("log: usage log list [debug|info|warn|error]\n");
                return;
            }
            size_t cap = 16384;
            char *buf = (char *)kmalloc(cap);
            if (!buf) {
                kprintf("log: out of memory\n");
                return;
            }
            size_t n = slog_dump(buf, cap, min_level);
            if (n == 0) {
                kprintf("log: empty\n");
            } else {
                kprintf("%s", buf);
            }
            kfree(buf);
            return;
        }
        if (strcmp(argv[1], "clear") == 0) {
            slog_clear();
            kprintf("log: cleared\n");
            return;
        }
        if (argc >= 3 && strcmp(argv[1], "level") == 0) {
            slog_level_t level = SLOG_LEVEL_DEBUG;
            if (!slog_level_from_text(argv[2], &level)) {
                kprintf("log: usage log level <debug|info|warn|error>\n");
                return;
            }
            slog_set_min_level(level);
            (void)config_set("log.level", argv[2]);
            (void)config_save();
            kprintf("log: min-level=%s\n", slog_level_name(slog_min_level()));
            return;
        }
        if (argc >= 5 && strcmp(argv[1], "write") == 0) {
            slog_level_t level = SLOG_LEVEL_INFO;
            if (!slog_level_from_text(argv[2], &level)) {
                kprintf("log: usage log write <level> <component> <message>\n");
                return;
            }
            char msg[256];
            msg[0] = '\0';
            for (int i = 4; i < argc; i++) {
                if (i > 4) {
                    strncat(msg, " ", sizeof(msg) - strlen(msg) - 1);
                }
                strncat(msg, argv[i], sizeof(msg) - strlen(msg) - 1);
            }
            slog_log(level, argv[3], msg);
            kprintf("log: wrote entry\n");
            return;
        }
        kprintf("log commands:\n");
        kprintf("  log list [debug|info|warn|error]\n");
        kprintf("  log level <debug|info|warn|error>\n");
        kprintf("  log write <level> <component> <message>\n");
        kprintf("  log clear\n");
        return;
    }

    if (strcmp(argv[0], "svc") == 0) {
        if (argc == 1 || strcmp(argv[1], "list") == 0) {
            size_t cap = 4096;
            char *buf = (char *)kmalloc(cap);
            if (!buf) {
                kprintf("svc: out of memory\n");
                return;
            }
            size_t n = service_dump(buf, cap);
            if (n == 0) {
                kprintf("svc: empty\n");
            } else {
                kprintf("%s", buf);
            }
            kfree(buf);
            return;
        }
        if (argc >= 3 && strcmp(argv[1], "start") == 0) {
            if (!service_start(argv[2])) {
                kprintf("svc: start failed for %s\n", argv[2]);
                return;
            }
            kprintf("svc: started %s\n", argv[2]);
            return;
        }
        if (argc >= 3 && strcmp(argv[1], "stop") == 0) {
            if (!service_stop(argv[2])) {
                kprintf("svc: stop failed for %s\n", argv[2]);
                return;
            }
            kprintf("svc: stopped %s\n", argv[2]);
            return;
        }
        if (argc >= 3 && strcmp(argv[1], "restart") == 0) {
            if (!service_restart(argv[2])) {
                kprintf("svc: restart failed for %s\n", argv[2]);
                return;
            }
            kprintf("svc: restarted %s\n", argv[2]);
            return;
        }
        if (argc >= 4 && strcmp(argv[1], "policy") == 0) {
            service_policy_t policy = SERVICE_POLICY_MANUAL;
            if (strcmp(argv[3], "always") == 0) {
                policy = SERVICE_POLICY_ALWAYS;
            } else if (strcmp(argv[3], "manual") == 0) {
                policy = SERVICE_POLICY_MANUAL;
            } else {
                kprintf("svc: usage svc policy <name> <always|manual>\n");
                return;
            }
            if (!service_set_policy(argv[2], policy)) {
                kprintf("svc: policy update failed for %s\n", argv[2]);
                return;
            }
            kprintf("svc: policy[%s]=%s\n", argv[2], policy == SERVICE_POLICY_ALWAYS ? "always" : "manual");
            return;
        }
        if (argc >= 6 && strcmp(argv[1], "limits") == 0) {
            uint32_t max_restarts = 0;
            uint32_t window_seconds = 0;
            uint32_t backoff_seconds = 0;
            if (!parse_u32_text(argv[3], &max_restarts) ||
                !parse_u32_text(argv[4], &window_seconds) ||
                !parse_u32_text(argv[5], &backoff_seconds)) {
                kprintf("svc: usage svc limits <name> <max> <window_s> <backoff_s>\n");
                return;
            }
            if (!service_set_restart_limits(argv[2], max_restarts, window_seconds, backoff_seconds)) {
                kprintf("svc: failed to update limits for %s\n", argv[2]);
                return;
            }
            kprintf("svc: limits updated for %s\n", argv[2]);
            return;
        }
        if (argc >= 4 && strcmp(argv[1], "persist-policy") == 0) {
            if (strcmp(argv[3], "always") != 0 && strcmp(argv[3], "manual") != 0) {
                kprintf("svc: usage svc persist-policy <name> <always|manual>\n");
                return;
            }
            char key[64];
            key[0] = '\0';
            strncat(key, "service.", sizeof(key) - strlen(key) - 1);
            strncat(key, argv[2], sizeof(key) - strlen(key) - 1);
            strncat(key, ".policy", sizeof(key) - strlen(key) - 1);
            if (!config_set(key, argv[3]) || !config_save()) {
                kprintf("svc: failed to persist policy\n");
                return;
            }
            kprintf("svc: persisted %s=%s\n", key, argv[3]);
            return;
        }
        kprintf("svc commands:\n");
        kprintf("  svc list\n");
        kprintf("  svc start <name>\n");
        kprintf("  svc stop <name>\n");
        kprintf("  svc restart <name>\n");
        kprintf("  svc policy <name> <always|manual>\n");
        kprintf("  svc limits <name> <max> <window_s> <backoff_s>\n");
        kprintf("  svc persist-policy <name> <always|manual>\n");
        return;
    }

    if (strcmp(argv[0], "cron") == 0) {
        if (argc == 1 || strcmp(argv[1], "list") == 0) {
            size_t cap = 4096;
            char *buf = (char *)kmalloc(cap);
            if (!buf) {
                kprintf("cron: out of memory\n");
                return;
            }
            size_t n = cron_list(buf, cap);
            if (n == 0) {
                kprintf("cron: empty\n");
            } else {
                kprintf("%s", buf);
            }
            kfree(buf);
            return;
        }
        if (strcmp(argv[1], "actions") == 0) {
            char out[256];
            cron_actions(out, sizeof(out));
            kprintf("%s", out);
            return;
        }
        if (argc >= 4 && strcmp(argv[1], "add") == 0) {
            uint32_t seconds = 0;
            if (!parse_u32_text(argv[3], &seconds) || seconds == 0) {
                kprintf("cron: usage cron add <action> <seconds>\n");
                return;
            }
            uint32_t id = 0;
            if (!cron_add(argv[2], seconds, &id)) {
                kprintf("cron: add failed\n");
                return;
            }
            (void)cron_save();
            kprintf("cron: added id=%u\n", (unsigned)id);
            return;
        }
        if (argc >= 3 && strcmp(argv[1], "remove") == 0) {
            uint32_t id = 0;
            if (!parse_u32_text(argv[2], &id)) {
                kprintf("cron: usage cron remove <id>\n");
                return;
            }
            if (!cron_remove(id)) {
                kprintf("cron: remove failed\n");
                return;
            }
            (void)cron_save();
            kprintf("cron: removed id=%u\n", (unsigned)id);
            return;
        }
        if (argc >= 4 && strcmp(argv[1], "enable") == 0) {
            uint32_t id = 0;
            int on = 0;
            if (!parse_u32_text(argv[2], &id) || !parse_on_off(argv[3], &on)) {
                kprintf("cron: usage cron enable <id> <on|off>\n");
                return;
            }
            if (!cron_set_enabled(id, on != 0)) {
                kprintf("cron: enable failed\n");
                return;
            }
            (void)cron_save();
            kprintf("cron: id=%u %s\n", (unsigned)id, on ? "enabled" : "disabled");
            return;
        }
        if (argc >= 3 && strcmp(argv[1], "run") == 0) {
            uint32_t id = 0;
            if (!parse_u32_text(argv[2], &id)) {
                kprintf("cron: usage cron run <id>\n");
                return;
            }
            if (!cron_run(id)) {
                kprintf("cron: run failed\n");
                return;
            }
            kprintf("cron: run id=%u\n", (unsigned)id);
            return;
        }
        if (strcmp(argv[1], "save") == 0) {
            if (!cron_save()) {
                kprintf("cron: save failed\n");
                return;
            }
            kprintf("cron: saved\n");
            return;
        }
        if (strcmp(argv[1], "load") == 0) {
            if (!cron_load()) {
                kprintf("cron: load failed or no file\n");
                return;
            }
            kprintf("cron: loaded\n");
            return;
        }
        kprintf("cron commands:\n");
        kprintf("  cron list\n");
        kprintf("  cron actions\n");
        kprintf("  cron add <action> <seconds>\n");
        kprintf("  cron remove <id>\n");
        kprintf("  cron enable <id> <on|off>\n");
        kprintf("  cron run <id>\n");
        kprintf("  cron save\n");
        kprintf("  cron load\n");
        return;
    }

    if (strcmp(argv[0], "config") == 0) {
        if (argc == 1 || strcmp(argv[1], "list") == 0) {
            size_t cap = 4096;
            char *buf = (char *)kmalloc(cap);
            if (!buf) {
                kprintf("config: out of memory\n");
                return;
            }
            size_t n = config_dump(buf, cap);
            if (n == 0) {
                kprintf("config: empty\n");
            } else {
                size_t pos = 0;
                int printed = 0;
                while (pos < n && buf[pos] != '\0') {
                    size_t start = pos;
                    while (pos < n && buf[pos] != '\n' && buf[pos] != '\0') {
                        pos++;
                    }
                    size_t end = pos;
                    if (pos < n && buf[pos] == '\n') {
                        pos++;
                    }
                    if (end <= start) {
                        continue;
                    }
                    char line[256];
                    size_t len = end - start;
                    if (len >= sizeof(line)) {
                        continue;
                    }
                    memcpy(line, buf + start, len);
                    line[len] = '\0';
                    char *eq = strchr(line, '=');
                    if (eq) {
                        *eq = '\0';
                        if (config_key_is_server_restricted(line)) {
                            continue;
                        }
                        *eq = '=';
                    }
                    kprintf("%s\n", line);
                    printed = 1;
                }
                if (!printed) {
                    kprintf("config: empty\n");
                }
            }
            kfree(buf);
            return;
        }
        if (argc >= 3 && strcmp(argv[1], "get") == 0) {
            if (config_key_is_server_restricted(argv[2])) {
                security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "config-get-server-key");
                kprintf("config: key restricted\n");
                return;
            }
            const char *value = config_get(argv[2]);
            if (!value) {
                kprintf("config: key not found\n");
                return;
            }
            kprintf("%s=%s\n", argv[2], value);
            return;
        }
        if (argc >= 4 && strcmp(argv[1], "set") == 0) {
            if (config_key_is_server_restricted(argv[2])) {
                security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "config-set-server-key");
                kprintf("config: key restricted\n");
                return;
            }
            char value[256];
            value[0] = '\0';
            for (int i = 3; i < argc; i++) {
                if (i > 3) {
                    strncat(value, " ", sizeof(value) - strlen(value) - 1);
                }
                strncat(value, argv[i], sizeof(value) - strlen(value) - 1);
            }
            if (!config_set(argv[2], value)) {
                kprintf("config: set failed\n");
                return;
            }
            kprintf("config: set %s=%s\n", argv[2], value);
            return;
        }
        if (argc >= 3 && strcmp(argv[1], "unset") == 0) {
            if (config_key_is_server_restricted(argv[2])) {
                security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "config-unset-server-key");
                kprintf("config: key restricted\n");
                return;
            }
            if (!config_unset(argv[2])) {
                kprintf("config: unset failed\n");
                return;
            }
            kprintf("config: removed %s\n", argv[2]);
            return;
        }
        if (strcmp(argv[1], "save") == 0) {
            if (!config_save()) {
                kprintf("config: save failed\n");
                return;
            }
            kprintf("config: saved\n");
            return;
        }
        if (strcmp(argv[1], "load") == 0) {
            if (!config_load()) {
                kprintf("config: load failed or no file\n");
                return;
            }
            kprintf("config: loaded\n");
            return;
        }
        kprintf("config commands:\n");
        kprintf("  config list\n");
        kprintf("  config get <key>\n");
        kprintf("  config set <key> <value>\n");
        kprintf("  config unset <key>\n");
        kprintf("  config save\n");
        kprintf("  config load\n");
        return;
    }

    if (strcmp(argv[0], "boot") == 0) {
        if (argc == 1 || strcmp(argv[1], "status") == 0) {
            const char *profile = config_get("boot.profile");
            if (!profile) {
                profile = "normal";
            }
            service_policy_t net_policy = service_policy("net");
            kprintf("boot: profile=%s quantum=%u net-policy=%s\n",
                    profile,
                    (unsigned)task_quantum_ticks(),
                    net_policy == SERVICE_POLICY_ALWAYS ? "always" : "manual");
            return;
        }
        if (argc >= 3 && strcmp(argv[1], "profile") == 0) {
            if (strcmp(argv[2], "normal") != 0 &&
                strcmp(argv[2], "safe") != 0 &&
                strcmp(argv[2], "perf") != 0) {
                kprintf("boot: usage boot profile <normal|safe|perf> [apply]\n");
                return;
            }
            config_set("boot.profile", argv[2]);
            if (strcmp(argv[2], "safe") == 0) {
                config_set("service.net.policy", "manual");
            } else {
                config_set("service.net.policy", "always");
            }
            if (!config_save()) {
                kprintf("boot: failed to persist profile\n");
                return;
            }
            if (argc >= 4 && strcmp(argv[3], "apply") == 0) {
                if (!apply_profile_runtime(argv[2])) {
                    kprintf("boot: apply failed\n");
                    return;
                }
                kprintf("boot: profile set+applied %s\n", argv[2]);
                return;
            }
            kprintf("boot: profile set to %s\n", argv[2]);
            return;
        }
        if (strcmp(argv[1], "apply") == 0) {
            const char *profile = argc >= 3 ? argv[2] : config_get("boot.profile");
            if (!profile) {
                profile = "normal";
            }
            if (!apply_profile_runtime(profile)) {
                kprintf("boot: usage boot apply [normal|safe|perf]\n");
                return;
            }
            kprintf("boot: applied %s\n", profile);
            return;
        }
        kprintf("boot commands:\n");
        kprintf("  boot status\n");
        kprintf("  boot profile <normal|safe|perf> [apply]\n");
        kprintf("  boot apply [normal|safe|perf]\n");
        return;
    }

    if (strcmp(argv[0], "fsck") == 0) {
        char report[4096];
        bool ok = sfs_check(report, sizeof(report));
        kprintf("%s", report);
        kprintf("fsck: %s\n", ok ? "clean" : "issues-found");
        return;
    }

    if (strcmp(argv[0], "ls") == 0) {
        char path[256];
        if (!path_resolve(argc > 1 ? argv[1] : cwd, path, sizeof(path))) {
            kprintf("ls: invalid path\n");
            return;
        }
        char out[2048];
        int n = sfs_list(path, out, sizeof(out));
        if (n < 0) {
            kprintf("ls: cannot access '%s'\n", path);
            return;
        }
        kprintf("%s", out);
        return;
    }

    if (strcmp(argv[0], "cd") == 0) {
        if (argc < 2) {
            kprintf("cd: missing operand\n");
            return;
        }

        char path[256];
        if (!path_resolve(argv[1], path, sizeof(path))) {
            kprintf("cd: invalid path\n");
            return;
        }

        char out[2];
        if (sfs_list(path, out, sizeof(out)) < 0) {
            kprintf("cd: not a directory: %s\n", path);
            return;
        }
        strncpy(cwd, path, sizeof(cwd) - 1);
        cwd[sizeof(cwd) - 1] = '\0';
        return;
    }

    if (strcmp(argv[0], "mkdir") == 0) {
        if (argc < 2) {
            kprintf("mkdir: missing operand\n");
            return;
        }
        if (security_lockdown_active()) {
            security_note_event(SECURITY_EVENT_FS_BLOCKED, "mkdir-lockdown");
            kprintf("mkdir: blocked in security lockdown\n");
            return;
        }
        char path[256];
        if (!path_resolve(argv[1], path, sizeof(path))) {
            kprintf("mkdir: invalid path\n");
            return;
        }
        if (path_has_prefix(path, "/etc") || path_has_prefix(path, "/bin") || path_has_prefix(path, "/boot")) {
            audit_log("SECURITY_BLOCK_MKDIR", path);
            security_note_event(SECURITY_EVENT_FS_BLOCKED, path);
            kprintf("mkdir: denied on protected path %s\n", path);
            return;
        }
        if (!sfs_make_dir(path)) {
            kprintf("mkdir: failed: %s\n", path);
            return;
        }
        if (sfs_persistence_enabled() && !sfs_sync()) {
            kprintf("mkdir: warning: sync failed\n");
        }
        return;
    }

    if (strcmp(argv[0], "apps") == 0) {
        size_t cap = 64 * 1024;
        char *out = (char *)kmalloc(cap);
        if (!out) {
            kprintf("apps: out of memory\n");
            return;
        }

        int n = sfs_list("/bin", out, cap);
        if (n < 0) {
            kprintf("apps: cannot access /bin\n");
            kfree(out);
            return;
        }

        if (argc >= 3 && strcmp(argv[1], "find") == 0) {
            const char *needle = argv[2];
            int found = 0;

            char *list_line = out;
            while (*list_line) {
                char *end = strchr(list_line, '\n');
                if (end) {
                    *end = '\0';
                }
                if (text_contains_ci(list_line, needle)) {
                    kprintf("%s\n", list_line);
                    found++;
                }
                if (!end) {
                    break;
                }
                list_line = end + 1;
            }

            if (found == 0) {
                kprintf("apps: no matches for '%s'\n", needle);
            }
            kfree(out);
            return;
        }

        kprintf("%s", out);
        if ((size_t)n >= cap - 2) {
            kprintf("apps: output truncated, use 'apps find <txt>'\n");
        }
        kfree(out);
        return;
    }

    if (strcmp(argv[0], "cat") == 0) {
        if (argc < 2) {
            kprintf("cat: missing operand\n");
            return;
        }
        char path[256];
        if (!path_resolve(argv[1], path, sizeof(path))) {
            kprintf("cat: invalid path\n");
            return;
        }
        if (path_is_sensitive_read(path)) {
            audit_log("SECURITY_BLOCK_READ", path);
            security_note_event(SECURITY_EVENT_FS_BLOCKED, path);
            kprintf("cat: denied on sensitive path %s\n", path);
            return;
        }
        size_t cap = 64 * 1024;
        char *buf = (char *)kmalloc(cap + 1);
        if (!buf) {
            kprintf("cat: out of memory\n");
            return;
        }
        size_t read = 0;
        if (!sfs_read_file(path, buf, cap, &read)) {
            kprintf("cat: cannot read %s\n", path);
            kfree(buf);
            return;
        }
        buf[read] = '\0';
        kprintf("%s\n", buf);
        kfree(buf);
        return;
    }

    if (strcmp(argv[0], "write") == 0) {
        if (argc < 3) {
            kprintf("write: usage write <path> <text>\n");
            return;
        }
        if (security_lockdown_active()) {
            security_note_event(SECURITY_EVENT_FS_BLOCKED, "write-lockdown");
            kprintf("write: blocked in security lockdown\n");
            return;
        }

        char path[256];
        if (!path_resolve(argv[1], path, sizeof(path))) {
            kprintf("write: invalid path\n");
            return;
        }
        if (path_is_security_protected(path)) {
            audit_log("SECURITY_BLOCK_WRITE", path);
            security_note_event(SECURITY_EVENT_FS_BLOCKED, path);
            kprintf("write: denied on protected path %s\n", path);
            return;
        }

        char payload[512];
        payload[0] = '\0';
        for (int i = 2; i < argc; i++) {
            if (i > 2) {
                strncat(payload, " ", sizeof(payload) - strlen(payload) - 1);
            }
            strncat(payload, argv[i], sizeof(payload) - strlen(payload) - 1);
        }
        strncat(payload, "\n", sizeof(payload) - strlen(payload) - 1);

        if (!sfs_write_file(path, payload, strlen(payload))) {
            kprintf("write: failed for %s\n", path);
            return;
        }
        if (sfs_persistence_enabled() && !sfs_sync()) {
            kprintf("write: warning: sync failed\n");
        }
        return;
    }

    if (strcmp(argv[0], "sync") == 0) {
        if (!sfs_persistence_enabled()) {
            kprintf("sync: persistence is disabled\n");
            return;
        }
        if (!sfs_sync()) {
            kprintf("sync: failed\n");
            return;
        }
        kprintf("sync: ok\n");
        return;
    }

    if (strcmp(argv[0], "cpuinfo") == 0) {
        kprintf("cpus: online=%u total=%u\n", (unsigned)mp_online_cpus(), (unsigned)mp_total_cpus());
        return;
    }

    if (strcmp(argv[0], "netinfo") == 0 || strcmp(argv[0], "ifconfig") == 0) {
        if (!security_allow_network_ops()) {
            kprintf("net: blocked by security policy\n");
            return;
        }
        if (!net_available()) {
            kprintf("net: unavailable\n");
            return;
        }

        uint8_t mac[6];
        net_get_mac(mac);
        uint32_t ip = net_ip_addr();

        kprintf("net: up ip=%u.%u.%u.%u mac=",
                (unsigned)((ip >> 24) & 0xFF), (unsigned)((ip >> 16) & 0xFF),
                (unsigned)((ip >> 8) & 0xFF), (unsigned)(ip & 0xFF));
        for (int i = 0; i < 6; i++) {
            if (i) {
                console_putc(':');
            }
            print_hex_byte(mac[i]);
        }
        kprintf(" listen=%u\n", (unsigned)net_tcp_listen_port());
        return;
    }

    if (strcmp(argv[0], "ping") == 0) {
        if (!security_allow_network_ops()) {
            kprintf("ping: blocked by security policy\n");
            return;
        }
        if (argc < 2) {
            kprintf("ping: usage ping <ip>\n");
            return;
        }
        uint32_t ip = 0;
        if (!parse_ipv4(argv[1], &ip)) {
            kprintf("ping: invalid ip\n");
            return;
        }
        if (security_ip_is_verification_server(ip)) {
            security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "ping-server-ip");
            kprintf("ping: destination restricted\n");
            return;
        }
        if (net_ping(ip)) {
            kprintf("ping: reply from %s\n", argv[1]);
        } else {
            kprintf("ping: timeout to %s\n", argv[1]);
        }
        return;
    }

    if (strcmp(argv[0], "tcplisten") == 0) {
        if (!security_allow_network_ops()) {
            kprintf("tcplisten: blocked by security policy\n");
            return;
        }
        if (argc < 2) {
            kprintf("tcplisten: usage tcplisten <port>\n");
            return;
        }
        int port = 0;
        for (const char *p = argv[1]; *p; p++) {
            if (*p < '0' || *p > '9') {
                kprintf("tcplisten: invalid port\n");
                return;
            }
            port = port * 10 + (*p - '0');
        }
        if (port <= 0 || port > 65535) {
            kprintf("tcplisten: invalid port\n");
            return;
        }
        net_set_tcp_listen_port((uint16_t)port);
        kprintf("tcplisten: %u\n", (unsigned)net_tcp_listen_port());
        return;
    }

    if (strcmp(argv[0], "tcpsend") == 0) {
        if (!security_allow_network_ops()) {
            kprintf("tcpsend: blocked by security policy\n");
            return;
        }
        if (argc < 4) {
            kprintf("tcpsend: usage tcpsend <ip> <port> <text>\n");
            return;
        }
        uint32_t ip = 0;
        if (!parse_ipv4(argv[1], &ip)) {
            kprintf("tcpsend: invalid ip\n");
            return;
        }
        if (security_ip_is_verification_server(ip)) {
            security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "tcpsend-server-ip");
            kprintf("tcpsend: destination restricted\n");
            return;
        }
        int port = 0;
        for (const char *p = argv[2]; *p; p++) {
            if (*p < '0' || *p > '9') {
                kprintf("tcpsend: invalid port\n");
                return;
            }
            port = port * 10 + (*p - '0');
        }
        if (port <= 0 || port > 65535) {
            kprintf("tcpsend: invalid port\n");
            return;
        }

        char msg[512];
        msg[0] = '\0';
        for (int i = 3; i < argc; i++) {
            if (i > 3) {
                strncat(msg, " ", sizeof(msg) - strlen(msg) - 1);
            }
            strncat(msg, argv[i], sizeof(msg) - strlen(msg) - 1);
        }

        if (net_tcp_send_text(ip, (uint16_t)port, msg)) {
            kprintf("tcpsend: sent\n");
        } else {
            kprintf("tcpsend: failed\n");
        }
        return;
    }

    if (strcmp(argv[0], "server") == 0) {
        if (argc == 1 || strcmp(argv[1], "status") == 0) {
            char endpoint_text[40];
            endpoint_text[0] = '\0';
            if (g_server_endpoint_ready) {
                format_ipv4_text(g_server_ip, endpoint_text, sizeof(endpoint_text));
                buf_append_text(endpoint_text, sizeof(endpoint_text), ":");
                buf_append_u32(endpoint_text, sizeof(endpoint_text), (uint32_t)g_server_port);
            } else {
                buf_append_text(endpoint_text, sizeof(endpoint_text), "unset");
            }
            kprintf("server: endpoint=%s features=%u/%u ideas=%u net=%s security-net=%s\n",
                    endpoint_text,
                    (unsigned)g_server_feature_enabled_count,
                    (unsigned)SERVER_FEATURE_COUNT,
                    (unsigned)SERVER_USE_CASE_COUNT,
                    net_available() ? "up" : "down",
                    security_allow_network_ops() ? "allow" : "blocked");
            return;
        }

        if (strcmp(argv[1], "endpoint") == 0) {
            if (argc == 3 && strcmp(argv[2], "clear") == 0) {
                char deny_reason[128];
                if (!security_allow_server_command("endpoint", deny_reason, sizeof(deny_reason))) {
                    kprintf("server: blocked (%s)\n", deny_reason[0] ? deny_reason : "policy");
                    return;
                }
                g_server_endpoint_ready = 0;
                g_server_ip = 0;
                g_server_port = 0;
                if (!server_save_endpoint()) {
                    kprintf("server: endpoint clear failed\n");
                    return;
                }
                audit_log("SERVER_ENDPOINT", "cleared");
                kprintf("server: endpoint cleared\n");
                return;
            }
            if (argc < 4) {
                kprintf("server: usage server endpoint <ip> <port>\n");
                kprintf("server: usage server endpoint clear\n");
                return;
            }
            uint32_t ip = 0;
            uint32_t port = 0;
            if (!parse_ipv4(argv[2], &ip) || !parse_u32_text(argv[3], &port) || port == 0 || port > 65535u) {
                kprintf("server: invalid endpoint\n");
                return;
            }
            char deny_reason[128];
            if (!security_allow_server_endpoint(ip, (uint16_t)port, deny_reason, sizeof(deny_reason))) {
                kprintf("server: blocked (%s)\n", deny_reason[0] ? deny_reason : "policy");
                return;
            }
            g_server_ip = ip;
            g_server_port = (uint16_t)port;
            g_server_endpoint_ready = 1;
            if (!server_save_endpoint()) {
                kprintf("server: endpoint save failed\n");
                return;
            }
            audit_log("SERVER_ENDPOINT", "updated");
            kprintf("server: endpoint set to %s:%u\n", argv[2], (unsigned)g_server_port);
            return;
        }

        if (strcmp(argv[1], "ping") == 0) {
            if (!g_server_endpoint_ready) {
                kprintf("server: set endpoint first\n");
                return;
            }
            char payload[160];
            payload[0] = '\0';
            buf_append_text(payload, sizeof(payload), "QOS_SERVER_PING uptime_ticks=");
            buf_append_u32(payload, sizeof(payload), (uint32_t)pit_ticks());
            buf_append_text(payload, sizeof(payload), " features=");
            buf_append_u32(payload, sizeof(payload), g_server_feature_enabled_count);
            char send_reason[128];
            if (server_send_payload(payload, send_reason, sizeof(send_reason))) {
                audit_log("SERVER_PING", "sent");
                kprintf("server: ping sent\n");
            } else {
                kprintf("server: ping failed (%s)\n", send_reason[0] ? send_reason : "unknown");
            }
            return;
        }

        if (strcmp(argv[1], "send") == 0) {
            if (argc < 3) {
                kprintf("server: usage server send <text>\n");
                return;
            }
            char payload[512];
            payload[0] = '\0';
            for (int i = 2; i < argc; i++) {
                if (i > 2) {
                    buf_append_text(payload, sizeof(payload), " ");
                }
                buf_append_text(payload, sizeof(payload), argv[i]);
            }
            char send_reason[128];
            if (!server_send_payload(payload, send_reason, sizeof(send_reason))) {
                kprintf("server: send failed (%s)\n", send_reason[0] ? send_reason : "unknown");
                return;
            }
            audit_log("SERVER_SEND", "ok");
            kprintf("server: sent\n");
            return;
        }

        if (strcmp(argv[1], "sync") == 0) {
            if (!g_server_endpoint_ready) {
                kprintf("server: set endpoint first\n");
                return;
            }
            char payload[196];
            payload[0] = '\0';
            buf_append_text(payload, sizeof(payload), "QOS_SERVER_SYNC enabled=");
            buf_append_u32(payload, sizeof(payload), g_server_feature_enabled_count);
            buf_append_text(payload, sizeof(payload), " total=");
            buf_append_u32(payload, sizeof(payload), SERVER_FEATURE_COUNT);
            buf_append_text(payload, sizeof(payload), " ideas=");
            buf_append_u32(payload, sizeof(payload), SERVER_USE_CASE_COUNT);
            buf_append_text(payload, sizeof(payload), " uptime_ticks=");
            buf_append_u32(payload, sizeof(payload), (uint32_t)pit_ticks());
            char send_reason[128];
            if (!server_send_payload(payload, send_reason, sizeof(send_reason))) {
                kprintf("server: sync failed (%s)\n", send_reason[0] ? send_reason : "unknown");
                return;
            }
            audit_log("SERVER_SYNC", "ok");
            kprintf("server: sync sent\n");
            return;
        }

        if (strcmp(argv[1], "features") == 0) {
            if (argc >= 3 && strcmp(argv[2], "save") == 0) {
                char deny_reason[128];
                if (!security_allow_server_command("features-save", deny_reason, sizeof(deny_reason))) {
                    kprintf("server: blocked (%s)\n", deny_reason[0] ? deny_reason : "policy");
                    return;
                }
                if (!server_save_features()) {
                    kprintf("server: feature save failed\n");
                    return;
                }
                audit_log("SERVER_FEATURES", "saved");
                kprintf("server: features saved\n");
                return;
            }
            if (argc >= 3 && strcmp(argv[2], "load") == 0) {
                char deny_reason[128];
                if (!security_allow_server_command("features-load", deny_reason, sizeof(deny_reason))) {
                    kprintf("server: blocked (%s)\n", deny_reason[0] ? deny_reason : "policy");
                    return;
                }
                server_load_features();
                audit_log("SERVER_FEATURES", "loaded");
                kprintf("server: features loaded (%u/%u enabled)\n",
                        (unsigned)g_server_feature_enabled_count,
                        (unsigned)SERVER_FEATURE_COUNT);
                return;
            }
            if (argc >= 3 && strcmp(argv[2], "reset") == 0) {
                char deny_reason[128];
                if (!security_allow_server_command("features-reset", deny_reason, sizeof(deny_reason))) {
                    kprintf("server: blocked (%s)\n", deny_reason[0] ? deny_reason : "policy");
                    return;
                }
                server_reset_features_defaults();
                audit_log("SERVER_FEATURES", "reset");
                kprintf("server: features reset (%u/%u enabled)\n",
                        (unsigned)g_server_feature_enabled_count,
                        (unsigned)SERVER_FEATURE_COUNT);
                return;
            }
            uint32_t page = 1;
            if (argc >= 3 && !parse_u32_text(argv[2], &page)) {
                kprintf("server: usage server features [page|save|load|reset]\n");
                return;
            }
            if (page == 0) {
                page = 1;
            }
            uint32_t per_page = 20;
            uint32_t total = SERVER_FEATURE_COUNT;
            uint32_t pages = (total + per_page - 1u) / per_page;
            if (page > pages) {
                page = pages;
            }
            uint32_t start = (page - 1u) * per_page;
            uint32_t end = start + per_page;
            if (end > total) {
                end = total;
            }
            kprintf("server features page %u/%u (%u/%u enabled):\n",
                    (unsigned)page,
                    (unsigned)pages,
                    (unsigned)g_server_feature_enabled_count,
                    (unsigned)SERVER_FEATURE_COUNT);
            for (uint32_t i = start; i < end; i++) {
                char name[96];
                name[0] = '\0';
                server_feature_name(i, name, sizeof(name));
                kprintf("  %u [%s] %s\n", (unsigned)(i + 1u), g_server_features[i] ? "on " : "off", name);
            }
            return;
        }

        if (strcmp(argv[1], "feature") == 0) {
            if (argc < 4) {
                kprintf("server: usage server feature <id> <on|off|toggle>\n");
                return;
            }
            char deny_reason[128];
            if (!security_allow_server_command("feature-toggle", deny_reason, sizeof(deny_reason))) {
                kprintf("server: blocked (%s)\n", deny_reason[0] ? deny_reason : "policy");
                return;
            }
            uint32_t id = 0;
            if (!parse_u32_text(argv[2], &id) || id == 0 || id > SERVER_FEATURE_COUNT) {
                kprintf("server: invalid feature id\n");
                return;
            }
            uint32_t idx = id - 1u;
            if (strcmp(argv[3], "toggle") == 0) {
                g_server_features[idx] = g_server_features[idx] ? 0u : 1u;
            } else {
                int on = 0;
                if (!parse_on_off(argv[3], &on)) {
                    kprintf("server: usage server feature <id> <on|off|toggle>\n");
                    return;
                }
                g_server_features[idx] = on ? 1u : 0u;
            }
            server_recount_enabled();
            kprintf("server: feature %u=%s\n", (unsigned)id, g_server_features[idx] ? "on" : "off");
            return;
        }

        if (strcmp(argv[1], "ideas") == 0) {
            uint32_t page = 1;
            if (argc >= 3 && !parse_u32_text(argv[2], &page)) {
                kprintf("server: usage server ideas [page]\n");
                return;
            }
            if (page == 0) {
                page = 1;
            }
            uint32_t per_page = 25;
            uint32_t total = SERVER_USE_CASE_COUNT;
            uint32_t pages = (total + per_page - 1u) / per_page;
            if (page > pages) {
                page = pages;
            }
            uint32_t start = (page - 1u) * per_page;
            uint32_t end = start + per_page;
            if (end > total) {
                end = total;
            }
            kprintf("server use-cases page %u/%u:\n", (unsigned)page, (unsigned)pages);
            for (uint32_t i = start; i < end; i++) {
                char line_buf[192];
                line_buf[0] = '\0';
                server_use_case_text(i, line_buf, sizeof(line_buf));
                kprintf("  %s\n", line_buf);
            }
            return;
        }

        if (strcmp(argv[1], "export") == 0) {
            if (argc < 3) {
                kprintf("server: usage server export <ideas|features> [path]\n");
                return;
            }
            int ideas_mode = 0;
            if (strcmp(argv[2], "ideas") == 0) {
                ideas_mode = 1;
            } else if (strcmp(argv[2], "features") == 0) {
                ideas_mode = 0;
            } else {
                kprintf("server: usage server export <ideas|features> [path]\n");
                return;
            }

            const char *target = 0;
            char resolved[256];
            if (argc >= 4) {
                if (!path_resolve(argv[3], resolved, sizeof(resolved))) {
                    kprintf("server: invalid export path\n");
                    return;
                }
                if (path_is_security_protected(resolved)) {
                    kprintf("server: export path protected\n");
                    return;
                }
                target = resolved;
            }
            {
                const char *effective = target ? target : (ideas_mode ? SERVER_DEFAULT_IDEA_EXPORT : SERVER_DEFAULT_FEATURE_EXPORT);
                char deny_reason[128];
                if (!security_allow_server_export(effective, deny_reason, sizeof(deny_reason))) {
                    kprintf("server: blocked (%s)\n", deny_reason[0] ? deny_reason : "policy");
                    return;
                }
            }
            if (!server_export_catalog(target, ideas_mode)) {
                kprintf("server: export failed\n");
                return;
            }
            kprintf("server: export ok -> %s\n",
                    target ? target : (ideas_mode ? SERVER_DEFAULT_IDEA_EXPORT : SERVER_DEFAULT_FEATURE_EXPORT));
            return;
        }

        kprintf("server commands:\n");
        kprintf("  server status\n");
        kprintf("  server endpoint <ip> <port>\n");
        kprintf("  server endpoint clear\n");
        kprintf("  server ping\n");
        kprintf("  server send <text>\n");
        kprintf("  server sync\n");
        kprintf("  server features [page]\n");
        kprintf("  server features save|load|reset\n");
        kprintf("  server feature <id> <on|off|toggle>\n");
        kprintf("  server ideas [page]\n");
        kprintf("  server export <ideas|features> [path]\n");
        return;
    }

    if (strcmp(argv[0], "compat") == 0) {
        if (argc < 3) {
            kprintf("compat commands:\n");
            kprintf("  compat probe <name|/bin/x>\n");
            kprintf("  compat run <name|/bin/x>\n");
            return;
        }

        char path[256];
        if (!resolve_bin_app_path(argv[2], path, sizeof(path))) {
            security_note_event(SECURITY_EVENT_APP_BLOCKED, "compat-path");
            kprintf("compat: invalid app path (must be under /bin)\n");
            return;
        }

        void *image = 0;
        size_t image_len = 0;
        if (!load_app_image(path, &image, &image_len)) {
            kprintf("compat: cannot open %s\n", path);
            return;
        }

        if (strcmp(argv[1], "probe") == 0) {
            app_runtime_info_t info;
            if (!app_runtime_probe(image, image_len, &info)) {
                kprintf("compat: format=unknown runnable=no detail=unrecognized\n");
            } else {
                kprintf("compat: format=%s wrapped=%s runnable=%s detail=%s\n",
                        app_runtime_kind_name(info.kind),
                        info.wrapped ? "yes" : "no",
                        info.runnable ? "yes" : "no",
                        info.detail);
            }
            kfree(image);
            return;
        }

        if (strcmp(argv[1], "run") == 0) {
            if (!license_usage_allowed()) {
                audit_log("RUN_BLOCKED", "license-not-authorized");
                security_note_event(SECURITY_EVENT_LICENSE_BLOCKED, "run-license");
                kprintf("compat: blocked. requires verified consumer monthly license and accepted terms.\n");
                kfree(image);
                return;
            }
            app_runtime_info_t info;
            if (!app_runtime_run(image, image_len, &info)) {
                kprintf("compat: failed format=%s detail=%s\n",
                        app_runtime_kind_name(info.kind),
                        info.detail[0] ? info.detail : "runtime failure");
                kfree(image);
                return;
            }
            kprintf("compat: process finished %s (%s)\n", path, app_runtime_kind_name(info.kind));
            kfree(image);
            return;
        }

        kprintf("compat: unknown command\n");
        kprintf("compat commands: probe, run\n");
        kfree(image);
        return;
    }

    if (strcmp(argv[0], "run") == 0) {
        if (argc < 2) {
            kprintf("run: missing operand\n");
            return;
        }
        if (!license_usage_allowed()) {
            audit_log("RUN_BLOCKED", "license-not-authorized");
            security_note_event(SECURITY_EVENT_LICENSE_BLOCKED, "run-license");
            kprintf("run: blocked. requires verified consumer monthly license and accepted terms.\n");
            return;
        }
        char path[256];
        if (!resolve_bin_app_path(argv[1], path, sizeof(path))) {
            security_note_event(SECURITY_EVENT_APP_BLOCKED, "run-path");
            audit_log("SECURITY_BLOCK_EXEC", argv[1]);
            kprintf("run: denied. executable path must be under /bin\n");
            return;
        }

        void *image = 0;
        size_t image_len = 0;
        if (!load_app_image(path, &image, &image_len)) {
            kprintf("run: cannot open %s\n", path);
            return;
        }

        app_runtime_info_t info;
        if (!app_runtime_run(image, image_len, &info)) {
            kprintf("run: failed to start %s (%s)\n",
                    path,
                    info.detail[0] ? info.detail : app_runtime_kind_name(info.kind));
        } else {
            kprintf("run: process finished %s (%s)\n", path, app_runtime_kind_name(info.kind));
        }
        kfree(image);
        return;
    }

    if (strcmp(argv[0], "diskread") == 0) {
        uint8_t *sector = (uint8_t *)kmalloc(512);
        if (!sector) {
            return;
        }
        if (ata_read28(0, 1, sector)) {
            kprintf("LBA0: %x %x %x %x\n", sector[0], sector[1], sector[2], sector[3]);
        } else {
            kprintf("diskread: failed\n");
        }
        kfree(sector);
        return;
    }

    kprintf("unknown command: %s\n", argv[0]);
}

void shell_init(void) {
    line_len = 0;
    line[0] = '\0';
    g_license_lock_mode = license_usage_allowed() ? 0 : 1;
    g_security_lock_mode = security_lockdown_active() ? 1 : 0;
    g_license_setup_active = 0;
    g_license_setup_attempts = 0;
    server_load_endpoint();
    server_load_features();
    if (g_license_lock_mode || g_security_lock_mode) {
        if (g_license_lock_mode) {
            kprintf("QuartzOS shell ready (LICENSE LOCK mode).\n");
        }
        if (g_security_lock_mode) {
            kprintf("QuartzOS shell ready (SECURITY LOCKDOWN mode).\n");
        }
        kprintf("Type 'help' for unlock instructions.\n");
    } else {
        kprintf("QuartzOS shell ready. type 'help'.\n");
    }
    if (g_license_lock_mode) {
        start_license_setup_app(1);
    } else {
        print_prompt();
    }
}

void shell_tick(void) {
    char c;
    while (keyboard_read_char(&c)) {
        if (c == '\n') {
            console_putc('\n');
            line[line_len] = '\0';
            if (g_license_setup_active) {
                handle_license_setup_line(line);
            } else {
                execute_line(line);
                print_prompt();
            }
            line_len = 0;
            line[0] = '\0';
        } else if (c == '\b') {
            if (line_len > 0) {
                line_len--;
                line[line_len] = '\0';
                console_putc('\b');
            }
        } else if (c >= 32 && c <= 126) {
            if (line_len < sizeof(line) - 1) {
                line[line_len++] = c;
                line[line_len] = '\0';
                console_putc(c);
            }
        }
    }

    task_schedule_if_needed();
}
