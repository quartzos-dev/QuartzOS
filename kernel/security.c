#include <drivers/pit.h>
#include <filesystem/sfs.h>
#include <kernel/audit.h>
#include <kernel/license.h>
#include <kernel/security.h>
#include <kernel/secure_store.h>
#include <kernel/service.h>
#include <kernel/slog.h>
#include <lib/string.h>
#include <memory/heap.h>
#include <net/net.h>

#define SECURITY_CFG_PATH "/etc/security.cfg"
#define SECURITY_MANIFEST_PATH "/etc/security_manifest.txt"
#define SECURITY_PIT_HZ 100u
#define SECURITY_DEFAULT_WINDOW_TICKS (30u * SECURITY_PIT_HZ)
#define SECURITY_DEFAULT_THRESHOLD 18u
#define SECURITY_FEATURE_BYTES ((SECURITY_FEATURE_COUNT + 7u) / 8u)
#define SECURITY_MAX_MANIFEST 16384u
#define SECURITY_MAX_FILE_READ (2u * 1024u * 1024u)
#define SECURITY_SERVER_TIMEOUT_TICKS (80u)

static const char *g_core_feature_names[33] = {
    "enforce-license-gate",
    "enforce-exec-path",
    "enforce-fs-guards",
    "enforce-net-guards",
    "enforce-audit",
    "failsafe-intrusion",
    "failsafe-integrity",
    "failsafe-net-killswitch",
    "failsafe-app-killswitch",
    "hardened-boot-default",
    "allow-app-custom",
    "allow-app-linux",
    "allow-app-windows",
    "allow-app-macos",
    "require-wrapper-foreign",
    "block-privileged-lockdown",
    "strict-syswrite",
    "rate-limit-events",
    "require-manifest",
    "allow-failsafe-reset",
    "allow-server-control",
    "allow-server-export",
    "allow-server-send",
    "server-require-private-endpoint",
    "server-restrict-privileged-ports",
    "server-restrict-risky-ports",
    "server-rate-limit-send",
    "server-block-in-lockdown",
    "server-require-license",
    "server-export-sandbox",
    "remote-av-required",
    "remote-license-required",
    "block-user-server-access"
};

static const char *g_feature_categories[10] = {
    "identity", "auth", "integrity", "memory", "execution",
    "filesystem", "network", "isolation", "audit", "platform"
};

#define CORE_FEATURE_NAME_COUNT (sizeof(g_core_feature_names) / sizeof(g_core_feature_names[0]))

typedef struct sha256_ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    size_t datalen;
} sha256_ctx_t;

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint8_t g_features[SECURITY_FEATURE_COUNT];
static security_mode_t g_mode;
static uint8_t g_manual_lockdown;
static uint8_t g_intrusion_failsafe;
static uint8_t g_integrity_failsafe;
static uint32_t g_intrusion_threshold;
static uint32_t g_intrusion_window_ticks;
static uint64_t g_intrusion_window_start;
static uint32_t g_recent_suspicious_events;
static uint32_t g_integrity_checked_entries;
static uint32_t g_integrity_failure_count;
static uint64_t g_server_send_window_start;
static uint32_t g_server_send_count;
static uint64_t g_server_av_retry_tick;

static uint32_t rot_right32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

static uint32_t sha_ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static uint32_t sha_maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t sha_ep0(uint32_t x) {
    return rot_right32(x, 2u) ^ rot_right32(x, 13u) ^ rot_right32(x, 22u);
}

static uint32_t sha_ep1(uint32_t x) {
    return rot_right32(x, 6u) ^ rot_right32(x, 11u) ^ rot_right32(x, 25u);
}

static uint32_t sha_sig0(uint32_t x) {
    return rot_right32(x, 7u) ^ rot_right32(x, 18u) ^ (x >> 3u);
}

static uint32_t sha_sig1(uint32_t x) {
    return rot_right32(x, 17u) ^ rot_right32(x, 19u) ^ (x >> 10u);
}

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64]) {
    uint32_t m[64];
    for (size_t i = 0; i < 16; i++) {
        m[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               (uint32_t)data[i * 4 + 3];
    }
    for (size_t i = 16; i < 64; i++) {
        m[i] = sha_sig1(m[i - 2]) + m[i - 7] + sha_sig0(m[i - 15]) + m[i - 16];
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (size_t i = 0; i < 64; i++) {
        uint32_t t1 = h + sha_ep1(e) + sha_ch(e, f, g) + SHA256_K[i] + m[i];
        uint32_t t2 = sha_ep0(a) + sha_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data) {
        return;
    }
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512u;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t out[32]) {
    if (!ctx || !out) {
        return;
    }

    size_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80u;
        while (i < 56) {
            ctx->data[i++] = 0x00u;
        }
    } else {
        ctx->data[i++] = 0x80u;
        while (i < 64) {
            ctx->data[i++] = 0x00u;
        }
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8u;
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    if (!bytes || !out) {
        return;
    }
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = digits[(bytes[i] >> 4) & 0x0Fu];
        out[i * 2 + 1] = digits[bytes[i] & 0x0Fu];
    }
    out[len * 2] = '\0';
}

static int parse_hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int parse_hex_bytes(const char *text, size_t text_len, uint8_t *out, size_t out_len) {
    if (!text || !out || text_len != out_len * 2u) {
        return 0;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi = parse_hex_nibble(text[i * 2]);
        int lo = parse_hex_nibble(text[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
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

static int parse_u32_dec(const char *text, uint32_t *out) {
    if (!text || !*text || !out) {
        return 0;
    }
    uint32_t value = 0;
    for (const char *p = text; *p; p++) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
        value = value * 10u + (uint32_t)(*p - '0');
    }
    *out = value;
    return 1;
}

static int path_has_prefix(const char *path, const char *prefix) {
    if (!path || !prefix) {
        return 0;
    }
    size_t plen = strlen(prefix);
    if (plen == 0 || strncmp(path, prefix, plen) != 0) {
        return 0;
    }
    return path[plen] == '\0' || path[plen] == '/';
}

static int ipv4_is_private(uint32_t ip) {
    uint8_t a = (uint8_t)((ip >> 24) & 0xFFu);
    uint8_t b = (uint8_t)((ip >> 16) & 0xFFu);

    if (a == 10u || a == 127u) {
        return 1;
    }
    if (a == 172u && b >= 16u && b <= 31u) {
        return 1;
    }
    if (a == 192u && b == 168u) {
        return 1;
    }
    if (a == 169u && b == 254u) {
        return 1;
    }
    return 0;
}

static int response_allows(const char *resp) {
    if (!resp || !resp[0]) {
        return 0;
    }
    return strncmp(resp, "OK", 2) == 0 ||
           strncmp(resp, "ALLOW", 5) == 0 ||
           strncmp(resp, "VALID", 5) == 0;
}

static int server_port_is_risky(uint16_t port) {
    switch (port) {
        case 20:
        case 21:
        case 22:
        case 23:
        case 25:
        case 53:
        case 69:
        case 80:
        case 110:
        case 143:
        case 443:
        case 445:
        case 1433:
        case 3306:
        case 3389:
        case 5432:
        case 5900:
        case 6379:
        case 9200:
            return 1;
        default:
            return 0;
    }
}

static int line_is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static void trim_in_place(char *line) {
    if (!line) {
        return;
    }

    size_t len = strlen(line);
    while (len > 0 && line_is_space(line[len - 1])) {
        line[len - 1] = '\0';
        len--;
    }

    size_t start = 0;
    while (line[start] && line_is_space(line[start])) {
        start++;
    }
    if (start > 0) {
        size_t i = 0;
        while (line[start + i]) {
            line[i] = line[start + i];
            i++;
        }
        line[i] = '\0';
    }
}

static const char *event_name(security_event_t event) {
    switch (event) {
        case SECURITY_EVENT_CMD_BLOCKED: return "cmd-blocked";
        case SECURITY_EVENT_FS_BLOCKED: return "fs-blocked";
        case SECURITY_EVENT_NET_BLOCKED: return "net-blocked";
        case SECURITY_EVENT_APP_BLOCKED: return "app-blocked";
        case SECURITY_EVENT_LICENSE_BLOCKED: return "license-blocked";
        case SECURITY_EVENT_INTEGRITY_FAIL: return "integrity-fail";
        case SECURITY_EVENT_SYSCALL_BLOCKED: return "syscall-blocked";
        case SECURITY_EVENT_AUTH_FAIL: return "auth-fail";
        case SECURITY_EVENT_SERVER_BLOCKED: return "server-blocked";
        default: return "unknown";
    }
}

static int event_is_suspicious(security_event_t event) {
    return event == SECURITY_EVENT_CMD_BLOCKED ||
           event == SECURITY_EVENT_FS_BLOCKED ||
           event == SECURITY_EVENT_NET_BLOCKED ||
           event == SECURITY_EVENT_APP_BLOCKED ||
           event == SECURITY_EVENT_LICENSE_BLOCKED ||
           event == SECURITY_EVENT_INTEGRITY_FAIL ||
           event == SECURITY_EVENT_SYSCALL_BLOCKED ||
           event == SECURITY_EVENT_AUTH_FAIL ||
           event == SECURITY_EVENT_SERVER_BLOCKED;
}

static void apply_killswitch_actions(const char *reason) {
    if (g_features[SECURITY_FEATURE_FAILSAFE_NET_KILLSWITCH]) {
        (void)service_set_policy("net", SERVICE_POLICY_MANUAL);
        (void)service_stop("net");
    }
    audit_log("SEC_FAILSAFE_ACTION", reason ? reason : "lockdown");
}

static void activate_intrusion_failsafe(const char *detail) {
    if (g_intrusion_failsafe) {
        return;
    }
    g_intrusion_failsafe = 1;
    slog_log(SLOG_LEVEL_WARN, "security", "intrusion failsafe active");
    audit_log("SEC_FAILSAFE_INTRUSION", detail ? detail : "threshold");
    apply_killswitch_actions("intrusion");
}

static void activate_integrity_failsafe(const char *detail) {
    if (g_integrity_failsafe) {
        return;
    }
    g_integrity_failsafe = 1;
    slog_log(SLOG_LEVEL_ERROR, "security", "integrity failsafe active");
    audit_log("SEC_FAILSAFE_INTEGRITY", detail ? detail : "manifest");
    apply_killswitch_actions("integrity");
}

static void feature_bytes_encode(uint8_t out[SECURITY_FEATURE_BYTES]) {
    memset(out, 0, SECURITY_FEATURE_BYTES);
    for (size_t i = 0; i < SECURITY_FEATURE_COUNT; i++) {
        if (g_features[i]) {
            out[i / 8u] |= (uint8_t)(1u << (i % 8u));
        }
    }
}

static void feature_bytes_decode(const uint8_t in[SECURITY_FEATURE_BYTES]) {
    for (size_t i = 0; i < SECURITY_FEATURE_COUNT; i++) {
        g_features[i] = (uint8_t)((in[i / 8u] >> (i % 8u)) & 0x1u);
    }
}

static void set_default_features(void) {
    for (size_t i = 0; i < SECURITY_FEATURE_COUNT; i++) {
        g_features[i] = 1u;
    }
    g_features[SECURITY_FEATURE_ALLOW_APP_CUSTOM] = 1u;
    g_features[SECURITY_FEATURE_ALLOW_APP_LINUX] = 1u;
    g_features[SECURITY_FEATURE_ALLOW_APP_WINDOWS] = 1u;
    g_features[SECURITY_FEATURE_ALLOW_APP_MACOS] = 1u;
}

static void init_defaults(void) {
    set_default_features();
    g_mode = SECURITY_MODE_HARDENED;
    g_manual_lockdown = 0;
    g_intrusion_failsafe = 0;
    g_integrity_failsafe = 0;
    g_intrusion_threshold = SECURITY_DEFAULT_THRESHOLD;
    g_intrusion_window_ticks = SECURITY_DEFAULT_WINDOW_TICKS;
    g_intrusion_window_start = pit_ticks();
    g_recent_suspicious_events = 0;
    g_integrity_checked_entries = 0;
    g_integrity_failure_count = 0;
    g_server_send_window_start = pit_ticks();
    g_server_send_count = 0;
    g_server_av_retry_tick = 0;
}

void security_init(void) {
    init_defaults();
}

bool security_load(void) {
    char blob[4096];
    size_t read = 0;
    if (!secure_store_read_text(SECURITY_CFG_PATH, blob, sizeof(blob) - 1, &read)) {
        return false;
    }
    blob[read] = '\0';

    size_t pos = 0;
    while (pos < read) {
        size_t start = pos;
        while (pos < read && blob[pos] != '\n') {
            pos++;
        }
        size_t end = pos;
        if (pos < read && blob[pos] == '\n') {
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
        memcpy(line, blob + start, len);
        line[len] = '\0';
        trim_in_place(line);
        if (!line[0] || line[0] == '#') {
            continue;
        }

        char *eq = strchr(line, '=');
        if (!eq) {
            continue;
        }
        *eq = '\0';
        const char *key = line;
        const char *value = eq + 1;

        if (strcmp(key, "mode") == 0) {
            if (strcmp(value, "normal") == 0) {
                g_mode = SECURITY_MODE_NORMAL;
                g_manual_lockdown = 0;
            } else if (strcmp(value, "hardened") == 0) {
                g_mode = SECURITY_MODE_HARDENED;
                g_manual_lockdown = 0;
            } else if (strcmp(value, "lockdown") == 0) {
                g_mode = SECURITY_MODE_LOCKDOWN;
                g_manual_lockdown = 1;
            }
        } else if (strcmp(key, "intrusion_threshold") == 0) {
            uint32_t v = 0;
            if (parse_u32_dec(value, &v) && v > 0) {
                g_intrusion_threshold = v;
            }
        } else if (strcmp(key, "intrusion_window_ticks") == 0) {
            uint32_t v = 0;
            if (parse_u32_dec(value, &v) && v > 0) {
                g_intrusion_window_ticks = v;
            }
        } else if (strcmp(key, "features_hex") == 0) {
            uint8_t bytes[SECURITY_FEATURE_BYTES];
            if (parse_hex_bytes(value, strlen(value), bytes, sizeof(bytes))) {
                feature_bytes_decode(bytes);
            }
        }
    }

    slog_log(SLOG_LEVEL_INFO, "security", "policy loaded");
    return true;
}

bool security_save(void) {
    char blob[4096];
    char features_hex[SECURITY_FEATURE_BYTES * 2u + 1u];
    uint8_t bytes[SECURITY_FEATURE_BYTES];

    feature_bytes_encode(bytes);
    bytes_to_hex(bytes, sizeof(bytes), features_hex);

    blob[0] = '\0';
    append_text(blob, sizeof(blob), "mode=");
    append_text(blob, sizeof(blob),
                g_manual_lockdown ? "lockdown" :
                (g_mode == SECURITY_MODE_NORMAL ? "normal" : "hardened"));
    append_text(blob, sizeof(blob), "\n");

    append_text(blob, sizeof(blob), "intrusion_threshold=");
    append_u32(blob, sizeof(blob), g_intrusion_threshold);
    append_text(blob, sizeof(blob), "\n");

    append_text(blob, sizeof(blob), "intrusion_window_ticks=");
    append_u32(blob, sizeof(blob), g_intrusion_window_ticks);
    append_text(blob, sizeof(blob), "\n");

    append_text(blob, sizeof(blob), "features_hex=");
    append_text(blob, sizeof(blob), features_hex);
    append_text(blob, sizeof(blob), "\n");

    if (!secure_store_write_text(SECURITY_CFG_PATH, blob, strlen(blob), sfs_persistence_enabled())) {
        return false;
    }
    slog_log(SLOG_LEVEL_INFO, "security", "policy saved");
    return true;
}

security_mode_t security_mode(void) {
    if (security_lockdown_active()) {
        return SECURITY_MODE_LOCKDOWN;
    }
    return g_mode;
}

const char *security_mode_name(security_mode_t mode) {
    switch (mode) {
        case SECURITY_MODE_NORMAL: return "normal";
        case SECURITY_MODE_HARDENED: return "hardened";
        case SECURITY_MODE_LOCKDOWN: return "lockdown";
        default: return "unknown";
    }
}

bool security_set_mode(security_mode_t mode) {
    if (mode != SECURITY_MODE_NORMAL && mode != SECURITY_MODE_HARDENED && mode != SECURITY_MODE_LOCKDOWN) {
        return false;
    }

    if (mode == SECURITY_MODE_LOCKDOWN) {
        g_manual_lockdown = 1;
        g_mode = SECURITY_MODE_LOCKDOWN;
        audit_log("SEC_MODE", "lockdown");
        apply_killswitch_actions("manual-lockdown");
        return true;
    }

    g_manual_lockdown = 0;
    g_mode = mode;
    audit_log("SEC_MODE", mode == SECURITY_MODE_NORMAL ? "normal" : "hardened");
    return true;
}

bool security_lockdown_active(void) {
    return g_manual_lockdown != 0 || g_intrusion_failsafe != 0 || g_integrity_failsafe != 0;
}

bool security_intrusion_failsafe_active(void) {
    return g_intrusion_failsafe != 0;
}

bool security_integrity_failsafe_active(void) {
    return g_integrity_failsafe != 0;
}

void security_reset_failsafes(bool intrusion, bool integrity) {
    if (intrusion) {
        g_intrusion_failsafe = 0;
        g_intrusion_window_start = pit_ticks();
        g_recent_suspicious_events = 0;
        audit_log("SEC_FAILSAFE_RESET", "intrusion");
    }
    if (integrity) {
        g_integrity_failsafe = 0;
        audit_log("SEC_FAILSAFE_RESET", "integrity");
    }
}

void security_note_event(security_event_t event, const char *detail) {
    if (g_features[SECURITY_FEATURE_ENFORCE_AUDIT]) {
        audit_log("SEC_EVENT", event_name(event));
    }

    if (!event_is_suspicious(event)) {
        return;
    }

    uint64_t now = pit_ticks();
    if (g_intrusion_window_start == 0 || now - g_intrusion_window_start >= g_intrusion_window_ticks) {
        g_intrusion_window_start = now;
        g_recent_suspicious_events = 0;
    }

    g_recent_suspicious_events++;

    if (detail && *detail && g_features[SECURITY_FEATURE_ENFORCE_AUDIT]) {
        audit_log("SEC_EVENT_DETAIL", detail);
    }

    if (g_features[SECURITY_FEATURE_FAILSAFE_INTRUSION] &&
        g_recent_suspicious_events >= g_intrusion_threshold) {
        activate_intrusion_failsafe("threshold-reached");
    }
}

size_t security_feature_count(void) {
    return SECURITY_FEATURE_COUNT;
}

size_t security_feature_enabled_count(void) {
    size_t enabled = 0;
    for (size_t i = 0; i < SECURITY_FEATURE_COUNT; i++) {
        if (g_features[i]) {
            enabled++;
        }
    }
    return enabled;
}

bool security_feature_enabled(size_t index) {
    if (index >= SECURITY_FEATURE_COUNT) {
        return false;
    }
    return g_features[index] != 0;
}

bool security_feature_set(size_t index, bool enabled) {
    if (index >= SECURITY_FEATURE_COUNT) {
        return false;
    }
    g_features[index] = enabled ? 1u : 0u;

    if (index == SECURITY_FEATURE_HARDENED_BOOT_DEFAULT && enabled && g_mode == SECURITY_MODE_NORMAL) {
        g_mode = SECURITY_MODE_HARDENED;
    }
    return true;
}

void security_feature_name(size_t index, char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return;
    }
    out[0] = '\0';

    if (index >= SECURITY_FEATURE_COUNT) {
        append_text(out, out_len, "invalid");
        return;
    }

    if (index < CORE_FEATURE_NAME_COUNT) {
        append_text(out, out_len, g_core_feature_names[index]);
        return;
    }

    append_text(out, out_len, "sec-");
    uint32_t u = (uint32_t)index;
    char id[8];
    id[0] = (char)('0' + (u / 100u));
    id[1] = (char)('0' + ((u / 10u) % 10u));
    id[2] = (char)('0' + (u % 10u));
    id[3] = '\0';
    append_text(out, out_len, id);
    append_text(out, out_len, "-");
    append_text(out, out_len, g_feature_categories[(index / 20u) % 10u]);
    append_text(out, out_len, "-ctrl");
}

bool security_allow_network_ops(void) {
    if (!g_features[SECURITY_FEATURE_ENFORCE_NET_GUARDS]) {
        return true;
    }
    if (g_features[SECURITY_FEATURE_ENFORCE_LICENSE_GATE] && !license_usage_allowed()) {
        security_note_event(SECURITY_EVENT_LICENSE_BLOCKED, "network-license-gate");
        return false;
    }
    if (security_lockdown_active()) {
        security_note_event(SECURITY_EVENT_NET_BLOCKED, "lockdown");
        return false;
    }
    return true;
}

bool security_allow_server_command(const char *verb, char *reason, size_t reason_len) {
    if (reason && reason_len > 0) {
        reason[0] = '\0';
    }
    if (g_features[SECURITY_FEATURE_BLOCK_USER_SERVER_ACCESS]) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "server access is kernel-only");
        }
        security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "server-user-access-blocked");
        return false;
    }

    if (!g_features[SECURITY_FEATURE_ALLOW_SERVER_CONTROL]) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "server control disabled by security policy");
        }
        security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "server-control-disabled");
        return false;
    }

    if (g_features[SECURITY_FEATURE_SERVER_REQUIRE_LICENSE] && !license_usage_allowed()) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "verified license required for server operations");
        }
        security_note_event(SECURITY_EVENT_LICENSE_BLOCKED, "server-license-gate");
        return false;
    }

    if (security_lockdown_active() && g_features[SECURITY_FEATURE_SERVER_BLOCK_IN_LOCKDOWN]) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "security lockdown active");
        }
        security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "server-lockdown");
        return false;
    }

    if (verb &&
        (strcmp(verb, "send") == 0 || strcmp(verb, "ping") == 0 || strcmp(verb, "sync") == 0) &&
        !security_allow_network_ops()) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "network operations blocked by security policy");
        }
        return false;
    }

    return true;
}

bool security_user_server_access_allowed(void) {
    return g_features[SECURITY_FEATURE_BLOCK_USER_SERVER_ACCESS] == 0u;
}

bool security_allow_server_endpoint(uint32_t ip, uint16_t port,
                                    char *reason, size_t reason_len) {
    if (!security_allow_server_command("endpoint", reason, reason_len)) {
        return false;
    }

    if (port == 0u) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "endpoint port must be non-zero");
        }
        security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "server-endpoint-port-invalid");
        return false;
    }

    if (g_features[SECURITY_FEATURE_SERVER_RESTRICT_PRIVILEGED_PORTS] && port < 1024u) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "privileged ports blocked by policy");
        }
        security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "server-endpoint-port-privileged");
        return false;
    }

    if (g_features[SECURITY_FEATURE_SERVER_RESTRICT_RISKY_PORTS] && server_port_is_risky(port)) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "high-risk endpoint port blocked by policy");
        }
        security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "server-endpoint-port-risky");
        return false;
    }

    if (g_features[SECURITY_FEATURE_SERVER_REQUIRE_PRIVATE_ENDPOINT] && !ipv4_is_private(ip)) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "endpoint must be private IPv4");
        }
        security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "server-endpoint-nonprivate");
        return false;
    }

    return true;
}

bool security_allow_server_payload(size_t payload_len, char *reason, size_t reason_len) {
    if (!security_allow_server_command("send", reason, reason_len)) {
        return false;
    }

    if (!g_features[SECURITY_FEATURE_ALLOW_SERVER_SEND]) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "server send blocked by security policy");
        }
        security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "server-send-disabled");
        return false;
    }

    size_t max_payload = 768u;
    if (security_lockdown_active()) {
        max_payload = 256u;
    } else if (g_mode == SECURITY_MODE_HARDENED) {
        max_payload = 512u;
    }

    if (payload_len == 0u || payload_len > max_payload) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "payload size blocked by policy");
        }
        security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "server-payload-size");
        return false;
    }

    if (g_features[SECURITY_FEATURE_SERVER_RATE_LIMIT_SEND]) {
        uint64_t now = pit_ticks();
        uint64_t window = 10u * SECURITY_PIT_HZ;
        if (g_server_send_window_start == 0u || now - g_server_send_window_start >= window) {
            g_server_send_window_start = now;
            g_server_send_count = 0u;
        }

        uint32_t max_sends = 10u;
        if (security_lockdown_active()) {
            max_sends = 2u;
        } else if (g_mode == SECURITY_MODE_HARDENED) {
            max_sends = 6u;
        }

        if (g_server_send_count >= max_sends) {
            if (reason && reason_len > 0) {
                append_text(reason, reason_len, "server send rate limit active");
            }
            security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "server-send-rate-limit");
            return false;
        }
        g_server_send_count++;
    }

    return true;
}

bool security_allow_server_export(const char *path, char *reason, size_t reason_len) {
    if (!security_allow_server_command("export", reason, reason_len)) {
        return false;
    }

    if (!g_features[SECURITY_FEATURE_ALLOW_SERVER_EXPORT]) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "server export blocked by security policy");
        }
        security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "server-export-disabled");
        return false;
    }

    if (!path || path[0] != '/') {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "export path must be absolute");
        }
        security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "server-export-path-invalid");
        return false;
    }

    if (g_features[SECURITY_FEATURE_SERVER_EXPORT_SANDBOX] && !path_has_prefix(path, "/server")) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "export path must be under /server");
        }
        security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "server-export-path-sandbox");
        return false;
    }

    if (path_has_prefix(path, "/etc") || path_has_prefix(path, "/boot") || path_has_prefix(path, "/bin")) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "export path targets protected area");
        }
        security_note_event(SECURITY_EVENT_SERVER_BLOCKED, "server-export-path-protected");
        return false;
    }

    return true;
}

bool security_server_antivirus_verify(const char *path, const char *sha256_hex,
                                      char *reason, size_t reason_len) {
    if (reason && reason_len > 0) {
        reason[0] = '\0';
    }
    if (!g_features[SECURITY_FEATURE_REMOTE_AV_REQUIRED]) {
        return true;
    }
    if (!path || !sha256_hex || strlen(sha256_hex) != 64u) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "invalid antivirus request");
        }
        return false;
    }
    uint64_t now = pit_ticks();
    if (g_server_av_retry_tick != 0 && now < g_server_av_retry_tick) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "antivirus server backoff active");
        }
        return false;
    }
    if (!net_available()) {
        g_server_av_retry_tick = now + (15u * SECURITY_PIT_HZ);
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "server unavailable");
        }
        return false;
    }

    char req[320];
    char resp[160];
    req[0] = '\0';
    resp[0] = '\0';

    append_text(req, sizeof(req), "QOS_AV_VERIFY path=");
    append_text(req, sizeof(req), path);
    append_text(req, sizeof(req), " sha256=");
    append_text(req, sizeof(req), sha256_hex);

    if (!net_tcp_request_text(SECURITY_SERVER_IP, SECURITY_SERVER_AV_PORT,
                              req, resp, sizeof(resp), SECURITY_SERVER_TIMEOUT_TICKS)) {
        g_server_av_retry_tick = now + (15u * SECURITY_PIT_HZ);
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "no antivirus server response");
        }
        return false;
    }

    trim_in_place(resp);
    if (!response_allows(resp)) {
        g_server_av_retry_tick = now + (5u * SECURITY_PIT_HZ);
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "antivirus server rejected file");
        }
        return false;
    }
    g_server_av_retry_tick = 0;
    return true;
}

bool security_server_license_verify(const char *license_key, char *reason, size_t reason_len) {
    if (reason && reason_len > 0) {
        reason[0] = '\0';
    }
    if (!g_features[SECURITY_FEATURE_REMOTE_LICENSE_REQUIRED]) {
        return true;
    }
    if (!license_key || !license_key[0]) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "invalid license key");
        }
        return false;
    }
    if (!net_available()) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "license server unavailable");
        }
        return false;
    }

    char req[192];
    char resp[160];
    req[0] = '\0';
    resp[0] = '\0';

    append_text(req, sizeof(req), "QOS_LICENSE_VERIFY key=");
    append_text(req, sizeof(req), license_key);

    if (!net_tcp_request_text(SECURITY_SERVER_IP, SECURITY_SERVER_LICENSE_PORT,
                              req, resp, sizeof(resp), SECURITY_SERVER_TIMEOUT_TICKS)) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "no license server response");
        }
        return false;
    }

    trim_in_place(resp);
    if (!response_allows(resp)) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "license not approved by server database");
        }
        return false;
    }
    return true;
}

bool security_allow_sys_write(size_t len) {
    if (!g_features[SECURITY_FEATURE_STRICT_SYSWRITE]) {
        return true;
    }

    size_t max_len = 4096u;
    if (security_lockdown_active()) {
        max_len = 512u;
    } else if (g_mode == SECURITY_MODE_HARDENED) {
        max_len = 2048u;
    }

    if (len > max_len) {
        security_note_event(SECURITY_EVENT_SYSCALL_BLOCKED, "write-length");
        return false;
    }
    return true;
}

bool security_allow_app_launch(security_app_kind_t kind, bool wrapped,
                               char *reason, size_t reason_len) {
    if (reason && reason_len > 0) {
        reason[0] = '\0';
    }

    if (g_features[SECURITY_FEATURE_ENFORCE_LICENSE_GATE] && !license_usage_allowed()) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "verified license required");
        }
        security_note_event(SECURITY_EVENT_LICENSE_BLOCKED, "app-license-gate");
        return false;
    }

    if (security_lockdown_active() && g_features[SECURITY_FEATURE_FAILSAFE_APP_KILLSWITCH]) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "security lockdown active");
        }
        security_note_event(SECURITY_EVENT_APP_BLOCKED, "lockdown");
        return false;
    }

    if (kind == SECURITY_APP_CUSTOM && !g_features[SECURITY_FEATURE_ALLOW_APP_CUSTOM]) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "custom apps blocked by policy");
        }
        security_note_event(SECURITY_EVENT_APP_BLOCKED, "custom-denied");
        return false;
    }
    if (kind == SECURITY_APP_LINUX && !g_features[SECURITY_FEATURE_ALLOW_APP_LINUX]) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "linux apps blocked by policy");
        }
        security_note_event(SECURITY_EVENT_APP_BLOCKED, "linux-denied");
        return false;
    }
    if (kind == SECURITY_APP_WINDOWS && !g_features[SECURITY_FEATURE_ALLOW_APP_WINDOWS]) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "windows apps blocked by policy");
        }
        security_note_event(SECURITY_EVENT_APP_BLOCKED, "windows-denied");
        return false;
    }
    if (kind == SECURITY_APP_MACOS && !g_features[SECURITY_FEATURE_ALLOW_APP_MACOS]) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "macos apps blocked by policy");
        }
        security_note_event(SECURITY_EVENT_APP_BLOCKED, "macos-denied");
        return false;
    }

    if ((kind == SECURITY_APP_WINDOWS || kind == SECURITY_APP_MACOS || kind == SECURITY_APP_LINUX) &&
        g_features[SECURITY_FEATURE_REQUIRE_WRAPPER_FOREIGN] && !wrapped) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "foreign app must use Quartz wrapper payload");
        }
        security_note_event(SECURITY_EVENT_APP_BLOCKED, "wrapper-required");
        return false;
    }

    if (kind == SECURITY_APP_UNKNOWN) {
        if (reason && reason_len > 0) {
            append_text(reason, reason_len, "unknown app format");
        }
        security_note_event(SECURITY_EVENT_APP_BLOCKED, "unknown-format");
        return false;
    }

    return true;
}

static bool verify_manifest_line(const char *path, const char *expected_hex,
                                 uint32_t *mismatch, uint32_t *missing) {
    uint8_t *file_buf = (uint8_t *)kmalloc(SECURITY_MAX_FILE_READ);
    if (!file_buf) {
        return false;
    }

    size_t read = 0;
    if (!sfs_read_file(path, file_buf, SECURITY_MAX_FILE_READ, &read)) {
        (*missing)++;
        kfree(file_buf);
        return true;
    }

    uint8_t digest[32];
    char actual_hex[65];
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, file_buf, read);
    sha256_final(&ctx, digest);
    bytes_to_hex(digest, sizeof(digest), actual_hex);

    if (strcmp(actual_hex, expected_hex) != 0) {
        (*mismatch)++;
    }

    kfree(file_buf);
    return true;
}

bool security_verify_integrity_now(char *summary, size_t summary_len) {
    if (summary && summary_len > 0) {
        summary[0] = '\0';
    }

    char *manifest = (char *)kmalloc(SECURITY_MAX_MANIFEST);
    if (!manifest) {
        if (summary && summary_len > 0) {
            append_text(summary, summary_len, "oom");
        }
        if (g_features[SECURITY_FEATURE_FAILSAFE_INTEGRITY]) {
            activate_integrity_failsafe("oom");
        }
        return false;
    }

    size_t mread = 0;
    if (!sfs_read_file(SECURITY_MANIFEST_PATH, manifest, SECURITY_MAX_MANIFEST - 1u, &mread)) {
        kfree(manifest);
        g_integrity_checked_entries = 0;
        g_integrity_failure_count = 1;
        if (summary && summary_len > 0) {
            append_text(summary, summary_len, "manifest-missing");
        }
        if (g_features[SECURITY_FEATURE_REQUIRE_MANIFEST] &&
            g_features[SECURITY_FEATURE_FAILSAFE_INTEGRITY]) {
            activate_integrity_failsafe("manifest-missing");
        }
        return false;
    }

    manifest[mread] = '\0';

    uint32_t checked = 0;
    uint32_t mismatch = 0;
    uint32_t missing = 0;
    uint32_t parse_errors = 0;
    uint32_t av_reject = 0;
    int av_channel_failed = 0;

    size_t pos = 0;
    while (pos < mread) {
        size_t start = pos;
        while (pos < mread && manifest[pos] != '\n') {
            pos++;
        }
        size_t end = pos;
        if (pos < mread && manifest[pos] == '\n') {
            pos++;
        }

        if (end <= start) {
            continue;
        }

        char line[256];
        size_t len = end - start;
        if (len >= sizeof(line)) {
            parse_errors++;
            continue;
        }
        memcpy(line, manifest + start, len);
        line[len] = '\0';
        trim_in_place(line);

        if (!line[0] || line[0] == '#') {
            continue;
        }

        char *sep = strchr(line, '|');
        if (!sep) {
            parse_errors++;
            continue;
        }
        *sep = '\0';
        char *path = line;
        char *expected = sep + 1;
        trim_in_place(path);
        trim_in_place(expected);

        if (!path[0] || strlen(expected) != 64u) {
            parse_errors++;
            continue;
        }

        checked++;
        uint32_t mismatch_before = mismatch;
        uint32_t missing_before = missing;
        if (!verify_manifest_line(path, expected, &mismatch, &missing)) {
            parse_errors++;
            continue;
        }
        if (mismatch == mismatch_before && missing == missing_before) {
            if (av_channel_failed) {
                av_reject++;
                continue;
            }
            char av_reason[96];
            if (!security_server_antivirus_verify(path, expected, av_reason, sizeof(av_reason))) {
                av_reject++;
                av_channel_failed = 1;
            }
        }
    }

    kfree(manifest);

    g_integrity_checked_entries = checked;
    g_integrity_failure_count = mismatch + missing + parse_errors + av_reject;

    if (summary && summary_len > 0) {
        append_text(summary, summary_len, "checked=");
        append_u32(summary, summary_len, checked);
        append_text(summary, summary_len, " mismatch=");
        append_u32(summary, summary_len, mismatch);
        append_text(summary, summary_len, " missing=");
        append_u32(summary, summary_len, missing);
        append_text(summary, summary_len, " parse=");
        append_u32(summary, summary_len, parse_errors);
        append_text(summary, summary_len, " av=");
        append_u32(summary, summary_len, av_reject);
    }

    if (checked == 0 || g_integrity_failure_count != 0) {
        security_note_event(SECURITY_EVENT_INTEGRITY_FAIL, "manifest-failed");
        if (g_features[SECURITY_FEATURE_FAILSAFE_INTEGRITY]) {
            activate_integrity_failsafe("manifest-failed");
        }
        return false;
    }

    return true;
}

uint32_t security_intrusion_threshold(void) {
    return g_intrusion_threshold;
}

bool security_set_intrusion_threshold(uint32_t value) {
    if (value == 0 || value > 10000u) {
        return false;
    }
    g_intrusion_threshold = value;
    return true;
}

uint32_t security_recent_suspicious_events(void) {
    return g_recent_suspicious_events;
}

uint32_t security_integrity_checked_entries(void) {
    return g_integrity_checked_entries;
}

uint32_t security_integrity_failure_count(void) {
    return g_integrity_failure_count;
}
