#include <drivers/pit.h>
#include <filesystem/sfs.h>
#include <kernel/audit.h>
#include <kernel/license.h>
#include <kernel/security.h>
#include <kernel/secure_store.h>
#include <lib/string.h>
#include <memory/heap.h>
#include <net/net.h>
#include <stdint.h>

#define LICENSE_DB_PATH "/etc/licenses.db"
#define LICENSE_REVOKED_PATH "/etc/licenses.revoked"
#define LICENSE_STATE_PATH "/etc/license.state"
#define LICENSE_TERMS_PATH "/etc/LICENSE.txt"
#define LICENSE_ACCEPT_PATH "/etc/license.accept"

#define LICENSE_V1_KEY_LEN 27
#define LICENSE_V2_KEY_LEN 44
#define LICENSE_V3_KEY_LEN 53
#define LICENSE_MAX_KEYS 2048
#define LICENSE_MAX_REVOCATIONS 2048
#define LICENSE_REQUIRE_MODERN_ACTIVATION 1

#define LICENSE_HZ 100u
#define LICENSE_FAIL_WINDOW_TICKS (30u * LICENSE_HZ)
#define LICENSE_LOCKOUT_TICKS (120u * LICENSE_HZ)
#define LICENSE_MAX_FAILS 3u
#define LICENSE_TERMS_MAX_BYTES (256u * 1024u)
#define LICENSE_SERVER_VERIFY_CACHE_TICKS (60u * LICENSE_HZ)

#define LICENSE_POLICY_SUBSCRIPTION 0x40u

#define LICENSE_TIER_CONSUMER 0x01u
#define LICENSE_TIER_ENTERPRISE 0x02u
#define LICENSE_TIER_EDUCATIONAL 0x03u
#define LICENSE_TIER_SERVER 0x04u
#define LICENSE_TIER_OEM 0x09u

typedef enum key_version {
    KEY_VERSION_INVALID = 0,
    KEY_VERSION_V1 = 1,
    KEY_VERSION_V2 = 2,
    KEY_VERSION_V3 = 3
} key_version_t;

typedef struct key_entry {
    char key[LICENSE_MAX_KEY_TEXT + 1];
    uint8_t len;
} key_entry_t;

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

static const uint8_t HMAC_KEY_V2[] = "QuartzOS-Licensing-HMAC-Key-V2-2026";
static const uint8_t HMAC_KEY_V3[] = "QuartzOS-Licensing-HMAC-Key-V3-2026";
static const uint8_t HMAC_KEY_STATE[] = "QuartzOS-License-State-MAC-V3-2026";

static key_entry_t g_registry[LICENSE_MAX_KEYS];
static key_entry_t g_revoked[LICENSE_MAX_REVOCATIONS];
static size_t g_registry_count;
static size_t g_revoked_count;

static int g_active;
static char g_active_key[LICENSE_MAX_KEY_TEXT + 1];
static uint8_t g_active_key_len;
static uint8_t g_active_tier_code;
static uint8_t g_active_policy_bits;

static uint32_t g_failed_attempts;
static uint64_t g_fail_window_start;
static uint64_t g_lock_until_tick;
static license_error_t g_last_error = LICENSE_ERR_NONE;
static int g_terms_available;
static int g_terms_accepted;
static char g_terms_hash[65];
static uint64_t g_server_verify_tick;
static int g_server_verify_ok;

static int version_allowed(key_version_t version) {
    if (!LICENSE_REQUIRE_MODERN_ACTIVATION) {
        return version != KEY_VERSION_INVALID;
    }
    return version == KEY_VERSION_V3;
}

static uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

static uint32_t sha_ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static uint32_t sha_maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t sha_ep0(uint32_t x) {
    return rotr32(x, 2u) ^ rotr32(x, 13u) ^ rotr32(x, 22u);
}

static uint32_t sha_ep1(uint32_t x) {
    return rotr32(x, 6u) ^ rotr32(x, 11u) ^ rotr32(x, 25u);
}

static uint32_t sha_sig0(uint32_t x) {
    return rotr32(x, 7u) ^ rotr32(x, 18u) ^ (x >> 3u);
}

static uint32_t sha_sig1(uint32_t x) {
    return rotr32(x, 17u) ^ rotr32(x, 19u) ^ (x >> 10u);
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

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out[32]) {
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t key_hash[32];
    uint8_t inner[32];
    const uint8_t *work_key = key;
    size_t work_len = key_len;

    if (work_len > 64) {
        sha256_ctx_t key_ctx;
        sha256_init(&key_ctx);
        sha256_update(&key_ctx, work_key, work_len);
        sha256_final(&key_ctx, key_hash);
        work_key = key_hash;
        work_len = 32;
    }

    memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));
    for (size_t i = 0; i < work_len; i++) {
        k_ipad[i] ^= work_key[i];
        k_opad[i] ^= work_key[i];
    }

    sha256_ctx_t inner_ctx;
    sha256_init(&inner_ctx);
    sha256_update(&inner_ctx, k_ipad, sizeof(k_ipad));
    sha256_update(&inner_ctx, msg, msg_len);
    sha256_final(&inner_ctx, inner);

    sha256_ctx_t outer_ctx;
    sha256_init(&outer_ctx);
    sha256_update(&outer_ctx, k_opad, sizeof(k_opad));
    sha256_update(&outer_ctx, inner, sizeof(inner));
    sha256_final(&outer_ctx, out);
}

static int is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static char to_upper_ascii(char c) {
    if (c >= 'a' && c <= 'z') {
        return (char)(c - 'a' + 'A');
    }
    return c;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

static int constant_time_equal(const char *a, const char *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static int constant_time_equal_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static int parse_hex_u32(const char *s, size_t len, uint32_t *out) {
    if (!s || !out || len == 0 || len > 8) {
        return 0;
    }
    uint32_t value = 0;
    for (size_t i = 0; i < len; i++) {
        int v = hex_value(s[i]);
        if (v < 0) {
            return 0;
        }
        value = (value << 4) | (uint32_t)v;
    }
    *out = value;
    return 1;
}

static int parse_hex_u64(const char *s, size_t len, uint64_t *out) {
    if (!s || !out || len == 0 || len > 16) {
        return 0;
    }
    uint64_t value = 0;
    for (size_t i = 0; i < len; i++) {
        int v = hex_value(s[i]);
        if (v < 0) {
            return 0;
        }
        value = (value << 4) | (uint64_t)v;
    }
    *out = value;
    return 1;
}

static int parse_hex_u8(const char *s, size_t len, uint8_t *out) {
    uint32_t value = 0;
    if (!out || !parse_hex_u32(s, len, &value) || value > 0xFFu) {
        return 0;
    }
    *out = (uint8_t)value;
    return 1;
}

static int parse_hex_bytes(const char *s, size_t len, uint8_t *out, size_t out_len) {
    if (!s || !out || len == 0 || (len % 2) != 0 || out_len != len / 2) {
        return 0;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_value(s[i * 2]);
        int lo = hex_value(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static void u16_to_hex4(uint16_t value, char out[5]) {
    static const char digits[] = "0123456789ABCDEF";
    for (int i = 3; i >= 0; i--) {
        out[i] = digits[value & 0x0Fu];
        value >>= 4;
    }
    out[4] = '\0';
}

static void u32_to_hex8(uint32_t value, char out[9]) {
    static const char digits[] = "0123456789ABCDEF";
    for (int i = 7; i >= 0; i--) {
        out[i] = digits[value & 0x0Fu];
        value >>= 4;
    }
    out[8] = '\0';
}

static void u8_to_hex2(uint8_t value, char out[3]) {
    static const char digits[] = "0123456789ABCDEF";
    out[0] = digits[(value >> 4) & 0x0Fu];
    out[1] = digits[value & 0x0Fu];
    out[2] = '\0';
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
    static const char digits[] = "0123456789ABCDEF";
    if (!bytes || !out) {
        return;
    }
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = digits[(bytes[i] >> 4) & 0x0Fu];
        out[i * 2 + 1] = digits[bytes[i] & 0x0Fu];
    }
    out[len * 2] = '\0';
}

static const char *tier_name_for_code(uint8_t code) {
    switch (code) {
        case 0x01: return "consumer";
        case 0x02: return "enterprise";
        case 0x03: return "educational";
        case 0x04: return "server";
        case 0x05: return "dev_standard";
        case 0x06: return "student_dev";
        case 0x07: return "startup_dev";
        case 0x08: return "open_lab";
        case 0x09: return "oem";
        default: return "unknown";
    }
}

static int tier_meets_minimum_consumer_monthly(uint8_t tier_code, uint8_t policy_bits) {
    if ((policy_bits & LICENSE_POLICY_SUBSCRIPTION) == 0) {
        return 0;
    }

    switch (tier_code) {
        case LICENSE_TIER_CONSUMER:
        case LICENSE_TIER_ENTERPRISE:
        case LICENSE_TIER_EDUCATIONAL:
        case LICENSE_TIER_SERVER:
        case LICENSE_TIER_OEM:
            return 1;
        default:
            return 0;
    }
}

static key_version_t key_version_for(size_t len) {
    if (len == LICENSE_V1_KEY_LEN) {
        return KEY_VERSION_V1;
    }
    if (len == LICENSE_V2_KEY_LEN) {
        return KEY_VERSION_V2;
    }
    if (len == LICENSE_V3_KEY_LEN) {
        return KEY_VERSION_V3;
    }
    return KEY_VERSION_INVALID;
}

static void key_metadata(const char *key, size_t key_len, key_version_t version,
                         uint8_t *out_tier_code, uint8_t *out_policy_bits) {
    uint8_t tier = 0;
    uint8_t policy = 0;
    if (key && version == KEY_VERSION_V3 && key_len == LICENSE_V3_KEY_LEN) {
        (void)parse_hex_u8(key + 14, 2, &tier);
        (void)parse_hex_u8(key + 17, 2, &policy);
    }
    if (out_tier_code) {
        *out_tier_code = tier;
    }
    if (out_policy_bits) {
        *out_policy_bits = policy;
    }
}

static int validate_hex_span(const char *key, size_t start, size_t end) {
    for (size_t i = start; i < end; i++) {
        if (hex_value(key[i]) < 0) {
            return 0;
        }
    }
    return 1;
}

static int normalize_key(const char *key, char out[LICENSE_MAX_KEY_TEXT + 1],
                         size_t *out_len, key_version_t *out_ver) {
    if (!key || !out) {
        return 0;
    }

    size_t len = strlen(key);
    key_version_t version = key_version_for(len);
    if (version == KEY_VERSION_INVALID) {
        return 0;
    }

    for (size_t i = 0; i < len; i++) {
        out[i] = to_upper_ascii(key[i]);
    }
    out[len] = '\0';

    if (version == KEY_VERSION_V1) {
        if (strncmp(out, "QOS1-", 5) != 0 || out[13] != '-' || out[18] != '-') {
            return 0;
        }
        if (!validate_hex_span(out, 5, 13) ||
            !validate_hex_span(out, 14, 18) ||
            !validate_hex_span(out, 19, 27)) {
            return 0;
        }
    } else if (version == KEY_VERSION_V2) {
        if (strncmp(out, "QOS2-", 5) != 0 || out[13] != '-' || out[18] != '-' || out[27] != '-') {
            return 0;
        }
        if (!validate_hex_span(out, 5, 13) ||
            !validate_hex_span(out, 14, 18) ||
            !validate_hex_span(out, 19, 27) ||
            !validate_hex_span(out, 28, 44)) {
            return 0;
        }
    } else {
        if (strncmp(out, "QOS3-", 5) != 0 || out[13] != '-' || out[16] != '-' ||
            out[19] != '-' || out[28] != '-') {
            return 0;
        }
        if (!validate_hex_span(out, 5, 13) ||
            !validate_hex_span(out, 14, 16) ||
            !validate_hex_span(out, 17, 19) ||
            !validate_hex_span(out, 20, 28) ||
            !validate_hex_span(out, 29, 53)) {
            return 0;
        }
    }

    if (out_len) {
        *out_len = len;
    }
    if (out_ver) {
        *out_ver = version;
    }
    return 1;
}

static uint32_t fnv1a32(const char *text) {
    uint32_t h = 2166136261u;
    if (!text) {
        return h;
    }
    while (*text) {
        h ^= (uint8_t)(*text);
        h *= 16777619u;
        text++;
    }
    return h;
}

static uint32_t license_signature_v1_for(uint32_t id, uint16_t feature_bits) {
    char id_hex[9];
    char feat_hex[5];
    char payload[64];

    u32_to_hex8(id, id_hex);
    u16_to_hex4(feature_bits, feat_hex);

    payload[0] = '\0';
    strncat(payload, "QOS1:", sizeof(payload) - strlen(payload) - 1);
    strncat(payload, id_hex, sizeof(payload) - strlen(payload) - 1);
    strncat(payload, ":", sizeof(payload) - strlen(payload) - 1);
    strncat(payload, feat_hex, sizeof(payload) - strlen(payload) - 1);
    strncat(payload, ":QUARTZOS-LICENSE-V1", sizeof(payload) - strlen(payload) - 1);
    return fnv1a32(payload);
}

static uint64_t digest_first_u64(const uint8_t digest[32]) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; i++) {
        value = (value << 8) | digest[i];
    }
    return value;
}

static uint64_t license_signature_v2_for(uint32_t id, uint16_t feature_bits, uint32_t nonce) {
    char id_hex[9];
    char feat_hex[5];
    char nonce_hex[9];
    char payload[96];
    uint8_t mac[32];

    u32_to_hex8(id, id_hex);
    u16_to_hex4(feature_bits, feat_hex);
    u32_to_hex8(nonce, nonce_hex);

    payload[0] = '\0';
    strncat(payload, "QOS2:", sizeof(payload) - strlen(payload) - 1);
    strncat(payload, id_hex, sizeof(payload) - strlen(payload) - 1);
    strncat(payload, ":", sizeof(payload) - strlen(payload) - 1);
    strncat(payload, feat_hex, sizeof(payload) - strlen(payload) - 1);
    strncat(payload, ":", sizeof(payload) - strlen(payload) - 1);
    strncat(payload, nonce_hex, sizeof(payload) - strlen(payload) - 1);
    strncat(payload, ":QUARTZOS-LICENSE-V2", sizeof(payload) - strlen(payload) - 1);

    hmac_sha256(HMAC_KEY_V2, sizeof(HMAC_KEY_V2) - 1,
                (const uint8_t *)payload, strlen(payload), mac);
    return digest_first_u64(mac);
}

static void license_signature_v3_for(uint32_t id, uint8_t tier_code,
                                     uint8_t policy_bits, uint32_t nonce,
                                     uint8_t out_sig[12]) {
    char id_hex[9];
    char tier_hex[3];
    char policy_hex[3];
    char nonce_hex[9];
    char payload[128];
    uint8_t mac[32];

    u32_to_hex8(id, id_hex);
    u8_to_hex2(tier_code, tier_hex);
    u8_to_hex2(policy_bits, policy_hex);
    u32_to_hex8(nonce, nonce_hex);

    payload[0] = '\0';
    strncat(payload, "QOS3:", sizeof(payload) - strlen(payload) - 1);
    strncat(payload, id_hex, sizeof(payload) - strlen(payload) - 1);
    strncat(payload, ":", sizeof(payload) - strlen(payload) - 1);
    strncat(payload, tier_hex, sizeof(payload) - strlen(payload) - 1);
    strncat(payload, ":", sizeof(payload) - strlen(payload) - 1);
    strncat(payload, policy_hex, sizeof(payload) - strlen(payload) - 1);
    strncat(payload, ":", sizeof(payload) - strlen(payload) - 1);
    strncat(payload, nonce_hex, sizeof(payload) - strlen(payload) - 1);
    strncat(payload, ":QUARTZOS-LICENSE-V3", sizeof(payload) - strlen(payload) - 1);

    hmac_sha256(HMAC_KEY_V3, sizeof(HMAC_KEY_V3) - 1,
                (const uint8_t *)payload, strlen(payload), mac);
    memcpy(out_sig, mac, 12);
}

static int key_signature_matches(const char *key, size_t key_len, key_version_t version) {
    if (!key || key_len == 0) {
        return 0;
    }

    if (version == KEY_VERSION_V1) {
        uint32_t id = 0;
        uint32_t feat = 0;
        uint32_t sig = 0;
        if (!parse_hex_u32(key + 5, 8, &id) ||
            !parse_hex_u32(key + 14, 4, &feat) ||
            !parse_hex_u32(key + 19, 8, &sig)) {
            return 0;
        }
        return sig == license_signature_v1_for(id, (uint16_t)feat);
    }

    if (version == KEY_VERSION_V2) {
        uint32_t id = 0;
        uint32_t feat = 0;
        uint32_t nonce = 0;
        uint64_t sig = 0;
        if (!parse_hex_u32(key + 5, 8, &id) ||
            !parse_hex_u32(key + 14, 4, &feat) ||
            !parse_hex_u32(key + 19, 8, &nonce) ||
            !parse_hex_u64(key + 28, 16, &sig)) {
            return 0;
        }
        return sig == license_signature_v2_for(id, (uint16_t)feat, nonce);
    }

    if (version == KEY_VERSION_V3) {
        uint32_t id = 0;
        uint8_t tier = 0;
        uint8_t policy = 0;
        uint32_t nonce = 0;
        uint8_t sig[12];
        uint8_t expected[12];
        if (!parse_hex_u32(key + 5, 8, &id) ||
            !parse_hex_u8(key + 14, 2, &tier) ||
            !parse_hex_u8(key + 17, 2, &policy) ||
            !parse_hex_u32(key + 20, 8, &nonce) ||
            !parse_hex_bytes(key + 29, 24, sig, sizeof(sig))) {
            return 0;
        }
        license_signature_v3_for(id, tier, policy, nonce, expected);
        return constant_time_equal_bytes(sig, expected, sizeof(sig));
    }

    return 0;
}

static int key_in_entries(const key_entry_t *entries, size_t count, const char *key, size_t key_len) {
    for (size_t i = 0; i < count; i++) {
        if (entries[i].len != key_len) {
            continue;
        }
        if (constant_time_equal(entries[i].key, key, key_len)) {
            return 1;
        }
    }
    return 0;
}

static int entries_add(key_entry_t *entries, size_t max_entries, size_t *count,
                       const char *key, size_t key_len) {
    if (!entries || !count || !key || key_len == 0 || key_len > LICENSE_MAX_KEY_TEXT) {
        return 0;
    }
    if (*count >= max_entries) {
        return 0;
    }
    if (key_in_entries(entries, *count, key, key_len)) {
        return 1;
    }

    key_entry_t *ent = &entries[*count];
    memcpy(ent->key, key, key_len);
    ent->key[key_len] = '\0';
    ent->len = (uint8_t)key_len;
    (*count)++;
    return 1;
}

static void entries_clear(key_entry_t *entries, size_t max_entries, size_t *count) {
    if (!entries || !count) {
        return;
    }
    memset(entries, 0, max_entries * sizeof(key_entry_t));
    *count = 0;
}

static void load_key_file(const char *path, key_entry_t *entries, size_t max_entries, size_t *count) {
    entries_clear(entries, max_entries, count);

    size_t cap = 512 * 1024;
    char *buf = (char *)kmalloc(cap + 1);
    if (!buf) {
        return;
    }

    size_t read = 0;
    if (!secure_store_read_text(path, buf, cap + 1, &read)) {
        kfree(buf);
        return;
    }
    buf[read] = '\0';

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

        while (start < end && is_space(buf[start])) {
            start++;
        }
        while (end > start && is_space(buf[end - 1])) {
            end--;
        }
        if (start >= end || buf[start] == '#' || buf[start] == ';') {
            continue;
        }

        size_t token_end = start;
        while (token_end < end && !is_space(buf[token_end]) && buf[token_end] != '#') {
            token_end++;
        }
        if (token_end <= start) {
            continue;
        }

        size_t token_len = token_end - start;
        if (token_len > LICENSE_MAX_KEY_TEXT) {
            continue;
        }

        char raw[LICENSE_MAX_KEY_TEXT + 1];
        memcpy(raw, buf + start, token_len);
        raw[token_len] = '\0';

        char normalized[LICENSE_MAX_KEY_TEXT + 1];
        size_t normalized_len = 0;
        key_version_t version = KEY_VERSION_INVALID;
        if (!normalize_key(raw, normalized, &normalized_len, &version)) {
            continue;
        }
        if (!version_allowed(version)) {
            continue;
        }
        if (!key_signature_matches(normalized, normalized_len, version)) {
            continue;
        }
        (void)entries_add(entries, max_entries, count, normalized, normalized_len);
    }

    kfree(buf);
}

static int key_is_registered(const char *key, size_t key_len) {
    return key_in_entries(g_registry, g_registry_count, key, key_len);
}

static int key_is_revoked(const char *key, size_t key_len) {
    return key_in_entries(g_revoked, g_revoked_count, key, key_len);
}

static uint64_t now_ticks(void) {
    return pit_ticks();
}

static void lockout_refresh(void) {
    uint64_t now = now_ticks();
    if (g_lock_until_tick != 0 && now >= g_lock_until_tick) {
        g_lock_until_tick = 0;
        g_failed_attempts = 0;
        g_fail_window_start = 0;
    }
}

static int lockout_active(void) {
    lockout_refresh();
    return g_lock_until_tick != 0 && now_ticks() < g_lock_until_tick;
}

static uint64_t signature_state_mac_v2(const char *value) {
    char payload[96];
    uint8_t mac[32];
    payload[0] = '\0';
    strncat(payload, "STATE:", sizeof(payload) - strlen(payload) - 1);
    strncat(payload, value, sizeof(payload) - strlen(payload) - 1);
    hmac_sha256(HMAC_KEY_V2, sizeof(HMAC_KEY_V2) - 1,
                (const uint8_t *)payload, strlen(payload), mac);
    return digest_first_u64(mac);
}

static void signature_state_mac_v3(const char *value, uint8_t out_mac[12]) {
    char payload[128];
    uint8_t mac[32];
    payload[0] = '\0';
    strncat(payload, "STATEV3:", sizeof(payload) - strlen(payload) - 1);
    strncat(payload, value, sizeof(payload) - strlen(payload) - 1);
    hmac_sha256(HMAC_KEY_STATE, sizeof(HMAC_KEY_STATE) - 1,
                (const uint8_t *)payload, strlen(payload), mac);
    memcpy(out_mac, mac, 12);
}

static int write_signed_value(const char *path, const char *value) {
    if (!path || !value || !*value) {
        return 0;
    }

    char mac_hex[25];
    char line[256];
    uint8_t mac[12];
    signature_state_mac_v3(value, mac);
    bytes_to_hex(mac, sizeof(mac), mac_hex);

    line[0] = '\0';
    strncat(line, value, sizeof(line) - strlen(line) - 1);
    strncat(line, "|", sizeof(line) - strlen(line) - 1);
    strncat(line, mac_hex, sizeof(line) - strlen(line) - 1);
    strncat(line, "\n", sizeof(line) - strlen(line) - 1);

    return secure_store_write_text(path, line, strlen(line), sfs_persistence_enabled()) ? 1 : 0;
}

static int read_signed_value(const char *path, char *value_out, size_t value_out_len, int *tampered) {
    if (!path || !value_out || value_out_len == 0) {
        return 0;
    }
    if (tampered) {
        *tampered = 0;
    }

    char buf[512];
    size_t read = 0;
    if (!secure_store_read_text(path, buf, sizeof(buf), &read)) {
        return 0;
    }
    buf[read] = '\0';

    size_t end = 0;
    while (end < read && buf[end] != '\n' && buf[end] != '\r') {
        end++;
    }
    if (end == 0 || end >= sizeof(buf)) {
        return 0;
    }
    buf[end] = '\0';

    char *sep = strchr(buf, '|');
    if (!sep) {
        if (tampered) {
            *tampered = 1;
        }
        return 0;
    }

    *sep = '\0';
    char *value = buf;
    char *mac_text = sep + 1;
    size_t mac_len = strlen(mac_text);

    if (mac_len == 16) {
        uint64_t file_mac = 0;
        if (!parse_hex_u64(mac_text, 16, &file_mac)) {
            if (tampered) {
                *tampered = 1;
            }
            return 0;
        }
        if (file_mac != signature_state_mac_v2(value)) {
            if (tampered) {
                *tampered = 1;
            }
            return 0;
        }
    } else if (mac_len == 24) {
        uint8_t file_mac[12];
        uint8_t expected[12];
        if (!parse_hex_bytes(mac_text, 24, file_mac, sizeof(file_mac))) {
            if (tampered) {
                *tampered = 1;
            }
            return 0;
        }
        signature_state_mac_v3(value, expected);
        if (!constant_time_equal_bytes(file_mac, expected, sizeof(file_mac))) {
            if (tampered) {
                *tampered = 1;
            }
            return 0;
        }
    } else {
        if (tampered) {
            *tampered = 1;
        }
        return 0;
    }

    size_t value_len = strlen(value);
    if (value_len + 1 > value_out_len) {
        return 0;
    }
    memcpy(value_out, value, value_len + 1);
    return 1;
}

static void write_state_value(const char *value) {
    (void)write_signed_value(LICENSE_STATE_PATH, value);
}

static void set_active_key(const char *key, size_t key_len) {
    g_active = 1;
    g_active_key_len = (uint8_t)key_len;
    memcpy(g_active_key, key, key_len);
    g_active_key[key_len] = '\0';
    key_metadata(g_active_key, g_active_key_len, key_version_for(g_active_key_len),
                 &g_active_tier_code, &g_active_policy_bits);
}

static void clear_active_key(void) {
    g_active = 0;
    g_active_key_len = 0;
    g_active_key[0] = '\0';
    g_active_tier_code = 0;
    g_active_policy_bits = 0;
    g_server_verify_tick = 0;
    g_server_verify_ok = 0;
}

static void clear_failures(void) {
    g_failed_attempts = 0;
    g_fail_window_start = 0;
    g_lock_until_tick = 0;
}

static void record_activation_failure(license_error_t err, const char *detail, int count_failure) {
    g_last_error = err;
    security_note_event(SECURITY_EVENT_AUTH_FAIL, detail ? detail : "license-auth-fail");

    if (count_failure) {
        uint64_t now = now_ticks();
        if (g_fail_window_start == 0 || now - g_fail_window_start > LICENSE_FAIL_WINDOW_TICKS) {
            g_fail_window_start = now;
            g_failed_attempts = 0;
        }
        if (g_failed_attempts < 0xFFFFFFFFu) {
            g_failed_attempts++;
        }
        if (g_failed_attempts >= LICENSE_MAX_FAILS) {
            g_lock_until_tick = now + LICENSE_LOCKOUT_TICKS;
            audit_log("LICENSE_LOCKOUT", "too-many-failures");
        }
    }

    audit_log("LICENSE_ACTIVATE_FAIL", detail ? detail : "unknown");
}

static int verify_key_with_server_db(const char *key, license_error_t *out_error, const char **out_detail) {
    if (out_error) {
        *out_error = LICENSE_ERR_NONE;
    }
    if (out_detail) {
        *out_detail = "none";
    }

    if (!security_server_license_verify(key, 0, 0)) {
        if (!net_available()) {
            if (out_error) {
                *out_error = LICENSE_ERR_SERVER_UNREACHABLE;
            }
            if (out_detail) {
                *out_detail = "server-unreachable";
            }
        } else {
            if (out_error) {
                *out_error = LICENSE_ERR_SERVER_REJECTED;
            }
            if (out_detail) {
                *out_detail = "server-rejected";
            }
        }
        return 0;
    }
    return 1;
}

static int refresh_active_server_verification(void) {
    if (!g_active) {
        return 0;
    }
    if (!security_feature_enabled(SECURITY_FEATURE_REMOTE_LICENSE_REQUIRED)) {
        g_server_verify_ok = 1;
        g_server_verify_tick = now_ticks();
        return 1;
    }

    uint64_t now = now_ticks();
    if (!g_server_verify_ok &&
        g_server_verify_tick != 0 &&
        (now - g_server_verify_tick) < (10u * LICENSE_HZ)) {
        return 0;
    }
    if (g_server_verify_ok &&
        g_server_verify_tick != 0 &&
        (now - g_server_verify_tick) < LICENSE_SERVER_VERIFY_CACHE_TICKS) {
        return 1;
    }

    license_error_t server_err = LICENSE_ERR_SERVER_REJECTED;
    const char *detail = "server-rejected";
    if (!verify_key_with_server_db(g_active_key, &server_err, &detail)) {
        g_server_verify_ok = 0;
        g_server_verify_tick = now;
        g_last_error = server_err;
        audit_log("LICENSE_SERVER_VERIFY_FAIL", detail);
        return 0;
    }

    g_server_verify_ok = 1;
    g_server_verify_tick = now;
    return 1;
}

static void load_registry(void) {
    load_key_file(LICENSE_DB_PATH, g_registry, LICENSE_MAX_KEYS, &g_registry_count);
}

static void load_revocations(void) {
    load_key_file(LICENSE_REVOKED_PATH, g_revoked, LICENSE_MAX_REVOCATIONS, &g_revoked_count);
}

static int load_terms_hash(void) {
    g_terms_available = 0;
    g_terms_hash[0] = '\0';

    size_t cap = LICENSE_TERMS_MAX_BYTES;
    char *buf = (char *)kmalloc(cap + 1u);
    if (!buf) {
        return 0;
    }

    size_t read = 0;
    if (!secure_store_read_text(LICENSE_TERMS_PATH, buf, cap + 1u, &read)) {
        kfree(buf);
        return 0;
    }
    buf[read] = '\0';

    uint8_t digest[32];
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)buf, read);
    sha256_final(&ctx, digest);
    bytes_to_hex(digest, sizeof(digest), g_terms_hash);

    g_terms_available = 1;
    kfree(buf);
    return 1;
}

static void write_accept_state(int accepted) {
    if (!g_terms_available || g_terms_hash[0] == '\0') {
        return;
    }

    char value[96];
    value[0] = '\0';
    strncat(value, "V1:", sizeof(value) - strlen(value) - 1);
    strncat(value, g_terms_hash, sizeof(value) - strlen(value) - 1);
    strncat(value, accepted ? ":1" : ":0", sizeof(value) - strlen(value) - 1);
    (void)write_signed_value(LICENSE_ACCEPT_PATH, value);
}

static void load_accept_state(void) {
    g_terms_accepted = 0;
    if (!g_terms_available || g_terms_hash[0] == '\0') {
        return;
    }

    char value[128];
    int tampered = 0;
    if (!read_signed_value(LICENSE_ACCEPT_PATH, value, sizeof(value), &tampered)) {
        if (tampered) {
            g_last_error = LICENSE_ERR_STATE_TAMPER;
            audit_log("LICENSE_ACCEPT_TAMPER", "signature-invalid");
            write_accept_state(0);
        }
        return;
    }

    size_t value_len = strlen(value);
    if (value_len != 69 || strncmp(value, "V1:", 3) != 0 || value[67] != ':') {
        g_last_error = LICENSE_ERR_STATE_TAMPER;
        audit_log("LICENSE_ACCEPT_TAMPER", "payload-invalid");
        write_accept_state(0);
        return;
    }

    char file_hash[65];
    memcpy(file_hash, value + 3, 64);
    file_hash[64] = '\0';
    if (strcmp(file_hash, g_terms_hash) != 0) {
        g_terms_accepted = 0;
        write_accept_state(0);
        return;
    }

    if (value[68] == '1') {
        g_terms_accepted = 1;
    } else if (value[68] == '0') {
        g_terms_accepted = 0;
    } else {
        g_last_error = LICENSE_ERR_STATE_TAMPER;
        audit_log("LICENSE_ACCEPT_TAMPER", "flag-invalid");
        write_accept_state(0);
    }
}

static void load_state(void) {
    clear_active_key();

    char value[128];
    int tampered = 0;
    if (!read_signed_value(LICENSE_STATE_PATH, value, sizeof(value), &tampered)) {
        if (tampered) {
            g_last_error = LICENSE_ERR_STATE_TAMPER;
            audit_log("LICENSE_STATE_TAMPER", "signature-invalid");
            write_state_value("NONE");
        }
        return;
    }

    if (strcmp(value, "NONE") == 0) {
        return;
    }

    char normalized[LICENSE_MAX_KEY_TEXT + 1];
    size_t normalized_len = 0;
    key_version_t version = KEY_VERSION_INVALID;
    if (!normalize_key(value, normalized, &normalized_len, &version)) {
        return;
    }
    if (!version_allowed(version)) {
        return;
    }
    if (!key_signature_matches(normalized, normalized_len, version)) {
        return;
    }
    if (!key_is_registered(normalized, normalized_len)) {
        return;
    }
    if (key_is_revoked(normalized, normalized_len)) {
        return;
    }
    uint8_t tier = 0;
    uint8_t policy = 0;
    key_metadata(normalized, normalized_len, version, &tier, &policy);
    if (!tier_meets_minimum_consumer_monthly(tier, policy)) {
        g_last_error = LICENSE_ERR_MINIMUM_TIER;
        audit_log("LICENSE_STATE_REJECT", "minimum-tier");
        write_state_value("NONE");
        return;
    }
    set_active_key(normalized, normalized_len);
}

void license_init(void) {
    entries_clear(g_registry, LICENSE_MAX_KEYS, &g_registry_count);
    entries_clear(g_revoked, LICENSE_MAX_REVOCATIONS, &g_revoked_count);
    clear_active_key();
    clear_failures();
    g_last_error = LICENSE_ERR_NONE;
    g_terms_available = 0;
    g_terms_accepted = 0;
    g_terms_hash[0] = '\0';
    g_server_verify_tick = 0;
    g_server_verify_ok = 0;

    load_registry();
    load_revocations();
    (void)load_terms_hash();
    load_accept_state();
    load_state();
}

void license_reload(void) {
    load_registry();
    load_revocations();
    (void)load_terms_hash();
    load_accept_state();

    if (g_active &&
        (!key_is_registered(g_active_key, g_active_key_len) ||
         key_is_revoked(g_active_key, g_active_key_len) ||
         !refresh_active_server_verification())) {
        audit_log("LICENSE", "active key revoked or removed");
        license_deactivate();
    }
}

bool license_signature_valid(const char *key) {
    char normalized[LICENSE_MAX_KEY_TEXT + 1];
    size_t key_len = 0;
    key_version_t version = KEY_VERSION_INVALID;
    if (!normalize_key(key, normalized, &key_len, &version)) {
        return false;
    }
    if (!version_allowed(version)) {
        return false;
    }
    return key_signature_matches(normalized, key_len, version) != 0;
}

bool license_registered(const char *key) {
    char normalized[LICENSE_MAX_KEY_TEXT + 1];
    size_t key_len = 0;
    key_version_t version = KEY_VERSION_INVALID;
    if (!normalize_key(key, normalized, &key_len, &version)) {
        return false;
    }
    if (!version_allowed(version)) {
        return false;
    }
    if (!key_signature_matches(normalized, key_len, version)) {
        return false;
    }
    return key_is_registered(normalized, key_len) != 0;
}

bool license_key_revoked(const char *key) {
    char normalized[LICENSE_MAX_KEY_TEXT + 1];
    size_t key_len = 0;
    key_version_t version = KEY_VERSION_INVALID;
    if (!normalize_key(key, normalized, &key_len, &version)) {
        return false;
    }
    if (!version_allowed(version)) {
        return false;
    }
    if (!key_signature_matches(normalized, key_len, version)) {
        return false;
    }
    return key_is_revoked(normalized, key_len) != 0;
}

bool license_activate(const char *key) {
    lockout_refresh();
    if (lockout_active()) {
        record_activation_failure(LICENSE_ERR_LOCKED, "locked", 0);
        return false;
    }

    char normalized[LICENSE_MAX_KEY_TEXT + 1];
    size_t key_len = 0;
    key_version_t version = KEY_VERSION_INVALID;
    if (!normalize_key(key, normalized, &key_len, &version)) {
        record_activation_failure(LICENSE_ERR_FORMAT, "format", 1);
        return false;
    }
    if (!version_allowed(version)) {
        record_activation_failure(LICENSE_ERR_LEGACY_DISABLED, "legacy-disabled", 1);
        return false;
    }
    if (!key_signature_matches(normalized, key_len, version)) {
        record_activation_failure(LICENSE_ERR_SIGNATURE, "signature", 1);
        return false;
    }
    if (!key_is_registered(normalized, key_len)) {
        record_activation_failure(LICENSE_ERR_NOT_ISSUED, "not-issued", 1);
        return false;
    }
    if (key_is_revoked(normalized, key_len)) {
        record_activation_failure(LICENSE_ERR_REVOKED, "revoked", 1);
        return false;
    }
    uint8_t tier = 0;
    uint8_t policy = 0;
    key_metadata(normalized, key_len, version, &tier, &policy);
    if (!tier_meets_minimum_consumer_monthly(tier, policy)) {
        record_activation_failure(LICENSE_ERR_MINIMUM_TIER, "minimum-tier", 1);
        return false;
    }
    if (security_feature_enabled(SECURITY_FEATURE_REMOTE_LICENSE_REQUIRED)) {
        license_error_t server_err = LICENSE_ERR_SERVER_REJECTED;
        const char *detail = "server-rejected";
        if (!verify_key_with_server_db(normalized, &server_err, &detail)) {
            record_activation_failure(server_err, detail, 1);
            return false;
        }
    }

    set_active_key(normalized, key_len);
    g_server_verify_ok = 1;
    g_server_verify_tick = now_ticks();
    write_state_value(normalized);
    clear_failures();
    g_last_error = LICENSE_ERR_NONE;
    audit_log("LICENSE_ACTIVATE_OK", normalized);
    return true;
}

void license_deactivate(void) {
    clear_active_key();
    write_state_value("NONE");
    g_last_error = LICENSE_ERR_NONE;
    audit_log("LICENSE_DEACTIVATE", "");
}

bool license_is_active(void) {
    if (!g_active) {
        return false;
    }
    if (!key_is_registered(g_active_key, g_active_key_len) ||
        key_is_revoked(g_active_key, g_active_key_len)) {
        clear_active_key();
        write_state_value("NONE");
        audit_log("LICENSE_AUTO_DEACTIVATE", "key-invalidated");
        return false;
    }
    if (!tier_meets_minimum_consumer_monthly(g_active_tier_code, g_active_policy_bits)) {
        clear_active_key();
        write_state_value("NONE");
        audit_log("LICENSE_AUTO_DEACTIVATE", "minimum-tier");
        return false;
    }
    if (!refresh_active_server_verification()) {
        clear_active_key();
        write_state_value("NONE");
        audit_log("LICENSE_AUTO_DEACTIVATE", "server-db-verify");
        return false;
    }
    return true;
}

bool license_usage_allowed(void) {
    if (!license_is_active()) {
        return false;
    }
    if (!tier_meets_minimum_consumer_monthly(g_active_tier_code, g_active_policy_bits)) {
        return false;
    }
    if (!g_terms_available) {
        return false;
    }
    return g_terms_accepted != 0;
}

size_t license_registered_count(void) {
    return g_registry_count;
}

size_t license_revoked_count(void) {
    return g_revoked_count;
}

void license_active_key(char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return;
    }
    if (!g_active) {
        strncpy(out, "NONE", out_len - 1);
        out[out_len - 1] = '\0';
        return;
    }
    strncpy(out, g_active_key, out_len - 1);
    out[out_len - 1] = '\0';
}

uint8_t license_active_tier_code(void) {
    return g_active_tier_code;
}

uint8_t license_active_policy_bits(void) {
    return g_active_policy_bits;
}

const char *license_active_tier_name(void) {
    return tier_name_for_code(g_active_tier_code);
}

bool license_terms_available(void) {
    return g_terms_available != 0;
}

bool license_terms_accepted(void) {
    return g_terms_available != 0 && g_terms_accepted != 0;
}

bool license_accept_terms(void) {
    if (!g_terms_available || g_terms_hash[0] == '\0') {
        return false;
    }
    g_terms_accepted = 1;
    write_accept_state(1);
    audit_log("LICENSE_TERMS_ACCEPT", g_terms_hash);
    return true;
}

bool license_reject_terms(void) {
    if (!g_terms_available || g_terms_hash[0] == '\0') {
        return false;
    }
    g_terms_accepted = 0;
    write_accept_state(0);
    audit_log("LICENSE_TERMS_REJECT", g_terms_hash);
    return true;
}

bool license_terms_hash(char *out, size_t out_len) {
    if (!out || out_len == 0 || !g_terms_available || g_terms_hash[0] == '\0') {
        return false;
    }
    strncpy(out, g_terms_hash, out_len - 1);
    out[out_len - 1] = '\0';
    return true;
}

bool license_read_terms(char *out, size_t out_len, size_t *out_read) {
    if (!out || out_len == 0 || !g_terms_available) {
        return false;
    }
    return secure_store_read_text(LICENSE_TERMS_PATH, out, out_len, out_read);
}

uint32_t license_failed_attempts(void) {
    lockout_refresh();
    return g_failed_attempts;
}

uint32_t license_lockout_remaining_seconds(void) {
    lockout_refresh();
    uint64_t now = now_ticks();
    if (g_lock_until_tick == 0 || now >= g_lock_until_tick) {
        return 0;
    }
    uint64_t remain_ticks = g_lock_until_tick - now;
    return (uint32_t)((remain_ticks + LICENSE_HZ - 1u) / LICENSE_HZ);
}

license_error_t license_last_error(void) {
    return g_last_error;
}

const char *license_error_text(license_error_t error) {
    switch (error) {
        case LICENSE_ERR_NONE: return "none";
        case LICENSE_ERR_FORMAT: return "invalid-format";
        case LICENSE_ERR_SIGNATURE: return "invalid-signature";
        case LICENSE_ERR_NOT_ISSUED: return "not-issued";
        case LICENSE_ERR_REVOKED: return "revoked";
        case LICENSE_ERR_LOCKED: return "activation-locked";
        case LICENSE_ERR_STATE_TAMPER: return "state-tampered";
        case LICENSE_ERR_LEGACY_DISABLED: return "legacy-key-disabled";
        case LICENSE_ERR_MINIMUM_TIER: return "minimum-tier-required";
        case LICENSE_ERR_SERVER_UNREACHABLE: return "license-server-unreachable";
        case LICENSE_ERR_SERVER_REJECTED: return "license-server-rejected";
        default: return "unknown";
    }
}
