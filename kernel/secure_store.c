#include <drivers/pit.h>
#include <filesystem/sfs.h>
#include <kernel/secure_store.h>
#include <lib/string.h>
#include <memory/heap.h>
#include <stdint.h>

#define SECURE_PREFIX "QENC1|"
#define SECURE_PREFIX_LEN 6u
#define SECURE_NONCE_BYTES 8u
#define SECURE_TAG_BYTES 32u

static const uint8_t SECURE_KEY_ENC[] = "QuartzOS-SecureStore-ENC-V1-2026";
static const uint8_t SECURE_KEY_MAC[] = "QuartzOS-SecureStore-MAC-V1-2026";
static const uint8_t SECURE_KEY_MAC_COMPAT[] = "QuartzOS-SecureStore-ENC-V1-2026";

static uint64_t g_nonce_ctr;

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

static int constant_time_equal_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static void generate_nonce(uint8_t nonce[SECURE_NONCE_BYTES]) {
    uint64_t seed = pit_ticks();
    g_nonce_ctr++;
    seed ^= (g_nonce_ctr * 0x9E3779B97F4A7C15ull);
    seed ^= (uint64_t)(uintptr_t)&seed;

    for (size_t i = 0; i < SECURE_NONCE_BYTES; i++) {
        seed ^= (seed << 13);
        seed ^= (seed >> 7);
        seed ^= (seed << 17);
        nonce[i] = (uint8_t)(seed >> (i * 3));
    }
}

static void stream_xor(const uint8_t nonce[SECURE_NONCE_BYTES],
                       const uint8_t *in, uint8_t *out, size_t len) {
    uint32_t counter = 0;
    size_t pos = 0;

    while (pos < len) {
        uint8_t msg[SECURE_NONCE_BYTES + 4];
        uint8_t block[32];

        memcpy(msg, nonce, SECURE_NONCE_BYTES);
        msg[SECURE_NONCE_BYTES] = (uint8_t)(counter >> 24);
        msg[SECURE_NONCE_BYTES + 1] = (uint8_t)(counter >> 16);
        msg[SECURE_NONCE_BYTES + 2] = (uint8_t)(counter >> 8);
        msg[SECURE_NONCE_BYTES + 3] = (uint8_t)(counter);

        hmac_sha256(SECURE_KEY_ENC, sizeof(SECURE_KEY_ENC) - 1, msg, sizeof(msg), block);
        size_t take = len - pos;
        if (take > sizeof(block)) {
            take = sizeof(block);
        }

        for (size_t i = 0; i < take; i++) {
            out[pos + i] = in[pos + i] ^ block[i];
        }

        counter++;
        pos += take;
    }
}

static void compute_tag_with_key(const uint8_t *key, size_t key_len,
                                 const uint8_t nonce[SECURE_NONCE_BYTES],
                                 const uint8_t *cipher, size_t cipher_len,
                                 uint8_t tag[SECURE_TAG_BYTES]) {
    size_t msg_len = SECURE_PREFIX_LEN + SECURE_NONCE_BYTES + cipher_len;
    uint8_t *msg = (uint8_t *)kmalloc(msg_len);
    if (!msg) {
        memset(tag, 0, SECURE_TAG_BYTES);
        return;
    }

    memcpy(msg, SECURE_PREFIX, SECURE_PREFIX_LEN);
    memcpy(msg + SECURE_PREFIX_LEN, nonce, SECURE_NONCE_BYTES);
    memcpy(msg + SECURE_PREFIX_LEN + SECURE_NONCE_BYTES, cipher, cipher_len);

    hmac_sha256(key, key_len, msg, msg_len, tag);
    kfree(msg);
}

static void compute_tag(const uint8_t nonce[SECURE_NONCE_BYTES],
                        const uint8_t *cipher, size_t cipher_len,
                        uint8_t tag[SECURE_TAG_BYTES]) {
    compute_tag_with_key(SECURE_KEY_MAC, sizeof(SECURE_KEY_MAC) - 1, nonce, cipher, cipher_len, tag);
}

bool secure_store_is_encrypted_blob(const char *text) {
    if (!text) {
        return false;
    }
    while (*text && is_space(*text)) {
        text++;
    }
    return strncmp(text, SECURE_PREFIX, SECURE_PREFIX_LEN) == 0;
}

static bool decrypt_text(const char *text, char *out, size_t out_len, size_t *out_read) {
    if (!text || !out || out_len == 0) {
        return false;
    }

    while (*text && is_space(*text)) {
        text++;
    }

    size_t len = strlen(text);
    while (len > 0 && is_space(text[len - 1])) {
        len--;
    }

    if (len < SECURE_PREFIX_LEN + 1 || strncmp(text, SECURE_PREFIX, SECURE_PREFIX_LEN) != 0) {
        return false;
    }

    const char *p = text + SECURE_PREFIX_LEN;
    const char *end = text + len;

    const char *pipe1 = p;
    while (pipe1 < end && *pipe1 != '|') {
        pipe1++;
    }
    if (pipe1 >= end) {
        return false;
    }

    const char *pipe2 = pipe1 + 1;
    while (pipe2 < end && *pipe2 != '|') {
        pipe2++;
    }
    if (pipe2 >= end) {
        return false;
    }

    size_t nonce_hex_len = (size_t)(pipe1 - p);
    size_t cipher_hex_len = (size_t)(pipe2 - (pipe1 + 1));
    size_t tag_hex_len = (size_t)(end - (pipe2 + 1));

    if (nonce_hex_len != SECURE_NONCE_BYTES * 2 ||
        tag_hex_len != SECURE_TAG_BYTES * 2 ||
        cipher_hex_len == 0 ||
        (cipher_hex_len % 2) != 0) {
        return false;
    }

    size_t cipher_len = cipher_hex_len / 2;
    if (cipher_len + 1 > out_len) {
        return false;
    }

    uint8_t nonce[SECURE_NONCE_BYTES];
    uint8_t tag[SECURE_TAG_BYTES];
    uint8_t expected_tag[SECURE_TAG_BYTES];
    uint8_t *cipher = (uint8_t *)kmalloc(cipher_len);
    if (!cipher) {
        return false;
    }

    bool ok = parse_hex_bytes(p, nonce_hex_len, nonce, sizeof(nonce)) &&
              parse_hex_bytes(pipe1 + 1, cipher_hex_len, cipher, cipher_len) &&
              parse_hex_bytes(pipe2 + 1, tag_hex_len, tag, sizeof(tag));

    if (!ok) {
        kfree(cipher);
        return false;
    }

    compute_tag(nonce, cipher, cipher_len, expected_tag);
    if (!constant_time_equal_bytes(tag, expected_tag, sizeof(tag))) {
        compute_tag_with_key(SECURE_KEY_MAC_COMPAT, sizeof(SECURE_KEY_MAC_COMPAT) - 1,
                             nonce, cipher, cipher_len, expected_tag);
        if (!constant_time_equal_bytes(tag, expected_tag, sizeof(tag))) {
            kfree(cipher);
            return false;
        }
    }

    stream_xor(nonce, cipher, (uint8_t *)out, cipher_len);
    out[cipher_len] = '\0';
    if (out_read) {
        *out_read = cipher_len;
    }
    kfree(cipher);
    return true;
}

bool secure_store_read_text(const char *path, char *out, size_t out_len, size_t *out_read) {
    if (!path || !out || out_len == 0) {
        return false;
    }

    size_t raw_cap = out_len * 3u + 256u;
    if (raw_cap < out_len + 1u) {
        raw_cap = out_len + 1u;
    }

    char *raw = (char *)kmalloc(raw_cap);
    if (!raw) {
        return false;
    }

    size_t read = 0;
    if (!sfs_read_file(path, raw, raw_cap - 1u, &read)) {
        kfree(raw);
        return false;
    }
    raw[read] = '\0';

    bool ok = true;
    if (secure_store_is_encrypted_blob(raw)) {
        ok = decrypt_text(raw, out, out_len, out_read);
    } else {
        if (read + 1u > out_len) {
            ok = false;
        } else {
            memcpy(out, raw, read + 1u);
            if (out_read) {
                *out_read = read;
            }
        }
    }

    kfree(raw);
    return ok;
}

bool secure_store_write_text(const char *path, const char *plain, size_t plain_len, bool sync_now) {
    if (!path || !plain) {
        return false;
    }

    uint8_t nonce[SECURE_NONCE_BYTES];
    uint8_t tag[SECURE_TAG_BYTES];
    generate_nonce(nonce);

    uint8_t *cipher = (uint8_t *)kmalloc(plain_len == 0 ? 1 : plain_len);
    if (!cipher) {
        return false;
    }
    if (plain_len > 0) {
        stream_xor(nonce, (const uint8_t *)plain, cipher, plain_len);
    }
    compute_tag(nonce, cipher, plain_len, tag);

    char nonce_hex[SECURE_NONCE_BYTES * 2 + 1];
    char tag_hex[SECURE_TAG_BYTES * 2 + 1];
    char *cipher_hex = (char *)kmalloc(plain_len * 2 + 1);
    if (!cipher_hex) {
        kfree(cipher);
        return false;
    }

    bytes_to_hex(nonce, sizeof(nonce), nonce_hex);
    bytes_to_hex(tag, sizeof(tag), tag_hex);
    bytes_to_hex(cipher, plain_len, cipher_hex);

    size_t encoded_cap = SECURE_PREFIX_LEN + strlen(nonce_hex) + 1 +
                         strlen(cipher_hex) + 1 + strlen(tag_hex) + 2;
    char *encoded = (char *)kmalloc(encoded_cap);
    if (!encoded) {
        kfree(cipher_hex);
        kfree(cipher);
        return false;
    }

    size_t idx = 0;
    memcpy(encoded + idx, SECURE_PREFIX, SECURE_PREFIX_LEN);
    idx += SECURE_PREFIX_LEN;
    memcpy(encoded + idx, nonce_hex, strlen(nonce_hex));
    idx += strlen(nonce_hex);
    encoded[idx++] = '|';
    memcpy(encoded + idx, cipher_hex, strlen(cipher_hex));
    idx += strlen(cipher_hex);
    encoded[idx++] = '|';
    memcpy(encoded + idx, tag_hex, strlen(tag_hex));
    idx += strlen(tag_hex);
    encoded[idx++] = '\n';
    encoded[idx] = '\0';

    bool ok = sfs_write_file(path, encoded, idx);
    if (ok && sync_now && sfs_persistence_enabled()) {
        ok = sfs_sync();
    }

    kfree(encoded);
    kfree(cipher_hex);
    kfree(cipher);
    return ok;
}
