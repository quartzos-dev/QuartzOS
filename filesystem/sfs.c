#include <drivers/ata.h>
#include <drivers/pit.h>
#include <filesystem/sfs.h>
#include <lib/string.h>
#include <memory/heap.h>

#define SFS_ROOT_PARENT 0xFFFFFFFFu
#define SFS_MAX_ENTRIES 4096
#define SFS_GROW_BYTES (16 * 1024 * 1024)
#define SFS_SECTOR_SIZE 512u

#define SFS_ENC_MAGIC "QFSENC1"
#define SFS_ENC_MAGIC_LEN 7u
#define SFS_ENC_VERSION 1u
#define SFS_ENC_NONCE_BYTES 8u
#define SFS_ENC_TAG_BYTES 32u
#define SFS_ENC_HEADER_BYTES (SFS_ENC_MAGIC_LEN + 1u + SFS_ENC_NONCE_BYTES + SFS_ENC_TAG_BYTES + 4u)

static const uint8_t SFS_ENC_KEY_ENC[] = "QuartzOS-SFS-ENC-V1-2026";
static const uint8_t SFS_ENC_KEY_MAC[] = "QuartzOS-SFS-MAC-V1-2026";

typedef struct sfs_header {
    uint32_t magic;
    uint32_t version;
    uint32_t entry_count;
    uint32_t entries_offset;
    uint32_t data_offset;
    uint32_t image_size;
} sfs_header_t;

static uint8_t *g_image;
static size_t g_capacity;
static sfs_header_t *g_header;
static sfs_entry_t *g_entries;

static int g_disk_enabled;
static uint32_t g_disk_start_lba;
static uint32_t g_disk_sector_count;
static uint32_t g_last_synced_sectors;
static uint64_t g_fsenc_nonce_ctr;

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

static int constant_time_equal_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static void generate_nonce(uint8_t nonce[SFS_ENC_NONCE_BYTES]) {
    uint64_t seed = pit_ticks();
    g_fsenc_nonce_ctr++;
    seed ^= (g_fsenc_nonce_ctr * 0x9E3779B97F4A7C15ull);
    seed ^= (uint64_t)(uintptr_t)&seed;

    for (size_t i = 0; i < SFS_ENC_NONCE_BYTES; i++) {
        seed ^= (seed << 13);
        seed ^= (seed >> 7);
        seed ^= (seed << 17);
        nonce[i] = (uint8_t)(seed >> (i * 3));
    }
}

static void stream_xor(const uint8_t nonce[SFS_ENC_NONCE_BYTES],
                       const uint8_t *in, uint8_t *out, size_t len) {
    uint32_t counter = 0;
    size_t pos = 0;

    while (pos < len) {
        uint8_t msg[SFS_ENC_NONCE_BYTES + 4];
        uint8_t block[32];

        memcpy(msg, nonce, SFS_ENC_NONCE_BYTES);
        msg[SFS_ENC_NONCE_BYTES] = (uint8_t)(counter >> 24);
        msg[SFS_ENC_NONCE_BYTES + 1] = (uint8_t)(counter >> 16);
        msg[SFS_ENC_NONCE_BYTES + 2] = (uint8_t)(counter >> 8);
        msg[SFS_ENC_NONCE_BYTES + 3] = (uint8_t)(counter);

        hmac_sha256(SFS_ENC_KEY_ENC, sizeof(SFS_ENC_KEY_ENC) - 1, msg, sizeof(msg), block);
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

static void encode_u32_le(uint32_t value, uint8_t out[4]) {
    out[0] = (uint8_t)(value & 0xFFu);
    out[1] = (uint8_t)((value >> 8) & 0xFFu);
    out[2] = (uint8_t)((value >> 16) & 0xFFu);
    out[3] = (uint8_t)((value >> 24) & 0xFFu);
}

static uint32_t decode_u32_le(const uint8_t in[4]) {
    return (uint32_t)in[0] |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

static bool fsenc_is_blob(const uint8_t *data, size_t len) {
    return data &&
           len >= SFS_ENC_HEADER_BYTES &&
           memcmp(data, SFS_ENC_MAGIC, SFS_ENC_MAGIC_LEN) == 0 &&
           data[SFS_ENC_MAGIC_LEN] == SFS_ENC_VERSION;
}

static void fsenc_compute_tag(const uint8_t nonce[SFS_ENC_NONCE_BYTES],
                              const uint8_t *cipher, size_t cipher_len,
                              uint32_t plain_len, uint8_t tag[SFS_ENC_TAG_BYTES]) {
    uint8_t len_bytes[4];
    encode_u32_le(plain_len, len_bytes);

    size_t msg_len = SFS_ENC_MAGIC_LEN + 1u + SFS_ENC_NONCE_BYTES + sizeof(len_bytes) + cipher_len;
    uint8_t *msg = (uint8_t *)kmalloc(msg_len);
    if (!msg) {
        memset(tag, 0, SFS_ENC_TAG_BYTES);
        return;
    }

    size_t idx = 0;
    memcpy(msg + idx, SFS_ENC_MAGIC, SFS_ENC_MAGIC_LEN);
    idx += SFS_ENC_MAGIC_LEN;
    msg[idx++] = (uint8_t)SFS_ENC_VERSION;
    memcpy(msg + idx, nonce, SFS_ENC_NONCE_BYTES);
    idx += SFS_ENC_NONCE_BYTES;
    memcpy(msg + idx, len_bytes, sizeof(len_bytes));
    idx += sizeof(len_bytes);
    memcpy(msg + idx, cipher, cipher_len);

    hmac_sha256(SFS_ENC_KEY_MAC, sizeof(SFS_ENC_KEY_MAC) - 1, msg, msg_len, tag);
    kfree(msg);
}

static bool fsenc_encrypt_buffer(const uint8_t *plain, size_t plain_len, uint8_t **out, size_t *out_len) {
    if (!out || !out_len || plain_len > 0xFFFFFFFFu) {
        return false;
    }
    if (plain_len > 0 && !plain) {
        return false;
    }

    size_t blob_len = SFS_ENC_HEADER_BYTES + plain_len;
    uint8_t *blob = (uint8_t *)kmalloc(blob_len == 0 ? 1 : blob_len);
    uint8_t *cipher = blob + SFS_ENC_HEADER_BYTES;
    uint8_t nonce[SFS_ENC_NONCE_BYTES];
    uint8_t tag[SFS_ENC_TAG_BYTES];

    if (!blob) {
        return false;
    }

    generate_nonce(nonce);
    if (plain_len > 0) {
        stream_xor(nonce, plain, cipher, plain_len);
    }
    fsenc_compute_tag(nonce, cipher, plain_len, (uint32_t)plain_len, tag);

    size_t idx = 0;
    memcpy(blob + idx, SFS_ENC_MAGIC, SFS_ENC_MAGIC_LEN);
    idx += SFS_ENC_MAGIC_LEN;
    blob[idx++] = (uint8_t)SFS_ENC_VERSION;
    memcpy(blob + idx, nonce, SFS_ENC_NONCE_BYTES);
    idx += SFS_ENC_NONCE_BYTES;
    memcpy(blob + idx, tag, SFS_ENC_TAG_BYTES);
    idx += SFS_ENC_TAG_BYTES;
    encode_u32_le((uint32_t)plain_len, blob + idx);

    *out = blob;
    *out_len = blob_len;
    return true;
}

static bool fsenc_decrypt_buffer(const uint8_t *blob, size_t blob_len, uint8_t **out, size_t *out_len) {
    if (!blob || !out || !out_len || !fsenc_is_blob(blob, blob_len)) {
        return false;
    }

    size_t idx = SFS_ENC_MAGIC_LEN + 1u;
    const uint8_t *nonce = blob + idx;
    idx += SFS_ENC_NONCE_BYTES;
    const uint8_t *tag = blob + idx;
    idx += SFS_ENC_TAG_BYTES;
    uint32_t plain_len = decode_u32_le(blob + idx);
    idx += 4u;

    if ((size_t)plain_len + SFS_ENC_HEADER_BYTES != blob_len) {
        return false;
    }

    const uint8_t *cipher = blob + idx;
    uint8_t expected_tag[SFS_ENC_TAG_BYTES];
    fsenc_compute_tag(nonce, cipher, plain_len, plain_len, expected_tag);
    if (!constant_time_equal_bytes(tag, expected_tag, SFS_ENC_TAG_BYTES)) {
        return false;
    }

    uint8_t *plain = (uint8_t *)kmalloc(plain_len == 0 ? 1 : plain_len);
    if (!plain) {
        return false;
    }
    if (plain_len > 0) {
        stream_xor(nonce, cipher, plain, plain_len);
    }

    *out = plain;
    *out_len = plain_len;
    return true;
}

static int str_equal(const char *a, const char *b) {
    return strcmp(a, b) == 0;
}

static size_t bounded_strlen(const char *s, size_t max_len) {
    size_t n = 0;
    while (n < max_len && s[n] != '\0') {
        n++;
    }
    return n;
}

static bool header_valid(const sfs_header_t *hdr, size_t max_size) {
    if (!hdr) {
        return false;
    }
    if (hdr->magic != SFS_MAGIC || hdr->version != 1) {
        return false;
    }
    if (hdr->entry_count == 0 || hdr->entry_count > SFS_MAX_ENTRIES) {
        return false;
    }
    uint64_t table_bytes = (uint64_t)hdr->entry_count * sizeof(sfs_entry_t);
    uint64_t table_end = (uint64_t)hdr->entries_offset + table_bytes;
    if (table_end > hdr->image_size) {
        return false;
    }
    if ((uint64_t)hdr->data_offset < table_end) {
        return false;
    }
    if (hdr->data_offset > hdr->image_size) {
        return false;
    }
    if (hdr->image_size > max_size) {
        return false;
    }
    return true;
}

static bool entries_valid(const sfs_header_t *hdr, const sfs_entry_t *entries) {
    if (!hdr || !entries) {
        return false;
    }

    for (uint32_t i = 0; i < hdr->entry_count; i++) {
        const sfs_entry_t *ent = &entries[i];
        size_t name_len = bounded_strlen(ent->name, sizeof(ent->name));
        if (name_len == 0 || name_len >= sizeof(ent->name)) {
            return false;
        }
        if (ent->type != SFS_TYPE_DIR && ent->type != SFS_TYPE_FILE) {
            return false;
        }

        if (i == 0) {
            if (ent->type != SFS_TYPE_DIR || ent->parent != SFS_ROOT_PARENT) {
                return false;
            }
            if (strcmp(ent->name, "/") != 0) {
                return false;
            }
            continue;
        }

        if (strchr(ent->name, '/') != 0) {
            return false;
        }

        if (ent->parent >= hdr->entry_count) {
            return false;
        }

        if (ent->type == SFS_TYPE_FILE) {
            uint64_t off = ent->offset;
            uint64_t end = off + ent->size;
            if (off < hdr->data_offset || end > hdr->image_size || end < off) {
                return false;
            }
        } else {
            if (ent->offset != 0 || ent->size != 0) {
                return false;
            }
        }
    }

    return true;
}

static uint32_t find_child(uint32_t parent, const char *name) {
    for (uint32_t i = 0; i < g_header->entry_count; i++) {
        sfs_entry_t *ent = &g_entries[i];
        if (ent->parent == parent && str_equal(ent->name, name)) {
            return i;
        }
    }
    return 0xFFFFFFFFu;
}

static uint32_t resolve_path(const char *path) {
    if (!path || !g_header) {
        return 0xFFFFFFFFu;
    }
    if (strcmp(path, "/") == 0) {
        return 0;
    }

    char tmp[256];
    if (strlen(path) >= sizeof(tmp)) {
        return 0xFFFFFFFFu;
    }
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    uint32_t cur = 0;
    char *p = tmp;
    while (*p == '/') {
        p++;
    }
    while (*p) {
        char *slash = strchr(p, '/');
        if (slash) {
            *slash = '\0';
        }

        if (*p != '\0') {
            uint32_t next = find_child(cur, p);
            if (next == 0xFFFFFFFFu) {
                return 0xFFFFFFFFu;
            }
            cur = next;
        }

        if (!slash) {
            break;
        }
        p = slash + 1;
        while (*p == '/') {
            p++;
        }
    }

    return cur;
}

static int split_parent(const char *path, char *parent_out, size_t parent_len, char *name_out, size_t name_len) {
    if (!path || path[0] != '/' || strlen(path) < 2) {
        return 0;
    }

    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') {
        len--;
    }

    size_t cut = len;
    while (cut > 1 && path[cut - 1] != '/') {
        cut--;
    }

    size_t nlen = len - cut;
    if (nlen == 0 || nlen >= name_len) {
        return 0;
    }

    if (cut == 1) {
        strncpy(parent_out, "/", parent_len);
    } else {
        size_t plen = cut - 1;
        if (plen >= parent_len) {
            return 0;
        }
        memcpy(parent_out, path, plen);
        parent_out[plen] = '\0';
    }

    memcpy(name_out, &path[cut], nlen);
    name_out[nlen] = '\0';
    return 1;
}

static uint32_t next_data_end(void) {
    uint32_t end = g_header->data_offset;
    for (uint32_t i = 0; i < g_header->entry_count; i++) {
        if (g_entries[i].type == SFS_TYPE_FILE) {
            uint64_t top64 = (uint64_t)g_entries[i].offset + g_entries[i].size;
            if (top64 > 0xFFFFFFFFu) {
                return 0xFFFFFFFFu;
            }
            uint32_t top = (uint32_t)top64;
            if (top > end) {
                end = top;
            }
        }
    }
    return end;
}

static bool read_image_from_disk(void) {
    if (!g_disk_enabled || !g_image || !g_header) {
        return false;
    }

    uint8_t sector[SFS_SECTOR_SIZE];
    if (!ata_read28(g_disk_start_lba, 1, sector)) {
        return false;
    }

    const sfs_header_t *hdr = (const sfs_header_t *)sector;
    size_t disk_cap = (size_t)g_disk_sector_count * SFS_SECTOR_SIZE;
    if (!header_valid(hdr, disk_cap) || hdr->image_size > g_capacity) {
        return false;
    }

    uint32_t image_size = hdr->image_size;
    uint32_t sectors = (image_size + SFS_SECTOR_SIZE - 1) / SFS_SECTOR_SIZE;

    for (uint32_t i = 0; i < sectors; i++) {
        if (!ata_read28(g_disk_start_lba + i, 1, sector)) {
            return false;
        }
        uint32_t off = i * SFS_SECTOR_SIZE;
        uint32_t remain = image_size - off;
        uint32_t n = remain > SFS_SECTOR_SIZE ? SFS_SECTOR_SIZE : remain;
        memcpy(g_image + off, sector, n);
    }

    if (!header_valid((const sfs_header_t *)g_image, g_capacity)) {
        return false;
    }

    g_header = (sfs_header_t *)g_image;
    g_entries = (sfs_entry_t *)(g_image + g_header->entries_offset);
    if (!entries_valid(g_header, g_entries)) {
        return false;
    }
    g_last_synced_sectors = sectors;
    return true;
}

bool sfs_mount(const void *image, size_t size) {
    if (!image || size < sizeof(sfs_header_t)) {
        return false;
    }

    if (g_image) {
        sfs_unmount();
    }

    const sfs_header_t *hdr = (const sfs_header_t *)image;
    if (!header_valid(hdr, size)) {
        return false;
    }
    const sfs_entry_t *entries = (const sfs_entry_t *)((const uint8_t *)image + hdr->entries_offset);
    if (!entries_valid(hdr, entries)) {
        return false;
    }

    g_capacity = size;
    if (g_capacity < SFS_GROW_BYTES) {
        g_capacity = SFS_GROW_BYTES;
    }

    g_image = (uint8_t *)kmalloc(g_capacity);
    if (!g_image) {
        return false;
    }
    memset(g_image, 0, g_capacity);
    memcpy(g_image, image, size);

    g_header = (sfs_header_t *)g_image;
    g_entries = (sfs_entry_t *)(g_image + g_header->entries_offset);

    g_disk_enabled = 0;
    g_disk_start_lba = 0;
    g_disk_sector_count = 0;
    g_last_synced_sectors = 0;

    return true;
}

void sfs_unmount(void) {
    if (g_image) {
        kfree(g_image);
    }
    g_image = 0;
    g_capacity = 0;
    g_header = 0;
    g_entries = 0;
    g_disk_enabled = 0;
    g_disk_start_lba = 0;
    g_disk_sector_count = 0;
    g_last_synced_sectors = 0;
}

int sfs_list(const char *path, char *out, size_t out_len) {
    if (!g_header || !out || out_len == 0) {
        return -1;
    }
    out[0] = '\0';

    uint32_t dir = resolve_path(path);
    if (dir == 0xFFFFFFFFu || g_entries[dir].type != SFS_TYPE_DIR) {
        return -1;
    }

    size_t written = 0;
    for (uint32_t i = 0; i < g_header->entry_count; i++) {
        sfs_entry_t *ent = &g_entries[i];
        if (ent->parent != dir) {
            continue;
        }

        size_t nlen = strlen(ent->name);
        if (written + nlen + 2 >= out_len) {
            break;
        }
        memcpy(out + written, ent->name, nlen);
        written += nlen;
        if (ent->type == SFS_TYPE_DIR) {
            out[written++] = '/';
        }
        out[written++] = '\n';
    }

    if (written < out_len) {
        out[written] = '\0';
    }
    return (int)written;
}

bool sfs_read_file(const char *path, void *out, size_t out_len, size_t *read_len) {
    if (!g_header) {
        return false;
    }
    uint32_t idx = resolve_path(path);
    if (idx == 0xFFFFFFFFu || g_entries[idx].type != SFS_TYPE_FILE) {
        return false;
    }

    sfs_entry_t *ent = &g_entries[idx];
    uint64_t end = (uint64_t)ent->offset + ent->size;
    if (ent->offset < g_header->data_offset || end > g_header->image_size || end < ent->offset) {
        return false;
    }

    const uint8_t *raw = g_image + ent->offset;
    size_t raw_len = ent->size;

    if (fsenc_is_blob(raw, raw_len)) {
        uint8_t *plain = 0;
        size_t plain_len = 0;
        if (!fsenc_decrypt_buffer(raw, raw_len, &plain, &plain_len)) {
            return false;
        }

        size_t n = plain_len;
        if (n > out_len) {
            n = out_len;
        }
        if (n > 0 && !out) {
            kfree(plain);
            return false;
        }
        if (n > 0) {
            memcpy(out, plain, n);
        }
        if (read_len) {
            *read_len = n;
        }
        kfree(plain);
        return true;
    }

    size_t n = raw_len;
    if (n > out_len) {
        n = out_len;
    }

    if (n > 0 && !out) {
        return false;
    }
    if (n > 0) {
        memcpy(out, raw, n);
    }
    if (read_len) {
        *read_len = n;
    }
    return true;
}

bool sfs_write_file(const char *path, const void *data, size_t size) {
    if (!g_header || !path) {
        return false;
    }
    if (size > 0 && !data) {
        return false;
    }

    bool ok = false;
    uint8_t *sealed = 0;
    const uint8_t *payload = (const uint8_t *)data;
    size_t payload_size = size;

    if (!fsenc_is_blob(payload, payload_size)) {
        if (!fsenc_encrypt_buffer(payload, payload_size, &sealed, &payload_size)) {
            return false;
        }
        payload = sealed;
    }

    if (payload_size > 0xFFFFFFFFu) {
        goto out;
    }
    uint32_t size32 = (uint32_t)payload_size;

    uint32_t idx = resolve_path(path);
    if (idx != 0xFFFFFFFFu && g_entries[idx].type == SFS_TYPE_FILE) {
        uint32_t pos = next_data_end();
        if (pos == 0xFFFFFFFFu || pos > 0xFFFFFFFFu - size32) {
            goto out;
        }
        if ((size_t)pos + payload_size > g_capacity) {
            goto out;
        }
        if (payload_size > 0) {
            memcpy(g_image + pos, payload, payload_size);
        }
        g_entries[idx].offset = pos;
        g_entries[idx].size = size32;
        g_header->image_size = pos + size32;
        ok = true;
        goto out;
    }

    if (g_header->entry_count >= SFS_MAX_ENTRIES) {
        goto out;
    }

    char parent[256];
    char name[SFS_MAX_NAME];
    if (!split_parent(path, parent, sizeof(parent), name, sizeof(name))) {
        goto out;
    }

    uint32_t parent_idx = resolve_path(parent);
    if (parent_idx == 0xFFFFFFFFu || g_entries[parent_idx].type != SFS_TYPE_DIR) {
        goto out;
    }

    uint32_t pos = next_data_end();
    if (pos == 0xFFFFFFFFu || pos > 0xFFFFFFFFu - size32) {
        goto out;
    }
    if ((size_t)pos + payload_size > g_capacity) {
        goto out;
    }

    if (payload_size > 0) {
        memcpy(g_image + pos, payload, payload_size);
    }

    sfs_entry_t *ent = &g_entries[g_header->entry_count++];
    memset(ent, 0, sizeof(*ent));
    strncpy(ent->name, name, sizeof(ent->name) - 1);
    ent->parent = parent_idx;
    ent->type = SFS_TYPE_FILE;
    ent->offset = pos;
    ent->size = size32;

    g_header->image_size = pos + size32;
    ok = true;

out:
    if (sealed) {
        kfree(sealed);
    }
    return ok;
}

typedef struct sfs_pack_slot {
    uint8_t *data;
    uint32_t size;
    int is_file;
} sfs_pack_slot_t;

bool sfs_encrypt_plain_files(size_t *converted, size_t *failed) {
    if (converted) {
        *converted = 0;
    }
    if (failed) {
        *failed = 0;
    }

    if (!g_header || !g_entries || !g_image) {
        return false;
    }

    size_t entry_count = g_header->entry_count;
    sfs_pack_slot_t *slots = (sfs_pack_slot_t *)kmalloc(entry_count * sizeof(sfs_pack_slot_t));
    if (!slots) {
        return false;
    }
    memset(slots, 0, entry_count * sizeof(sfs_pack_slot_t));

    size_t converted_local = 0;
    size_t failed_local = 0;
    size_t total_bytes = g_header->data_offset;
    uint32_t old_image_size = g_header->image_size;
    int ok = 1;

    for (uint32_t i = 0; i < g_header->entry_count; i++) {
        if (g_entries[i].type != SFS_TYPE_FILE) {
            continue;
        }
        slots[i].is_file = 1;

        uint64_t end = (uint64_t)g_entries[i].offset + g_entries[i].size;
        if (g_entries[i].offset < g_header->data_offset || end > g_header->image_size || end < g_entries[i].offset) {
            failed_local++;
            ok = 0;
            break;
        }

        const uint8_t *raw = g_image + g_entries[i].offset;
        size_t raw_len = g_entries[i].size;

        if (fsenc_is_blob(raw, raw_len)) {
            slots[i].data = (uint8_t *)kmalloc(raw_len == 0 ? 1 : raw_len);
            if (!slots[i].data) {
                failed_local++;
                ok = 0;
                break;
            }
            if (raw_len > 0) {
                memcpy(slots[i].data, raw, raw_len);
            }
            slots[i].size = (uint32_t)raw_len;
        } else {
            uint8_t *sealed = 0;
            size_t sealed_len = 0;
            if (!fsenc_encrypt_buffer(raw, raw_len, &sealed, &sealed_len) || sealed_len > 0xFFFFFFFFu) {
                if (sealed) {
                    kfree(sealed);
                }
                failed_local++;
                ok = 0;
                break;
            }
            slots[i].data = sealed;
            slots[i].size = (uint32_t)sealed_len;
            converted_local++;
        }

        if (slots[i].size > g_capacity || total_bytes > g_capacity - slots[i].size) {
            failed_local++;
            ok = 0;
            break;
        }
        total_bytes += slots[i].size;
    }

    if (ok) {
        uint32_t cursor = g_header->data_offset;
        for (uint32_t i = 0; i < g_header->entry_count; i++) {
            if (!slots[i].is_file) {
                continue;
            }
            if (slots[i].size > 0) {
                memcpy(g_image + cursor, slots[i].data, slots[i].size);
            }
            g_entries[i].offset = cursor;
            g_entries[i].size = slots[i].size;
            cursor += slots[i].size;
        }

        if (old_image_size > cursor && old_image_size <= g_capacity) {
            memset(g_image + cursor, 0, old_image_size - cursor);
        }
        g_header->image_size = cursor;
    }

    for (size_t i = 0; i < entry_count; i++) {
        if (slots[i].data) {
            kfree(slots[i].data);
        }
    }
    kfree(slots);

    if (converted) {
        *converted = ok ? converted_local : 0;
    }
    if (failed) {
        *failed = failed_local;
    }
    return ok != 0;
}

bool sfs_make_dir(const char *path) {
    if (!g_header || !path) {
        return false;
    }
    if (resolve_path(path) != 0xFFFFFFFFu) {
        return true;
    }

    if (g_header->entry_count >= SFS_MAX_ENTRIES) {
        return false;
    }

    char parent[256];
    char name[SFS_MAX_NAME];
    if (!split_parent(path, parent, sizeof(parent), name, sizeof(name))) {
        return false;
    }

    uint32_t parent_idx = resolve_path(parent);
    if (parent_idx == 0xFFFFFFFFu || g_entries[parent_idx].type != SFS_TYPE_DIR) {
        return false;
    }

    sfs_entry_t *ent = &g_entries[g_header->entry_count++];
    memset(ent, 0, sizeof(*ent));
    strncpy(ent->name, name, sizeof(ent->name) - 1);
    ent->parent = parent_idx;
    ent->type = SFS_TYPE_DIR;
    ent->offset = 0;
    ent->size = 0;
    return true;
}

bool sfs_exists(const char *path) {
    return resolve_path(path) != 0xFFFFFFFFu;
}

bool sfs_attach_block_device(uint32_t start_lba, uint32_t sector_count) {
    if (!g_header || sector_count == 0 || !ata_present()) {
        return false;
    }

    g_disk_start_lba = start_lba;
    g_disk_sector_count = sector_count;
    g_disk_enabled = 1;

    if (read_image_from_disk()) {
        return true;
    }

    return sfs_sync();
}

bool sfs_sync(void) {
    if (!g_header || !g_disk_enabled || !ata_present()) {
        return false;
    }

    uint32_t image_size = g_header->image_size;
    if (image_size == 0 || image_size > g_capacity) {
        return false;
    }

    uint32_t sectors = (image_size + SFS_SECTOR_SIZE - 1) / SFS_SECTOR_SIZE;
    if (sectors > g_disk_sector_count) {
        return false;
    }

    uint8_t sector[SFS_SECTOR_SIZE];
    for (uint32_t i = 0; i < sectors; i++) {
        uint32_t off = i * SFS_SECTOR_SIZE;
        uint32_t remain = image_size - off;
        uint32_t n = remain > SFS_SECTOR_SIZE ? SFS_SECTOR_SIZE : remain;

        memset(sector, 0, sizeof(sector));
        memcpy(sector, g_image + off, n);

        if (!ata_write28(g_disk_start_lba + i, 1, sector)) {
            return false;
        }
    }

    if (g_last_synced_sectors > sectors) {
        memset(sector, 0, sizeof(sector));
        for (uint32_t i = sectors; i < g_last_synced_sectors; i++) {
            if (!ata_write28(g_disk_start_lba + i, 1, sector)) {
                return false;
            }
        }
    }

    g_last_synced_sectors = sectors;
    return true;
}

bool sfs_persistence_enabled(void) {
    return g_disk_enabled != 0;
}

static void fsck_append(char *out, size_t out_len, const char *text) {
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

static void fsck_append_u32(char *out, size_t out_len, uint32_t value) {
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
        fsck_append(out, out_len, c);
        idx--;
    }
}

bool sfs_check(char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return false;
    }
    out[0] = '\0';

    if (!g_header || !g_entries || !g_image) {
        fsck_append(out, out_len, "fsck: filesystem not mounted\n");
        return false;
    }

    uint32_t issues = 0;
    uint32_t dirs = 0;
    uint32_t files = 0;

    if (!header_valid(g_header, g_capacity)) {
        fsck_append(out, out_len, "fsck: invalid header\n");
        issues++;
    } else {
        fsck_append(out, out_len, "fsck: header ok\n");
    }

    if (!entries_valid(g_header, g_entries)) {
        fsck_append(out, out_len, "fsck: invalid entries table\n");
        issues++;
    } else {
        fsck_append(out, out_len, "fsck: entry table basic checks ok\n");
    }

    for (uint32_t i = 0; i < g_header->entry_count; i++) {
        if (g_entries[i].type == SFS_TYPE_DIR) {
            dirs++;
        } else if (g_entries[i].type == SFS_TYPE_FILE) {
            files++;
        }
    }

    for (uint32_t i = 1; i < g_header->entry_count; i++) {
        uint32_t cur = i;
        uint32_t guard = 0;
        int reached_root = 0;
        while (guard++ < g_header->entry_count) {
            if (cur == 0) {
                reached_root = 1;
                break;
            }
            cur = g_entries[cur].parent;
            if (cur >= g_header->entry_count) {
                break;
            }
        }
        if (!reached_root) {
            fsck_append(out, out_len, "fsck: orphan/cycle at entry ");
            fsck_append_u32(out, out_len, i);
            fsck_append(out, out_len, "\n");
            issues++;
        }
    }

    for (uint32_t i = 0; i < g_header->entry_count; i++) {
        for (uint32_t j = i + 1; j < g_header->entry_count; j++) {
            if (g_entries[i].parent == g_entries[j].parent &&
                strcmp(g_entries[i].name, g_entries[j].name) == 0) {
                fsck_append(out, out_len, "fsck: duplicate sibling name '");
                fsck_append(out, out_len, g_entries[i].name);
                fsck_append(out, out_len, "'\n");
                issues++;
            }
        }
    }

    for (uint32_t i = 0; i < g_header->entry_count; i++) {
        if (g_entries[i].type != SFS_TYPE_FILE) {
            continue;
        }
        uint64_t a0 = g_entries[i].offset;
        uint64_t a1 = a0 + g_entries[i].size;
        for (uint32_t j = i + 1; j < g_header->entry_count; j++) {
            if (g_entries[j].type != SFS_TYPE_FILE) {
                continue;
            }
            uint64_t b0 = g_entries[j].offset;
            uint64_t b1 = b0 + g_entries[j].size;
            if (a0 < b1 && b0 < a1) {
                fsck_append(out, out_len, "fsck: overlapping file regions at entries ");
                fsck_append_u32(out, out_len, i);
                fsck_append(out, out_len, " and ");
                fsck_append_u32(out, out_len, j);
                fsck_append(out, out_len, "\n");
                issues++;
            }
        }
    }

    fsck_append(out, out_len, "fsck: dirs=");
    fsck_append_u32(out, out_len, dirs);
    fsck_append(out, out_len, " files=");
    fsck_append_u32(out, out_len, files);
    fsck_append(out, out_len, " issues=");
    fsck_append_u32(out, out_len, issues);
    fsck_append(out, out_len, "\n");

    return issues == 0;
}
