#include <drivers/ata.h>
#include <filesystem/sfs.h>
#include <lib/string.h>
#include <memory/heap.h>

#define SFS_ROOT_PARENT 0xFFFFFFFFu
#define SFS_MAX_ENTRIES 4096
#define SFS_GROW_BYTES (4 * 1024 * 1024)
#define SFS_SECTOR_SIZE 512u

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

    size_t n = ent->size;
    if (n > out_len) {
        n = out_len;
    }

    if (n > 0 && !out) {
        return false;
    }
    if (n > 0) {
        memcpy(out, g_image + ent->offset, n);
    }
    if (read_len) {
        *read_len = n;
    }
    return true;
}

bool sfs_write_file(const char *path, const void *data, size_t size) {
    if (!g_header || !path || !data || size == 0) {
        return false;
    }
    if (size > 0xFFFFFFFFu) {
        return false;
    }
    uint32_t size32 = (uint32_t)size;

    uint32_t idx = resolve_path(path);
    if (idx != 0xFFFFFFFFu && g_entries[idx].type == SFS_TYPE_FILE) {
        uint32_t pos = next_data_end();
        if (pos == 0xFFFFFFFFu || pos > 0xFFFFFFFFu - size32) {
            return false;
        }
        if ((size_t)pos + size > g_capacity) {
            return false;
        }
        memcpy(g_image + pos, data, size);
        g_entries[idx].offset = pos;
        g_entries[idx].size = size32;
        g_header->image_size = pos + size32;
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

    uint32_t pos = next_data_end();
    if (pos == 0xFFFFFFFFu || pos > 0xFFFFFFFFu - size32) {
        return false;
    }
    if ((size_t)pos + size > g_capacity) {
        return false;
    }

    memcpy(g_image + pos, data, size);

    sfs_entry_t *ent = &g_entries[g_header->entry_count++];
    memset(ent, 0, sizeof(*ent));
    strncpy(ent->name, name, sizeof(ent->name) - 1);
    ent->parent = parent_idx;
    ent->type = SFS_TYPE_FILE;
    ent->offset = pos;
    ent->size = size32;

    g_header->image_size = pos + size32;
    return true;
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
    return true;
}

bool sfs_persistence_enabled(void) {
    return g_disk_enabled != 0;
}

static void fsck_append(char *out, size_t out_len, const char *text) {
    if (!out || out_len == 0 || !text) {
        return;
    }
    strncat(out, text, out_len - strlen(out) - 1);
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
