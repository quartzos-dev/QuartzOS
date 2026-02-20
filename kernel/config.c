#include <filesystem/sfs.h>
#include <kernel/config.h>
#include <kernel/slog.h>
#include <lib/string.h>

#define CONFIG_PATH "/etc/system.cfg"
#define CONFIG_MAX_ITEMS 64
#define CONFIG_KEY_LEN 31
#define CONFIG_VAL_LEN 95

typedef struct config_item {
    char key[CONFIG_KEY_LEN + 1];
    char value[CONFIG_VAL_LEN + 1];
    uint8_t used;
} config_item_t;

static config_item_t g_items[CONFIG_MAX_ITEMS];

static int parse_u32_dec(const char *text, uint32_t *out_value) {
    if (!text || !*text || !out_value) {
        return 0;
    }
    uint32_t value = 0;
    for (const char *p = text; *p; p++) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
        value = value * 10u + (uint32_t)(*p - '0');
    }
    *out_value = value;
    return 1;
}

static config_item_t *find_item(const char *key) {
    if (!key) {
        return 0;
    }
    for (size_t i = 0; i < CONFIG_MAX_ITEMS; i++) {
        if (g_items[i].used && strcmp(g_items[i].key, key) == 0) {
            return &g_items[i];
        }
    }
    return 0;
}

void config_init(void) {
    memset(g_items, 0, sizeof(g_items));
}

bool config_set(const char *key, const char *value) {
    if (!key || !*key || !value) {
        return false;
    }
    if (strlen(key) > CONFIG_KEY_LEN || strlen(value) > CONFIG_VAL_LEN) {
        return false;
    }
    if (strchr(key, '=') || strchr(key, '\n')) {
        return false;
    }
    if (strchr(value, '\n')) {
        return false;
    }

    config_item_t *item = find_item(key);
    if (!item) {
        for (size_t i = 0; i < CONFIG_MAX_ITEMS; i++) {
            if (!g_items[i].used) {
                item = &g_items[i];
                item->used = 1;
                strncpy(item->key, key, sizeof(item->key) - 1);
                item->key[sizeof(item->key) - 1] = '\0';
                break;
            }
        }
    }
    if (!item) {
        return false;
    }
    strncpy(item->value, value, sizeof(item->value) - 1);
    item->value[sizeof(item->value) - 1] = '\0';
    slog_log(SLOG_LEVEL_DEBUG, "config", "set key");
    return true;
}

bool config_unset(const char *key) {
    if (!key || !*key) {
        return false;
    }
    config_item_t *item = find_item(key);
    if (!item) {
        return false;
    }
    memset(item, 0, sizeof(*item));
    slog_log(SLOG_LEVEL_DEBUG, "config", "unset key");
    return true;
}

const char *config_get(const char *key) {
    config_item_t *item = find_item(key);
    if (!item) {
        return 0;
    }
    return item->value;
}

bool config_get_u32(const char *key, uint32_t *out_value) {
    const char *value = config_get(key);
    if (!value) {
        return false;
    }
    return parse_u32_dec(value, out_value) != 0;
}

bool config_save(void) {
    char blob[8192];
    blob[0] = '\0';

    for (size_t i = 0; i < CONFIG_MAX_ITEMS; i++) {
        if (!g_items[i].used) {
            continue;
        }
        strncat(blob, g_items[i].key, sizeof(blob) - strlen(blob) - 1);
        strncat(blob, "=", sizeof(blob) - strlen(blob) - 1);
        strncat(blob, g_items[i].value, sizeof(blob) - strlen(blob) - 1);
        strncat(blob, "\n", sizeof(blob) - strlen(blob) - 1);
    }

    if (!sfs_write_file(CONFIG_PATH, blob, strlen(blob))) {
        slog_log(SLOG_LEVEL_WARN, "config", "save failed");
        return false;
    }
    if (sfs_persistence_enabled()) {
        bool ok = sfs_sync();
        if (!ok) {
            slog_log(SLOG_LEVEL_WARN, "config", "sync failed");
        } else {
            slog_log(SLOG_LEVEL_INFO, "config", "saved");
        }
        return ok;
    }
    slog_log(SLOG_LEVEL_INFO, "config", "saved");
    return true;
}

bool config_load(void) {
    char blob[8192];
    size_t read = 0;
    if (!sfs_read_file(CONFIG_PATH, blob, sizeof(blob) - 1, &read)) {
        slog_log(SLOG_LEVEL_DEBUG, "config", "no config file");
        return false;
    }
    blob[read] = '\0';

    memset(g_items, 0, sizeof(g_items));

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
        char line[160];
        size_t len = end - start;
        if (len >= sizeof(line)) {
            continue;
        }
        memcpy(line, &blob[start], len);
        line[len] = '\0';
        if (line[0] == '#') {
            continue;
        }
        char *eq = strchr(line, '=');
        if (!eq) {
            continue;
        }
        *eq = '\0';
        const char *key = line;
        const char *value = eq + 1;
        (void)config_set(key, value);
    }

    slog_log(SLOG_LEVEL_INFO, "config", "loaded");
    return true;
}

size_t config_dump(char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return 0;
    }
    out[0] = '\0';
    for (size_t i = 0; i < CONFIG_MAX_ITEMS; i++) {
        if (!g_items[i].used) {
            continue;
        }
        strncat(out, g_items[i].key, out_len - strlen(out) - 1);
        strncat(out, "=", out_len - strlen(out) - 1);
        strncat(out, g_items[i].value, out_len - strlen(out) - 1);
        strncat(out, "\n", out_len - strlen(out) - 1);
    }
    return strlen(out);
}
