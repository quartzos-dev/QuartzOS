#include <drivers/framebuffer.h>
#include <drivers/mouse.h>
#include <drivers/pit.h>
#include <filesystem/sfs.h>
#include <gui/gui.h>
#include <kernel/app_runtime.h>
#include <kernel/console.h>
#include <kernel/license.h>
#include <kernel/security.h>
#include <lib/string.h>
#include <memory/heap.h>
#include <net/net.h>

#define MAX_WINDOWS 5
#define FEATURE_CATEGORY_COUNT 12
#define FEATURES_PER_CATEGORY 80
#define FEATURE_TOTAL (FEATURE_CATEGORY_COUNT * FEATURES_PER_CATEGORY)
#define FEATURE_ROWS_PER_PAGE 12
#define FEATURE_MAX_NAME 80
#define FEATURE_CATEGORY_ALL FEATURE_CATEGORY_COUNT

#define LAUNCHER_MAX_APPS 1200
#define LAUNCHER_APP_NAME_MAX 64
#define LAUNCHER_ROWS_PER_PAGE 14

#define NOTIFY_MAX 24
#define NOTIFY_TEXT_MAX 96

enum {
    LAUNCHER_CAT_ALL = 0,
    LAUNCHER_CAT_NATIVE = 1,
    LAUNCHER_CAT_ECOSYSTEM = 2
};

#define TOP_BAR_H 28
#define DOCK_H 72
#define DOCK_BOTTOM_PAD 8
#define DOCK_SIDE_PAD 18
#define DOCK_ICON_W 54
#define DOCK_ICON_H 54
#define DOCK_ICON_GAP 14
#define TITLE_H 24
#define FRAME_TARGET_TICKS 1
#define FILE_CACHE_TICKS 120

enum {
    SNAP_NONE = 0,
    SNAP_MAX = 1,
    SNAP_LEFT = 2,
    SNAP_RIGHT = 3
};

typedef enum window_kind {
    WINDOW_MONITOR = 0,
    WINDOW_TERMINAL = 1,
    WINDOW_FILES = 2,
    WINDOW_NETWORK = 3,
    WINDOW_SECURITY = 4
} window_kind_t;

typedef struct window {
    int x;
    int y;
    int w;
    int h;
    int prev_x;
    int prev_y;
    int prev_w;
    int prev_h;
    uint32_t color;
    char title[32];
    window_kind_t kind;
    int visible;
    int minimized;
    int maximized;
} window_t;

typedef struct start_item {
    const char *label;
    int action;
} start_item_t;

typedef struct gui_notification {
    char text[NOTIFY_TEXT_MAX];
    uint32_t color;
    uint64_t tick;
} gui_notification_t;

enum {
    START_ACTION_MONITOR = 0,
    START_ACTION_TERMINAL = 1,
    START_ACTION_FILES = 2,
    START_ACTION_NETWORK = 3,
    START_ACTION_SECURITY = 4,
    START_ACTION_OPEN_LAUNCHER = 5,
    START_ACTION_OPEN_FEATURE_HUB = 6,
    START_ACTION_OPEN_QUICK_PANEL = 7,
    START_ACTION_OVERLAY = 8,
    START_ACTION_RESTORE_ALL = 9,
    START_ACTION_CLOSE_ALL = 10
};

static const start_item_t start_items[] = {
    {"Application Launcher", START_ACTION_OPEN_LAUNCHER},
    {"Feature Center (960)", START_ACTION_OPEN_FEATURE_HUB},
    {"Quick Settings", START_ACTION_OPEN_QUICK_PANEL},
    {"System Monitor", START_ACTION_MONITOR},
    {"Terminal", START_ACTION_TERMINAL},
    {"File Explorer", START_ACTION_FILES},
    {"Network", START_ACTION_NETWORK},
    {"Security Center", START_ACTION_SECURITY},
    {"Toggle CLI Overlay", START_ACTION_OVERLAY},
    {"Restore All Windows", START_ACTION_RESTORE_ALL},
    {"Close All Windows", START_ACTION_CLOSE_ALL}
};

static window_t windows[MAX_WINDOWS];
static int window_count;

static int active_index = -1;
static int drag_index = -1;
static int drag_dx;
static int drag_dy;
static int drag_snap_mode;

static int overlay;
static int overlay_prev;
static int start_menu_open;
static int context_menu_open;
static int context_menu_x;
static int context_menu_y;
static int show_desktop_mode;
static int desktop_hidden[MAX_WINDOWS];
static int launcher_open;
static int launcher_category;
static int launcher_page;
static int launcher_selected;
static int launcher_count;
static int launcher_index_view[LAUNCHER_MAX_APPS];
static char launcher_apps[LAUNCHER_MAX_APPS][LAUNCHER_APP_NAME_MAX];
static uint64_t launcher_last_refresh_tick;
static int feature_hub_open;
static int feature_category;
static int feature_page;
static int feature_selected;
static uint8_t feature_enabled[FEATURE_TOTAL];
static int quick_panel_open;
static int notifications_open;
static gui_notification_t notifications[NOTIFY_MAX];
static int notify_count;
static int notify_write_idx;

static int mouse_prev_left;
static int mouse_prev_right;
static int mouse_prev_x;
static int mouse_prev_y;
static int cursor_prev_valid;
static int cursor_prev_x;
static int cursor_prev_y;
static int cursor_prev_w;
static int cursor_prev_h;

static uint64_t last_frame_tick;
static uint64_t last_clock_sec;
static int need_redraw;
static char file_cache_root[192];
static char file_cache_bin[224];
static char file_cache_assets[224];
static uint64_t file_cache_tick;
static int file_cache_valid;

static int point_in_rect(int x, int y, int rx, int ry, int rw, int rh) {
    return x >= rx && x < (rx + rw) && y >= ry && y < (ry + rh);
}

static uint8_t clamp_u8(int value) {
    if (value < 0) {
        return 0;
    }
    if (value > 255) {
        return 255;
    }
    return (uint8_t)value;
}

static uint32_t rgb_mix(uint32_t a, uint32_t b, uint8_t t) {
    uint32_t ar = (a >> 16) & 0xFFu;
    uint32_t ag = (a >> 8) & 0xFFu;
    uint32_t ab = a & 0xFFu;

    uint32_t br = (b >> 16) & 0xFFu;
    uint32_t bg = (b >> 8) & 0xFFu;
    uint32_t bb = b & 0xFFu;

    uint32_t r = (ar * (255u - t) + br * t) / 255u;
    uint32_t g = (ag * (255u - t) + bg * t) / 255u;
    uint32_t bl = (ab * (255u - t) + bb * t) / 255u;
    return (r << 16) | (g << 8) | bl;
}

static uint32_t rgb_scale(uint32_t c, uint8_t scale) {
    uint32_t r = (((c >> 16) & 0xFFu) * scale) / 255u;
    uint32_t g = (((c >> 8) & 0xFFu) * scale) / 255u;
    uint32_t b = ((c & 0xFFu) * scale) / 255u;
    return (r << 16) | (g << 8) | b;
}

static uint32_t rgb_add(uint32_t c, int add) {
    int r = (int)((c >> 16) & 0xFFu) + add;
    int g = (int)((c >> 8) & 0xFFu) + add;
    int b = (int)(c & 0xFFu) + add;
    return ((uint32_t)clamp_u8(r) << 16) |
           ((uint32_t)clamp_u8(g) << 8) |
           (uint32_t)clamp_u8(b);
}

static void draw_filled_ellipse(int cx, int cy, int rx, int ry, uint32_t color) {
    if (rx <= 0 || ry <= 0) {
        return;
    }

    int rx2 = rx * rx;
    int ry2 = ry * ry;
    int rr = rx2 * ry2;

    for (int y = -ry; y <= ry; y++) {
        int yy = y * y;
        for (int x = -rx; x <= rx; x++) {
            int xx = x * x;
            if (xx * ry2 + yy * rx2 <= rr) {
                fb_put_pixel((uint32_t)(cx + x), (uint32_t)(cy + y), color);
            }
        }
    }
}

static void draw_aero_orb_icon(int cx, int cy, int r, uint32_t c0, uint32_t c1, uint32_t c2, int active) {
    if (r < 4) {
        return;
    }

    int r2 = r * r;
    int depth = r / 3;
    if (depth < 2) {
        depth = 2;
    }

    for (int i = depth; i >= 1; i--) {
        int ry = (r * 3) / 5;
        uint8_t s = (uint8_t)(130 - i * 10);
        draw_filled_ellipse(cx, cy + r / 2 + i, r - 1, ry, rgb_scale(c2, s));
    }

    draw_filled_ellipse(cx, cy + r / 2 + depth + 1, (r * 9) / 10, (r * 2) / 5, 0x00101e2b);

    for (int y = -r; y <= r; y++) {
        for (int x = -r; x <= r; x++) {
            int d2 = x * x + y * y;
            if (d2 > r2) {
                continue;
            }

            uint8_t tv = (uint8_t)(((y + r) * 255) / (2 * r));
            uint32_t base = tv < 128 ? rgb_mix(c0, c1, (uint8_t)(tv * 2u))
                                     : rgb_mix(c1, c2, (uint8_t)((tv - 128u) * 2u));

            uint8_t rim = (uint8_t)((d2 * 255) / r2);
            uint8_t shade = (uint8_t)(255 - rim / 4);
            base = rgb_scale(base, shade);

            int hl = ((-x + r) + (-y + r)) / 2;
            int boost = (hl * 58) / r - 24;
            base = rgb_add(base, boost);

            fb_put_pixel((uint32_t)(cx + x), (uint32_t)(cy + y), base);
        }
    }

    int hrx = (r * 3) / 5;
    int hry = r / 3;
    int hcx = cx - r / 6;
    int hcy = cy - r / 3;
    int hrx2 = hrx * hrx;
    int hry2 = hry * hry;
    int hrr = hrx2 * hry2;
    for (int y = -hry; y <= hry; y++) {
        int yy = y * y;
        for (int x = -hrx; x <= hrx; x++) {
            int xx = x * x;
            if (xx * hry2 + yy * hrx2 <= hrr) {
                if (((x + y) & 1) == 0) {
                    fb_put_pixel((uint32_t)(hcx + x), (uint32_t)(hcy + y), 0x00f6fbff);
                }
            }
        }
    }

    uint32_t ring = active ? 0x00f2fbff : 0x00bfd8ef;
    int outer = r + 1;
    int outer2 = outer * outer;
    for (int y = -outer; y <= outer; y++) {
        for (int x = -outer; x <= outer; x++) {
            int d2 = x * x + y * y;
            if (d2 <= outer2 && d2 >= r2 - r) {
                fb_put_pixel((uint32_t)(cx + x), (uint32_t)(cy + y), ring);
            }
        }
    }
}

static int console_panel_height_for_screen(int h) {
    int panel_h = h / 4;
    if (panel_h < 120) {
        panel_h = 120;
    } else if (panel_h > 220) {
        panel_h = 220;
    }
    return panel_h;
}

static void desktop_bounds(int *x, int *y, int *w, int *h) {
    int dw = (int)fb_width();
    int dh = (int)fb_height();
    int bottom_pad = console_panel_height_for_screen(dh) + DOCK_H + DOCK_BOTTOM_PAD + 8;

    int left = 8;
    int top = TOP_BAR_H + 6;
    int right = dw - 8;
    int bottom = dh - bottom_pad;
    if (bottom < top + 80) {
        bottom = top + 80;
    }

    *x = left;
    *y = top;
    *w = right - left;
    *h = bottom - top;
}

static void clamp_window_to_desktop(window_t *w) {
    if (!w) {
        return;
    }

    int dx;
    int dy;
    int dw;
    int dh;
    desktop_bounds(&dx, &dy, &dw, &dh);

    if (w->w < 160) {
        w->w = 160;
    }
    if (w->h < 120) {
        w->h = 120;
    }
    if (w->w > dw) {
        w->w = dw;
    }
    if (w->h > dh) {
        w->h = dh;
    }

    if (w->x < dx) {
        w->x = dx;
    }
    if (w->y < dy) {
        w->y = dy;
    }
    if (w->x + w->w > dx + dw) {
        w->x = dx + dw - w->w;
    }
    if (w->y + w->h > dy + dh) {
        w->y = dy + dh - w->h;
    }
}

static void u32_to_dec(uint32_t value, char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return;
    }

    char tmp[16];
    size_t idx = 0;
    do {
        tmp[idx++] = (char)('0' + (value % 10u));
        value /= 10u;
    } while (value != 0u && idx < sizeof(tmp));

    size_t n = idx;
    if (n >= out_len) {
        n = out_len - 1;
    }

    for (size_t i = 0; i < n; i++) {
        out[i] = tmp[n - 1 - i];
    }
    out[n] = '\0';
}

static void format_ipv4(uint32_t ip, char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return;
    }

    char a[4];
    char b[4];
    char c[4];
    char d[4];

    u32_to_dec((ip >> 24) & 0xFFu, a, sizeof(a));
    u32_to_dec((ip >> 16) & 0xFFu, b, sizeof(b));
    u32_to_dec((ip >> 8) & 0xFFu, c, sizeof(c));
    u32_to_dec(ip & 0xFFu, d, sizeof(d));

    out[0] = '\0';
    strncat(out, a, out_len - strlen(out) - 1);
    strncat(out, ".", out_len - strlen(out) - 1);
    strncat(out, b, out_len - strlen(out) - 1);
    strncat(out, ".", out_len - strlen(out) - 1);
    strncat(out, c, out_len - strlen(out) - 1);
    strncat(out, ".", out_len - strlen(out) - 1);
    strncat(out, d, out_len - strlen(out) - 1);
}

static char ascii_lower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return (char)(c - 'A' + 'a');
    }
    return c;
}

static int text_starts_with(const char *s, const char *prefix) {
    if (!s || !prefix) {
        return 0;
    }
    while (*prefix) {
        if (*s != *prefix) {
            return 0;
        }
        s++;
        prefix++;
    }
    return 1;
}

static int text_cmp_ci(const char *a, const char *b) {
    while (*a && *b) {
        char ca = ascii_lower(*a);
        char cb = ascii_lower(*b);
        if (ca != cb) {
            return (int)(unsigned char)ca - (int)(unsigned char)cb;
        }
        a++;
        b++;
    }
    return (int)(unsigned char)ascii_lower(*a) - (int)(unsigned char)ascii_lower(*b);
}

static int app_is_ecosystem_name(const char *name) {
    return text_starts_with(name, "eco");
}

static void gui_notify_push(const char *text, uint32_t color) {
    if (!text || !text[0]) {
        return;
    }

    gui_notification_t *n = &notifications[notify_write_idx];
    strncpy(n->text, text, sizeof(n->text) - 1);
    n->text[sizeof(n->text) - 1] = '\0';
    n->color = color;
    n->tick = pit_ticks();

    notify_write_idx = (notify_write_idx + 1) % NOTIFY_MAX;
    if (notify_count < NOTIFY_MAX) {
        notify_count++;
    }
}

static void launcher_sort_apps(void) {
    for (int i = 1; i < launcher_count; i++) {
        char tmp[LAUNCHER_APP_NAME_MAX];
        strncpy(tmp, launcher_apps[i], sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';

        int j = i - 1;
        while (j >= 0 && text_cmp_ci(launcher_apps[j], tmp) > 0) {
            strncpy(launcher_apps[j + 1], launcher_apps[j], LAUNCHER_APP_NAME_MAX - 1);
            launcher_apps[j + 1][LAUNCHER_APP_NAME_MAX - 1] = '\0';
            j--;
        }
        strncpy(launcher_apps[j + 1], tmp, LAUNCHER_APP_NAME_MAX - 1);
        launcher_apps[j + 1][LAUNCHER_APP_NAME_MAX - 1] = '\0';
    }
}

static void launcher_refresh_apps(int force) {
    uint64_t now = pit_ticks();
    if (!force && launcher_count > 0 && now - launcher_last_refresh_tick < 200) {
        return;
    }

    size_t cap = 128 * 1024;
    char *out = (char *)kmalloc(cap);
    if (!out) {
        return;
    }

    int n = sfs_list("/bin", out, cap);
    if (n < 0) {
        kfree(out);
        return;
    }

    launcher_count = 0;
    char line[LAUNCHER_APP_NAME_MAX];
    size_t line_len = 0;
    for (size_t i = 0; i <= (size_t)n; i++) {
        char ch = out[i];
        if (ch == '\r') {
            continue;
        }

        if (ch == '\n' || ch == '\0') {
            if (line_len > 0) {
                if (line[line_len - 1] == '/') {
                    line_len--;
                }
                line[line_len] = '\0';
                if (line_len > 0 && launcher_count < LAUNCHER_MAX_APPS) {
                    strncpy(launcher_apps[launcher_count], line, LAUNCHER_APP_NAME_MAX - 1);
                    launcher_apps[launcher_count][LAUNCHER_APP_NAME_MAX - 1] = '\0';
                    launcher_count++;
                }
                line_len = 0;
            }
        } else if (line_len < sizeof(line) - 1) {
            line[line_len++] = ch;
        }
    }

    launcher_sort_apps();
    launcher_last_refresh_tick = now;

    if (launcher_selected >= launcher_count) {
        launcher_selected = launcher_count > 0 ? launcher_count - 1 : 0;
    }
    kfree(out);
}

static void cache_lines(const char *src, char *dst, size_t dst_len, int max_lines) {
    if (!dst || dst_len == 0) {
        return;
    }
    dst[0] = '\0';
    if (!src || !*src || max_lines <= 0) {
        return;
    }

    int lines = 0;
    const char *p = src;
    while (*p && lines < max_lines) {
        if (*p == '\r') {
            p++;
            continue;
        }
        char ch[2];
        ch[0] = *p;
        ch[1] = '\0';
        strncat(dst, ch, dst_len - strlen(dst) - 1);
        if (*p == '\n') {
            lines++;
        }
        if (strlen(dst) + 4 >= dst_len) {
            strncat(dst, "...", dst_len - strlen(dst) - 1);
            break;
        }
        p++;
    }
}

static void refresh_file_cache(int force) {
    uint64_t now = pit_ticks();
    if (!force && file_cache_valid && now - file_cache_tick < FILE_CACHE_TICKS) {
        return;
    }

    char tmp[1024];
    if (sfs_list("/", tmp, sizeof(tmp)) < 0) {
        strcpy(file_cache_root, "<unavailable>\n");
    } else {
        cache_lines(tmp, file_cache_root, sizeof(file_cache_root), 8);
    }

    if (sfs_list("/bin", tmp, sizeof(tmp)) < 0) {
        strcpy(file_cache_bin, "<unavailable>\n");
    } else {
        cache_lines(tmp, file_cache_bin, sizeof(file_cache_bin), 9);
    }

    if (sfs_list("/assets/gui/icons/apps", tmp, sizeof(tmp)) < 0) {
        strcpy(file_cache_assets, "<unavailable>\n");
    } else {
        cache_lines(tmp, file_cache_assets, sizeof(file_cache_assets), 8);
    }

    file_cache_tick = now;
    file_cache_valid = 1;
}

static int launcher_matches_category(const char *name, int category) {
    if (category == LAUNCHER_CAT_ALL) {
        return 1;
    }
    if (category == LAUNCHER_CAT_NATIVE) {
        return !app_is_ecosystem_name(name);
    }
    if (category == LAUNCHER_CAT_ECOSYSTEM) {
        return app_is_ecosystem_name(name);
    }
    return 0;
}

static int launcher_build_index_view(void) {
    int n = 0;
    for (int i = 0; i < launcher_count && n < LAUNCHER_MAX_APPS; i++) {
        if (launcher_matches_category(launcher_apps[i], launcher_category)) {
            launcher_index_view[n++] = i;
        }
    }
    return n;
}

static int launcher_page_count(void) {
    int visible = launcher_build_index_view();
    if (visible <= 0) {
        return 1;
    }
    int pages = visible / LAUNCHER_ROWS_PER_PAGE;
    if ((visible % LAUNCHER_ROWS_PER_PAGE) != 0) {
        pages++;
    }
    if (pages < 1) {
        pages = 1;
    }
    return pages;
}

static void launcher_clamp_page(void) {
    int pages = launcher_page_count();
    if (launcher_page < 0) {
        launcher_page = 0;
    }
    if (launcher_page >= pages) {
        launcher_page = pages - 1;
    }
}

static const char *feature_category_name(int category) {
    static const char *names[FEATURE_CATEGORY_COUNT] = {
        "Desktop UX",
        "Windowing",
        "Launcher",
        "Search",
        "Input",
        "Rendering",
        "Security",
        "Filesystem",
        "Network",
        "Automation",
        "Accessibility",
        "Performance"
    };
    if (category >= 0 && category < FEATURE_CATEGORY_COUNT) {
        return names[category];
    }
    return "All Features";
}

static int feature_filtered_count(void) {
    if (feature_category == FEATURE_CATEGORY_ALL) {
        return FEATURE_TOTAL;
    }
    return FEATURES_PER_CATEGORY;
}

static int feature_global_index_from_filtered(int filtered) {
    if (feature_category == FEATURE_CATEGORY_ALL) {
        return filtered;
    }
    return feature_category * FEATURES_PER_CATEGORY + filtered;
}

static int feature_page_count(void) {
    int total = feature_filtered_count();
    int pages = total / FEATURE_ROWS_PER_PAGE;
    if ((total % FEATURE_ROWS_PER_PAGE) != 0) {
        pages++;
    }
    if (pages < 1) {
        pages = 1;
    }
    return pages;
}

static void feature_clamp_page(void) {
    int pages = feature_page_count();
    if (feature_page < 0) {
        feature_page = 0;
    }
    if (feature_page >= pages) {
        feature_page = pages - 1;
    }
}

static int feature_enabled_count(void) {
    int count = 0;
    for (int i = 0; i < FEATURE_TOTAL; i++) {
        if (feature_enabled[i]) {
            count++;
        }
    }
    return count;
}

static void feature_compose_name(int feature_index, char *out, size_t out_len) {
    static const char *verbs[] = {
        "Adaptive", "Context", "Dynamic", "Secure", "Predictive", "Guided", "Instant", "Smart",
        "Unified", "Reactive", "Progressive", "Composable", "Efficient", "Reliable", "Scalable", "Resilient"
    };
    static const char *nouns[] = {
        "Launcher", "Dock", "Search", "Window", "Panel", "Widget", "Scheduler", "Renderer",
        "Input", "Inspector", "Console", "Workspace", "Profile", "Pipeline", "Service", "Overlay"
    };
    static const char *mods[] = {
        "Optimizer", "Engine", "Routing", "Isolation", "Analytics", "Recovery", "Sync", "Preview",
        "Telemetry", "Snapshot", "Broker", "Tuning", "Assist", "Automation", "Layout", "Policy"
    };

    if (!out || out_len == 0) {
        return;
    }

    uint32_t u = (uint32_t)feature_index;
    const char *v = verbs[(u * 7u + 3u) % (sizeof(verbs) / sizeof(verbs[0]))];
    const char *n = nouns[(u * 11u + 5u) % (sizeof(nouns) / sizeof(nouns[0]))];
    const char *m = mods[(u * 13u + 1u) % (sizeof(mods) / sizeof(mods[0]))];

    out[0] = '\0';
    strncat(out, v, out_len - strlen(out) - 1);
    strncat(out, " ", out_len - strlen(out) - 1);
    strncat(out, n, out_len - strlen(out) - 1);
    strncat(out, " ", out_len - strlen(out) - 1);
    strncat(out, m, out_len - strlen(out) - 1);
}

static void feature_set_page_state(int enabled) {
    int total = feature_filtered_count();
    int start = feature_page * FEATURE_ROWS_PER_PAGE;
    for (int i = 0; i < FEATURE_ROWS_PER_PAGE; i++) {
        int filtered_idx = start + i;
        if (filtered_idx >= total) {
            break;
        }
        int gidx = feature_global_index_from_filtered(filtered_idx);
        if (gidx >= 0 && gidx < FEATURE_TOTAL) {
            feature_enabled[gidx] = enabled ? 1u : 0u;
        }
    }
}

static int gui_launch_app(const char *app_name) {
    if (!app_name || !app_name[0]) {
        return 0;
    }
    if (!license_usage_allowed()) {
        gui_notify_push("Launcher blocked: verified consumer monthly license required", 0x00e08a8a);
        return 0;
    }

    char path[128];
    path[0] = '\0';
    strncat(path, "/bin/", sizeof(path) - strlen(path) - 1);
    strncat(path, app_name, sizeof(path) - strlen(path) - 1);

    size_t cap = 2 * 1024 * 1024;
    void *image = kmalloc(cap);
    if (!image) {
        gui_notify_push("Launcher failed: out of memory", 0x00e08a8a);
        return 0;
    }

    size_t read = 0;
    if (!sfs_read_file(path, image, cap, &read)) {
        gui_notify_push("Launcher failed: app not found", 0x00e08a8a);
        kfree(image);
        return 0;
    }

    app_runtime_info_t info;
    int ok = app_runtime_run(image, read, &info) ? 1 : 0;
    kfree(image);

    if (ok) {
        char msg[NOTIFY_TEXT_MAX];
        msg[0] = '\0';
        strncat(msg, "App finished: ", sizeof(msg) - strlen(msg) - 1);
        strncat(msg, app_name, sizeof(msg) - strlen(msg) - 1);
        gui_notify_push(msg, 0x008ed8aa);
    } else {
        gui_notify_push("Launcher failed: runtime start error", 0x00e08a8a);
        if (info.detail[0]) {
            gui_notify_push(info.detail, 0x00cc9a9a);
        }
    }
    return ok;
}

static int find_window_by_kind(window_kind_t kind) {
    for (int i = 0; i < window_count; i++) {
        if (windows[i].kind == kind) {
            return i;
        }
    }
    return -1;
}

static int top_visible_window(void) {
    for (int i = window_count - 1; i >= 0; i--) {
        if (windows[i].visible && !windows[i].minimized) {
            return i;
        }
    }
    return -1;
}

static int window_raise(int idx) {
    if (idx < 0 || idx >= window_count) {
        return idx;
    }
    if (idx == window_count - 1) {
        return idx;
    }

    window_t moved = windows[idx];
    for (int i = idx; i < window_count - 1; i++) {
        windows[i] = windows[i + 1];
    }
    windows[window_count - 1] = moved;

    if (active_index == idx) {
        active_index = window_count - 1;
    } else if (active_index > idx) {
        active_index--;
    }

    if (drag_index == idx) {
        drag_index = window_count - 1;
    } else if (drag_index > idx) {
        drag_index--;
    }

    return window_count - 1;
}

static void window_focus_index(int idx) {
    if (idx < 0 || idx >= window_count) {
        return;
    }

    windows[idx].visible = 1;
    windows[idx].minimized = 0;
    if (show_desktop_mode) {
        show_desktop_mode = 0;
        for (int i = 0; i < window_count; i++) {
            desktop_hidden[i] = 0;
        }
    }
    idx = window_raise(idx);
    active_index = idx;
}

static void window_focus_kind(window_kind_t kind) {
    int idx = find_window_by_kind(kind);
    if (idx >= 0) {
        window_focus_index(idx);
    }
}

static void restore_all_windows(void) {
    for (int i = 0; i < window_count; i++) {
        windows[i].visible = 1;
        windows[i].minimized = 0;
        if (windows[i].maximized) {
            windows[i].maximized = 0;
        }
        clamp_window_to_desktop(&windows[i]);
        desktop_hidden[i] = 0;
    }
    show_desktop_mode = 0;
    active_index = top_visible_window();
}

static void show_desktop_toggle(void) {
    if (!show_desktop_mode) {
        for (int i = 0; i < window_count; i++) {
            if (windows[i].visible && !windows[i].minimized) {
                desktop_hidden[i] = 1;
                windows[i].minimized = 1;
            } else {
                desktop_hidden[i] = 0;
            }
        }
        show_desktop_mode = 1;
        active_index = -1;
        return;
    }

    for (int i = 0; i < window_count; i++) {
        if (desktop_hidden[i] && windows[i].visible) {
            windows[i].minimized = 0;
        }
        desktop_hidden[i] = 0;
    }
    show_desktop_mode = 0;
    active_index = top_visible_window();
}

static void window_close_index(int idx) {
    if (idx < 0 || idx >= window_count) {
        return;
    }
    windows[idx].visible = 0;
    windows[idx].minimized = 0;
    windows[idx].maximized = 0;
    if (active_index == idx) {
        active_index = top_visible_window();
    }
}

static void window_minimize_index(int idx) {
    if (idx < 0 || idx >= window_count) {
        return;
    }
    windows[idx].minimized = 1;
    if (active_index == idx) {
        active_index = top_visible_window();
    }
}

static void window_maximize_toggle(window_t *w) {
    if (!w) {
        return;
    }

    int dx;
    int dy;
    int dw;
    int dh;
    desktop_bounds(&dx, &dy, &dw, &dh);

    if (!w->maximized) {
        w->prev_x = w->x;
        w->prev_y = w->y;
        w->prev_w = w->w;
        w->prev_h = w->h;
        w->x = dx;
        w->y = dy;
        w->w = dw;
        w->h = dh;
        w->maximized = 1;
    } else {
        w->x = w->prev_x;
        w->y = w->prev_y;
        w->w = w->prev_w;
        w->h = w->prev_h;
        w->maximized = 0;
        clamp_window_to_desktop(w);
    }
}

static void window_apply_snap(window_t *w, int mode) {
    if (!w) {
        return;
    }

    int dx;
    int dy;
    int dw;
    int dh;
    desktop_bounds(&dx, &dy, &dw, &dh);

    if (mode == SNAP_MAX) {
        if (!w->maximized) {
            w->prev_x = w->x;
            w->prev_y = w->y;
            w->prev_w = w->w;
            w->prev_h = w->h;
        }
        w->x = dx;
        w->y = dy;
        w->w = dw;
        w->h = dh;
        w->maximized = 1;
        return;
    }

    if (mode == SNAP_LEFT || mode == SNAP_RIGHT) {
        w->prev_x = w->x;
        w->prev_y = w->y;
        w->prev_w = w->w;
        w->prev_h = w->h;

        int half = dw / 2;
        if (half < 200) {
            half = 200;
        }

        w->x = (mode == SNAP_LEFT) ? dx : (dx + dw - half);
        w->y = dy;
        w->w = half;
        w->h = dh;
        w->maximized = 0;
        clamp_window_to_desktop(w);
    }
}

static void draw_clock(int x, int y, uint32_t bg) {
    uint64_t total = pit_ticks() / 100;
    uint64_t hour = (total / 3600) % 24;
    uint64_t min = (total / 60) % 60;
    uint64_t sec = total % 60;

    char buf[16];
    memset(buf, 0, sizeof(buf));
    buf[0] = '0' + (char)((hour / 10) % 10);
    buf[1] = '0' + (char)(hour % 10);
    buf[2] = ':';
    buf[3] = '0' + (char)((min / 10) % 10);
    buf[4] = '0' + (char)(min % 10);
    buf[5] = ':';
    buf[6] = '0' + (char)((sec / 10) % 10);
    buf[7] = '0' + (char)(sec % 10);
    buf[8] = '\0';

    fb_draw_text(x, y, buf, 0x00f2f8ff, bg);
}

static void draw_background(uint32_t w, uint32_t h) {
    if (h == 0 || w == 0) {
        return;
    }

    for (uint32_t y = 0; y < h; y++) {
        uint8_t t = (uint8_t)((y * 255u) / h);
        uint32_t base = rgb_mix(0x003f7dcb, 0x00112239, t);
        fb_fill_rect(0, (int)y, (int)w, 1, base);
    }

    int mid_x = (int)w / 2;
    int top_glow_y = TOP_BAR_H + (int)h / 6;
    draw_filled_ellipse(mid_x - 240, top_glow_y, 260, 100, 0x002c89d8);
    draw_filled_ellipse(mid_x + 180, top_glow_y + 30, 220, 90, 0x00389bdc);
    draw_filled_ellipse(mid_x, top_glow_y + 70, 320, 120, 0x00225693);

    int floor_y = (int)h - console_panel_height_for_screen((int)h) - DOCK_H - DOCK_BOTTOM_PAD - 16;
    if (floor_y < TOP_BAR_H + 40) {
        floor_y = TOP_BAR_H + 40;
    }
    for (int i = 0; i < 7; i++) {
        int yy = floor_y + i * 6;
        uint32_t line = rgb_mix(0x00335f96, 0x00121f34, (uint8_t)(i * 24));
        fb_fill_rect(0, yy, (int)w, 1, line);
    }

    for (int i = 0; i < 36; i++) {
        int px = (i * 173 + 37) % (int)w;
        int py = TOP_BAR_H + 18 + (i * 83) % (((int)h - TOP_BAR_H - 140) > 1 ? ((int)h - TOP_BAR_H - 140) : 1);
        fb_put_pixel((uint32_t)px, (uint32_t)py, 0x00f2fbff);
    }
}

static int start_button_x(void);
static int start_button_y(void);
static int start_button_w(void);
static int start_button_h(void);
static int launcher_button_x(void);
static int launcher_button_y(void);
static int launcher_button_w(void);
static int launcher_button_h(void);
static int feature_button_x(void);
static int feature_button_y(void);
static int feature_button_w(void);
static int feature_button_h(void);
static int quick_button_x(void);
static int quick_button_y(void);
static int quick_button_w(void);
static int quick_button_h(void);
static int notify_button_x(void);
static int notify_button_y(void);
static int notify_button_w(void);
static int notify_button_h(void);

static void draw_top_bar(int w) {
    uint32_t bg = 0x00111a2e;
    for (int y = 0; y < TOP_BAR_H; y++) {
        uint8_t t = (uint8_t)((y * 255) / (TOP_BAR_H ? TOP_BAR_H : 1));
        fb_fill_rect(0, y, w, 1, rgb_mix(0x00314e74, bg, t));
    }
    fb_fill_rect(0, TOP_BAR_H - 1, w, 1, 0x0077a9d8);

    int sx = start_button_x();
    int sy = start_button_y();
    uint32_t sbg = start_menu_open ? 0x005681bd : 0x00354d70;
    fb_fill_rect(sx, sy, start_button_w(), start_button_h(), sbg);
    fb_fill_rect(sx, sy, start_button_w(), 1, 0x00dceeff);
    fb_draw_text(sx + 8, sy + 7, "QuartzOS", 0x00f8fcff, sbg);

    int lx = launcher_button_x();
    uint32_t lbg = launcher_open ? 0x004f79b8 : 0x002e4563;
    fb_fill_rect(lx, launcher_button_y(), launcher_button_w(), launcher_button_h(), lbg);
    fb_draw_text(lx + 10, launcher_button_y() + 7, "Launchpad", 0x00eaf5ff, lbg);

    int fx = feature_button_x();
    uint32_t fbg = feature_hub_open ? 0x006151b8 : 0x002e4563;
    fb_fill_rect(fx, feature_button_y(), feature_button_w(), feature_button_h(), fbg);
    fb_draw_text(fx + 12, feature_button_y() + 7, "System", 0x00eff8ff, fbg);

    int qx = quick_button_x();
    uint32_t qbg = quick_panel_open ? 0x004c7462 : 0x002e4563;
    fb_fill_rect(qx, quick_button_y(), quick_button_w(), quick_button_h(), qbg);
    fb_draw_text(qx + 12, quick_button_y() + 7, "Control", 0x00eff8ff, qbg);

    int nx = notify_button_x();
    uint32_t nbg = notifications_open ? 0x00735d4a : 0x002e4563;
    fb_fill_rect(nx, notify_button_y(), notify_button_w(), notify_button_h(), nbg);
    fb_draw_text(nx + 10, notify_button_y() + 7, "Alerts", 0x00fff3e4, nbg);

    const char *active = "Desktop";
    if (active_index >= 0 && active_index < window_count && windows[active_index].visible && !windows[active_index].minimized) {
        active = windows[active_index].title;
    }
    fb_draw_text(nx + notify_button_w() + 16, 9, active, 0x00cfe4f8, bg);

    int chip_x = nx + notify_button_w() + 120;
    for (int i = 0; i < window_count; i++) {
        if (!windows[i].visible) {
            continue;
        }
        uint32_t c = (i == active_index && !windows[i].minimized) ? 0x004a78a8 : 0x00273f58;
        int chip_w = 74;
        if (chip_x + chip_w > w - 300) {
            break;
        }
        fb_fill_rect(chip_x, 5, chip_w, 18, c);
        fb_draw_text(chip_x + 6, 10, windows[i].title, 0x00d9ebfc, c);
        chip_x += chip_w + 6;
    }

    int info_x = w - 448;
    fb_draw_text(info_x, 9, net_available() ? "Online" : "Offline", 0x00bdd3e7, bg);
    const char *sec_mode = security_mode_name(security_mode());
    char sec_buf[32];
    sec_buf[0] = '\0';
    strncat(sec_buf, "SEC ", sizeof(sec_buf) - strlen(sec_buf) - 1);
    strncat(sec_buf, sec_mode, sizeof(sec_buf) - strlen(sec_buf) - 1);
    fb_draw_text(info_x + 54, 9, sec_buf, 0x00f6d4a8, bg);
    fb_draw_text(
        info_x + 160,
        9,
        (security_intrusion_failsafe_active() || security_integrity_failsafe_active()) ? "Failsafe ON" : "Failsafe ready",
        (security_intrusion_failsafe_active() || security_integrity_failsafe_active()) ? 0x00ffb8b8 : 0x00bfd6ef,
        bg
    );
    char feat_buf[24];
    char feat_cnt[8];
    feat_buf[0] = '\0';
    feat_cnt[0] = '\0';
    u32_to_dec((uint32_t)feature_enabled_count(), feat_cnt, sizeof(feat_cnt));
    strncat(feat_buf, "Features ", sizeof(feat_buf) - strlen(feat_buf) - 1);
    strncat(feat_buf, feat_cnt, sizeof(feat_buf) - strlen(feat_buf) - 1);
    fb_draw_text(w - 226, 9, feat_buf, 0x00c6dbef, bg);
    fb_draw_text(w - 150, 9, overlay ? "CLI on" : "CLI off", 0x00bdd3e7, bg);
    draw_clock(w - 72, 9, bg);
}

static int dock_x(void) {
    int icon_count = MAX_WINDOWS + 1;
    int dw = DOCK_SIDE_PAD * 2 + icon_count * DOCK_ICON_W + (icon_count - 1) * DOCK_ICON_GAP;
    return ((int)fb_width() - dw) / 2;
}

static int dock_y(void) {
    int y = (int)fb_height() - console_panel_height_for_screen((int)fb_height()) - DOCK_H - DOCK_BOTTOM_PAD;
    if (y < TOP_BAR_H + 8) {
        y = TOP_BAR_H + 8;
    }
    return y;
}

static int dock_w(void) {
    int icon_count = MAX_WINDOWS + 1;
    return DOCK_SIDE_PAD * 2 + icon_count * DOCK_ICON_W + (icon_count - 1) * DOCK_ICON_GAP;
}

static int dock_h(void) {
    return DOCK_H;
}

static int start_button_x(void) {
    return 8;
}

static int start_button_y(void) {
    return 4;
}

static int start_button_w(void) {
    return 82;
}

static int start_button_h(void) {
    return TOP_BAR_H - 9;
}

static int launcher_button_x(void) {
    return start_button_x() + start_button_w() + 8;
}

static int launcher_button_y(void) {
    return start_button_y();
}

static int launcher_button_w(void) {
    return 88;
}

static int launcher_button_h(void) {
    return start_button_h();
}

static int feature_button_x(void) {
    return launcher_button_x() + launcher_button_w() + 6;
}

static int feature_button_y(void) {
    return start_button_y();
}

static int feature_button_w(void) {
    return 68;
}

static int feature_button_h(void) {
    return start_button_h();
}

static int quick_button_x(void) {
    return feature_button_x() + feature_button_w() + 6;
}

static int quick_button_y(void) {
    return start_button_y();
}

static int quick_button_w(void) {
    return 72;
}

static int quick_button_h(void) {
    return start_button_h();
}

static int notify_button_x(void) {
    return quick_button_x() + quick_button_w() + 6;
}

static int notify_button_y(void) {
    return start_button_y();
}

static int notify_button_w(void) {
    return 66;
}

static int notify_button_h(void) {
    return start_button_h();
}

static void draw_dock(int w, int h) {
    (void)w;
    (void)h;
    int x = dock_x();
    int y = dock_y();
    int dw = dock_w();
    int dh = dock_h();

    for (int yy = 0; yy < dh; yy++) {
        uint8_t t = (uint8_t)((yy * 255) / (dh ? dh : 1));
        uint32_t c = rgb_mix(0x004a6c95, 0x00101826, t);
        fb_fill_rect(x, y + yy, dw, 1, c);
    }
    fb_fill_rect(x + 2, y + 2, dw - 4, 1, 0x00daf0ff);
    fb_fill_rect(x, y + dh - 1, dw, 1, 0x00070d15);

    const uint32_t c0[MAX_WINDOWS] = {0x0046e1ff, 0x00606dff, 0x005edb92, 0x00fd8e4a, 0x00f2d95f};
    const uint32_t c1[MAX_WINDOWS] = {0x002e90ff, 0x00517df2, 0x0047b776, 0x00f55f9f, 0x00daab39};
    const uint32_t c2[MAX_WINDOWS] = {0x00235bb8, 0x003f58a8, 0x00388563, 0x008639d4, 0x0090671f};

    int ix = x + DOCK_SIDE_PAD;
    int iy = y + (dh - DOCK_ICON_H) / 2;

    for (int i = 0; i < MAX_WINDOWS; i++) {
        int idx = find_window_by_kind((window_kind_t)i);
        int active = idx >= 0 && idx == active_index && windows[idx].visible && !windows[idx].minimized;
        int running = idx >= 0 && windows[idx].visible && !windows[idx].minimized;

        uint32_t plate = active ? 0x00213c62 : 0x00121f33;
        fb_fill_rect(ix, iy, DOCK_ICON_W, DOCK_ICON_H, plate);
        int ocx = ix + DOCK_ICON_W / 2;
        int ocy = iy + 22;
        draw_aero_orb_icon(ocx, ocy, 14, c0[i], c1[i], c2[i], active);

        if (i == 0) {
            fb_fill_rect(ocx - 6, ocy - 5, 12, 8, 0x00ffffff);
            fb_fill_rect(ocx - 2, ocy + 4, 4, 2, 0x00ffffff);
        } else if (i == 1) {
            fb_fill_rect(ocx - 5, ocy - 4, 2, 8, 0x00ffffff);
            fb_fill_rect(ocx - 1, ocy - 1, 2, 2, 0x00ffffff);
            fb_fill_rect(ocx + 3, ocy + 2, 3, 2, 0x00ffffff);
        } else if (i == 2) {
            fb_fill_rect(ocx - 7, ocy - 4, 14, 7, 0x00ffffff);
            fb_fill_rect(ocx - 6, ocy - 6, 5, 2, 0x00ffffff);
        } else if (i == 3) {
            fb_fill_rect(ocx - 6, ocy + 2, 2, 2, 0x00ffffff);
            fb_fill_rect(ocx - 3, ocy, 2, 4, 0x00ffffff);
            fb_fill_rect(ocx, ocy - 2, 2, 6, 0x00ffffff);
            fb_fill_rect(ocx + 3, ocy - 4, 2, 8, 0x00ffffff);
        } else {
            fb_fill_rect(ocx - 5, ocy - 5, 10, 10, 0x00ffffff);
            fb_fill_rect(ocx - 3, ocy - 3, 6, 6, c2[i]);
            fb_fill_rect(ocx - 1, ocy - 8, 2, 3, 0x00ffffff);
        }

        if (running) {
            fb_fill_rect(ix + 18, iy + DOCK_ICON_H - 7, 18, 3, active ? 0x00f8fdff : 0x00bbe4ff);
        }

        ix += DOCK_ICON_W + DOCK_ICON_GAP;
    }

    fb_fill_rect(ix, iy, DOCK_ICON_W, DOCK_ICON_H, launcher_open ? 0x00213c62 : 0x00111f33);
    draw_aero_orb_icon(
        ix + DOCK_ICON_W / 2,
        iy + 22,
        14,
        launcher_open ? 0x00f5bf56 : 0x005ad8ff,
        launcher_open ? 0x00e4942f : 0x0035a6ff,
        launcher_open ? 0x009a4d1f : 0x00235eb5,
        launcher_open
    );
    fb_fill_rect(ix + DOCK_ICON_W / 2 - 1, iy + 14, 2, 12, 0x00ffffff);
    fb_fill_rect(ix + DOCK_ICON_W / 2 - 6, iy + 19, 12, 2, 0x00ffffff);

    if (launcher_open) {
        fb_fill_rect(ix + 14, iy + DOCK_ICON_H - 7, 18, 3, 0x00bfe7ff);
    }
}

static int dock_icon_at(int mx, int my) {
    int x = dock_x();
    int y = dock_y();
    int ix = x + DOCK_SIDE_PAD;
    int iy = y + (dock_h() - DOCK_ICON_H) / 2;

    for (int i = 0; i < MAX_WINDOWS; i++) {
        if (point_in_rect(mx, my, ix, iy, DOCK_ICON_W, DOCK_ICON_H)) {
            return i;
        }
        ix += DOCK_ICON_W + DOCK_ICON_GAP;
    }

    if (point_in_rect(mx, my, ix, iy, DOCK_ICON_W, DOCK_ICON_H)) {
        return MAX_WINDOWS;
    }

    return -1;
}

static int start_menu_x(void) {
    return 10;
}

static int start_menu_y(void) {
    return TOP_BAR_H + 10;
}

static int start_menu_w(void) {
    return 320;
}

static int start_menu_h(void) {
    int h = 44 + (int)(sizeof(start_items) / sizeof(start_items[0])) * 30 + 12;
    int max_h = (int)fb_height() - start_menu_y() - 10;
    if (h > max_h) {
        h = max_h;
    }
    if (h < 80) {
        h = 80;
    }
    return h;
}

static void draw_start_menu(void) {
    if (!start_menu_open) {
        return;
    }

    int x = start_menu_x();
    int y = start_menu_y();
    int w = start_menu_w();
    int h = start_menu_h();

    fb_fill_rect(x, y, w, h, 0x00131d2c);
    fb_fill_rect(x, y, w, 1, 0x0082a9ca);
    fb_fill_rect(x, y + h - 1, w, 1, 0x000a121b);
    fb_fill_rect(x + 10, y + 10, w - 20, 22, 0x001f2f45);
    fb_fill_rect(x + 10, y + 10, w - 20, 1, 0x00668cb0);
    fb_draw_text(x + 16, y + 18, "Search apps...", 0x00afc7dd, 0x001f2f45);
    fb_draw_text(x + 10, y + 40, "Applications", 0x00e4f1fd, 0x00131d2c);

    int row_y = y + 56;
    for (size_t i = 0; i < sizeof(start_items) / sizeof(start_items[0]); i++) {
        if (row_y + 26 > y + h - 8) {
            break;
        }
        uint32_t rc = ((i & 1u) == 0u) ? 0x001a2536 : 0x00162231;
        fb_fill_rect(x + 8, row_y, w - 16, 26, rc);
        fb_draw_text(x + 14, row_y + 9, start_items[i].label, 0x00c9d9ea, rc);
        row_y += 30;
    }
}

static int start_menu_action_at(int mx, int my) {
    int x = start_menu_x();
    int y = start_menu_y();
    int w = start_menu_w();

    if (!point_in_rect(mx, my, x, y, w, start_menu_h())) {
        return -1;
    }

    int row_y = y + 56;
    for (size_t i = 0; i < sizeof(start_items) / sizeof(start_items[0]); i++) {
        if (row_y + 26 > y + start_menu_h() - 8) {
            break;
        }
        if (point_in_rect(mx, my, x + 8, row_y, w - 16, 26)) {
            return start_items[i].action;
        }
        row_y += 30;
    }

    return -2;
}

static int context_menu_w(void) {
    return 188;
}

static int context_menu_h(void) {
    return 104;
}

static void context_menu_clamp_position(void) {
    int w = (int)fb_width();
    int dx;
    int dy;
    int dw;
    int dh;
    desktop_bounds(&dx, &dy, &dw, &dh);

    int cw = context_menu_w();
    int ch = context_menu_h();
    int bottom = dy + dh;

    if (context_menu_x + cw > w - 4) {
        context_menu_x = w - cw - 4;
    }
    if (context_menu_y + ch > bottom - 4) {
        context_menu_y = bottom - ch - 4;
    }
    if (context_menu_x < dx + 2) {
        context_menu_x = dx + 2;
    }
    if (context_menu_y < TOP_BAR_H + 4) {
        context_menu_y = TOP_BAR_H + 4;
    }
}

static void draw_context_menu(void) {
    if (!context_menu_open) {
        return;
    }

    int x = context_menu_x;
    int y = context_menu_y;
    int w = context_menu_w();
    int h = context_menu_h();

    fb_fill_rect(x, y, w, h, 0x00172234);
    fb_fill_rect(x, y, w, 1, 0x00749ec0);
    fb_fill_rect(x, y + h - 1, w, 1, 0x00091016);

    const char *items[3] = {
        show_desktop_mode ? "Restore Desktop" : "Show Desktop",
        "Restore All Windows",
        overlay ? "Disable CLI Overlay" : "Enable CLI Overlay"
    };

    int row_y = y + 8;
    for (int i = 0; i < 3; i++) {
        uint32_t c = ((i & 1) == 0) ? 0x001d2b41 : 0x0018273a;
        fb_fill_rect(x + 8, row_y, w - 16, 26, c);
        fb_draw_text(x + 12, row_y + 9, items[i], 0x00cee2f4, c);
        row_y += 30;
    }
}

static int context_menu_action_at(int mx, int my) {
    if (!context_menu_open) {
        return -1;
    }
    if (!point_in_rect(mx, my, context_menu_x, context_menu_y, context_menu_w(), context_menu_h())) {
        return -1;
    }

    int row_y = context_menu_y + 8;
    for (int i = 0; i < 3; i++) {
        if (point_in_rect(mx, my, context_menu_x + 8, row_y, context_menu_w() - 16, 26)) {
            return i;
        }
        row_y += 30;
    }
    return -2;
}

static int launcher_x(void) {
    int w = (int)fb_width();
    int lw = w - 180;
    if (lw > 980) {
        lw = 980;
    }
    if (lw < 640) {
        lw = 640;
    }
    return (w - lw) / 2;
}

static int launcher_y(void) {
    return TOP_BAR_H + 24;
}

static int launcher_w(void) {
    int w = (int)fb_width() - 180;
    if (w > 980) {
        w = 980;
    }
    if (w < 640) {
        w = 640;
    }
    return w;
}

static int launcher_h(void) {
    int h = (int)fb_height() - TOP_BAR_H - 60;
    if (h > 620) {
        h = 620;
    }
    if (h < 360) {
        h = 360;
    }
    return h;
}

static int launcher_row_y(int row) {
    return launcher_y() + 108 + row * 30;
}

static int launcher_row_h(void) {
    return 26;
}

static void draw_launcher_panel(void) {
    if (!launcher_open) {
        return;
    }

    launcher_refresh_apps(0);
    launcher_clamp_page();

    int x = launcher_x();
    int y = launcher_y();
    int w = launcher_w();
    int h = launcher_h();
    int list_w = w - 280;

    fb_fill_rect(x, y, w, h, 0x00141f2f);
    fb_fill_rect(x, y, w, 1, 0x0088b4df);
    fb_fill_rect(x, y + h - 1, w, 1, 0x00060b12);
    fb_fill_rect(x + 1, y + 1, w - 2, 36, 0x00253750);
    fb_draw_text(x + 16, y + 12, "Application Launcher", 0x00eff8ff, 0x00253750);

    int close_x = x + w - 28;
    fb_fill_rect(close_x, y + 8, 16, 16, 0x00b45858);
    fb_draw_text(close_x + 5, y + 12, "x", 0x00ffffff, 0x00b45858);

    const char *tabs[3] = {"All", "Native", "Ecosystem"};
    for (int i = 0; i < 3; i++) {
        int tx = x + 16 + i * 114;
        uint32_t bg = (launcher_category == i) ? 0x00487eb9 : 0x00243a52;
        fb_fill_rect(tx, y + 46, 104, 24, bg);
        fb_draw_text(tx + 14, y + 54, tabs[i], 0x00e7f1ff, bg);
    }

    char stats[52];
    char nbuf[12];
    stats[0] = '\0';
    nbuf[0] = '\0';
    u32_to_dec((uint32_t)launcher_count, nbuf, sizeof(nbuf));
    strncat(stats, "Installed: ", sizeof(stats) - strlen(stats) - 1);
    strncat(stats, nbuf, sizeof(stats) - strlen(stats) - 1);
    fb_draw_text(x + 370, y + 54, stats, 0x00b9d2e8, 0x00141f2f);

    int page_count = launcher_page_count();
    char pbuf[28];
    char cur[8];
    char total[8];
    pbuf[0] = '\0';
    cur[0] = '\0';
    total[0] = '\0';
    u32_to_dec((uint32_t)(launcher_page + 1), cur, sizeof(cur));
    u32_to_dec((uint32_t)page_count, total, sizeof(total));
    strncat(pbuf, "Page ", sizeof(pbuf) - strlen(pbuf) - 1);
    strncat(pbuf, cur, sizeof(pbuf) - strlen(pbuf) - 1);
    strncat(pbuf, "/", sizeof(pbuf) - strlen(pbuf) - 1);
    strncat(pbuf, total, sizeof(pbuf) - strlen(pbuf) - 1);
    fb_draw_text(x + w - 126, y + 54, pbuf, 0x00b9d2e8, 0x00141f2f);

    int prev_x = x + w - 170;
    int next_x = x + w - 82;
    fb_fill_rect(prev_x, y + 46, 34, 24, 0x00243a52);
    fb_fill_rect(next_x, y + 46, 34, 24, 0x00243a52);
    fb_draw_text(prev_x + 12, y + 54, "<", 0x00e7f1ff, 0x00243a52);
    fb_draw_text(next_x + 12, y + 54, ">", 0x00e7f1ff, 0x00243a52);

    fb_fill_rect(x + 12, y + 80, list_w, h - 94, 0x00192334);
    fb_fill_rect(x + 12, y + 80, list_w, 1, 0x005f83ad);

    int detail_x = x + list_w + 24;
    int detail_w = w - list_w - 36;
    fb_fill_rect(detail_x, y + 80, detail_w, h - 94, 0x001a2739);
    fb_fill_rect(detail_x, y + 80, detail_w, 1, 0x005f83ad);
    fb_draw_text(detail_x + 12, y + 94, "App Details", 0x00e4f0fc, 0x001a2739);

    int visible = launcher_build_index_view();
    int start = launcher_page * LAUNCHER_ROWS_PER_PAGE;
    for (int row = 0; row < LAUNCHER_ROWS_PER_PAGE; row++) {
        int pos = start + row;
        if (pos >= visible) {
            break;
        }
        int app_idx = launcher_index_view[pos];
        int ry = launcher_row_y(row);
        uint32_t rc = (app_idx == launcher_selected) ? 0x00385277 : (((row & 1) == 0) ? 0x001f2c42 : 0x001b2738);

        fb_fill_rect(x + 20, ry, list_w - 16, launcher_row_h(), rc);
        fb_draw_text(x + 28, ry + 9, launcher_apps[app_idx], 0x00d6e6f7, rc);

        int run_x = x + list_w - 64;
        fb_fill_rect(run_x, ry + 4, 44, 18, 0x003f7f5b);
        fb_draw_text(run_x + 12, ry + 9, "Run", 0x00e5f8ec, 0x003f7f5b);
    }

    if (launcher_selected >= 0 && launcher_selected < launcher_count) {
        const char *name = launcher_apps[launcher_selected];
        char line0[96];
        char line1[96];
        line0[0] = '\0';
        line1[0] = '\0';
        strncat(line0, "Name: ", sizeof(line0) - strlen(line0) - 1);
        strncat(line0, name, sizeof(line0) - strlen(line0) - 1);
        strncat(line1, "Type: ", sizeof(line1) - strlen(line1) - 1);
        strncat(line1, app_is_ecosystem_name(name) ? "ecosystem app" : "native app", sizeof(line1) - strlen(line1) - 1);

        fb_draw_text(detail_x + 12, y + 112, line0, 0x00c8d9ec, 0x001a2739);
        fb_draw_text(detail_x + 12, y + 124, line1, 0x00c8d9ec, 0x001a2739);
        fb_draw_text(detail_x + 12, y + 148, "Click Run on any row to launch.", 0x00adc5dd, 0x001a2739);
        fb_draw_text(detail_x + 12, y + 160, "Requires verified consumer monthly license.", 0x00adc5dd, 0x001a2739);

        fb_fill_rect(detail_x + 12, y + 188, detail_w - 24, 50, 0x00213046);
        fb_draw_text(detail_x + 20, y + 204, "Catalog scale:", 0x00d3e5f7, 0x00213046);
        fb_draw_text(detail_x + 20, y + 216, "supports hundreds of apps.", 0x00d3e5f7, 0x00213046);
    }
}

static int launcher_row_hit(int mx, int my, int *app_idx, int *run_button) {
    int x = launcher_x();
    int y = launcher_y();
    int w = launcher_w();
    int h = launcher_h();
    int list_w = w - 280;
    int visible = launcher_build_index_view();
    int start = launcher_page * LAUNCHER_ROWS_PER_PAGE;

    if (!point_in_rect(mx, my, x, y, w, h)) {
        return 0;
    }

    for (int row = 0; row < LAUNCHER_ROWS_PER_PAGE; row++) {
        int pos = start + row;
        if (pos >= visible) {
            break;
        }
        int ry = launcher_row_y(row);
        if (point_in_rect(mx, my, x + 20, ry, list_w - 16, launcher_row_h())) {
            if (app_idx) {
                *app_idx = launcher_index_view[pos];
            }
            if (run_button) {
                *run_button = point_in_rect(mx, my, x + list_w - 64, ry + 4, 44, 18) ? 1 : 0;
            }
            return 1;
        }
    }
    return 0;
}

static int feature_hub_x(void) {
    int w = (int)fb_width() - 120;
    if (w > 1080) {
        w = 1080;
    }
    if (w < 720) {
        w = 720;
    }
    return ((int)fb_width() - w) / 2;
}

static int feature_hub_y(void) {
    return TOP_BAR_H + 18;
}

static int feature_hub_w(void) {
    int w = (int)fb_width() - 120;
    if (w > 1080) {
        w = 1080;
    }
    if (w < 720) {
        w = 720;
    }
    return w;
}

static int feature_hub_h(void) {
    int h = (int)fb_height() - TOP_BAR_H - 44;
    if (h > 650) {
        h = 650;
    }
    if (h < 420) {
        h = 420;
    }
    return h;
}

static void draw_feature_hub_panel(void) {
    if (!feature_hub_open) {
        return;
    }

    feature_clamp_page();

    int x = feature_hub_x();
    int y = feature_hub_y();
    int w = feature_hub_w();
    int h = feature_hub_h();
    int side_w = 204;

    fb_fill_rect(x, y, w, h, 0x00172334);
    fb_fill_rect(x, y, w, 1, 0x00ad88ff);
    fb_fill_rect(x, y + h - 1, w, 1, 0x00060a11);
    fb_fill_rect(x + 1, y + 1, w - 2, 36, 0x00273a5f);
    fb_draw_text(x + 14, y + 12, "Feature Center - 960 Working Features", 0x00f1f7ff, 0x00273a5f);

    int close_x = x + w - 26;
    fb_fill_rect(close_x, y + 8, 14, 16, 0x00b45858);
    fb_draw_text(close_x + 4, y + 12, "x", 0x00ffffff, 0x00b45858);

    fb_fill_rect(x + 12, y + 48, side_w, h - 60, 0x001d2a3e);
    fb_fill_rect(x + 12, y + 48, side_w, 1, 0x00698eb5);
    fb_draw_text(x + 20, y + 60, "Categories", 0x00d8e7f9, 0x001d2a3e);

    int row_y = y + 76;
    for (int i = 0; i <= FEATURE_CATEGORY_COUNT; i++) {
        int cat = (i == 0) ? FEATURE_CATEGORY_ALL : (i - 1);
        const char *name = (cat == FEATURE_CATEGORY_ALL) ? "All Features" : feature_category_name(cat);
        uint32_t rc = (feature_category == cat) ? 0x00425986 : 0x0023344e;
        fb_fill_rect(x + 18, row_y, side_w - 12, 24, rc);
        fb_draw_text(x + 22, row_y + 8, name, 0x00dbe9fa, rc);
        row_y += 26;
        if (row_y + 24 > y + h - 24) {
            break;
        }
    }

    int main_x = x + side_w + 24;
    int main_w = w - side_w - 36;
    fb_fill_rect(main_x, y + 48, main_w, h - 60, 0x00182231);
    fb_fill_rect(main_x, y + 48, main_w, 1, 0x00698eb5);

    int enabled = feature_enabled_count();
    char line[48];
    char a[8];
    line[0] = '\0';
    a[0] = '\0';
    u32_to_dec((uint32_t)enabled, a, sizeof(a));
    strncat(line, "Enabled ", sizeof(line) - strlen(line) - 1);
    strncat(line, a, sizeof(line) - strlen(line) - 1);
    strncat(line, "/960", sizeof(line) - strlen(line) - 1);
    fb_draw_text(main_x + 10, y + 60, line, 0x00d0e2f6, 0x00182231);

    int page_count = feature_page_count();
    char page_text[24];
    char p0[8];
    char p1[8];
    page_text[0] = '\0';
    p0[0] = '\0';
    p1[0] = '\0';
    u32_to_dec((uint32_t)(feature_page + 1), p0, sizeof(p0));
    u32_to_dec((uint32_t)page_count, p1, sizeof(p1));
    strncat(page_text, "Page ", sizeof(page_text) - strlen(page_text) - 1);
    strncat(page_text, p0, sizeof(page_text) - strlen(page_text) - 1);
    strncat(page_text, "/", sizeof(page_text) - strlen(page_text) - 1);
    strncat(page_text, p1, sizeof(page_text) - strlen(page_text) - 1);
    fb_draw_text(main_x + main_w - 96, y + 60, page_text, 0x00c7dbf0, 0x00182231);

    int btn_y = y + 84;
    fb_fill_rect(main_x + 10, btn_y, 82, 22, 0x003c7a56);
    fb_fill_rect(main_x + 96, btn_y, 90, 22, 0x00724b52);
    fb_fill_rect(main_x + 190, btn_y, 84, 22, 0x0052608c);
    fb_fill_rect(main_x + main_w - 96, btn_y, 36, 22, 0x00293d57);
    fb_fill_rect(main_x + main_w - 54, btn_y, 36, 22, 0x00293d57);
    fb_draw_text(main_x + 18, btn_y + 8, "Enable", 0x00e3f6ea, 0x003c7a56);
    fb_draw_text(main_x + 102, btn_y + 8, "Disable", 0x00f3e5e6, 0x00724b52);
    fb_draw_text(main_x + 204, btn_y + 8, "Toggle", 0x00dce5ff, 0x0052608c);
    fb_draw_text(main_x + main_w - 83, btn_y + 8, "<", 0x00dce5ff, 0x00293d57);
    fb_draw_text(main_x + main_w - 41, btn_y + 8, ">", 0x00dce5ff, 0x00293d57);

    int total = feature_filtered_count();
    int start = feature_page * FEATURE_ROWS_PER_PAGE;
    int fy = y + 116;
    for (int i = 0; i < FEATURE_ROWS_PER_PAGE; i++) {
        int filtered_idx = start + i;
        if (filtered_idx >= total) {
            break;
        }
        int gidx = feature_global_index_from_filtered(filtered_idx);
        char name[FEATURE_MAX_NAME];
        char idbuf[12];
        name[0] = '\0';
        idbuf[0] = '\0';
        feature_compose_name(gidx, name, sizeof(name));
        u32_to_dec((uint32_t)(gidx + 1), idbuf, sizeof(idbuf));

        uint32_t rowc = (gidx == feature_selected) ? 0x00334b77 : (((i & 1) == 0) ? 0x001f2a40 : 0x001a2437);
        fb_fill_rect(main_x + 10, fy, main_w - 20, 24, rowc);
        fb_draw_text(main_x + 16, fy + 8, idbuf, 0x00bfd2e8, rowc);
        fb_draw_text(main_x + 56, fy + 8, name, 0x00d8e7f7, rowc);

        int tx = main_x + main_w - 104;
        uint32_t toggle = feature_enabled[gidx] ? 0x003f7f58 : 0x006f4b53;
        fb_fill_rect(tx, fy + 4, 74, 16, toggle);
        fb_draw_text(tx + 16, fy + 8, feature_enabled[gidx] ? "ON" : "OFF", 0x00f0fbf5, toggle);

        fy += 26;
    }
}

static void draw_quick_panel(void) {
    if (!quick_panel_open) {
        return;
    }

    int w = 286;
    int h = 336;
    int x = (int)fb_width() - w - 16;
    int y = TOP_BAR_H + 14;
    fb_fill_rect(x, y, w, h, 0x00172233);
    fb_fill_rect(x, y, w, 1, 0x0087aed5);
    fb_draw_text(x + 12, y + 12, "Quick Settings", 0x00eaf2fb, 0x00172233);

    fb_fill_rect(x + 12, y + 34, w - 24, 24, overlay ? 0x003d7f5d : 0x006b4850);
    fb_draw_text(x + 18, y + 42, overlay ? "CLI Overlay: ON" : "CLI Overlay: OFF", 0x00eaf2fb, overlay ? 0x003d7f5d : 0x006b4850);

    fb_fill_rect(x + 12, y + 62, w - 24, 24, show_desktop_mode ? 0x00355f86 : 0x003c5369);
    fb_draw_text(x + 18, y + 70, show_desktop_mode ? "Desktop Focus: ON" : "Desktop Focus: OFF", 0x00eaf2fb, show_desktop_mode ? 0x00355f86 : 0x003c5369);

    fb_fill_rect(x + 12, y + 90, w - 24, 24, launcher_open ? 0x003f5a86 : 0x002f4259);
    fb_draw_text(x + 18, y + 98, launcher_open ? "Launcher: OPEN" : "Launcher: CLOSED", 0x00eaf2fb, launcher_open ? 0x003f5a86 : 0x002f4259);

    fb_fill_rect(x + 12, y + 118, w - 24, 24, feature_hub_open ? 0x00564990 : 0x00353f62);
    fb_draw_text(x + 18, y + 126, feature_hub_open ? "Feature Center: OPEN" : "Feature Center: CLOSED", 0x00eaf2fb, feature_hub_open ? 0x00564990 : 0x00353f62);

    char sec_line[48];
    sec_line[0] = '\0';
    strncat(sec_line, "Security mode: ", sizeof(sec_line) - strlen(sec_line) - 1);
    strncat(sec_line, security_mode_name(security_mode()), sizeof(sec_line) - strlen(sec_line) - 1);
    fb_fill_rect(x + 12, y + 146, w - 24, 24, 0x00333f62);
    fb_draw_text(x + 18, y + 154, sec_line, 0x00f7dfbf, 0x00333f62);

    fb_fill_rect(
        x + 12,
        y + 174,
        w - 24,
        24,
        (security_intrusion_failsafe_active() || security_integrity_failsafe_active()) ? 0x00704b4f : 0x00325f56
    );
    fb_draw_text(
        x + 18,
        y + 182,
        (security_intrusion_failsafe_active() || security_integrity_failsafe_active()) ? "Failsafe: ACTIVE" : "Failsafe: ready",
        0x00f1f7ff,
        (security_intrusion_failsafe_active() || security_integrity_failsafe_active()) ? 0x00704b4f : 0x00325f56
    );

    fb_fill_rect(x + 12, y + 206, 120, 24, 0x004c6f96);
    fb_fill_rect(x + 136, y + 206, 120, 24, 0x006b4b52);
    fb_draw_text(x + 28, y + 214, "Hardened", 0x00eaf2fb, 0x004c6f96);
    fb_draw_text(x + 156, y + 214, "Lockdown", 0x00eaf2fb, 0x006b4b52);

    fb_fill_rect(x + 12, y + 236, 120, 24, 0x00305f87);
    fb_fill_rect(x + 136, y + 236, 120, 24, 0x0040675d);
    fb_draw_text(x + 42, y + 244, "Verify", 0x00eaf2fb, 0x00305f87);
    fb_draw_text(x + 152, y + 244, "Reset Failsafe", 0x00eaf2fb, 0x0040675d);

    fb_fill_rect(x + 12, y + 266, 120, 24, 0x003c7a56);
    fb_fill_rect(x + 136, y + 266, 120, 24, 0x006b4b52);
    fb_draw_text(x + 26, y + 274, "Enable All", 0x00eaf2fb, 0x003c7a56);
    fb_draw_text(x + 156, y + 274, "Disable All", 0x00eaf2fb, 0x006b4b52);

    fb_fill_rect(x + 12, y + 298, w - 24, 28, 0x00243043);
    fb_draw_text(x + 18, y + 308, "Launcher + Security Center are linked", 0x00bfd2e7, 0x00243043);
}

static void draw_notification_toasts(void) {
    uint64_t now = pit_ticks();
    int shown = 0;
    int max_toast = 4;
    int toast_w = 300;
    int x = (int)fb_width() - toast_w - 16;
    int y = TOP_BAR_H + 18;

    for (int i = 0; i < notify_count && shown < max_toast; i++) {
        int idx = (notify_write_idx - 1 - i + NOTIFY_MAX) % NOTIFY_MAX;
        gui_notification_t *n = &notifications[idx];
        if (n->tick == 0 || now - n->tick > 900) {
            continue;
        }
        uint32_t bg = rgb_mix(0x00192638, n->color, 72);
        fb_fill_rect(x, y + shown * 30, toast_w, 24, bg);
        fb_draw_text(x + 10, y + shown * 30 + 8, n->text, 0x00e7f1fb, bg);
        shown++;
    }
}

static void draw_notifications_panel(void) {
    if (!notifications_open) {
        return;
    }

    int w = 380;
    int h = 320;
    int x = (int)fb_width() - w - 16;
    int y = TOP_BAR_H + 14;
    fb_fill_rect(x, y, w, h, 0x00162231);
    fb_fill_rect(x, y, w, 1, 0x00e5b884);
    fb_draw_text(x + 12, y + 12, "Alerts", 0x00fff2df, 0x00162231);

    int row_y = y + 34;
    for (int i = 0; i < notify_count; i++) {
        int idx = (notify_write_idx - 1 - i + NOTIFY_MAX) % NOTIFY_MAX;
        gui_notification_t *n = &notifications[idx];
        if (n->tick == 0) {
            continue;
        }
        if (row_y + 22 > y + h - 10) {
            break;
        }
        uint32_t bg = rgb_mix(0x001b2a3e, n->color, 64);
        fb_fill_rect(x + 10, row_y, w - 20, 20, bg);
        fb_draw_text(x + 16, row_y + 7, n->text, 0x00edf5ff, bg);
        row_y += 22;
    }
}

static int window_control_at(const window_t *w, int x, int y) {
    int by = w->y + 7;
    if (point_in_rect(x, y, w->x + 8, by, 11, 11)) {
        return 1;
    }
    if (point_in_rect(x, y, w->x + 24, by, 11, 11)) {
        return 2;
    }
    if (point_in_rect(x, y, w->x + 40, by, 11, 11)) {
        return 3;
    }
    return 0;
}

static int point_in_window(const window_t *w, int x, int y) {
    return w->visible && !w->minimized && point_in_rect(x, y, w->x, w->y, w->w, w->h);
}

static int point_in_titlebar(const window_t *w, int x, int y) {
    return point_in_rect(x, y, w->x, w->y, w->w, TITLE_H);
}

static void draw_window_content(const window_t *w) {
    int tx = w->x + 10;
    int ty = w->y + TITLE_H + 10;

    if (w->kind == WINDOW_MONITOR) {
        char t0[16];
        char t1[16];
        char t2[16];
        u32_to_dec((uint32_t)(pit_ticks() / 100u), t0, sizeof(t0));
        u32_to_dec((uint32_t)window_count, t1, sizeof(t1));
        u32_to_dec((uint32_t)feature_enabled_count(), t2, sizeof(t2));

        char line0[48];
        char line1[48];
        char line2[56];

        line0[0] = '\0';
        strncat(line0, "uptime(s): ", sizeof(line0) - strlen(line0) - 1);
        strncat(line0, t0, sizeof(line0) - strlen(line0) - 1);

        line1[0] = '\0';
        strncat(line1, "windows: ", sizeof(line1) - strlen(line1) - 1);
        strncat(line1, t1, sizeof(line1) - strlen(line1) - 1);

        line2[0] = '\0';
        strncat(line2, "features enabled: ", sizeof(line2) - strlen(line2) - 1);
        strncat(line2, t2, sizeof(line2) - strlen(line2) - 1);
        strncat(line2, "/960", sizeof(line2) - strlen(line2) - 1);

        fb_draw_text(tx, ty, "Kernel monitor", 0x00dde9f5, w->color);
        fb_draw_text(tx, ty + 12, line0, 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 24, line1, 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 36, line2, 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 48, "Round-robin scheduler active", 0x00b7cce0, w->color);
        return;
    }

    if (w->kind == WINDOW_TERMINAL) {
        fb_draw_text(tx, ty, "Shell shortcuts", 0x00dde9f5, w->color);
        fb_draw_text(tx, ty + 12, "help, apps, run /bin/greeter", 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 24, "Launcher button: browse and run apps", 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 36, "Features button: manage 960 toggles", 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 48, "tcpsend / ping / netinfo", 0x00b7cce0, w->color);
        return;
    }

    if (w->kind == WINDOW_FILES) {
        refresh_file_cache(0);

        fb_draw_text(tx, ty, "Explorer", 0x00dde9f5, w->color);
        fb_draw_text(tx, ty + 12, "root:", 0x00b7cce0, w->color);
        fb_draw_text(tx + 44, ty + 12, file_cache_root, 0x00a6c0d9, w->color);
        fb_draw_text(tx, ty + 54, "/bin:", 0x00b7cce0, w->color);
        fb_draw_text(tx + 44, ty + 54, file_cache_bin, 0x00a6c0d9, w->color);
        fb_draw_text(tx, ty + 96, "assets:", 0x00b7cce0, w->color);
        fb_draw_text(tx + 52, ty + 96, file_cache_assets, 0x00a6c0d9, w->color);
        return;
    }

    if (w->kind == WINDOW_NETWORK) {
        char ip[32];
        format_ipv4(net_ip_addr(), ip, sizeof(ip));

        char line[64];
        line[0] = '\0';
        strncat(line, "ip: ", sizeof(line) - strlen(line) - 1);
        strncat(line, ip, sizeof(line) - strlen(line) - 1);

        fb_draw_text(tx, ty, "Network", 0x00dde9f5, w->color);
        fb_draw_text(tx, ty + 12, net_available() ? "adapter: up" : "adapter: down", 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 24, line, 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 36, "Commands: netinfo ping tcpsend", 0x00b7cce0, w->color);
        return;
    }

    if (w->kind == WINDOW_SECURITY) {
        char sec_features[40];
        char suspicious[40];
        char integrity[56];
        char mode[48];
        char feat_num[12];
        char susp_num[12];
        char ok_num[12];
        char fail_num[12];

        feat_num[0] = '\0';
        susp_num[0] = '\0';
        ok_num[0] = '\0';
        fail_num[0] = '\0';
        u32_to_dec((uint32_t)security_feature_enabled_count(), feat_num, sizeof(feat_num));
        u32_to_dec(security_recent_suspicious_events(), susp_num, sizeof(susp_num));
        u32_to_dec(security_integrity_checked_entries(), ok_num, sizeof(ok_num));
        u32_to_dec(security_integrity_failure_count(), fail_num, sizeof(fail_num));

        mode[0] = '\0';
        strncat(mode, "mode: ", sizeof(mode) - strlen(mode) - 1);
        strncat(mode, security_mode_name(security_mode()), sizeof(mode) - strlen(mode) - 1);

        sec_features[0] = '\0';
        strncat(sec_features, "controls: ", sizeof(sec_features) - strlen(sec_features) - 1);
        strncat(sec_features, feat_num, sizeof(sec_features) - strlen(sec_features) - 1);
        strncat(sec_features, "/200", sizeof(sec_features) - strlen(sec_features) - 1);

        suspicious[0] = '\0';
        strncat(suspicious, "suspicious events: ", sizeof(suspicious) - strlen(suspicious) - 1);
        strncat(suspicious, susp_num, sizeof(suspicious) - strlen(suspicious) - 1);

        integrity[0] = '\0';
        strncat(integrity, "integrity checked/fail: ", sizeof(integrity) - strlen(integrity) - 1);
        strncat(integrity, ok_num, sizeof(integrity) - strlen(integrity) - 1);
        strncat(integrity, "/", sizeof(integrity) - strlen(integrity) - 1);
        strncat(integrity, fail_num, sizeof(integrity) - strlen(integrity) - 1);

        fb_draw_text(tx, ty, "Security Center", 0x00f6dfbf, w->color);
        fb_draw_text(tx, ty + 12, mode, 0x00c8d9ea, w->color);
        fb_draw_text(tx, ty + 24, sec_features, 0x00c8d9ea, w->color);
        fb_draw_text(tx, ty + 36, suspicious, 0x00c8d9ea, w->color);
        fb_draw_text(tx, ty + 48, integrity, 0x00c8d9ea, w->color);
        fb_draw_text(
            tx,
            ty + 60,
            (security_intrusion_failsafe_active() || security_integrity_failsafe_active()) ? "failsafe: ACTIVE" : "failsafe: armed",
            (security_intrusion_failsafe_active() || security_integrity_failsafe_active()) ? 0x00ffbaba : 0x00bed7f0,
            w->color
        );
        fb_draw_text(tx, ty + 72, "Quick Panel: Hardened / Lockdown / Verify", 0x00bed7f0, w->color);
    }
}

static void draw_window(const window_t *w, int active) {
    if (!w->visible || w->minimized) {
        return;
    }

    uint32_t border = active ? 0x0092c6ef : 0x00577693;
    uint32_t title_top = active ? 0x004e7197 : 0x00374f6c;
    uint32_t title_bot = active ? 0x003b5b7f : 0x002d435f;

    fb_fill_rect(w->x + 3, w->y + 3, w->w + 2, w->h + 2, 0x00080f18);

    fb_fill_rect(w->x, w->y, w->w, w->h, 0x00111d2b);
    fb_fill_rect(w->x + 1, w->y + 1, w->w - 2, 8, title_top);
    fb_fill_rect(w->x + 1, w->y + 9, w->w - 2, TITLE_H - 9, title_bot);
    fb_fill_rect(w->x + 1, w->y + TITLE_H, w->w - 2, w->h - TITLE_H - 1, w->color);

    fb_fill_rect(w->x, w->y, w->w, 1, border);
    fb_fill_rect(w->x, w->y + w->h - 1, w->w, 1, 0x000e1824);
    fb_fill_rect(w->x, w->y, 1, w->h, border);
    fb_fill_rect(w->x + w->w - 1, w->y, 1, w->h, 0x000e1824);

    int by = w->y + 7;
    fb_fill_rect(w->x + 8, by, 11, 11, 0x00cb5757);
    fb_fill_rect(w->x + 24, by, 11, 11, 0x00c2a14f);
    fb_fill_rect(w->x + 40, by, 11, 11, 0x005fa46e);

    fb_draw_text(w->x + 56, w->y + 8, w->title, 0x00f4f9ff, title_top);

    draw_window_content(w);
}

static void draw_snap_preview(void) {
    if (drag_index < 0 || drag_snap_mode == SNAP_NONE) {
        return;
    }

    int dx;
    int dy;
    int dw;
    int dh;
    desktop_bounds(&dx, &dy, &dw, &dh);

    int x = dx;
    int y = dy;
    int w = dw;
    int h = dh;

    if (drag_snap_mode == SNAP_LEFT || drag_snap_mode == SNAP_RIGHT) {
        w = dw / 2;
        if (w < 200) {
            w = 200;
        }
        if (drag_snap_mode == SNAP_RIGHT) {
            x = dx + dw - w;
        }
    }

    fb_fill_rect(x, y, w, 2, 0x0079b5e8);
    fb_fill_rect(x, y + h - 2, w, 2, 0x0079b5e8);
    fb_fill_rect(x, y, 2, h, 0x0079b5e8);
    fb_fill_rect(x + w - 2, y, 2, h, 0x0079b5e8);
}

static void draw_cursor(const mouse_state_t *m, int front_only) {
    static const char cursor_shape[22][16] = {
        "X               ",
        "XX              ",
        "X.X             ",
        "X..X            ",
        "X...X           ",
        "X....X          ",
        "X.....X         ",
        "X......X        ",
        "X.......X       ",
        "X........X      ",
        "X..+++++++X     ",
        "X..+.....+X     ",
        "X..+..++++XX    ",
        "X..+..+....X    ",
        "X..+..+....X    ",
        "X..+..+....X    ",
        "X..+..+....X    ",
        "X..+..+....X    ",
        " X.+..+...X     ",
        "  XX..+..X      ",
        "    X...X       ",
        "     XXX        "
    };

    uint32_t border = 0x00050a13;
    uint32_t fill = (m->left || m->right || m->middle) ? 0x00d3eaff : 0x00ffffff;
    uint32_t edge = 0x00b4d8ff;
    uint32_t shadow = 0x000a1220;

    void (*plot)(uint32_t, uint32_t, uint32_t) = front_only ? fb_put_pixel_front : fb_put_pixel;

    for (int row = 0; row < 22; row++) {
        for (int col = 0; col < 16; col++) {
            char ch = cursor_shape[row][col];
            if (ch == '\0') {
                ch = ' ';
            }
            if (ch != ' ') {
                plot((uint32_t)(m->x + col + 1), (uint32_t)(m->y + row + 1), shadow);
            }
        }
    }

    for (int row = 0; row < 22; row++) {
        for (int col = 0; col < 16; col++) {
            char ch = cursor_shape[row][col];
            if (ch == '\0' || ch == ' ') {
                continue;
            }
            uint32_t c = fill;
            if (ch == 'X') {
                c = border;
            } else if (ch == '+') {
                c = edge;
            }
            plot((uint32_t)(m->x + col), (uint32_t)(m->y + row), c);
        }
    }
}

static void cursor_rect_from_state(const mouse_state_t *m, int *x, int *y, int *w, int *h) {
    int px = m ? m->x : 0;
    int py = m ? m->y : 0;
    int rw = 18;
    int rh = 24;
    if (x) {
        *x = px;
    }
    if (y) {
        *y = py;
    }
    if (w) {
        *w = rw;
    }
    if (h) {
        *h = rh;
    }
}

static void cursor_restore_previous(void) {
    if (!cursor_prev_valid) {
        return;
    }
    fb_present_region(cursor_prev_x, cursor_prev_y, cursor_prev_w, cursor_prev_h);
    cursor_prev_valid = 0;
}

static void cursor_draw_front(const mouse_state_t *mouse) {
    if (!mouse) {
        return;
    }
    draw_cursor(mouse, 1);
    cursor_rect_from_state(mouse, &cursor_prev_x, &cursor_prev_y, &cursor_prev_w, &cursor_prev_h);
    cursor_prev_valid = 1;
}

static void cursor_present_only(const mouse_state_t *mouse) {
    cursor_restore_previous();
    cursor_draw_front(mouse);
}

static void gui_redraw(const mouse_state_t *mouse) {
    uint32_t w = fb_width();
    uint32_t h = fb_height();

    draw_background(w, h);
    draw_top_bar((int)w);
    draw_dock((int)w, (int)h);

    for (int i = 0; i < window_count; i++) {
        draw_window(&windows[i], i == active_index);
    }

    draw_snap_preview();
    draw_start_menu();
    draw_context_menu();
    draw_quick_panel();
    draw_launcher_panel();
    draw_feature_hub_panel();
    draw_notifications_panel();
    draw_notification_toasts();

    if (overlay) {
        console_render();
    }

    fb_present();
    cursor_prev_valid = 0;
    if (mouse) {
        cursor_draw_front(mouse);
    }
}

void gui_set_console_overlay(bool enabled) {
    overlay = enabled ? 1 : 0;
    need_redraw = 1;
}

bool gui_console_overlay(void) {
    return overlay != 0;
}

void gui_init(void) {
    int dx;
    int dy;
    int dw;
    int dh;
    desktop_bounds(&dx, &dy, &dw, &dh);

    window_count = 5;

    windows[0].x = dx + 12;
    windows[0].y = dy + 12;
    windows[0].w = 330;
    windows[0].h = 220;
    windows[0].color = 0x00203244;
    windows[0].kind = WINDOW_MONITOR;
    windows[0].visible = 1;
    windows[0].minimized = 0;
    windows[0].maximized = 0;
    strcpy(windows[0].title, "System Monitor");

    windows[1].x = dx + (dw / 2) - 220;
    windows[1].y = dy + 56;
    windows[1].w = 470;
    windows[1].h = 260;
    windows[1].color = 0x0019202c;
    windows[1].kind = WINDOW_TERMINAL;
    windows[1].visible = 1;
    windows[1].minimized = 0;
    windows[1].maximized = 0;
    strcpy(windows[1].title, "Terminal");

    windows[2].x = dx + 76;
    windows[2].y = dy + dh - 232;
    windows[2].w = 420;
    windows[2].h = 220;
    windows[2].color = 0x00212731;
    windows[2].kind = WINDOW_FILES;
    windows[2].visible = 1;
    windows[2].minimized = 0;
    windows[2].maximized = 0;
    strcpy(windows[2].title, "File Explorer");

    windows[3].x = dx + dw - 312;
    windows[3].y = dy + 24;
    windows[3].w = 300;
    windows[3].h = 190;
    windows[3].color = 0x00252c3a;
    windows[3].kind = WINDOW_NETWORK;
    windows[3].visible = 1;
    windows[3].minimized = 0;
    windows[3].maximized = 0;
    strcpy(windows[3].title, "Network");

    windows[4].x = dx + dw - 356;
    windows[4].y = dy + dh - 214;
    windows[4].w = 344;
    windows[4].h = 202;
    windows[4].color = 0x00212939;
    windows[4].kind = WINDOW_SECURITY;
    windows[4].visible = 1;
    windows[4].minimized = 0;
    windows[4].maximized = 0;
    strcpy(windows[4].title, "Security");

    for (int i = 0; i < window_count; i++) {
        windows[i].prev_x = windows[i].x;
        windows[i].prev_y = windows[i].y;
        windows[i].prev_w = windows[i].w;
        windows[i].prev_h = windows[i].h;
        clamp_window_to_desktop(&windows[i]);
    }

    active_index = window_count - 1;
    drag_index = -1;
    drag_snap_mode = SNAP_NONE;

    overlay = 1;
    overlay_prev = overlay;
    start_menu_open = 0;
    context_menu_open = 0;
    context_menu_x = 0;
    context_menu_y = 0;
    show_desktop_mode = 0;
    launcher_open = 0;
    launcher_category = LAUNCHER_CAT_ALL;
    launcher_page = 0;
    launcher_selected = 0;
    launcher_count = 0;
    launcher_last_refresh_tick = 0;
    feature_hub_open = 0;
    feature_category = FEATURE_CATEGORY_ALL;
    feature_page = 0;
    feature_selected = 0;
    for (int i = 0; i < FEATURE_TOTAL; i++) {
        feature_enabled[i] = ((i % 3) == 0 || (i % 7) == 0) ? 1u : 0u;
    }
    quick_panel_open = 0;
    notifications_open = 0;
    notify_count = 0;
    notify_write_idx = 0;
    for (int i = 0; i < NOTIFY_MAX; i++) {
        notifications[i].text[0] = '\0';
        notifications[i].color = 0x002a3e5a;
        notifications[i].tick = 0;
    }
    for (int i = 0; i < MAX_WINDOWS; i++) {
        desktop_hidden[i] = 0;
    }
    file_cache_root[0] = '\0';
    file_cache_bin[0] = '\0';
    file_cache_assets[0] = '\0';
    file_cache_tick = 0;
    file_cache_valid = 0;
    refresh_file_cache(1);

    gui_notify_push("QuartzOS desktop initialized", 0x0074c2ff);
    gui_notify_push("Feature Center online (960 features)", 0x00957ff5);
    gui_notify_push("Launcher ready: click Launcher", 0x008acfa3);

    mouse_state_t mouse = mouse_get_state();
    mouse_prev_left = mouse.left ? 1 : 0;
    mouse_prev_right = mouse.right ? 1 : 0;
    mouse_prev_x = mouse.x;
    mouse_prev_y = mouse.y;
    cursor_prev_valid = 0;
    cursor_prev_x = mouse.x;
    cursor_prev_y = mouse.y;
    cursor_prev_w = 0;
    cursor_prev_h = 0;

    uint64_t now = pit_ticks();
    last_frame_tick = (now >= FRAME_TARGET_TICKS) ? (now - FRAME_TARGET_TICKS) : 0;
    last_clock_sec = now / 100;
    need_redraw = 1;
}

static void run_start_action(int action) {
    if (action == START_ACTION_MONITOR) {
        window_focus_kind(WINDOW_MONITOR);
    } else if (action == START_ACTION_TERMINAL) {
        window_focus_kind(WINDOW_TERMINAL);
    } else if (action == START_ACTION_FILES) {
        window_focus_kind(WINDOW_FILES);
    } else if (action == START_ACTION_NETWORK) {
        window_focus_kind(WINDOW_NETWORK);
    } else if (action == START_ACTION_SECURITY) {
        window_focus_kind(WINDOW_SECURITY);
    } else if (action == START_ACTION_OPEN_LAUNCHER) {
        launcher_open = !launcher_open;
        launcher_refresh_apps(1);
        quick_panel_open = 0;
        notifications_open = 0;
    } else if (action == START_ACTION_OPEN_FEATURE_HUB) {
        feature_hub_open = !feature_hub_open;
        launcher_open = 0;
        quick_panel_open = 0;
        notifications_open = 0;
    } else if (action == START_ACTION_OPEN_QUICK_PANEL) {
        quick_panel_open = !quick_panel_open;
        launcher_open = 0;
        feature_hub_open = 0;
        notifications_open = 0;
    } else if (action == START_ACTION_OVERLAY) {
        overlay = !overlay;
    } else if (action == START_ACTION_RESTORE_ALL) {
        restore_all_windows();
    } else if (action == START_ACTION_CLOSE_ALL) {
        for (int i = 0; i < window_count; i++) {
            windows[i].visible = 0;
            windows[i].minimized = 0;
            windows[i].maximized = 0;
            desktop_hidden[i] = 0;
        }
        show_desktop_mode = 0;
        active_index = -1;
    }

    need_redraw = 1;
}

void gui_tick(void) {
    mouse_state_t mouse = mouse_get_state();
    uint64_t now_ticks = pit_ticks();
    uint64_t now_secs = now_ticks / 100;

    int dirty = 0;
    int prev_left = mouse_prev_left;
    int prev_right = mouse_prev_right;
    int cursor_changed = (mouse.x != mouse_prev_x ||
                          mouse.y != mouse_prev_y ||
                          mouse.left != (prev_left != 0) ||
                          mouse.right != (prev_right != 0));

    int pressed = mouse.left && !prev_left;
    int released = !mouse.left && prev_left;
    int right_pressed = mouse.right && !prev_right;

    if (right_pressed) {
        context_menu_open = 1;
        context_menu_x = mouse.x;
        context_menu_y = mouse.y;
        context_menu_clamp_position();
        start_menu_open = 0;
        launcher_open = 0;
        feature_hub_open = 0;
        quick_panel_open = 0;
        notifications_open = 0;
        drag_index = -1;
        drag_snap_mode = SNAP_NONE;
        dirty = 1;
    }

    if (pressed) {
        int handled = 0;

        if (context_menu_open) {
            int action = context_menu_action_at(mouse.x, mouse.y);
            if (action == 0) {
                show_desktop_toggle();
                context_menu_open = 0;
                handled = 1;
                dirty = 1;
            } else if (action == 1) {
                restore_all_windows();
                context_menu_open = 0;
                handled = 1;
                dirty = 1;
            } else if (action == 2) {
                overlay = !overlay;
                context_menu_open = 0;
                handled = 1;
                dirty = 1;
            } else if (action == -1) {
                context_menu_open = 0;
                dirty = 1;
            } else if (action == -2) {
                handled = 1;
            }
        }

        if (!handled && point_in_rect(mouse.x, mouse.y, start_button_x(), start_button_y(), start_button_w(), start_button_h())) {
            start_menu_open = !start_menu_open;
            context_menu_open = 0;
            launcher_open = 0;
            feature_hub_open = 0;
            quick_panel_open = 0;
            notifications_open = 0;
            handled = 1;
            dirty = 1;
        }

        if (!handled && point_in_rect(mouse.x, mouse.y, launcher_button_x(), launcher_button_y(), launcher_button_w(), launcher_button_h())) {
            launcher_open = !launcher_open;
            feature_hub_open = 0;
            quick_panel_open = 0;
            notifications_open = 0;
            start_menu_open = 0;
            launcher_refresh_apps(1);
            handled = 1;
            dirty = 1;
        }

        if (!handled && point_in_rect(mouse.x, mouse.y, feature_button_x(), feature_button_y(), feature_button_w(), feature_button_h())) {
            feature_hub_open = !feature_hub_open;
            launcher_open = 0;
            quick_panel_open = 0;
            notifications_open = 0;
            start_menu_open = 0;
            handled = 1;
            dirty = 1;
        }

        if (!handled && point_in_rect(mouse.x, mouse.y, quick_button_x(), quick_button_y(), quick_button_w(), quick_button_h())) {
            quick_panel_open = !quick_panel_open;
            start_menu_open = 0;
            context_menu_open = 0;
            launcher_open = 0;
            feature_hub_open = 0;
            notifications_open = 0;
            handled = 1;
            dirty = 1;
        }

        if (!handled && point_in_rect(mouse.x, mouse.y, notify_button_x(), notify_button_y(), notify_button_w(), notify_button_h())) {
            notifications_open = !notifications_open;
            start_menu_open = 0;
            context_menu_open = 0;
            launcher_open = 0;
            feature_hub_open = 0;
            quick_panel_open = 0;
            handled = 1;
            dirty = 1;
        }

        if (!handled && launcher_open) {
            int x = launcher_x();
            int y = launcher_y();
            int w = launcher_w();
            int h = launcher_h();

            if (!point_in_rect(mouse.x, mouse.y, x, y, w, h)) {
                launcher_open = 0;
                dirty = 1;
                handled = 1;
            } else if (point_in_rect(mouse.x, mouse.y, x + w - 28, y + 8, 16, 16)) {
                launcher_open = 0;
                dirty = 1;
                handled = 1;
            } else {
                for (int i = 0; i < 3 && !handled; i++) {
                    int tx = x + 16 + i * 114;
                    if (point_in_rect(mouse.x, mouse.y, tx, y + 46, 104, 24)) {
                        launcher_category = i;
                        launcher_page = 0;
                        launcher_clamp_page();
                        handled = 1;
                        dirty = 1;
                    }
                }

                if (!handled && point_in_rect(mouse.x, mouse.y, x + w - 170, y + 46, 34, 24)) {
                    launcher_page--;
                    launcher_clamp_page();
                    handled = 1;
                    dirty = 1;
                }
                if (!handled && point_in_rect(mouse.x, mouse.y, x + w - 82, y + 46, 34, 24)) {
                    launcher_page++;
                    launcher_clamp_page();
                    handled = 1;
                    dirty = 1;
                }

                if (!handled) {
                    int app_idx = -1;
                    int run_button = 0;
                    if (launcher_row_hit(mouse.x, mouse.y, &app_idx, &run_button)) {
                        launcher_selected = app_idx;
                        handled = 1;
                        dirty = 1;
                        if (run_button) {
                            if (gui_launch_app(launcher_apps[app_idx])) {
                                launcher_open = 0;
                            }
                        }
                    }
                }
            }
        }

        if (!handled && feature_hub_open) {
            int x = feature_hub_x();
            int y = feature_hub_y();
            int w = feature_hub_w();
            int h = feature_hub_h();
            int side_w = 204;
            int main_x = x + side_w + 24;
            int main_w = w - side_w - 36;

            if (!point_in_rect(mouse.x, mouse.y, x, y, w, h)) {
                feature_hub_open = 0;
                handled = 1;
                dirty = 1;
            } else if (point_in_rect(mouse.x, mouse.y, x + w - 26, y + 8, 14, 16)) {
                feature_hub_open = 0;
                handled = 1;
                dirty = 1;
            } else {
                int row_y = y + 76;
                for (int i = 0; i <= FEATURE_CATEGORY_COUNT; i++) {
                    int cat = (i == 0) ? FEATURE_CATEGORY_ALL : (i - 1);
                    if (point_in_rect(mouse.x, mouse.y, x + 18, row_y, side_w - 12, 24)) {
                        feature_category = cat;
                        feature_page = 0;
                        feature_clamp_page();
                        handled = 1;
                        dirty = 1;
                        break;
                    }
                    row_y += 26;
                    if (row_y + 24 > y + h - 24) {
                        break;
                    }
                }

                int btn_y = y + 84;
                if (!handled && point_in_rect(mouse.x, mouse.y, main_x + 10, btn_y, 82, 22)) {
                    feature_set_page_state(1);
                    gui_notify_push("Feature page enabled", 0x0080d8a2);
                    handled = 1;
                    dirty = 1;
                }
                if (!handled && point_in_rect(mouse.x, mouse.y, main_x + 96, btn_y, 90, 22)) {
                    feature_set_page_state(0);
                    gui_notify_push("Feature page disabled", 0x00d18992);
                    handled = 1;
                    dirty = 1;
                }
                if (!handled && point_in_rect(mouse.x, mouse.y, main_x + 190, btn_y, 84, 22)) {
                    int total = feature_filtered_count();
                    int start = feature_page * FEATURE_ROWS_PER_PAGE;
                    for (int i = 0; i < FEATURE_ROWS_PER_PAGE; i++) {
                        int fi = start + i;
                        if (fi >= total) {
                            break;
                        }
                        int gidx = feature_global_index_from_filtered(fi);
                        feature_enabled[gidx] = feature_enabled[gidx] ? 0u : 1u;
                    }
                    gui_notify_push("Feature page toggled", 0x00999cf0);
                    handled = 1;
                    dirty = 1;
                }
                if (!handled && point_in_rect(mouse.x, mouse.y, main_x + main_w - 96, btn_y, 36, 22)) {
                    feature_page--;
                    feature_clamp_page();
                    handled = 1;
                    dirty = 1;
                }
                if (!handled && point_in_rect(mouse.x, mouse.y, main_x + main_w - 54, btn_y, 36, 22)) {
                    feature_page++;
                    feature_clamp_page();
                    handled = 1;
                    dirty = 1;
                }

                if (!handled) {
                    int total = feature_filtered_count();
                    int start = feature_page * FEATURE_ROWS_PER_PAGE;
                    int fy = y + 116;
                    for (int i = 0; i < FEATURE_ROWS_PER_PAGE; i++) {
                        int fi = start + i;
                        if (fi >= total) {
                            break;
                        }
                        int gidx = feature_global_index_from_filtered(fi);
                        if (point_in_rect(mouse.x, mouse.y, main_x + 10, fy, main_w - 20, 24)) {
                            feature_selected = gidx;
                            if (point_in_rect(mouse.x, mouse.y, main_x + main_w - 104, fy + 4, 74, 16)) {
                                feature_enabled[gidx] = feature_enabled[gidx] ? 0u : 1u;
                            }
                            handled = 1;
                            dirty = 1;
                            break;
                        }
                        fy += 26;
                    }
                }
            }
        }

        if (!handled && quick_panel_open) {
            int w = 286;
            int h = 336;
            int x = (int)fb_width() - w - 16;
            int y = TOP_BAR_H + 14;
            if (!point_in_rect(mouse.x, mouse.y, x, y, w, h)) {
                quick_panel_open = 0;
                handled = 1;
                dirty = 1;
            } else if (point_in_rect(mouse.x, mouse.y, x + 12, y + 34, w - 24, 24)) {
                overlay = !overlay;
                handled = 1;
                dirty = 1;
            } else if (point_in_rect(mouse.x, mouse.y, x + 12, y + 62, w - 24, 24)) {
                show_desktop_toggle();
                handled = 1;
                dirty = 1;
            } else if (point_in_rect(mouse.x, mouse.y, x + 12, y + 90, w - 24, 24)) {
                launcher_open = !launcher_open;
                if (launcher_open) {
                    launcher_refresh_apps(1);
                }
                handled = 1;
                dirty = 1;
            } else if (point_in_rect(mouse.x, mouse.y, x + 12, y + 118, w - 24, 24)) {
                feature_hub_open = !feature_hub_open;
                handled = 1;
                dirty = 1;
            } else if (point_in_rect(mouse.x, mouse.y, x + 12, y + 206, 120, 24)) {
                if (security_set_mode(SECURITY_MODE_HARDENED)) {
                    (void)security_save();
                    gui_notify_push("Security mode: hardened", 0x00a9d7ff);
                } else {
                    gui_notify_push("Security mode change blocked", 0x00d18992);
                }
                handled = 1;
                dirty = 1;
            } else if (point_in_rect(mouse.x, mouse.y, x + 136, y + 206, 120, 24)) {
                if (security_set_mode(SECURITY_MODE_LOCKDOWN)) {
                    (void)security_save();
                    gui_notify_push("Security mode: lockdown", 0x00d8a8a8);
                } else {
                    gui_notify_push("Lockdown mode blocked", 0x00d18992);
                }
                handled = 1;
                dirty = 1;
            } else if (point_in_rect(mouse.x, mouse.y, x + 12, y + 236, 120, 24)) {
                char report[96];
                if (security_verify_integrity_now(report, sizeof(report))) {
                    gui_notify_push("Integrity verification passed", 0x0080d8a2);
                } else {
                    gui_notify_push(report[0] ? report : "Integrity verification failed", 0x00d18992);
                }
                handled = 1;
                dirty = 1;
            } else if (point_in_rect(mouse.x, mouse.y, x + 136, y + 236, 120, 24)) {
                security_reset_failsafes(true, true);
                (void)security_save();
                gui_notify_push("Failsafes reset", 0x00a9d7ff);
                handled = 1;
                dirty = 1;
            } else if (point_in_rect(mouse.x, mouse.y, x + 12, y + 266, 120, 24)) {
                for (int i = 0; i < FEATURE_TOTAL; i++) {
                    feature_enabled[i] = 1;
                }
                gui_notify_push("All features enabled", 0x0080d8a2);
                handled = 1;
                dirty = 1;
            } else if (point_in_rect(mouse.x, mouse.y, x + 136, y + 266, 120, 24)) {
                for (int i = 0; i < FEATURE_TOTAL; i++) {
                    feature_enabled[i] = 0;
                }
                gui_notify_push("All features disabled", 0x00d18992);
                handled = 1;
                dirty = 1;
            }
        }

        if (!handled && notifications_open) {
            int w = 380;
            int h = 320;
            int x = (int)fb_width() - w - 16;
            int y = TOP_BAR_H + 14;
            if (!point_in_rect(mouse.x, mouse.y, x, y, w, h)) {
                notifications_open = 0;
                handled = 1;
                dirty = 1;
            }
        }

        if (!handled && start_menu_open) {
            int action = start_menu_action_at(mouse.x, mouse.y);
            if (action >= 0) {
                run_start_action(action);
                start_menu_open = 0;
                handled = 1;
                dirty = 1;
            } else if (action == -2) {
                handled = 1;
            } else {
                start_menu_open = 0;
                dirty = 1;
            }
        }

        if (!handled) {
            int dock_icon = dock_icon_at(mouse.x, mouse.y);
            if (dock_icon == MAX_WINDOWS) {
                launcher_open = !launcher_open;
                if (launcher_open) {
                    launcher_refresh_apps(1);
                }
                feature_hub_open = 0;
                quick_panel_open = 0;
                notifications_open = 0;
                context_menu_open = 0;
                start_menu_open = 0;
                handled = 1;
                dirty = 1;
            } else if (dock_icon >= 0 && dock_icon < MAX_WINDOWS) {
                int idx = find_window_by_kind((window_kind_t)dock_icon);
                if (idx >= 0 && idx == active_index && windows[idx].visible && !windows[idx].minimized) {
                    window_minimize_index(idx);
                } else {
                    window_focus_kind((window_kind_t)dock_icon);
                }
                start_menu_open = 0;
                context_menu_open = 0;
                handled = 1;
                dirty = 1;
            }
        }

        if (!handled) {
            for (int i = window_count - 1; i >= 0; i--) {
                if (!point_in_window(&windows[i], mouse.x, mouse.y)) {
                    continue;
                }

                int idx = window_raise(i);
                active_index = idx;
                start_menu_open = 0;
                context_menu_open = 0;
                dirty = 1;
                handled = 1;

                int ctl = window_control_at(&windows[idx], mouse.x, mouse.y);
                if (ctl == 1) {
                    window_close_index(idx);
                } else if (ctl == 2) {
                    window_minimize_index(idx);
                } else if (ctl == 3) {
                    window_maximize_toggle(&windows[idx]);
                } else if (point_in_titlebar(&windows[idx], mouse.x, mouse.y) && !windows[idx].maximized) {
                    drag_index = idx;
                    drag_dx = mouse.x - windows[idx].x;
                    drag_dy = mouse.y - windows[idx].y;
                    drag_snap_mode = SNAP_NONE;
                }
                break;
            }
        }

        if (!handled && start_menu_open) {
            start_menu_open = 0;
            dirty = 1;
        }
    }

    if (drag_index >= 0 && drag_index < window_count && mouse.left) {
        window_t *w = &windows[drag_index];

        int old_x = w->x;
        int old_y = w->y;

        w->x = mouse.x - drag_dx;
        w->y = mouse.y - drag_dy;
        clamp_window_to_desktop(w);

        drag_snap_mode = SNAP_NONE;
        int dx;
        int dy;
        int dw;
        int dh;
        desktop_bounds(&dx, &dy, &dw, &dh);
        if (mouse.y <= dy + 1) {
            drag_snap_mode = SNAP_MAX;
        } else if (mouse.x <= dx + 2) {
            drag_snap_mode = SNAP_LEFT;
        } else if (mouse.x >= dx + dw - 2) {
            drag_snap_mode = SNAP_RIGHT;
        }

        if (w->x != old_x || w->y != old_y) {
            dirty = 1;
        }
    }

    if (released) {
        if (drag_index >= 0 && drag_index < window_count) {
            if (drag_snap_mode != SNAP_NONE) {
                window_apply_snap(&windows[drag_index], drag_snap_mode);
            }
            drag_index = -1;
            drag_snap_mode = SNAP_NONE;
            dirty = 1;
        }
    }

    if (overlay != overlay_prev) {
        dirty = 1;
    }
    if (now_secs != last_clock_sec) {
        dirty = 1;
    }
    if (need_redraw) {
        dirty = 1;
    }

    uint64_t elapsed = now_ticks - last_frame_tick;
    if (dirty && elapsed >= FRAME_TARGET_TICKS) {
        gui_redraw(&mouse);
        last_frame_tick = now_ticks;
        last_clock_sec = now_secs;
        overlay_prev = overlay;
        need_redraw = 0;
    } else if (!dirty && cursor_changed) {
        if (fb_backbuffer_enabled()) {
            cursor_present_only(&mouse);
        } else {
            gui_redraw(&mouse);
            last_frame_tick = now_ticks;
            last_clock_sec = now_secs;
            overlay_prev = overlay;
            need_redraw = 0;
        }
    }

    mouse_prev_x = mouse.x;
    mouse_prev_y = mouse.y;
    mouse_prev_left = mouse.left ? 1 : 0;
    mouse_prev_right = mouse.right ? 1 : 0;
}
