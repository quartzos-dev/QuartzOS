#include <drivers/framebuffer.h>
#include <drivers/mouse.h>
#include <drivers/pit.h>
#include <filesystem/sfs.h>
#include <gui/gui.h>
#include <kernel/console.h>
#include <lib/string.h>
#include <net/net.h>

#define MAX_WINDOWS 4

#define TOP_BAR_H 30
#define LEFT_DOCK_W 64
#define LEFT_DOCK_PAD 8
#define DOCK_ICON_W 44
#define DOCK_ICON_H 54
#define DOCK_ICON_GAP 10
#define TITLE_H 24
#define FRAME_TARGET_TICKS 2

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
    WINDOW_NETWORK = 3
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

enum {
    START_ACTION_MONITOR = 0,
    START_ACTION_TERMINAL = 1,
    START_ACTION_FILES = 2,
    START_ACTION_NETWORK = 3,
    START_ACTION_OVERLAY = 4,
    START_ACTION_RESTORE_ALL = 5,
    START_ACTION_CLOSE_ALL = 6
};

static const start_item_t start_items[] = {
    {"System Monitor", START_ACTION_MONITOR},
    {"Terminal", START_ACTION_TERMINAL},
    {"File Explorer", START_ACTION_FILES},
    {"Network", START_ACTION_NETWORK},
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

static int mouse_prev_left;
static int mouse_prev_right;
static int mouse_prev_x;
static int mouse_prev_y;

static uint64_t last_frame_tick;
static uint64_t last_clock_sec;
static int need_redraw;

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
    int bottom_pad = console_panel_height_for_screen(dh) + 6;

    int left = LEFT_DOCK_W + 8;
    int top = TOP_BAR_H + 6;
    int right = dw - 6;
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
    for (uint32_t y = 0; y < h; y++) {
        uint8_t t = (uint8_t)((y * 255u) / (h ? h : 1u));
        uint32_t base = rgb_mix(0x002f69b7, 0x000e1f37, t);
        fb_fill_rect(0, (int)y, (int)w, 1, base);
    }

    int sun_x = (int)(w / 5u);
    int sun_y = TOP_BAR_H + (int)(h / 7u);
    int sun_r = (int)(h / 6u);
    for (int y = -sun_r; y <= sun_r; y++) {
        for (int x = -sun_r; x <= sun_r; x++) {
            int d2 = x * x + y * y;
            if (d2 > sun_r * sun_r) {
                continue;
            }
            if (((x + y) & 1) != 0) {
                continue;
            }
            int boost = (sun_r * sun_r - d2) / (sun_r / 2 + 1);
            uint32_t c = rgb_add(0x0058b8ff, boost / 8);
            fb_put_pixel((uint32_t)(sun_x + x), (uint32_t)(sun_y + y), c);
        }
    }

    const uint32_t ribbon_colors[5] = {0x0036c8ff, 0x00a05dff, 0x00ff7ab0, 0x00f5c95a, 0x005ad9b4};
    for (int i = 0; i < 5; i++) {
        int y0 = TOP_BAR_H + 70 + i * 92;
        int thickness = 16 + i * 2;
        for (uint32_t x = 0; x < w; x++) {
            int phase = ((int)x + i * 97) % 320;
            if (phase < 0) {
                phase += 320;
            }
            int tri = phase < 160 ? phase : (320 - phase);
            int center = y0 + (tri - 80) / 3;
            for (int t = -thickness; t <= thickness; t++) {
                int yy = center + t;
                if (yy < TOP_BAR_H + 2 || yy >= (int)h) {
                    continue;
                }
                int abs_t = t < 0 ? -t : t;
                if (abs_t > thickness) {
                    continue;
                }
                uint8_t shade = (uint8_t)(255 - (abs_t * 190) / (thickness ? thickness : 1));
                uint32_t col = rgb_scale(ribbon_colors[i], shade);
                fb_put_pixel(x, (uint32_t)yy, col);
            }
        }
    }

    for (int i = 0; i < 90; i++) {
        int bx = (i * 131) % (int)w;
        int by = TOP_BAR_H + 20 + ((i * 89) % ((int)h > TOP_BAR_H + 40 ? ((int)h - TOP_BAR_H - 40) : 1));
        int r = 2 + (i % 4);
        for (int y = -r; y <= r; y++) {
            for (int x = -r; x <= r; x++) {
                if (x * x + y * y > r * r) {
                    continue;
                }
                if (((x + y + i) & 1) == 0) {
                    fb_put_pixel((uint32_t)(bx + x), (uint32_t)(by + y), 0x00d9efff);
                }
            }
        }
    }
}

static int start_button_x(void);
static int start_button_y(void);
static int start_button_w(void);
static int start_button_h(void);

static void draw_top_bar(int w) {
    uint32_t bg = 0x001f334a;
    fb_fill_rect(0, 0, w, TOP_BAR_H, bg);
    fb_fill_rect(0, TOP_BAR_H - 1, w, 1, 0x006184a8);

    int sx = start_button_x();
    int sy = start_button_y();
    uint32_t sbg = start_menu_open ? 0x00425f7d : 0x00334c67;
    fb_fill_rect(sx, sy, start_button_w(), start_button_h(), sbg);
    fb_fill_rect(sx, sy, start_button_w(), 1, 0x00d0e4f7);
    fb_draw_text(sx + 10, sy + 8, "Activities", 0x00f8fcff, sbg);

    const char *active = "Desktop";
    if (active_index >= 0 && active_index < window_count && windows[active_index].visible && !windows[active_index].minimized) {
        active = windows[active_index].title;
    }
    fb_draw_text(sx + start_button_w() + 14, 10, active, 0x00c8dcef, bg);

    int info_x = w - 250;
    if (info_x < sx + start_button_w() + 120) {
        info_x = sx + start_button_w() + 120;
    }
    fb_draw_text(info_x, 10, net_available() ? "Network up" : "Network down", 0x00bdd3e7, bg);
    fb_draw_text(w - 136, 10, overlay ? "CLI on" : "CLI off", 0x00bdd3e7, bg);
    draw_clock(w - 72, 10, bg);
}

static int dock_x(void) {
    return LEFT_DOCK_PAD;
}

static int dock_y(void) {
    return TOP_BAR_H + 12;
}

static int dock_w(void) {
    return LEFT_DOCK_W - 14;
}

static int dock_h(void) {
    int h = (int)fb_height() - dock_y() - 8;
    if (h < 160) {
        h = 160;
    }
    return h;
}

static int start_button_x(void) {
    return 8;
}

static int start_button_y(void) {
    return 4;
}

static int start_button_w(void) {
    return 92;
}

static int start_button_h(void) {
    return TOP_BAR_H - 8;
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
        uint32_t c = rgb_mix(0x0025476d, 0x0010192b, t);
        fb_fill_rect(x, y + yy, dw, 1, c);
    }
    fb_fill_rect(x, y, dw, 1, 0x0098c7f0);
    fb_fill_rect(x + dw - 1, y, 1, dh, 0x000c141f);
    fb_fill_rect(x, y + dh - 1, dw, 1, 0x00070d15);

    const uint32_t c0[MAX_WINDOWS] = {0x0046e1ff, 0x00606dff, 0x005edb92, 0x00fd8e4a};
    const uint32_t c1[MAX_WINDOWS] = {0x002e90ff, 0x00517df2, 0x0047b776, 0x00f55f9f};
    const uint32_t c2[MAX_WINDOWS] = {0x00235bb8, 0x003f58a8, 0x00388563, 0x008639d4};

    int ix = x + (dw - DOCK_ICON_W) / 2;
    int iy = y + 12;

    for (int i = 0; i < MAX_WINDOWS; i++) {
        if (iy + DOCK_ICON_H > y + dh - DOCK_ICON_H - 14) {
            break;
        }

        int idx = find_window_by_kind((window_kind_t)i);
        int active = idx >= 0 && idx == active_index && windows[idx].visible && !windows[idx].minimized;
        int running = idx >= 0 && windows[idx].visible && !windows[idx].minimized;

        fb_fill_rect(ix, iy, DOCK_ICON_W, DOCK_ICON_H, 0x00111f33);
        int ocx = ix + DOCK_ICON_W / 2;
        int ocy = iy + 18;
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
        } else {
            fb_fill_rect(ocx - 6, ocy + 2, 2, 2, 0x00ffffff);
            fb_fill_rect(ocx - 3, ocy, 2, 4, 0x00ffffff);
            fb_fill_rect(ocx, ocy - 2, 2, 6, 0x00ffffff);
            fb_fill_rect(ocx + 3, ocy - 4, 2, 8, 0x00ffffff);
        }

        if (running) {
            fb_fill_rect(ix + 14, iy + DOCK_ICON_H - 7, 16, 3, active ? 0x00f8fdff : 0x00bbe4ff);
        }

        iy += DOCK_ICON_H + DOCK_ICON_GAP;
    }

    int apps_y = y + dh - DOCK_ICON_H - 10;
    fb_fill_rect(ix, apps_y, DOCK_ICON_W, DOCK_ICON_H, 0x00111f33);
    draw_aero_orb_icon(
        ix + DOCK_ICON_W / 2,
        apps_y + 18,
        14,
        start_menu_open ? 0x00f5bf56 : 0x005ad8ff,
        start_menu_open ? 0x00e4942f : 0x0035a6ff,
        start_menu_open ? 0x009a4d1f : 0x00235eb5,
        start_menu_open
    );
    fb_fill_rect(ix + DOCK_ICON_W / 2 - 1, apps_y + 12, 2, 12, 0x00ffffff);
    fb_fill_rect(ix + DOCK_ICON_W / 2 - 6, apps_y + 17, 12, 2, 0x00ffffff);

    if (start_menu_open) {
        fb_fill_rect(ix + 13, apps_y + DOCK_ICON_H + 2, DOCK_ICON_W - 26, 2, 0x00bfe7ff);
    }
}

static int dock_icon_at(int mx, int my) {
    int x = dock_x();
    int y = dock_y();
    int dw = dock_w();
    int dh = dock_h();
    int ix = x + (dw - DOCK_ICON_W) / 2;
    int iy = y + 12;

    for (int i = 0; i < MAX_WINDOWS; i++) {
        if (iy + DOCK_ICON_H > y + dh - DOCK_ICON_H - 14) {
            break;
        }
        if (point_in_rect(mx, my, ix, iy, DOCK_ICON_W, DOCK_ICON_H)) {
            return i;
        }
        iy += DOCK_ICON_H + DOCK_ICON_GAP;
    }

    int apps_y = y + dh - DOCK_ICON_H - 10;
    if (point_in_rect(mx, my, ix, apps_y, DOCK_ICON_W, DOCK_ICON_H)) {
        return MAX_WINDOWS;
    }

    return -1;
}

static int start_menu_x(void) {
    return LEFT_DOCK_W + 12;
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
        u32_to_dec((uint32_t)(pit_ticks() / 100u), t0, sizeof(t0));
        u32_to_dec((uint32_t)window_count, t1, sizeof(t1));

        char line0[48];
        char line1[48];

        line0[0] = '\0';
        strncat(line0, "uptime(s): ", sizeof(line0) - strlen(line0) - 1);
        strncat(line0, t0, sizeof(line0) - strlen(line0) - 1);

        line1[0] = '\0';
        strncat(line1, "windows: ", sizeof(line1) - strlen(line1) - 1);
        strncat(line1, t1, sizeof(line1) - strlen(line1) - 1);

        fb_draw_text(tx, ty, "Kernel monitor", 0x00dde9f5, w->color);
        fb_draw_text(tx, ty + 12, line0, 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 24, line1, 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 36, "Round-robin scheduler active", 0x00b7cce0, w->color);
        return;
    }

    if (w->kind == WINDOW_TERMINAL) {
        fb_draw_text(tx, ty, "Shell shortcuts", 0x00dde9f5, w->color);
        fb_draw_text(tx, ty + 12, "help, apps, run /bin/greeter", 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 24, "gui toggles CLI overlay", 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 36, "tcpsend / ping / netinfo", 0x00b7cce0, w->color);
        return;
    }

    if (w->kind == WINDOW_FILES) {
        char root[160];
        char bin[160];
        char assets[180];
        root[0] = '\0';
        bin[0] = '\0';
        assets[0] = '\0';

        if (sfs_list("/", root, sizeof(root)) < 0) {
            strcpy(root, "<unavailable>\n");
        }
        if (sfs_list("/bin", bin, sizeof(bin)) < 0) {
            strcpy(bin, "<unavailable>\n");
        }
        if (sfs_list("/assets/gui/icons/apps", assets, sizeof(assets)) < 0) {
            strcpy(assets, "<unavailable>\n");
        }

        fb_draw_text(tx, ty, "Explorer", 0x00dde9f5, w->color);
        fb_draw_text(tx, ty + 12, "root:", 0x00b7cce0, w->color);
        fb_draw_text(tx + 44, ty + 12, root, 0x00a6c0d9, w->color);
        fb_draw_text(tx, ty + 54, "/bin:", 0x00b7cce0, w->color);
        fb_draw_text(tx + 44, ty + 54, bin, 0x00a6c0d9, w->color);
        fb_draw_text(tx, ty + 96, "assets:", 0x00b7cce0, w->color);
        fb_draw_text(tx + 52, ty + 96, assets, 0x00a6c0d9, w->color);
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
    }
}

static void draw_window(const window_t *w, int active) {
    if (!w->visible || w->minimized) {
        return;
    }

    uint32_t border = active ? 0x007eb4e5 : 0x00485f79;
    uint32_t title_top = active ? 0x0039526e : 0x0027394b;
    uint32_t title_bot = active ? 0x00314963 : 0x00233141;

    fb_fill_rect(w->x + 4, w->y + 4, w->w, w->h, 0x00070d15);

    fb_fill_rect(w->x, w->y, w->w, w->h, 0x000f1822);
    fb_fill_rect(w->x + 1, w->y + 1, w->w - 2, 10, title_top);
    fb_fill_rect(w->x + 1, w->y + 11, w->w - 2, TITLE_H - 11, title_bot);
    fb_fill_rect(w->x + 1, w->y + TITLE_H, w->w - 2, w->h - TITLE_H - 1, w->color);

    fb_fill_rect(w->x, w->y, w->w, 1, border);
    fb_fill_rect(w->x, w->y + w->h - 1, w->w, 1, 0x000f1722);
    fb_fill_rect(w->x, w->y, 1, w->h, border);
    fb_fill_rect(w->x + w->w - 1, w->y, 1, w->h, 0x000f1722);

    int by = w->y + 7;
    fb_fill_rect(w->x + 8, by, 11, 11, 0x00cb5757);
    fb_fill_rect(w->x + 24, by, 11, 11, 0x00c2a14f);
    fb_fill_rect(w->x + 40, by, 11, 11, 0x005fa46e);

    fb_draw_text(w->x + 56, w->y + 8, w->title, 0x00f2f8ff, title_top);

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

static void draw_cursor(const mouse_state_t *m) {
    static const char cursor_shape[24][17] = {
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
        "X.........X     ",
        "X......XXXXX    ",
        "X...X..X        ",
        "X..X X..X       ",
        "X.X  X..X       ",
        "XX    X..X      ",
        "X      X..X     ",
        "       X..X     ",
        "        X..X    ",
        "         X..X   ",
        "          X..X  ",
        "           X..X ",
        "            X..X",
        "             XX "
    };

    uint32_t border = 0x00040a12;
    uint32_t fill = (m->left || m->right || m->middle) ? 0x00c8e2ff : 0x00f7fbff;
    uint32_t shadow = 0x00090f17;

    for (int row = 0; row < 24; row++) {
        for (int col = 0; col < 16; col++) {
            char ch = cursor_shape[row][col];
            if (ch == '\0') {
                ch = ' ';
            }
            if (ch != ' ') {
                fb_put_pixel((uint32_t)(m->x + col + 1), (uint32_t)(m->y + row + 1), shadow);
            }
        }
    }

    for (int row = 0; row < 24; row++) {
        for (int col = 0; col < 16; col++) {
            char ch = cursor_shape[row][col];
            if (ch == '\0' || ch == ' ') {
                continue;
            }
            uint32_t c = (ch == 'X') ? border : fill;
            fb_put_pixel((uint32_t)(m->x + col), (uint32_t)(m->y + row), c);
        }
    }
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

    if (overlay) {
        console_render();
    }

    if (mouse) {
        draw_cursor(mouse);
    }
    fb_present();
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

    window_count = 4;

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
    for (int i = 0; i < MAX_WINDOWS; i++) {
        desktop_hidden[i] = 0;
    }

    mouse_state_t mouse = mouse_get_state();
    mouse_prev_left = mouse.left ? 1 : 0;
    mouse_prev_right = mouse.right ? 1 : 0;
    mouse_prev_x = mouse.x;
    mouse_prev_y = mouse.y;

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

    int pressed = mouse.left && !prev_left;
    int released = !mouse.left && prev_left;
    int right_pressed = mouse.right && !prev_right;

    if (right_pressed) {
        context_menu_open = 1;
        context_menu_x = mouse.x;
        context_menu_y = mouse.y;
        context_menu_clamp_position();
        start_menu_open = 0;
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
            handled = 1;
            dirty = 1;
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
                start_menu_open = !start_menu_open;
                context_menu_open = 0;
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

    if (mouse.x != mouse_prev_x || mouse.y != mouse_prev_y || mouse.left != prev_left || mouse.right != prev_right) {
        dirty = 1;
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
    }

    mouse_prev_x = mouse.x;
    mouse_prev_y = mouse.y;
    mouse_prev_left = mouse.left ? 1 : 0;
    mouse_prev_right = mouse.right ? 1 : 0;
}
