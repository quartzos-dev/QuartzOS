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

static int window_on_workspace(const window_t *w, int workspace) {
    if (!w) {
        return 0;
    }
    return w->workspace == workspace;
}

static int window_on_current_workspace(const window_t *w) {
    return window_on_workspace(w, current_workspace);
}

static int workspace_visible_count(int workspace) {
    int count = 0;
    for (int i = 0; i < window_count; i++) {
        if (windows[i].workspace == workspace && windows[i].visible && !windows[i].minimized) {
            count++;
        }
    }
    return count;
}

static int find_window_by_kind(window_kind_t kind) {
    for (int i = 0; i < window_count; i++) {
        if (windows[i].kind == kind && windows[i].workspace == current_workspace) {
            return i;
        }
    }
    for (int i = 0; i < window_count; i++) {
        if (windows[i].kind == kind) {
            return i;
        }
    }
    return -1;
}

static int top_visible_window(void) {
    for (int i = window_count - 1; i >= 0; i--) {
        if (windows[i].visible && !windows[i].minimized && windows[i].workspace == current_workspace) {
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

    if (resize_index == idx) {
        resize_index = window_count - 1;
    } else if (resize_index > idx) {
        resize_index--;
    }

    return window_count - 1;
}

static void workspace_switch(int workspace) {
    if (workspace < 0 || workspace >= MAX_WORKSPACES || workspace == current_workspace) {
        return;
    }

    if (show_desktop_mode) {
        show_desktop_mode = 0;
        for (int i = 0; i < window_count; i++) {
            if (desktop_hidden[i] && windows[i].visible) {
                windows[i].minimized = 0;
            }
            desktop_hidden[i] = 0;
        }
    }

    current_workspace = workspace;
    active_index = top_visible_window();
    drag_index = -1;
    drag_snap_mode = SNAP_NONE;
    resize_index = -1;
    resize_mode = RESIZE_NONE;
    need_redraw = 1;
}

static void window_move_to_workspace(int idx, int workspace) {
    if (idx < 0 || idx >= window_count) {
        return;
    }
    if (workspace < 0 || workspace >= MAX_WORKSPACES) {
        return;
    }
    windows[idx].workspace = workspace;
    windows[idx].minimized = 0;
    windows[idx].visible = 1;
    if (workspace != current_workspace && active_index == idx) {
        active_index = top_visible_window();
    }
}

static void window_focus_index(int idx) {
    if (idx < 0 || idx >= window_count) {
        return;
    }

    if (windows[idx].workspace != current_workspace) {
        workspace_switch(windows[idx].workspace);
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
            if (!window_on_current_workspace(&windows[i])) {
                desktop_hidden[i] = 0;
                continue;
            }
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
        if (!window_on_current_workspace(&windows[i])) {
            desktop_hidden[i] = 0;
            continue;
        }
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
