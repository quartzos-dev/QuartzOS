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
static int workspace_chip_x(int workspace);
static int workspace_chip_y(void);
static int workspace_chip_w(void);
static int workspace_chip_h(void);
static int workspace_chip_at(int mx, int my);

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
    draw_quartz_logo_mark(sx + 12, sy + start_button_h() / 2, 8, sbg, start_menu_open);
    fb_draw_text(sx + 24, sy + 7, "QuartzOS", 0x00f8fcff, sbg);

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

    int ws_y = workspace_chip_y();
    for (int ws = 0; ws < MAX_WORKSPACES; ws++) {
        int wx = workspace_chip_x(ws);
        uint32_t wbg = (ws == current_workspace) ? 0x004a78a8 : 0x00263d57;
        fb_fill_rect(wx, ws_y, workspace_chip_w(), workspace_chip_h(), wbg);
        char label[5];
        label[0] = 'W';
        label[1] = 'S';
        label[2] = (char)('1' + ws);
        label[3] = '\0';
        fb_draw_text(wx + 7, ws_y + 7, label, 0x00dff0ff, wbg);
        if (workspace_visible_count(ws) > 0) {
            fb_fill_rect(wx + workspace_chip_w() - 7, ws_y + workspace_chip_h() - 5, 3, 3, 0x00f2fbff);
        }
    }

    const char *active = "Desktop";
    if (active_index >= 0 &&
        active_index < window_count &&
        windows[active_index].visible &&
        !windows[active_index].minimized &&
        windows[active_index].workspace == current_workspace) {
        active = windows[active_index].title;
    }
    int active_x = workspace_chip_x(MAX_WORKSPACES - 1) + workspace_chip_w() + 10;
    fb_draw_text(active_x, 9, active, 0x00cfe4f8, bg);

    int info_x = w - 448;
    int chip_x = active_x + 96;
    for (int i = 0; i < window_count; i++) {
        if (!windows[i].visible || windows[i].workspace != current_workspace) {
            continue;
        }
        uint32_t c = (i == active_index && !windows[i].minimized) ? 0x004a78a8 : 0x00273f58;
        int chip_w = 74;
        if (chip_x + chip_w > info_x - 8) {
            break;
        }
        fb_fill_rect(chip_x, 5, chip_w, 18, c);
        fb_draw_text(chip_x + 6, 10, windows[i].title, 0x00d9ebfc, c);
        chip_x += chip_w + 6;
    }

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
    return 104;
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

static int workspace_chip_x(int workspace) {
    return notify_button_x() + notify_button_w() + 12 + workspace * (workspace_chip_w() + 4);
}

static int workspace_chip_y(void) {
    return 4;
}

static int workspace_chip_w(void) {
    return 34;
}

static int workspace_chip_h(void) {
    return TOP_BAR_H - 9;
}

static int workspace_chip_at(int mx, int my) {
    for (int ws = 0; ws < MAX_WORKSPACES; ws++) {
        if (point_in_rect(mx, my, workspace_chip_x(ws), workspace_chip_y(), workspace_chip_w(), workspace_chip_h())) {
            return ws;
        }
    }
    return -1;
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
    int h = 366;
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

    fb_fill_rect(x + 12, y + 298, 120, 24, 0x00345d84);
    fb_fill_rect(x + 136, y + 298, 120, 24, 0x00426076);
    fb_draw_text(x + 32, y + 306, "Next WS", 0x00eaf2fb, 0x00345d84);
    fb_draw_text(x + 144, y + 306, "Move Active", 0x00eaf2fb, 0x00426076);

    fb_fill_rect(x + 12, y + 328, w - 24, 28, 0x00243043);
    fb_draw_text(x + 18, y + 338, "Launcher + Security Center are linked", 0x00bfd2e7, 0x00243043);
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
