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
    return w->visible &&
           !w->minimized &&
           window_on_current_workspace(w) &&
           point_in_rect(x, y, w->x, w->y, w->w, w->h);
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
        char t3[16];
        char t4[16];
        u32_to_dec((uint32_t)(pit_ticks() / 100u), t0, sizeof(t0));
        u32_to_dec((uint32_t)window_count, t1, sizeof(t1));
        u32_to_dec((uint32_t)feature_enabled_count(), t2, sizeof(t2));
        u32_to_dec((uint32_t)(current_workspace + 1), t3, sizeof(t3));
        u32_to_dec((uint32_t)workspace_visible_count(current_workspace), t4, sizeof(t4));

        char line0[48];
        char line1[48];
        char line2[56];
        char line3[64];

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

        line3[0] = '\0';
        strncat(line3, "workspace WS", sizeof(line3) - strlen(line3) - 1);
        strncat(line3, t3, sizeof(line3) - strlen(line3) - 1);
        strncat(line3, " visible: ", sizeof(line3) - strlen(line3) - 1);
        strncat(line3, t4, sizeof(line3) - strlen(line3) - 1);

        fb_draw_text(tx, ty, "Kernel monitor", 0x00dde9f5, w->color);
        fb_draw_text(tx, ty + 12, line0, 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 24, line1, 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 36, line2, 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 48, line3, 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 60, "Round-robin scheduler active", 0x00b7cce0, w->color);
        return;
    }

    if (w->kind == WINDOW_TERMINAL) {
        fb_draw_text(tx, ty, "Shell shortcuts", 0x00dde9f5, w->color);
        fb_draw_text(tx, ty + 12, "help, apps, run /bin/greeter", 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 24, "Launcher button: browse and run apps", 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 36, "WS1..WS4 in top bar switch workspaces", 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 48, "Drag edges/corner to resize windows", 0x00b7cce0, w->color);
        fb_draw_text(tx, ty + 60, "Double-click title bar to maximize", 0x00b7cce0, w->color);
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
    if (!w->visible || w->minimized || !window_on_current_workspace(w)) {
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

    if (active && !w->maximized) {
        int gx = w->x + w->w - 12;
        int gy = w->y + w->h - 12;
        fb_fill_rect(gx, gy, 10, 10, 0x00243a57);
        fb_fill_rect(gx + 2, gy + 6, 6, 1, 0x00b9d7f4);
        fb_fill_rect(gx + 4, gy + 4, 4, 1, 0x00b9d7f4);
        fb_fill_rect(gx + 6, gy + 2, 2, 1, 0x00b9d7f4);
    }

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
    if (resize_index >= 0) {
        fill = 0x00ffe6b9;
    }
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
