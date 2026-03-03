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

static void draw_license_lock_screen(int sw, int sh) {
    (void)sw;
    (void)sh;
    int host_mode = license_vm_host_mode();

    int px = license_panel_x();
    int py = license_panel_y();
    int pw = license_panel_w();
    int ph = license_panel_h();

    fb_fill_rect(px - 2, py - 2, pw + 4, ph + 4, 0x00070d17);
    fb_fill_rect(px, py, pw, ph, 0x00101a2a);
    fb_fill_rect(px + 1, py + 1, pw - 2, 30, 0x00386bb0);
    fb_fill_rect(px + 1, py + 31, pw - 2, ph - 32, 0x00131f31);
    fb_fill_rect(px, py, pw, 1, 0x0094c9ff);
    fb_fill_rect(px, py + ph - 1, pw, 1, 0x00233854);
    fb_fill_rect(px, py, 1, ph, 0x0094c9ff);
    fb_fill_rect(px + pw - 1, py, 1, ph, 0x00233854);

    fb_draw_text(px + 16, py + 10, "QuartzOS License Activation", 0x00f4fbff, 0x00386bb0);
    fb_draw_text(px + 16, py + 44, "A verified Consumer Monthly license is required to continue.", 0x00d2e4f5, 0x00131f31);
    fb_draw_text(px + 16, py + 60, "Use keyboard typing or click the key buttons below.", 0x00bdd3e8, 0x00131f31);

    const char *lock_reason = security_lockdown_active()
        ? "Security lockdown is active. Clear failsafes in CLI if unlock is denied."
        : "Security state normal.";
    fb_draw_text(px + 16, py + 76, lock_reason, security_lockdown_active() ? 0x00f6b3b3 : 0x00a9d6b3, 0x00131f31);
    if (host_mode) {
        fb_draw_text(px + 16, py + 92, "VM mode: using host License Activation app.", 0x00b8d4ef, 0x00131f31);
        fb_draw_text(px + 16, py + 110, "A launch request is emitted to QEMU serial when lock mode starts.", 0x00aac6e1, 0x00131f31);
        fb_draw_text(px + 16, py + 128, "Use launch script with serial=file to auto-open host app on macOS.", 0x00aac6e1, 0x00131f31);

        int ay2 = license_action_row2_y();
        fb_fill_rect(license_btn_activate_x(), ay2, license_btn_activate_w(), license_button_h(), 0x003d6ea7);
        fb_draw_text(license_btn_activate_x() + 12, ay2 + 10, "Open Host License App", 0x00eef7ff, 0x003d6ea7);
    } else {
        fb_draw_text(px + 16, py + 92, license_terms_accepted() ? "Terms: accepted" : "Terms: pending", license_terms_accepted() ? 0x00a9d6b3 : 0x00f2cf8b, 0x00131f31);

        int fx = license_field_x();
        int fy = license_field_y();
        int fw = license_field_w();
        int fh = license_field_h();
        fb_fill_rect(fx, fy, fw, fh, 0x000f1928);
        fb_fill_rect(fx, fy, fw, 1, 0x0079a7d4);
        fb_fill_rect(fx, fy + fh - 1, fw, 1, 0x0023374d);
        fb_fill_rect(fx, fy, 1, fh, 0x0079a7d4);
        fb_fill_rect(fx + fw - 1, fy, 1, fh, 0x0023374d);
        if (license_lock_key_len > 0) {
            fb_draw_text(fx + 10, fy + 11, license_lock_key, 0x00e5f2ff, 0x000f1928);
        } else {
            fb_draw_text(fx + 10, fy + 11, "Enter QOS3 key...", 0x00869db5, 0x000f1928);
        }

        for (int i = 0; i < LICENSE_KEYPAD_COUNT; i++) {
            int bx = license_keypad_button_x(i);
            int by = license_keypad_button_y(i);
            fb_fill_rect(bx, by, license_keypad_cell_w(), license_keypad_cell_h(), 0x00243853);
            fb_fill_rect(bx, by, license_keypad_cell_w(), 1, 0x005784b2);
            fb_fill_rect(bx, by + license_keypad_cell_h() - 1, license_keypad_cell_w(), 1, 0x001b2e43);
            fb_fill_rect(bx, by, 1, license_keypad_cell_h(), 0x005784b2);
            fb_fill_rect(bx + license_keypad_cell_w() - 1, by, 1, license_keypad_cell_h(), 0x001b2e43);
            char label[2];
            label[0] = license_keypad_chars[i];
            label[1] = '\0';
            fb_draw_text(bx + (license_keypad_cell_w() / 2) - 4, by + 16, label, 0x00e4f3ff, 0x00243853);
        }

        int ay = license_action_row_y();
        int ay2 = license_action_row2_y();
        fb_fill_rect(license_btn_accept_x(), ay, license_btn_accept_w(), license_button_h(), 0x0037644f);
        fb_draw_text(license_btn_accept_x() + 12, ay + 10, "Accept Terms", 0x00d9f0df, 0x0037644f);

        fb_fill_rect(license_btn_reload_x(), ay, license_btn_reload_w(), license_button_h(), 0x00364f6c);
        fb_draw_text(license_btn_reload_x() + 12, ay + 10, "Reload DB", 0x00d5e8fb, 0x00364f6c);

        fb_fill_rect(license_btn_backspace_x(), ay, license_btn_backspace_w(), license_button_h(), 0x004d3e63);
        fb_draw_text(license_btn_backspace_x() + 12, ay + 10, "Backspace", 0x00e9dcf9, 0x004d3e63);

        fb_fill_rect(license_btn_clear_x(), ay, license_btn_clear_w(), license_button_h(), 0x00523f47);
        fb_draw_text(license_btn_clear_x() + 14, ay + 10, "Clear", 0x00f4d9e0, 0x00523f47);

        fb_fill_rect(license_btn_activate_x(), ay2, license_btn_activate_w(), license_button_h(), 0x003d6ea7);
        fb_draw_text(license_btn_activate_x() + 12, ay2 + 10, "Activate + Unlock", 0x00eef7ff, 0x003d6ea7);
    }

    fb_fill_rect(px + 16, py + ph - 54, pw - 32, 30, 0x00111d2c);
    fb_draw_text(px + 24, py + ph - 43, license_lock_status[0] ? license_lock_status : "Ready.", license_lock_status_color ? license_lock_status_color : 0x00b9d9f4, 0x00111d2c);
}

static void gui_redraw(const mouse_state_t *mouse) {
    uint32_t w = fb_width();
    uint32_t h = fb_height();

    draw_background(w, h);
    if (license_lock_active()) {
        draw_license_lock_screen((int)w, (int)h);
        fb_present();
        cursor_prev_valid = 0;
        if (mouse) {
            cursor_draw_front(mouse);
        }
        return;
    }

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
