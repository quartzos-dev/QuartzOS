void gui_set_console_overlay(bool enabled) {
    overlay = enabled ? 1 : 0;
    need_redraw = 1;
}

bool gui_console_overlay(void) {
    return overlay != 0;
}

static int window_resize_mode_at(const window_t *w, int x, int y) {
    if (!w || w->maximized) {
        return RESIZE_NONE;
    }

    int edge = 8;
    int on_left = point_in_rect(x, y, w->x, w->y, edge, w->h);
    int on_right = point_in_rect(x, y, w->x + w->w - edge, w->y, edge, w->h);
    int on_top = point_in_rect(x, y, w->x, w->y, w->w, edge);
    int on_bottom = point_in_rect(x, y, w->x, w->y + w->h - edge, w->w, edge);

    if (on_right && on_bottom) {
        return RESIZE_CORNER;
    }
    if (on_right) {
        return RESIZE_RIGHT;
    }
    if (on_left) {
        return RESIZE_LEFT;
    }
    if (on_bottom) {
        return RESIZE_BOTTOM;
    }
    if (on_top) {
        return RESIZE_TOP;
    }
    return RESIZE_NONE;
}

static void begin_window_resize(int idx, int mode, const mouse_state_t *mouse) {
    if (!mouse || idx < 0 || idx >= window_count || mode == RESIZE_NONE) {
        return;
    }

    resize_index = idx;
    resize_mode = mode;
    resize_origin_x = windows[idx].x;
    resize_origin_y = windows[idx].y;
    resize_origin_w = windows[idx].w;
    resize_origin_h = windows[idx].h;
    resize_origin_mouse_x = mouse->x;
    resize_origin_mouse_y = mouse->y;
    drag_index = -1;
    drag_snap_mode = SNAP_NONE;
}

static void apply_window_resize(window_t *w, const mouse_state_t *mouse) {
    if (!w || !mouse) {
        return;
    }

    int dx;
    int dy;
    int dw;
    int dh;
    desktop_bounds(&dx, &dy, &dw, &dh);

    int ddx = mouse->x - resize_origin_mouse_x;
    int ddy = mouse->y - resize_origin_mouse_y;

    int nx = resize_origin_x;
    int ny = resize_origin_y;
    int nw = resize_origin_w;
    int nh = resize_origin_h;

    if (resize_mode == RESIZE_RIGHT || resize_mode == RESIZE_CORNER) {
        nw = resize_origin_w + ddx;
    }
    if (resize_mode == RESIZE_BOTTOM || resize_mode == RESIZE_CORNER) {
        nh = resize_origin_h + ddy;
    }
    if (resize_mode == RESIZE_LEFT) {
        nx = resize_origin_x + ddx;
        nw = resize_origin_w - ddx;
    }
    if (resize_mode == RESIZE_TOP) {
        ny = resize_origin_y + ddy;
        nh = resize_origin_h - ddy;
    }

    if (nw < 160) {
        if (resize_mode == RESIZE_LEFT) {
            nx -= (160 - nw);
        }
        nw = 160;
    }
    if (nh < 120) {
        if (resize_mode == RESIZE_TOP) {
            ny -= (120 - nh);
        }
        nh = 120;
    }

    if (nx < dx) {
        if (resize_mode == RESIZE_LEFT) {
            nw -= (dx - nx);
        }
        nx = dx;
    }
    if (ny < dy) {
        if (resize_mode == RESIZE_TOP) {
            nh -= (dy - ny);
        }
        ny = dy;
    }
    if (nx + nw > dx + dw) {
        nw = dx + dw - nx;
    }
    if (ny + nh > dy + dh) {
        nh = dy + dh - ny;
    }
    if (nw < 160) {
        nw = 160;
    }
    if (nh < 120) {
        nh = 120;
    }

    w->x = nx;
    w->y = ny;
    w->w = nw;
    w->h = nh;
    w->maximized = 0;
    clamp_window_to_desktop(w);
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
    windows[0].workspace = 0;
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
    windows[1].workspace = 0;
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
    windows[2].workspace = 0;
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
    windows[3].workspace = 1;
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
    windows[4].workspace = 2;
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

    current_workspace = 0;
    active_index = top_visible_window();
    drag_index = -1;
    drag_snap_mode = SNAP_NONE;
    resize_index = -1;
    resize_mode = RESIZE_NONE;
    last_title_click_tick = 0;
    last_title_click_index = -1;

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
    gui_notify_push("Workspace controls: WS1..WS4 in top bar", 0x0099b8ff);

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
        resize_index = -1;
        resize_mode = RESIZE_NONE;
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

        if (!handled) {
            int ws = workspace_chip_at(mouse.x, mouse.y);
            if (ws >= 0) {
                workspace_switch(ws);
                start_menu_open = 0;
                context_menu_open = 0;
                launcher_open = 0;
                feature_hub_open = 0;
                quick_panel_open = 0;
                notifications_open = 0;
                handled = 1;
                dirty = 1;
            }
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
            int h = 366;
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
            } else if (point_in_rect(mouse.x, mouse.y, x + 12, y + 298, 120, 24)) {
                workspace_switch((current_workspace + 1) % MAX_WORKSPACES);
                handled = 1;
                dirty = 1;
            } else if (point_in_rect(mouse.x, mouse.y, x + 136, y + 298, 120, 24)) {
                if (active_index >= 0 && active_index < window_count) {
                    int next_ws = (windows[active_index].workspace + 1) % MAX_WORKSPACES;
                    window_move_to_workspace(active_index, next_ws);
                    workspace_switch(next_ws);
                    gui_notify_push("Active window moved to next workspace", 0x0099b8ff);
                } else {
                    gui_notify_push("No active window to move", 0x00d18992);
                }
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
                int resize_hit = window_resize_mode_at(&windows[idx], mouse.x, mouse.y);
                if (ctl == 1) {
                    window_close_index(idx);
                    last_title_click_index = -1;
                } else if (ctl == 2) {
                    window_minimize_index(idx);
                    last_title_click_index = -1;
                } else if (ctl == 3) {
                    window_maximize_toggle(&windows[idx]);
                    last_title_click_index = -1;
                } else if (resize_hit != RESIZE_NONE) {
                    begin_window_resize(idx, resize_hit, &mouse);
                    last_title_click_index = -1;
                } else if (point_in_titlebar(&windows[idx], mouse.x, mouse.y) && !windows[idx].maximized) {
                    if (last_title_click_index == idx && (now_ticks - last_title_click_tick) <= 35) {
                        window_maximize_toggle(&windows[idx]);
                        last_title_click_index = -1;
                        last_title_click_tick = 0;
                    } else {
                        drag_index = idx;
                        drag_dx = mouse.x - windows[idx].x;
                        drag_dy = mouse.y - windows[idx].y;
                        drag_snap_mode = SNAP_NONE;
                        resize_index = -1;
                        resize_mode = RESIZE_NONE;
                        last_title_click_index = idx;
                        last_title_click_tick = now_ticks;
                    }
                } else {
                    last_title_click_index = -1;
                }
                break;
            }
        }

        if (!handled && start_menu_open) {
            start_menu_open = 0;
            dirty = 1;
        }
    }

    if (resize_index >= 0 && resize_index < window_count && mouse.left) {
        window_t *w = &windows[resize_index];
        int old_x = w->x;
        int old_y = w->y;
        int old_w = w->w;
        int old_h = w->h;

        apply_window_resize(w, &mouse);

        if (w->x != old_x || w->y != old_y || w->w != old_w || w->h != old_h) {
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
        if (resize_index >= 0 && resize_index < window_count) {
            resize_index = -1;
            resize_mode = RESIZE_NONE;
            dirty = 1;
        }
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
