#include <drivers/framebuffer.h>
#include <drivers/serial.h>
#include <kernel/console.h>
#include <kernel/trace.h>
#include <lib/string.h>

#define CONSOLE_MAX_ROWS 256
#define CONSOLE_MAX_COLS 256

static char console_buffer[CONSOLE_MAX_ROWS][CONSOLE_MAX_COLS];
static size_t cur_row;
static size_t cur_col;
static char prompt[64] = "/";

static void scroll_if_needed(void) {
    if (cur_row < CONSOLE_MAX_ROWS) {
        return;
    }
    for (size_t r = 1; r < CONSOLE_MAX_ROWS; r++) {
        memcpy(console_buffer[r - 1], console_buffer[r], CONSOLE_MAX_COLS);
    }
    memset(console_buffer[CONSOLE_MAX_ROWS - 1], 0, CONSOLE_MAX_COLS);
    cur_row = CONSOLE_MAX_ROWS - 1;
}

void console_init(void) {
    memset(console_buffer, 0, sizeof(console_buffer));
    cur_row = 0;
    cur_col = 0;
}

void console_clear(void) {
    memset(console_buffer, 0, sizeof(console_buffer));
    cur_row = 0;
    cur_col = 0;
}

void console_set_prompt(const char *cwd) {
    strncpy(prompt, cwd, sizeof(prompt) - 1);
    prompt[sizeof(prompt) - 1] = '\0';
}

void console_putc(char c) {
    if (c == '\r') {
        return;
    }
    if (c == '\n') {
        trace_capture_char(c);
        cur_row++;
        cur_col = 0;
        scroll_if_needed();
        serial_putc('\r');
        serial_putc('\n');
        return;
    }
    if (c == '\b') {
        trace_capture_char(c);
        if (cur_col > 0) {
            cur_col--;
            console_buffer[cur_row][cur_col] = '\0';
        }
        return;
    }
    if (cur_col >= CONSOLE_MAX_COLS - 1) {
        cur_row++;
        cur_col = 0;
        scroll_if_needed();
    }
    trace_capture_char(c);
    console_buffer[cur_row][cur_col++] = c;
    serial_putc(c);
}

void console_write(const char *str) {
    while (*str) {
        console_putc(*str++);
    }
}

void console_write_len(const char *str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        console_putc(str[i]);
    }
}

void console_render(void) {
    int w = (int)fb_width();
    int h = (int)fb_height();
    int panel_h = h / 4;
    if (panel_h < 140) {
        panel_h = 140;
    } else if (panel_h > 220) {
        panel_h = 220;
    }
    int y0 = h - panel_h;

    fb_fill_rect(0, y0, w, panel_h, 0x00131a1f);
    fb_fill_rect(0, y0, w, 1, 0x00405868);

    int rows_visible = (panel_h - 18) / 9;
    if (rows_visible < 1) {
        rows_visible = 1;
    }
    int first = 0;
    if ((int)cur_row + 1 > rows_visible) {
        first = (int)cur_row + 1 - rows_visible;
    }

    char prompt_line[96];
    prompt_line[0] = '\0';
    strcpy(prompt_line, "shell:");
    strncat(prompt_line, prompt, sizeof(prompt_line) - strlen(prompt_line) - 1);
    strncat(prompt_line, "$", sizeof(prompt_line) - strlen(prompt_line) - 1);
    fb_draw_text(8, y0 + 4, prompt_line, 0x00d7e3ee, 0x00131a1f);

    int draw_y = y0 + 14;
    for (int r = 0; r < rows_visible; r++) {
        int idx = first + r;
        if (idx >= CONSOLE_MAX_ROWS) {
            break;
        }
        fb_draw_text(8, draw_y, console_buffer[idx], 0x00d7e3ee, 0x00131a1f);
        draw_y += 9;
    }
}
