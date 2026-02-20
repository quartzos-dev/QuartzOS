#include <arch/x86_64/io.h>
#include <drivers/mouse.h>

static mouse_state_t g_mouse;
static uint8_t packet[3];
static int packet_index;
static int limit_x;
static int limit_y;
static int invert_x;
static int invert_y;
static int raw_x;
static int raw_y;
static int smooth_x_fp;
static int smooth_y_fp;

#define MOUSE_FP_SHIFT 8
#define MOUSE_FP_ONE (1 << MOUSE_FP_SHIFT)

static int abs_i(int value) {
    return value < 0 ? -value : value;
}

static int accel_delta(int delta, int mag) {
    int scale = 100;
    if (mag > 2) {
        scale += (mag - 2) * 12;
    }
    if (scale > 220) {
        scale = 220;
    }
    int out = (delta * scale) / 100;
    if (out == 0 && delta != 0) {
        out = delta > 0 ? 1 : -1;
    }
    return out;
}

static int smooth_step(int value_fp, int target_fp, int alpha) {
    int diff = target_fp - value_fp;
    int step = (diff * alpha) / 256;
    if (step == 0 && diff != 0) {
        step = diff > 0 ? 1 : -1;
    }
    return value_fp + step;
}

static int clamp_coord(int value, int limit) {
    if (value < 0) {
        return 0;
    }
    if (value >= limit) {
        return limit - 1;
    }
    return value;
}

static void mouse_wait_write(void) {
    for (int i = 0; i < 100000; i++) {
        if ((inb(0x64) & 2) == 0) {
            return;
        }
    }
}

static void mouse_wait_read(void) {
    for (int i = 0; i < 100000; i++) {
        if (inb(0x64) & 1) {
            return;
        }
    }
}

static void mouse_write(uint8_t value) {
    mouse_wait_write();
    outb(0x64, 0xD4);
    mouse_wait_write();
    outb(0x60, value);
}

static uint8_t mouse_read(void) {
    mouse_wait_read();
    return inb(0x60);
}

void mouse_init(int max_x, int max_y) {
    limit_x = max_x > 0 ? max_x : 1;
    limit_y = max_y > 0 ? max_y : 1;
    invert_x = 0;
    invert_y = 0;

    raw_x = max_x / 2;
    raw_y = max_y / 2;
    smooth_x_fp = raw_x * MOUSE_FP_ONE;
    smooth_y_fp = raw_y * MOUSE_FP_ONE;

    g_mouse.x = raw_x;
    g_mouse.y = raw_y;
    g_mouse.left = false;
    g_mouse.right = false;
    g_mouse.middle = false;

    outb(0x64, 0xA8);

    mouse_wait_write();
    outb(0x64, 0x20);
    mouse_wait_read();
    uint8_t status = inb(0x60) | 2;

    mouse_wait_write();
    outb(0x64, 0x60);
    mouse_wait_write();
    outb(0x60, status);

    mouse_write(0xF6);
    mouse_read();
    mouse_write(0xF4);
    mouse_read();

    packet_index = 0;
}

void mouse_handle_irq(void) {
    uint8_t status = inb(0x64);
    if ((status & 0x01u) == 0 || (status & 0x20u) == 0) {
        return;
    }

    uint8_t data = inb(0x60);
    if (packet_index == 0 && (data & 0x08u) == 0) {
        return;
    }
    packet[packet_index++] = data;
    if (packet_index < 3) {
        return;
    }
    packet_index = 0;

    if (packet[0] & 0xC0u) {
        return;
    }

    int8_t dx = (int8_t)packet[1];
    int8_t dy = (int8_t)packet[2];

    int mx = invert_x ? -(int)dx : (int)dx;
    int my = invert_y ? (int)dy : -(int)dy;
    int mag = abs_i(mx) + abs_i(my);

    mx = accel_delta(mx, mag);
    my = accel_delta(my, mag);

    raw_x = clamp_coord(raw_x + mx, limit_x);
    raw_y = clamp_coord(raw_y + my, limit_y);

    g_mouse.left = (packet[0] & 0x1) != 0;
    g_mouse.right = (packet[0] & 0x2) != 0;
    g_mouse.middle = (packet[0] & 0x4) != 0;
}

mouse_state_t mouse_get_state(void) {
    int alpha = (g_mouse.left || g_mouse.right || g_mouse.middle) ? 192 : 124;
    smooth_x_fp = smooth_step(smooth_x_fp, raw_x * MOUSE_FP_ONE, alpha);
    smooth_y_fp = smooth_step(smooth_y_fp, raw_y * MOUSE_FP_ONE, alpha);

    g_mouse.x = clamp_coord(smooth_x_fp >> MOUSE_FP_SHIFT, limit_x);
    g_mouse.y = clamp_coord(smooth_y_fp >> MOUSE_FP_SHIFT, limit_y);
    return g_mouse;
}

void mouse_set_invert_x(bool enabled) {
    invert_x = enabled ? 1 : 0;
}

void mouse_set_invert_y(bool enabled) {
    invert_y = enabled ? 1 : 0;
}

bool mouse_invert_x(void) {
    return invert_x != 0;
}

bool mouse_invert_y(void) {
    return invert_y != 0;
}

void mouse_center(void) {
    raw_x = limit_x / 2;
    raw_y = limit_y / 2;
    smooth_x_fp = raw_x * MOUSE_FP_ONE;
    smooth_y_fp = raw_y * MOUSE_FP_ONE;
    g_mouse.x = raw_x;
    g_mouse.y = raw_y;
}
