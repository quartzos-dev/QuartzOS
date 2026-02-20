#include <arch/x86_64/io.h>
#include <drivers/keyboard.h>

#define KBD_BUFFER_SIZE 256

static char kbd_buffer[KBD_BUFFER_SIZE];
static volatile unsigned int kbd_head;
static volatile unsigned int kbd_tail;
static int shift;

static const char scancode_map[128] = {
    0, 27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b', '\t',
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n', 0, 'a', 's',
    'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\', 'z', 'x', 'c', 'v',
    'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static const char scancode_shift_map[128] = {
    0, 27, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\b', '\t',
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n', 0, 'A', 'S',
    'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0, '|', 'Z', 'X', 'C', 'V',
    'B', 'N', 'M', '<', '>', '?', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void keyboard_init(void) {
    kbd_head = 0;
    kbd_tail = 0;
    shift = 0;
}

static void buffer_push(char c) {
    unsigned int next = (kbd_head + 1U) % KBD_BUFFER_SIZE;
    if (next == kbd_tail) {
        return;
    }
    kbd_buffer[kbd_head] = c;
    kbd_head = next;
}

void keyboard_handle_irq(void) {
    uint8_t sc = inb(0x60);

    if (sc == 0x2A || sc == 0x36) {
        shift = 1;
        return;
    }
    if (sc == 0xAA || sc == 0xB6) {
        shift = 0;
        return;
    }
    if (sc & 0x80) {
        return;
    }

    char c = shift ? scancode_shift_map[sc] : scancode_map[sc];
    if (c) {
        buffer_push(c);
    }
}

bool keyboard_read_char(char *out) {
    if (kbd_head == kbd_tail) {
        return false;
    }
    *out = kbd_buffer[kbd_tail];
    kbd_tail = (kbd_tail + 1U) % KBD_BUFFER_SIZE;
    return true;
}
