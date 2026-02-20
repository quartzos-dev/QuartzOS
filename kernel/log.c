#include <kernel/console.h>
#include <kernel/log.h>
#include <stdarg.h>
#include <stdint.h>

static void print_unsigned(uint64_t value, uint32_t base) {
    char buf[32];
    const char *digits = "0123456789abcdef";
    int i = 0;
    if (value == 0) {
        console_putc('0');
        return;
    }
    while (value && i < (int)sizeof(buf)) {
        buf[i++] = digits[value % base];
        value /= base;
    }
    while (i--) {
        console_putc(buf[i]);
    }
}

static void print_signed(int64_t value) {
    if (value < 0) {
        console_putc('-');
        print_unsigned((uint64_t)(-value), 10);
    } else {
        print_unsigned((uint64_t)value, 10);
    }
}

void kprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    while (*fmt) {
        if (*fmt != '%') {
            console_putc(*fmt++);
            continue;
        }

        fmt++;
        switch (*fmt) {
            case '%':
                console_putc('%');
                break;
            case 'c': {
                int c = va_arg(ap, int);
                console_putc((char)c);
                break;
            }
            case 's': {
                const char *s = va_arg(ap, const char *);
                if (!s) {
                    s = "(null)";
                }
                console_write(s);
                break;
            }
            case 'd':
            case 'i': {
                int v = va_arg(ap, int);
                print_signed(v);
                break;
            }
            case 'u': {
                unsigned int v = va_arg(ap, unsigned int);
                print_unsigned(v, 10);
                break;
            }
            case 'x': {
                unsigned int v = va_arg(ap, unsigned int);
                print_unsigned(v, 16);
                break;
            }
            case 'p': {
                uint64_t v = (uint64_t)va_arg(ap, void *);
                console_write("0x");
                print_unsigned(v, 16);
                break;
            }
            default:
                console_putc('%');
                console_putc(*fmt);
                break;
        }
        fmt++;
    }

    va_end(ap);
}
