#ifndef KERNEL_CONSOLE_H
#define KERNEL_CONSOLE_H

#include <stddef.h>

void console_init(void);
void console_clear(void);
void console_putc(char c);
void console_write(const char *str);
void console_write_len(const char *str, size_t len);
void console_set_prompt(const char *cwd);
void console_render(void);

#endif
