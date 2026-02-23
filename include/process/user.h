#ifndef PROCESS_USER_H
#define PROCESS_USER_H

#include <stdbool.h>
#include <stddef.h>

bool user_run_elf(const void *image, size_t size);
bool user_active(void);
bool user_pointer_readable(const void *ptr, size_t len);
void user_exit_current(void) __attribute__((noreturn));

#endif
