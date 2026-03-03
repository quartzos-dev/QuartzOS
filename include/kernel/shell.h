#ifndef KERNEL_SHELL_H
#define KERNEL_SHELL_H

#include <stdbool.h>

void shell_init(void);
void shell_tick(void);
bool shell_unlock_runtime_services(void);

#endif
