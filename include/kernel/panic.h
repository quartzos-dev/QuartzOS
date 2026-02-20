#ifndef KERNEL_PANIC_H
#define KERNEL_PANIC_H

__attribute__((noreturn)) void panic(const char *msg);

#endif
