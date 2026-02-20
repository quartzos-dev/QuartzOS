#ifndef KERNEL_SYSCALL_H
#define KERNEL_SYSCALL_H

#include <stdint.h>

enum syscall_id {
    SYS_WRITE = 1,
    SYS_EXIT = 2,
    SYS_YIELD = 3
};

uint64_t syscall_handle(uint64_t id, uint64_t arg0, uint64_t arg1, uint64_t arg2);

#endif
