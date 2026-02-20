#ifndef KERNEL_GDT_H
#define KERNEL_GDT_H

#include <stdint.h>

void gdt_init(void);
void tss_set_rsp0(uint64_t rsp0);

#define KERNEL_CS 0x08
#define KERNEL_DS 0x10
#define USER_DS 0x23
#define USER_CS 0x1b

#endif
