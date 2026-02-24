#ifndef KERNEL_CPU_HARDENING_H
#define KERNEL_CPU_HARDENING_H

#include <stdbool.h>

void cpu_hardening_init(void);
bool cpu_hardening_smep_enabled(void);
bool cpu_hardening_smap_enabled(void);
void cpu_user_access_begin(void);
void cpu_user_access_end(void);

#endif
