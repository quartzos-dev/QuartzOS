#ifndef KERNEL_AUDIT_H
#define KERNEL_AUDIT_H

#include <stddef.h>

void audit_init(void);
void audit_log(const char *event, const char *detail);
size_t audit_dump(char *out, size_t out_len);
void audit_clear(void);

#endif
