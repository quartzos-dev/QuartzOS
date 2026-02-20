#ifndef KERNEL_TRACE_H
#define KERNEL_TRACE_H

#include <stddef.h>

void trace_init(void);
void trace_capture_char(char c);
size_t trace_copy(char *out, size_t out_len);
void trace_clear(void);
size_t trace_size(void);

#endif
