#ifndef KERNEL_CONFIG_H
#define KERNEL_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void config_init(void);
bool config_load(void);
bool config_save(void);

bool config_set(const char *key, const char *value);
bool config_unset(const char *key);
const char *config_get(const char *key);
bool config_get_u32(const char *key, uint32_t *out_value);
size_t config_dump(char *out, size_t out_len);

#endif
