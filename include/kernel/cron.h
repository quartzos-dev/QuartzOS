#ifndef KERNEL_CRON_H
#define KERNEL_CRON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void cron_init(void);
void cron_tick(void);
bool cron_load(void);
bool cron_save(void);

bool cron_add(const char *action_name, uint32_t seconds, uint32_t *out_id);
bool cron_remove(uint32_t id);
bool cron_run(uint32_t id);
bool cron_set_enabled(uint32_t id, bool enabled);
size_t cron_list(char *out, size_t out_len);
size_t cron_actions(char *out, size_t out_len);

#endif
