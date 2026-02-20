#ifndef KERNEL_SERVICE_H
#define KERNEL_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <process/task.h>

typedef task_t *(*service_spawn_fn)(void *arg);

typedef enum service_policy {
    SERVICE_POLICY_MANUAL = 0,
    SERVICE_POLICY_ALWAYS = 1
} service_policy_t;

void service_init(void);
bool service_register(const char *name, service_spawn_fn spawn, void *arg, service_policy_t policy);
bool service_bind_task(const char *name, uint64_t task_id);
bool service_start(const char *name);
bool service_stop(const char *name);
bool service_restart(const char *name);
bool service_set_policy(const char *name, service_policy_t policy);
bool service_set_restart_limits(const char *name, uint32_t max_restarts,
                                uint32_t window_seconds, uint32_t backoff_seconds);
uint64_t service_task_id(const char *name);
service_policy_t service_policy(const char *name);
void service_tick(void);
size_t service_dump(char *out, size_t out_len);

#endif
