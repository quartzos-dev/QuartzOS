#ifndef PROCESS_MUTEX_H
#define PROCESS_MUTEX_H

#include <stdbool.h>
#include <stdint.h>

#include <process/task.h>

typedef struct kmutex {
    task_t *owner;
    uint32_t recursion;
    uint64_t contentions;
    int max_wait_priority;
} kmutex_t;

void kmutex_init(kmutex_t *mutex);
bool kmutex_try_lock(kmutex_t *mutex);
void kmutex_lock(kmutex_t *mutex);
void kmutex_unlock(kmutex_t *mutex);

uint64_t kmutex_global_locks(void);
uint64_t kmutex_global_contentions(void);

#endif
