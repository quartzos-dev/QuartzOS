#ifndef PROCESS_TASK_H
#define PROCESS_TASK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef void (*task_entry_t)(void *arg);

typedef enum task_state {
    TASK_READY = 0,
    TASK_RUNNING = 1,
    TASK_DEAD = 2
} task_state_t;

typedef enum task_class {
    TASK_CLASS_NORMAL = 0,
    TASK_CLASS_RT = 1
} task_class_t;

typedef struct task {
    uint64_t rsp;
    uint64_t id;
    task_state_t state;
    task_class_t sched_class;
    int base_priority;
    int effective_priority;
    int boosted;
    uint32_t run_ticks;
    uint64_t vruntime;
    task_entry_t entry;
    void *arg;
    void *stack_base;
    size_t stack_size;
    struct task *next;
    char name[32];
} task_t;

void tasking_init(void);
task_t *task_create(const char *name, task_entry_t entry, void *arg, size_t stack_size);
void task_yield(void);
void task_tick(void);
void task_schedule_if_needed(void);
void task_exit(void) __attribute__((noreturn));
uint64_t task_current_id(void);
task_t *task_current(void);

uint32_t task_quantum_ticks(void);
void task_set_quantum_ticks(uint32_t ticks);
uint64_t task_tick_count(void);
uint64_t task_switch_count(void);

bool task_set_priority(uint64_t id, int priority);
bool task_set_realtime(uint64_t id, bool realtime);
void task_debug_dump(void);
bool task_exists(uint64_t id);
bool task_kill(uint64_t id);

void task_boost_priority(task_t *task, int priority);
void task_restore_priority(task_t *task);
int task_effective_priority(const task_t *task);

#endif
