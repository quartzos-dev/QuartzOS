#include <kernel/interrupts.h>
#include <kernel/log.h>
#include <lib/string.h>
#include <memory/heap.h>
#include <process/task.h>

extern void task_switch(uint64_t *old_rsp, uint64_t new_rsp);

static task_t *task_list;
static task_t *current_task;
static task_t *sched_cursor;
static uint64_t next_id = 1;
static uint64_t ticks;
static uint64_t context_switches;
static uint32_t sched_quantum_ticks = 10;
static volatile int need_resched;

static int clamp_priority(int priority) {
    if (priority < 0) {
        return 0;
    }
    if (priority > 31) {
        return 31;
    }
    return priority;
}

static int task_score(const task_t *task) {
    int score = task->effective_priority;
    if (task->sched_class == TASK_CLASS_RT) {
        score += 1000;
    }
    return score;
}

static uint32_t vruntime_weight(const task_t *task) {
    int prio = clamp_priority(task->effective_priority);
    uint32_t weight = (uint32_t)(40 - prio);
    if (weight == 0) {
        weight = 1;
    }
    if (task->sched_class == TASK_CLASS_RT) {
        weight = (weight > 4u) ? (weight / 4u) : 1u;
    }
    return weight;
}

static task_t *choose_next_ready(void) {
    if (!task_list) {
        return 0;
    }

    task_t *start = sched_cursor ? sched_cursor->next : task_list;
    task_t *iter = start;
    task_t *best = 0;
    uint64_t best_vruntime = 0;
    int best_score = -1000000;

    do {
        if (iter->state == TASK_READY) {
            int score = task_score(iter);
            if (!best ||
                iter->vruntime < best_vruntime ||
                (iter->vruntime == best_vruntime && score > best_score)) {
                best = iter;
                best_vruntime = iter->vruntime;
                best_score = score;
            }
        }
        iter = iter->next;
    } while (iter != start);

    if (best) {
        sched_cursor = best;
    }
    return best;
}

static void task_bootstrap(void) {
    if (current_task && current_task->entry) {
        current_task->entry(current_task->arg);
    }
    task_exit();
}

static void task_list_append(task_t *task) {
    if (!task_list) {
        task_list = task;
        task->next = task;
        return;
    }
    task_t *iter = task_list;
    while (iter->next != task_list) {
        iter = iter->next;
    }
    iter->next = task;
    task->next = task_list;
}

void tasking_init(void) {
    task_t *boot = (task_t *)kcalloc(1, sizeof(task_t));
    boot->id = next_id++;
    boot->state = TASK_RUNNING;
    boot->sched_class = TASK_CLASS_NORMAL;
    boot->base_priority = 16;
    boot->effective_priority = 16;
    boot->boosted = 0;
    boot->run_ticks = 0;
    boot->vruntime = 0;
    boot->entry = 0;
    boot->arg = 0;
    boot->stack_base = 0;
    boot->stack_size = 0;
    strcpy(boot->name, "kernel-main");

    task_list = boot;
    boot->next = boot;
    current_task = boot;
    sched_cursor = boot;
    ticks = 0;
    context_switches = 0;
    sched_quantum_ticks = 10;
    need_resched = 0;
}

task_t *task_create(const char *name, task_entry_t entry, void *arg, size_t stack_size) {
    if (stack_size < 4096) {
        stack_size = 4096;
    }

    task_t *task = (task_t *)kcalloc(1, sizeof(task_t));
    if (!task) {
        return 0;
    }

    void *stack = kmalloc(stack_size);
    if (!stack) {
        kfree(task);
        return 0;
    }

    uint64_t *sp = (uint64_t *)((uint8_t *)stack + stack_size - sizeof(uint64_t));
    *--sp = (uint64_t)task_bootstrap;
    *--sp = 0;
    *--sp = 0;
    *--sp = 0;
    *--sp = 0;
    *--sp = 0;
    *--sp = 0;

    task->rsp = (uint64_t)sp;
    task->id = next_id++;
    task->state = TASK_READY;
    task->sched_class = TASK_CLASS_NORMAL;
    task->base_priority = 16;
    task->effective_priority = 16;
    task->boosted = 0;
    task->run_ticks = 0;
    task->vruntime = current_task ? current_task->vruntime : 0;
    task->entry = entry;
    task->arg = arg;
    task->stack_base = stack;
    task->stack_size = stack_size;
    task->next = 0;
    strncpy(task->name, name ? name : "task", sizeof(task->name) - 1);

    task_list_append(task);
    return task;
}

static void task_cleanup(void) {
    if (!task_list) {
        return;
    }

    task_t *old_head = task_list;
    task_t *iter = old_head;
    task_t *new_head = 0;
    task_t *new_tail = 0;

    do {
        task_t *next = iter->next;
        int keep = (iter->state != TASK_DEAD) || (iter == current_task);

        if (keep) {
            if (!new_head) {
                new_head = iter;
                new_tail = iter;
                new_tail->next = new_head;
            } else {
                new_tail->next = iter;
                new_tail = iter;
                new_tail->next = new_head;
            }
        } else {
            if (sched_cursor == iter) {
                sched_cursor = 0;
            }
            if (iter->stack_base) {
                kfree(iter->stack_base);
            }
            kfree(iter);
        }

        iter = next;
    } while (iter != old_head);

    task_list = new_head;
    if (!task_list) {
        current_task = 0;
        sched_cursor = 0;
        need_resched = 0;
        return;
    }

    if (!sched_cursor || sched_cursor->state == TASK_DEAD) {
        sched_cursor = task_list;
    }
}

void task_yield(void) {
    if (!current_task) {
        need_resched = 0;
        task_cleanup();
        return;
    }

    task_t *prev = current_task;
    if (prev->state == TASK_RUNNING) {
        prev->state = TASK_READY;
    }

    task_t *next = choose_next_ready();
    if (!next) {
        if (prev->state == TASK_READY) {
            prev->state = TASK_RUNNING;
            prev->run_ticks = 0;
            current_task = prev;
        }
        need_resched = 0;
        task_cleanup();
        return;
    }

    next->state = TASK_RUNNING;
    next->run_ticks = 0;
    current_task = next;
    need_resched = 0;

    if (next == prev) {
        task_cleanup();
        return;
    }

    context_switches++;
    task_switch(&prev->rsp, next->rsp);
    task_cleanup();
}

void task_tick(void) {
    ticks++;
    if (current_task && current_task->state == TASK_RUNNING) {
        current_task->run_ticks++;
        current_task->vruntime += (uint64_t)vruntime_weight(current_task);
    }
    if (current_task && current_task->run_ticks >= sched_quantum_ticks) {
        need_resched = 1;
    }
}

uint64_t task_current_id(void) {
    return current_task ? current_task->id : 0;
}

task_t *task_current(void) {
    return current_task;
}

void task_exit(void) {
    interrupts_disable();
    if (current_task) {
        current_task->state = TASK_DEAD;
    }
    interrupts_enable();
    for (;;) {
        task_yield();
        __asm__ volatile("hlt");
    }
}

void task_schedule_if_needed(void) {
    if (need_resched) {
        task_yield();
    }
}

uint32_t task_quantum_ticks(void) {
    return sched_quantum_ticks;
}

void task_set_quantum_ticks(uint32_t ticks_value) {
    if (ticks_value == 0) {
        ticks_value = 1;
    }
    sched_quantum_ticks = ticks_value;
}

uint64_t task_tick_count(void) {
    return ticks;
}

uint64_t task_switch_count(void) {
    return context_switches;
}

static task_t *task_find_by_id(uint64_t id) {
    if (!task_list) {
        return 0;
    }
    task_t *iter = task_list;
    do {
        if (iter->id == id) {
            return iter;
        }
        iter = iter->next;
    } while (iter != task_list);
    return 0;
}

bool task_set_priority(uint64_t id, int priority) {
    task_t *task = task_find_by_id(id);
    if (!task) {
        return false;
    }
    task->base_priority = clamp_priority(priority);
    if (!task->boosted) {
        task->effective_priority = task->base_priority;
    }
    return true;
}

bool task_set_realtime(uint64_t id, bool realtime) {
    task_t *task = task_find_by_id(id);
    if (!task) {
        return false;
    }
    task->sched_class = realtime ? TASK_CLASS_RT : TASK_CLASS_NORMAL;
    return true;
}

void task_boost_priority(task_t *task, int priority) {
    if (!task) {
        return;
    }
    int target = clamp_priority(priority);
    if (task->effective_priority < target) {
        task->effective_priority = target;
        task->boosted = 1;
    }
}

void task_restore_priority(task_t *task) {
    if (!task) {
        return;
    }
    task->effective_priority = task->base_priority;
    task->boosted = 0;
}

int task_effective_priority(const task_t *task) {
    if (!task) {
        return 0;
    }
    return task->effective_priority;
}

void task_debug_dump(void) {
    if (!task_list) {
        kprintf("ps: no tasks\n");
        return;
    }

    kprintf("id  class prio state ticks name\n");
    task_t *iter = task_list;
    do {
        const char *cls = iter->sched_class == TASK_CLASS_RT ? "rt" : "norm";
        const char *state = "dead";
        if (iter->state == TASK_RUNNING) {
            state = "run";
        } else if (iter->state == TASK_READY) {
            state = "ready";
        }
        kprintf("%u  %s  %u/%u %s %u %s\n",
                (unsigned)iter->id,
                cls,
                (unsigned)iter->effective_priority,
                (unsigned)iter->base_priority,
                state,
                (unsigned)iter->run_ticks,
                iter->name);
        iter = iter->next;
    } while (iter != task_list);
}

bool task_exists(uint64_t id) {
    task_t *task = task_find_by_id(id);
    return task && task->state != TASK_DEAD;
}

bool task_kill(uint64_t id) {
    task_t *task = task_find_by_id(id);
    if (!task) {
        return false;
    }
    if (current_task && task == current_task) {
        return false;
    }
    task->state = TASK_DEAD;
    need_resched = 1;
    return true;
}
