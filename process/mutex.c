#include <process/mutex.h>
#include <process/task.h>

static uint64_t g_mutex_locks;
static uint64_t g_mutex_contentions;

void kmutex_init(kmutex_t *mutex) {
    if (!mutex) {
        return;
    }
    mutex->owner = 0;
    mutex->recursion = 0;
    mutex->contentions = 0;
    mutex->max_wait_priority = 0;
}

bool kmutex_try_lock(kmutex_t *mutex) {
    if (!mutex) {
        return false;
    }

    task_t *cur = task_current();
    if (!cur) {
        return false;
    }

    if (!mutex->owner) {
        mutex->owner = cur;
        mutex->recursion = 1;
        mutex->max_wait_priority = task_effective_priority(cur);
        g_mutex_locks++;
        return true;
    }

    if (mutex->owner == cur) {
        mutex->recursion++;
        return true;
    }

    return false;
}

void kmutex_lock(kmutex_t *mutex) {
    if (!mutex) {
        return;
    }

    task_t *cur = task_current();
    if (!cur) {
        return;
    }

    while (!kmutex_try_lock(mutex)) {
        mutex->contentions++;
        g_mutex_contentions++;

        int wait_prio = task_effective_priority(cur);
        if (wait_prio > mutex->max_wait_priority) {
            mutex->max_wait_priority = wait_prio;
        }

        if (mutex->owner && task_effective_priority(mutex->owner) < wait_prio) {
            task_boost_priority(mutex->owner, wait_prio);
        }

        task_yield();
    }
}

void kmutex_unlock(kmutex_t *mutex) {
    if (!mutex) {
        return;
    }

    task_t *cur = task_current();
    if (!cur || mutex->owner != cur || mutex->recursion == 0) {
        return;
    }

    mutex->recursion--;
    if (mutex->recursion > 0) {
        return;
    }

    task_restore_priority(cur);
    mutex->owner = 0;
    mutex->max_wait_priority = 0;
}

uint64_t kmutex_global_locks(void) {
    return g_mutex_locks;
}

uint64_t kmutex_global_contentions(void) {
    return g_mutex_contentions;
}
