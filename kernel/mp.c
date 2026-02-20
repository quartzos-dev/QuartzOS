#include <kernel/mp.h>

#define MP_WORK_CAPACITY 256

typedef struct mp_work_item {
    mp_work_fn_t fn;
    void *arg;
} mp_work_item_t;

static volatile uint32_t g_total_cpus = 1;
static volatile uint32_t g_online_cpus = 1;

static mp_work_item_t g_work_queue[MP_WORK_CAPACITY];
static volatile uint32_t g_work_head;
static volatile uint32_t g_work_tail;
static volatile uint32_t g_work_lock;

static void spin_lock(volatile uint32_t *lock) {
    while (__atomic_test_and_set(lock, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause");
    }
}

static void spin_unlock(volatile uint32_t *lock) {
    __atomic_clear(lock, __ATOMIC_RELEASE);
}

void mp_record_bootstrap(uint32_t total, uint32_t online) {
    g_total_cpus = total;
    g_online_cpus = online;
}

uint32_t mp_total_cpus(void) {
    return g_total_cpus;
}

uint32_t mp_online_cpus(void) {
    return g_online_cpus;
}

void mp_init_work_queue(void) {
    g_work_head = 0;
    g_work_tail = 0;
    g_work_lock = 0;
}

bool mp_submit_work(mp_work_fn_t fn, void *arg) {
    if (!fn) {
        return false;
    }

    spin_lock(&g_work_lock);

    uint32_t next_tail = (g_work_tail + 1) % MP_WORK_CAPACITY;
    if (next_tail == g_work_head) {
        spin_unlock(&g_work_lock);
        return false;
    }

    g_work_queue[g_work_tail].fn = fn;
    g_work_queue[g_work_tail].arg = arg;
    g_work_tail = next_tail;

    spin_unlock(&g_work_lock);
    return true;
}

bool mp_service_one_work(void) {
    mp_work_item_t item;
    bool have_item = false;

    spin_lock(&g_work_lock);
    if (g_work_head != g_work_tail) {
        item = g_work_queue[g_work_head];
        g_work_head = (g_work_head + 1) % MP_WORK_CAPACITY;
        have_item = true;
    }
    spin_unlock(&g_work_lock);

    if (!have_item) {
        return false;
    }

    item.fn(item.arg);
    return true;
}

void mp_ap_loop(void) {
    for (;;) {
        if (!mp_service_one_work()) {
            for (int i = 0; i < 1024; i++) {
                __asm__ volatile("pause");
            }
        }
    }
}
