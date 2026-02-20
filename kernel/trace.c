#include <kernel/trace.h>

#define TRACE_RING_SIZE 65536

static char g_ring[TRACE_RING_SIZE];
static size_t g_head;
static size_t g_used;
static volatile unsigned int g_lock;

static void lock_acquire(void) {
    while (__atomic_test_and_set(&g_lock, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause");
    }
}

static void lock_release(void) {
    __atomic_clear(&g_lock, __ATOMIC_RELEASE);
}

void trace_init(void) {
    g_head = 0;
    g_used = 0;
    g_lock = 0;
}

void trace_capture_char(char c) {
    lock_acquire();
    g_ring[g_head] = c;
    g_head = (g_head + 1) % TRACE_RING_SIZE;
    if (g_used < TRACE_RING_SIZE) {
        g_used++;
    }
    lock_release();
}

size_t trace_copy(char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return 0;
    }

    lock_acquire();
    size_t available = g_used;
    size_t max_copy = out_len - 1;
    size_t take = available;
    if (take > max_copy) {
        take = max_copy;
    }

    size_t start = (g_head + TRACE_RING_SIZE - g_used) % TRACE_RING_SIZE;
    if (take < available) {
        start = (start + (available - take)) % TRACE_RING_SIZE;
    }

    for (size_t i = 0; i < take; i++) {
        out[i] = g_ring[(start + i) % TRACE_RING_SIZE];
    }
    out[take] = '\0';
    lock_release();
    return take;
}

void trace_clear(void) {
    lock_acquire();
    g_head = 0;
    g_used = 0;
    lock_release();
}

size_t trace_size(void) {
    lock_acquire();
    size_t n = g_used;
    lock_release();
    return n;
}
