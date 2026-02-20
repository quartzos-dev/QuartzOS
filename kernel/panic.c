#include <drivers/pit.h>
#include <filesystem/sfs.h>
#include <kernel/log.h>
#include <kernel/panic.h>
#include <kernel/trace.h>
#include <lib/string.h>

static uint32_t g_panic_seq;

static void u64_to_dec(uint64_t value, char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return;
    }
    char tmp[32];
    size_t idx = 0;
    do {
        tmp[idx++] = (char)('0' + (value % 10u));
        value /= 10u;
    } while (value != 0u && idx < sizeof(tmp));

    size_t n = idx;
    if (n >= out_len) {
        n = out_len - 1;
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = tmp[n - 1 - i];
    }
    out[n] = '\0';
}

static void panic_write_dump(const char *msg) {
    char trace_buf[2048];
    char dump[4096];
    char tick_buf[32];
    char seq_buf[16];
    char path[64];

    (void)trace_copy(trace_buf, sizeof(trace_buf));
    u64_to_dec(pit_ticks(), tick_buf, sizeof(tick_buf));
    u64_to_dec(++g_panic_seq, seq_buf, sizeof(seq_buf));

    dump[0] = '\0';
    strncat(dump, "QuartzOS panic dump\n", sizeof(dump) - strlen(dump) - 1);
    strncat(dump, "seq: ", sizeof(dump) - strlen(dump) - 1);
    strncat(dump, seq_buf, sizeof(dump) - strlen(dump) - 1);
    strncat(dump, "\n", sizeof(dump) - strlen(dump) - 1);
    strncat(dump, "ticks: ", sizeof(dump) - strlen(dump) - 1);
    strncat(dump, tick_buf, sizeof(dump) - strlen(dump) - 1);
    strncat(dump, "\n", sizeof(dump) - strlen(dump) - 1);
    strncat(dump, "message: ", sizeof(dump) - strlen(dump) - 1);
    strncat(dump, msg ? msg : "(null)", sizeof(dump) - strlen(dump) - 1);
    strncat(dump, "\n\ntrace tail:\n", sizeof(dump) - strlen(dump) - 1);
    strncat(dump, trace_buf, sizeof(dump) - strlen(dump) - 1);
    strncat(dump, "\n", sizeof(dump) - strlen(dump) - 1);

    sfs_make_dir("/var");
    sfs_make_dir("/var/crash");

    path[0] = '\0';
    strncat(path, "/var/crash/panic_", sizeof(path) - strlen(path) - 1);
    strncat(path, seq_buf, sizeof(path) - strlen(path) - 1);
    strncat(path, ".log", sizeof(path) - strlen(path) - 1);

    if (sfs_write_file(path, dump, strlen(dump)) && sfs_persistence_enabled()) {
        sfs_sync();
    }
    (void)sfs_write_file("/var/crash/panic.log", dump, strlen(dump));
}

__attribute__((noreturn)) void panic(const char *msg) {
    panic_write_dump(msg);
    kprintf("\nPANIC: %s\n", msg);
    __asm__ volatile("cli");
    for (;;) {
        __asm__ volatile("hlt");
    }
}
