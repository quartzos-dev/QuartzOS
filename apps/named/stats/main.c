#include "../common/runtime.h"

static void sort_u32(uint32_t *a, uint32_t n) {
    for (uint32_t i = 1; i < n; i++) {
        uint32_t key = a[i];
        uint32_t j = i;
        while (j > 0 && a[j - 1] > key) {
            a[j] = a[j - 1];
            j--;
        }
        a[j] = key;
    }
}

void _start(void) {
    static uint32_t data[] = {34, 12, 89, 55, 21, 13, 8, 144, 3, 67, 42, 30, 77, 95, 18, 61};
    uint64_t sum = 0;
    uint32_t n = (uint32_t)(sizeof(data) / sizeof(data[0]));
    uint32_t min = data[0];
    uint32_t max = data[0];

    app_begin("stats", "Descriptive statistics + histogram bands");

    for (uint32_t i = 0; i < n; i++) {
        uint32_t v = data[i];
        sum += v;
        if (v < min) {
            min = v;
        }
        if (v > max) {
            max = v;
        }
    }

    sort_u32(data, n);
    uint32_t median = (data[(n / 2u) - 1u] + data[n / 2u]) / 2u;
    uint32_t mean_x100 = (uint32_t)((sum * 100u) / n);

    uint64_t var_acc = 0;
    for (uint32_t i = 0; i < n; i++) {
        int32_t delta = (int32_t)(data[i] * 100u) - (int32_t)mean_x100;
        var_acc += (uint64_t)((delta < 0 ? -delta : delta) * (delta < 0 ? -delta : delta));
    }
    uint32_t var_x100 = (uint32_t)(var_acc / n);
    uint32_t stdev_x10 = app_u32_sqrt(var_x100) / 10u;

    app_write("count=");
    app_write_u32(n);
    app_write(" sum=");
    app_write_u64(sum);
    app_newline();

    app_write("min=");
    app_write_u32(min);
    app_write(" median=");
    app_write_u32(median);
    app_write(" max=");
    app_write_u32(max);
    app_newline();

    app_write("mean=");
    app_write_u32(mean_x100 / 100u);
    app_write_ch('.');
    app_write_u32((mean_x100 / 10u) % 10u);
    app_write_u32(mean_x100 % 10u);
    app_write(" stdev~");
    app_write_u32(stdev_x10 / 10u);
    app_write_ch('.');
    app_write_u32(stdev_x10 % 10u);
    app_newline();

    app_write_line("bands:");
    for (uint32_t b = 0; b < 6; b++) {
        uint32_t lo = b * 25u;
        uint32_t hi = lo + 24u;
        uint32_t hit = 0;
        for (uint32_t i = 0; i < n; i++) {
            if (data[i] >= lo && data[i] <= hi) {
                hit++;
            }
        }
        app_write("  ");
        app_write_padded_u32(lo, 3);
        app_write("-");
        app_write_padded_u32(hi, 3);
        app_write(" ");
        app_write_bar(hit, n, 16, '#', '.');
        app_write(" ");
        app_write_u32(hit);
        app_newline();
        app_yield();
    }

    app_end("stats");
    app_exit();
}
