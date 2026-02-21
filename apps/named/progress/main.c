#include "../common/runtime.h"

typedef struct {
    const char *name;
    uint32_t steps;
    uint32_t weight;
} stage_t;

void _start(void) {
    static const stage_t stages[] = {
        {"plan", 8, 10},
        {"compile", 18, 40},
        {"link", 7, 20},
        {"verify", 10, 20},
        {"package", 6, 10},
    };

    uint32_t completed_weight = 0;

    app_begin("progress", "Weighted build pipeline simulator");

    for (uint32_t s = 0; s < (sizeof(stages) / sizeof(stages[0])); s++) {
        const stage_t *stage = &stages[s];
        for (uint32_t step = 1; step <= stage->steps; step++) {
            uint32_t stage_x10 = (step * 1000u) / stage->steps;
            uint32_t total_x10 = completed_weight * 10u + (stage->weight * stage_x10) / 10u;

            app_write(stage->name);
            app_write(" ");
            app_write_padded_u32(step, 2);
            app_write("/");
            app_write_padded_u32(stage->steps, 2);
            app_write(" stage=");
            app_write_percent_x10(stage_x10);
            app_write(" total=");
            app_write_percent_x10(total_x10);
            app_write(" ");
            app_write_bar(total_x10, 1000u, 24, '#', '.');
            app_newline();
            app_yield();
        }
        completed_weight += stage->weight;
    }

    app_end("progress");
    app_exit();
}
