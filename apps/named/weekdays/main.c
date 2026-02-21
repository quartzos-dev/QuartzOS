#include "../common/runtime.h"

typedef struct {
    const char *day;
    const char *focus;
    uint32_t deep_hours;
    uint32_t meeting_hours;
} plan_t;

void _start(void) {
    static const plan_t plan[] = {
        {"Monday", "kernel", 5, 2},
        {"Tuesday", "drivers", 4, 3},
        {"Wednesday", "filesystem", 6, 1},
        {"Thursday", "ui", 4, 3},
        {"Friday", "release", 5, 2},
        {"Saturday", "testing", 3, 1},
        {"Sunday", "planning", 2, 1},
    };

    uint32_t deep_total = 0;
    uint32_t meet_total = 0;

    app_begin("weekdays", "Weekly execution planner");
    app_write_line("day        deep  meetings  focus");

    for (uint32_t i = 0; i < (sizeof(plan) / sizeof(plan[0])); i++) {
        app_write(plan[i].day);
        if (app_strlen(plan[i].day) < 10u) {
            app_spaces(10u - (uint32_t)app_strlen(plan[i].day));
        }
        app_write("  ");
        app_write_padded_u32(plan[i].deep_hours, 2);
        app_write("      ");
        app_write_padded_u32(plan[i].meeting_hours, 2);
        app_write("     ");
        app_write_line(plan[i].focus);

        deep_total += plan[i].deep_hours;
        meet_total += plan[i].meeting_hours;
        app_yield();
    }

    app_write("totals deep=");
    app_write_u32(deep_total);
    app_write(" meetings=");
    app_write_u32(meet_total);
    app_newline();

    app_end("weekdays");
    app_exit();
}
