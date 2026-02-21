#include "../common/runtime.h"

void _start(void) {
    static const char *quotes[] = {
        "Reliability is not magic. It is explicit design, strict boundaries, and boring execution at scale.",
        "Good operating systems hide complexity from users without hiding truth from developers.",
        "Performance wins when data structures, scheduling, and I/O policy are designed as one system.",
        "Security starts by reducing assumptions, then proving what remains with instrumentation."
    };

    app_begin("quotes", "Curated systems quotes with wrapped typography");

    for (uint32_t i = 0; i < (sizeof(quotes) / sizeof(quotes[0])); i++) {
        app_write("quote ");
        app_write_u32(i + 1u);
        app_write(": ");
        app_newline();
        app_write_wrapped(quotes[i], 68u);
        app_newline();
        app_yield_n(2);
    }

    app_end("quotes");
    app_exit();
}
