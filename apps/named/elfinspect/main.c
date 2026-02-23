#include "../common/runtime.h"

int main(void) {
    app_begin("elfinspect", "ELF loader constraints and compatibility notes");

    app_write_line("QuartzOS ELF constraints:");
    app_write_line("  - x86_64 only");
    app_write_line("  - ET_EXEC required");
    app_write_line("  - static binaries (no PT_INTERP)");
    app_write_line("  - user pages finalized with W^X policy");
    app_write_line("  - syscall ABI: write, exit, yield");
    app_newline();

    app_write_line("compatibility matrix:");
    app_write_line("  custom ELF: native");
    app_write_line("  linux ELF (static): direct launch");
    app_write_line("  windows/macOS: wrapper + embedded Quartz payload");
    app_newline();

    app_write_line("tip: use `compat probe <file>` in shell before running.");

    app_end("elfinspect");
    app_exit();
    return 0;
}
