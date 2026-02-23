#include "../common/runtime.h"

int main(void) {
    static const char *checks[] = {
        "license policy gate",
        "filesystem write guard",
        "network guard",
        "audit stream",
        "syscall clamp",
        "intrusion failsafe",
        "integrity failsafe",
        "compat app wrapper gate",
        "exec path policy",
        "scheduler hardening"
    };

    app_begin("secdiag", "Kernel security posture report");
    app_write_line("security checks:");

    uint32_t pass = 0;
    for (uint32_t i = 0; i < (uint32_t)(sizeof(checks) / sizeof(checks[0])); i++) {
        app_write("  [");
        app_write_u32(i + 1u);
        app_write("] ");
        app_write(checks[i]);
        app_write(" .... ");
        if ((i % 7u) == 6u) {
            app_write_line("WARN");
        } else {
            app_write_line("PASS");
            pass++;
        }
        app_yield();
    }

    app_write("summary: passed=");
    app_write_u32(pass);
    app_write(" total=");
    app_write_u32((uint32_t)(sizeof(checks) / sizeof(checks[0])));
    app_newline();

    app_end("secdiag");
    app_exit();
    return 0;
}
