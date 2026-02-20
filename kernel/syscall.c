#include <kernel/console.h>
#include <kernel/syscall.h>
#include <process/user.h>

uint64_t syscall_handle(uint64_t id, uint64_t arg0, uint64_t arg1, uint64_t arg2) {
    (void)arg2;

    switch (id) {
        case SYS_WRITE:
            if (!arg0) {
                return (uint64_t)-1;
            }
            console_write_len((const char *)arg0, (size_t)arg1);
            return arg1;
        case SYS_EXIT:
            user_exit_current();
            return 0;
        case SYS_YIELD:
            return 0;
        default:
            return (uint64_t)-1;
    }
}
