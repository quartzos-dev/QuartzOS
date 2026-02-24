#include <kernel/console.h>
#include <kernel/cpu_hardening.h>
#include <kernel/security.h>
#include <kernel/syscall.h>
#include <lib/string.h>
#include <memory/heap.h>
#include <process/user.h>

#define SYS_WRITE_MAX 4096u

uint64_t syscall_handle(uint64_t id, uint64_t arg0, uint64_t arg1, uint64_t arg2) {
    (void)arg2;

    switch (id) {
        case SYS_WRITE: {
            if (arg1 == 0) {
                return 0;
            }
            if (!arg0 || arg1 > SYS_WRITE_MAX) {
                return (uint64_t)-1;
            }
            if (!security_allow_sys_write((size_t)arg1)) {
                return (uint64_t)-1;
            }
            if (!user_pointer_readable((const void *)(uintptr_t)arg0, (size_t)arg1)) {
                return (uint64_t)-1;
            }
            char *tmp = (char *)kmalloc((size_t)arg1);
            if (!tmp) {
                return (uint64_t)-1;
            }
            cpu_user_access_begin();
            memcpy(tmp, (const void *)(uintptr_t)arg0, (size_t)arg1);
            cpu_user_access_end();
            console_write_len(tmp, (size_t)arg1);
            kfree(tmp);
            return arg1;
        }
        case SYS_EXIT:
            user_exit_current();
            return 0;
        case SYS_YIELD:
            return 0;
        default:
            return (uint64_t)-1;
    }
}
