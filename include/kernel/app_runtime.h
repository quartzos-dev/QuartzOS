#ifndef KERNEL_APP_RUNTIME_H
#define KERNEL_APP_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>

#include <kernel/security.h>

typedef enum app_runtime_kind {
    APP_RUNTIME_UNKNOWN = 0,
    APP_RUNTIME_CUSTOM_ELF = 1,
    APP_RUNTIME_LINUX_ELF = 2,
    APP_RUNTIME_WINDOWS_PE = 3,
    APP_RUNTIME_MACOS_MACHO = 4
} app_runtime_kind_t;

typedef struct app_runtime_info {
    app_runtime_kind_t kind;
    bool wrapped;
    bool runnable;
    char detail[96];
} app_runtime_info_t;

const char *app_runtime_kind_name(app_runtime_kind_t kind);
security_app_kind_t app_runtime_security_kind(app_runtime_kind_t kind);
bool app_runtime_probe(const void *image, size_t size, app_runtime_info_t *out);
bool app_runtime_run(const void *image, size_t size, app_runtime_info_t *out);

#endif
