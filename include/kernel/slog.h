#ifndef KERNEL_SLOG_H
#define KERNEL_SLOG_H

#include <stddef.h>
#include <stdint.h>

typedef enum slog_level {
    SLOG_LEVEL_DEBUG = 0,
    SLOG_LEVEL_INFO = 1,
    SLOG_LEVEL_WARN = 2,
    SLOG_LEVEL_ERROR = 3
} slog_level_t;

void slog_init(void);
void slog_set_min_level(slog_level_t level);
slog_level_t slog_min_level(void);
const char *slog_level_name(slog_level_t level);
int slog_level_from_text(const char *text, slog_level_t *out_level);
void slog_log(slog_level_t level, const char *component, const char *message);
size_t slog_dump(char *out, size_t out_len, slog_level_t min_level);
void slog_clear(void);

#endif
