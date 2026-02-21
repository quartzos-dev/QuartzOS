#ifndef QUARTZ_APP_RUNTIME_H
#define QUARTZ_APP_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state;
} app_rng_t;

void app_begin(const char *name, const char *summary);
void app_end(const char *name);
void app_exit(void);
void app_yield(void);
void app_yield_n(uint32_t count);

size_t app_strlen(const char *s);
void app_write_len(const char *s, size_t n);
void app_write(const char *s);
void app_write_ch(char c);
void app_newline(void);
void app_write_line(const char *s);
void app_spaces(uint32_t count);
void app_repeat(char ch, uint32_t count);

void app_write_u32(uint32_t value);
void app_write_u64(uint64_t value);
void app_write_i32(int32_t value);
void app_write_hex8(uint8_t value);
void app_write_hex16(uint16_t value);
void app_write_hex32(uint32_t value);
void app_write_percent_x10(uint32_t value_x10);
void app_write_fixed3(uint32_t scaled);
void app_write_padded_u32(uint32_t value, uint32_t width);
void app_write_bar(uint32_t done, uint32_t total, uint32_t width, char fill, char empty);
void app_write_wrapped(const char *text, uint32_t width);

void app_rng_seed(app_rng_t *rng, uint32_t seed);
uint32_t app_rng_next(app_rng_t *rng);
uint32_t app_rng_range(app_rng_t *rng, uint32_t bound);

uint32_t app_u32_sqrt(uint32_t value);
uint32_t app_gcd_u32(uint32_t a, uint32_t b);
int app_is_prime_u32(uint32_t value);

#endif
