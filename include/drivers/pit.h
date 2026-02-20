#ifndef DRIVERS_PIT_H
#define DRIVERS_PIT_H

#include <stdint.h>

void pit_init(uint32_t freq_hz);
uint64_t pit_ticks(void);
void pit_handle_tick(void);

#endif
