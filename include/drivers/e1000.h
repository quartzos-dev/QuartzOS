#ifndef DRIVERS_E1000_H
#define DRIVERS_E1000_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void e1000_init(void);
void e1000_handle_irq(void);
bool e1000_available(void);
int e1000_irq_line(void);
void e1000_get_mac(uint8_t out[6]);
int e1000_send_raw(const uint8_t *frame, size_t len);
int e1000_poll_receive(uint8_t *out, size_t out_len);

#endif
