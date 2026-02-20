#ifndef DRIVERS_KEYBOARD_H
#define DRIVERS_KEYBOARD_H

#include <stdbool.h>

void keyboard_init(void);
void keyboard_handle_irq(void);
bool keyboard_read_char(char *out);

#endif
