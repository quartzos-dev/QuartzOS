#ifndef DRIVERS_MOUSE_H
#define DRIVERS_MOUSE_H

#include <stdbool.h>
#include <stdint.h>

typedef struct mouse_state {
    int x;
    int y;
    bool left;
    bool right;
    bool middle;
} mouse_state_t;

void mouse_init(int max_x, int max_y);
void mouse_handle_irq(void);
mouse_state_t mouse_get_state(void);
void mouse_set_invert_x(bool enabled);
void mouse_set_invert_y(bool enabled);
bool mouse_invert_x(void);
bool mouse_invert_y(void);
void mouse_center(void);

#endif
