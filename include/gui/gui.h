#ifndef GUI_GUI_H
#define GUI_GUI_H

#include <stdbool.h>

void gui_init(void);
void gui_tick(void);
void gui_set_console_overlay(bool enabled);
bool gui_console_overlay(void);

#endif
