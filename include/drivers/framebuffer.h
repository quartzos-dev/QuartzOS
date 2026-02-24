#ifndef DRIVERS_FRAMEBUFFER_H
#define DRIVERS_FRAMEBUFFER_H

#include <stdbool.h>
#include <stdint.h>

void framebuffer_init(void *address, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp);
void fb_clear(uint32_t color);
void fb_put_pixel(uint32_t x, uint32_t y, uint32_t color);
void fb_fill_rect(int x, int y, int w, int h, uint32_t color);
void fb_draw_char(int x, int y, char c, uint32_t fg, uint32_t bg);
void fb_draw_text(int x, int y, const char *text, uint32_t fg, uint32_t bg);
bool fb_enable_backbuffer(void);
bool fb_backbuffer_enabled(void);
void fb_present(void);
void fb_present_region(int x, int y, int w, int h);
void fb_put_pixel_front(uint32_t x, uint32_t y, uint32_t color);

uint32_t fb_width(void);
uint32_t fb_height(void);

#endif
