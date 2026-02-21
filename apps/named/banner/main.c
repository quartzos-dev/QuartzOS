#include "../common/runtime.h"

static const uint8_t GLYPH_A[7] = {0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11};
static const uint8_t GLYPH_O[7] = {0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E};
static const uint8_t GLYPH_Q[7] = {0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D};
static const uint8_t GLYPH_R[7] = {0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11};
static const uint8_t GLYPH_S[7] = {0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E};
static const uint8_t GLYPH_T[7] = {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
static const uint8_t GLYPH_U[7] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E};
static const uint8_t GLYPH_Z[7] = {0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F};

static const uint8_t *glyph_for(char ch) {
    switch (ch) {
        case 'A': return GLYPH_A;
        case 'O': return GLYPH_O;
        case 'Q': return GLYPH_Q;
        case 'R': return GLYPH_R;
        case 'S': return GLYPH_S;
        case 'T': return GLYPH_T;
        case 'U': return GLYPH_U;
        case 'Z': return GLYPH_Z;
        default: return GLYPH_O;
    }
}

void _start(void) {
    const char *word = "QUARTZOS";
    static const char shades[] = {' ', '.', ':', '*', '#'};

    app_begin("banner", "Vector-like ASCII logo renderer");

    for (uint32_t row = 0; row < 7; row++) {
        for (uint32_t i = 0; word[i]; i++) {
            const uint8_t *g = glyph_for(word[i]);
            for (uint32_t col = 0; col < 5; col++) {
                uint8_t bit = (uint8_t)((g[row] >> (4u - col)) & 1u);
                char px = bit ? shades[4] : shades[(row + i + col) % 2];
                app_write_ch(px);
                app_write_ch(px);
            }
            app_write_ch(' ');
        }
        app_newline();
    }

    app_write_line("Aero profile: glass text + dual-pass raster");
    app_end("banner");
    app_exit();
}
