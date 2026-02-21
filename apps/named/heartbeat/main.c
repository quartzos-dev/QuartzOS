#include "../common/runtime.h"

static const uint8_t ecg[] = {
    8, 8, 8, 8, 8, 9, 7, 10,
    5, 13, 2, 15, 1, 8, 9, 8,
    8, 8, 8, 8, 8, 8, 8, 8
};

void _start(void) {
    uint32_t bpm = 72;
    uint32_t beats = 0;

    app_begin("heartbeat", "ECG waveform stream with bpm drift tracking");

    for (uint32_t t = 0; t < 72; t++) {
        uint32_t v = ecg[t % (sizeof(ecg) / sizeof(ecg[0]))];

        if (t % 24u == 0u) {
            beats++;
            bpm += (t & 1u) ? 1u : 2u;
        }

        app_write("frame ");
        app_write_padded_u32(t, 2);
        app_write(" bpm=");
        app_write_u32(bpm);
        app_write(" ");

        app_spaces(16u - v);
        app_write_ch('|');
        app_repeat('#', v);
        app_newline();

        app_yield();
    }

    app_write("detected beats=");
    app_write_u32(beats);
    app_newline();

    app_end("heartbeat");
    app_exit();
}
