#include "../common/runtime.h"

int main(void) {
    app_begin("nettrace", "Synthetic packet flow timeline for network debugging");

    static const char *stages[] = {
        "ARP resolve gateway",
        "TCP SYN send",
        "TCP SYN/ACK receive",
        "ACK transmit",
        "payload transfer",
        "FIN handshake"
    };

    uint32_t t = 0;
    for (uint32_t i = 0; i < (uint32_t)(sizeof(stages) / sizeof(stages[0])); i++) {
        t += 7u + (i * 3u);
        app_write("t+");
        app_write_u32(t);
        app_write("ms  ");
        app_write_line(stages[i]);
        app_yield();
    }

    app_write_line("result: synthetic flow complete");
    app_end("nettrace");
    app_exit();
    return 0;
}
