#ifndef NET_NET_H
#define NET_NET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void net_init(void);
void net_tick(void);
bool net_available(void);
uint32_t net_ip_addr(void);
void net_get_mac(uint8_t out[6]);

bool net_ping(uint32_t ip);
bool net_tcp_send_text(uint32_t ip, uint16_t port, const char *text);
void net_set_tcp_listen_port(uint16_t port);
uint16_t net_tcp_listen_port(void);

#endif
