#include <drivers/e1000.h>
#include <drivers/pit.h>
#include <kernel/console.h>
#include <kernel/log.h>
#include <kernel/mp.h>
#include <lib/string.h>
#include <memory/heap.h>
#include <net/net.h>

#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IPV4 0x0800

#define IPV4_PROTO_ICMP 1
#define IPV4_PROTO_TCP 6

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0

#define TCP_FLAG_FIN 0x001
#define TCP_FLAG_SYN 0x002
#define TCP_FLAG_RST 0x004
#define TCP_FLAG_PSH 0x008
#define TCP_FLAG_ACK 0x010

#define NET_ARP_CACHE_SIZE 16
#define NET_MAX_FRAME 1600
#define NET_MAX_TCP_CONN 8
#define NET_TCP_ACTIVE_RX_MAX 512
#define NET_TIMEOUT_STAGNANT_LIMIT 200000u

typedef struct eth_header {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
} __attribute__((packed)) eth_header_t;

typedef struct arp_packet {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
} __attribute__((packed)) arp_packet_t;

typedef struct ipv4_header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed)) ipv4_header_t;

typedef struct icmp_echo {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} __attribute__((packed)) icmp_echo_t;

typedef struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t offset_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} __attribute__((packed)) tcp_header_t;

typedef struct arp_entry {
    int valid;
    uint32_t ip;
    uint8_t mac[6];
    uint64_t updated;
} arp_entry_t;

typedef enum tcp_state {
    TCP_STATE_CLOSED = 0,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RCVD,
    TCP_STATE_ESTABLISHED
} tcp_state_t;

typedef struct tcp_conn {
    int used;
    int active_open;
    int established;
    uint32_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t snd_nxt;
    uint32_t rcv_nxt;
    uint8_t remote_mac[6];
    uint16_t rx_len;
    uint8_t rx_ready;
    char rx_data[NET_TCP_ACTIVE_RX_MAX];
    tcp_state_t state;
} tcp_conn_t;

typedef struct frame_job {
    size_t len;
    uint8_t data[];
} frame_job_t;

static int g_net_available;
static uint8_t g_mac[6];
static uint32_t g_ip = 0x0A00020F;       /* 10.0.2.15 */
static uint32_t g_mask = 0xFFFFFF00;     /* /24 */
static uint32_t g_gateway = 0x0A000202;  /* 10.0.2.2 */

static volatile uint32_t g_net_lock;
static volatile uint32_t g_tick_lock;
static arp_entry_t g_arp[NET_ARP_CACHE_SIZE];

static volatile int g_ping_waiting;
static volatile uint32_t g_ping_ip;
static volatile uint16_t g_ping_seq;
static volatile int g_ping_result;

static tcp_conn_t g_tcp[NET_MAX_TCP_CONN];
static uint16_t g_tcp_listen_port = 8080;
static uint16_t g_tcp_next_ephemeral = 49152;

static inline uint16_t bswap16(uint16_t value) {
    return (uint16_t)((value << 8) | (value >> 8));
}

static inline uint32_t bswap32(uint32_t value) {
    return ((value & 0x000000FFu) << 24) |
           ((value & 0x0000FF00u) << 8) |
           ((value & 0x00FF0000u) >> 8) |
           ((value & 0xFF000000u) >> 24);
}

static inline uint16_t htons(uint16_t value) {
    return bswap16(value);
}

static inline uint16_t ntohs(uint16_t value) {
    return bswap16(value);
}

static inline uint32_t htonl(uint32_t value) {
    return bswap32(value);
}

static inline uint32_t ntohl(uint32_t value) {
    return bswap32(value);
}

static void spin_lock(volatile uint32_t *lock) {
    while (__atomic_test_and_set(lock, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause");
    }
}

static void spin_unlock(volatile uint32_t *lock) {
    __atomic_clear(lock, __ATOMIC_RELEASE);
}

static uint16_t checksum16(const void *data, size_t len) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t sum = 0;

    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint16_t)bytes[i] << 8) | bytes[i + 1];
    }
    if (len & 1) {
        sum += (uint16_t)bytes[len - 1] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

static uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip, const void *segment, size_t seg_len) {
    uint32_t sum = 0;

    uint32_t src_n = htonl(src_ip);
    uint32_t dst_n = htonl(dst_ip);

    sum += (src_n >> 16) & 0xFFFFu;
    sum += src_n & 0xFFFFu;
    sum += (dst_n >> 16) & 0xFFFFu;
    sum += dst_n & 0xFFFFu;
    sum += IPV4_PROTO_TCP;
    sum += (uint16_t)seg_len;

    const uint8_t *bytes = (const uint8_t *)segment;
    for (size_t i = 0; i + 1 < seg_len; i += 2) {
        sum += ((uint16_t)bytes[i] << 8) | bytes[i + 1];
    }
    if (seg_len & 1) {
        sum += (uint16_t)bytes[seg_len - 1] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static int mac_equal(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

static void arp_update(uint32_t ip, const uint8_t mac[6]) {
    uint32_t slot = 0;
    uint64_t oldest = (uint64_t)-1;

    for (uint32_t i = 0; i < NET_ARP_CACHE_SIZE; i++) {
        if (g_arp[i].valid && g_arp[i].ip == ip) {
            memcpy(g_arp[i].mac, mac, 6);
            g_arp[i].updated = pit_ticks();
            return;
        }
        if (!g_arp[i].valid) {
            slot = i;
            oldest = 0;
        } else if (oldest != 0 && g_arp[i].updated < oldest) {
            oldest = g_arp[i].updated;
            slot = i;
        }
    }

    g_arp[slot].valid = 1;
    g_arp[slot].ip = ip;
    memcpy(g_arp[slot].mac, mac, 6);
    g_arp[slot].updated = pit_ticks();
}

static int arp_lookup(uint32_t ip, uint8_t mac[6]) {
    int found = 0;

    spin_lock(&g_net_lock);
    for (uint32_t i = 0; i < NET_ARP_CACHE_SIZE; i++) {
        if (g_arp[i].valid && g_arp[i].ip == ip) {
            memcpy(mac, g_arp[i].mac, 6);
            found = 1;
            break;
        }
    }
    spin_unlock(&g_net_lock);

    return found;
}

static int send_frame(const uint8_t dst_mac[6], uint16_t eth_type, const void *payload, size_t payload_len) {
    size_t frame_len = sizeof(eth_header_t) + payload_len;
    if (frame_len < 60) {
        frame_len = 60;
    }

    uint8_t *frame = (uint8_t *)kmalloc(frame_len);
    if (!frame) {
        return -1;
    }
    memset(frame, 0, frame_len);

    eth_header_t *eth = (eth_header_t *)frame;
    memcpy(eth->dst, dst_mac, 6);
    memcpy(eth->src, g_mac, 6);
    eth->type = htons(eth_type);

    memcpy(frame + sizeof(eth_header_t), payload, payload_len);
    int sent = e1000_send_raw(frame, frame_len);
    kfree(frame);
    return sent;
}

static int send_arp_request(uint32_t target_ip) {
    uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    arp_packet_t arp;
    memset(&arp, 0, sizeof(arp));

    arp.htype = htons(1);
    arp.ptype = htons(ETH_TYPE_IPV4);
    arp.hlen = 6;
    arp.plen = 4;
    arp.opcode = htons(1);
    memcpy(arp.sender_mac, g_mac, 6);
    arp.sender_ip = htonl(g_ip);
    arp.target_ip = htonl(target_ip);

    return send_frame(broadcast, ETH_TYPE_ARP, &arp, sizeof(arp));
}

static int send_arp_reply(const uint8_t dst_mac[6], uint32_t dst_ip) {
    arp_packet_t arp;
    memset(&arp, 0, sizeof(arp));

    arp.htype = htons(1);
    arp.ptype = htons(ETH_TYPE_IPV4);
    arp.hlen = 6;
    arp.plen = 4;
    arp.opcode = htons(2);
    memcpy(arp.sender_mac, g_mac, 6);
    arp.sender_ip = htonl(g_ip);
    memcpy(arp.target_mac, dst_mac, 6);
    arp.target_ip = htonl(dst_ip);

    return send_frame(dst_mac, ETH_TYPE_ARP, &arp, sizeof(arp));
}

static int route_to(uint32_t dst_ip, uint32_t *next_hop) {
    if ((dst_ip & g_mask) == (g_ip & g_mask)) {
        *next_hop = dst_ip;
    } else {
        *next_hop = g_gateway;
    }
    return 1;
}

static int resolve_mac(uint32_t dst_ip, uint8_t out_mac[6], uint64_t timeout_ticks) {
    uint32_t next_hop = 0;
    if (!route_to(dst_ip, &next_hop)) {
        return 0;
    }

    if (arp_lookup(next_hop, out_mac)) {
        return 1;
    }

    send_arp_request(next_hop);

    uint64_t deadline = pit_ticks() + timeout_ticks;
    uint64_t last_tick = pit_ticks();
    uint32_t stagnant = 0;
    while (pit_ticks() < deadline) {
        uint64_t now = pit_ticks();
        if (now == last_tick) {
            if (++stagnant > NET_TIMEOUT_STAGNANT_LIMIT) {
                break;
            }
        } else {
            last_tick = now;
            stagnant = 0;
        }
        net_tick();
        if (arp_lookup(next_hop, out_mac)) {
            return 1;
        }
        mp_service_one_work();
    }
    return 0;
}

static int send_ipv4_to_mac(const uint8_t dst_mac[6], uint32_t dst_ip, uint8_t proto,
                            const void *payload, size_t payload_len, uint16_t ident, uint8_t ttl) {
    size_t ip_len = sizeof(ipv4_header_t) + payload_len;
    if (ip_len > 1500) {
        return -1;
    }

    uint8_t *packet = (uint8_t *)kmalloc(ip_len);
    if (!packet) {
        return -1;
    }

    ipv4_header_t *ip = (ipv4_header_t *)packet;
    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->total_length = htons((uint16_t)ip_len);
    ip->identification = htons(ident);
    ip->flags_fragment = htons(0x4000);
    ip->ttl = ttl;
    ip->protocol = proto;
    ip->checksum = 0;
    ip->src_ip = htonl(g_ip);
    ip->dst_ip = htonl(dst_ip);

    memcpy(packet + sizeof(ipv4_header_t), payload, payload_len);
    ip->checksum = checksum16(packet, sizeof(ipv4_header_t));

    int sent = send_frame(dst_mac, ETH_TYPE_IPV4, packet, ip_len);
    kfree(packet);
    return sent;
}

static int send_ipv4(uint32_t dst_ip, uint8_t proto, const void *payload, size_t payload_len,
                     uint16_t ident, uint8_t ttl) {
    uint8_t dst_mac[6];
    if (!resolve_mac(dst_ip, dst_mac, 200)) {
        return -1;
    }
    return send_ipv4_to_mac(dst_mac, dst_ip, proto, payload, payload_len, ident, ttl);
}

static tcp_conn_t *tcp_find(uint32_t remote_ip, uint16_t remote_port, uint16_t local_port) {
    for (int i = 0; i < NET_MAX_TCP_CONN; i++) {
        if (!g_tcp[i].used) {
            continue;
        }
        if (g_tcp[i].remote_ip == remote_ip &&
            g_tcp[i].remote_port == remote_port &&
            g_tcp[i].local_port == local_port) {
            return &g_tcp[i];
        }
    }
    return 0;
}

static tcp_conn_t *tcp_alloc(void) {
    for (int i = 0; i < NET_MAX_TCP_CONN; i++) {
        if (!g_tcp[i].used) {
            memset(&g_tcp[i], 0, sizeof(g_tcp[i]));
            g_tcp[i].used = 1;
            g_tcp[i].state = TCP_STATE_CLOSED;
            return &g_tcp[i];
        }
    }
    return 0;
}

static int tcp_send_segment(tcp_conn_t *conn, uint16_t flags, const void *payload, size_t payload_len,
                            uint32_t seq, uint32_t ack) {
    size_t seg_len = sizeof(tcp_header_t) + payload_len;
    uint8_t *segment = (uint8_t *)kmalloc(seg_len);
    if (!segment) {
        return -1;
    }

    tcp_header_t *tcp = (tcp_header_t *)segment;
    memset(tcp, 0, sizeof(*tcp));
    tcp->src_port = htons(conn->local_port);
    tcp->dst_port = htons(conn->remote_port);
    tcp->seq = htonl(seq);
    tcp->ack = htonl(ack);
    tcp->offset_flags = htons((uint16_t)((5u << 12) | (flags & 0x1FFu)));
    tcp->window = htons(65535);

    if (payload_len) {
        memcpy(segment + sizeof(tcp_header_t), payload, payload_len);
    }

    tcp->checksum = 0;
    tcp->checksum = tcp_checksum(g_ip, conn->remote_ip, segment, seg_len);

    int sent = send_ipv4_to_mac(conn->remote_mac, conn->remote_ip, IPV4_PROTO_TCP,
                                segment, seg_len, (uint16_t)(pit_ticks() & 0xFFFFu), 64);
    kfree(segment);
    return sent;
}

static void handle_icmp(uint32_t src_ip, const uint8_t src_mac[6], const uint8_t *payload, size_t len) {
    if (len < sizeof(icmp_echo_t)) {
        return;
    }

    const icmp_echo_t *icmp = (const icmp_echo_t *)payload;

    if (icmp->type == ICMP_ECHO_REQUEST) {
        uint8_t *reply = (uint8_t *)kmalloc(len);
        if (!reply) {
            return;
        }
        memcpy(reply, payload, len);

        icmp_echo_t *echo = (icmp_echo_t *)reply;
        echo->type = ICMP_ECHO_REPLY;
        echo->checksum = 0;
        echo->checksum = checksum16(reply, len);

        send_ipv4_to_mac(src_mac, src_ip, IPV4_PROTO_ICMP, reply, len,
                         (uint16_t)(pit_ticks() & 0xFFFFu), 64);
        kfree(reply);
        return;
    }

    if (icmp->type == ICMP_ECHO_REPLY) {
        uint16_t seq = ntohs(icmp->seq);
        if (g_ping_waiting && src_ip == g_ping_ip && seq == g_ping_seq) {
            g_ping_result = 1;
            g_ping_waiting = 0;
        }
    }
}

static void tcp_close(tcp_conn_t *conn) {
    if (!conn) {
        return;
    }
    memset(conn, 0, sizeof(*conn));
}

static void handle_tcp(uint32_t src_ip, const uint8_t src_mac[6], const uint8_t *payload, size_t len) {
    if (len < sizeof(tcp_header_t)) {
        return;
    }

    const tcp_header_t *tcp = (const tcp_header_t *)payload;
    uint16_t src_port = ntohs(tcp->src_port);
    uint16_t dst_port = ntohs(tcp->dst_port);
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack = ntohl(tcp->ack);

    uint16_t off_flags = ntohs(tcp->offset_flags);
    uint8_t data_offset = (uint8_t)((off_flags >> 12) & 0x0F);
    uint16_t flags = off_flags & 0x01FF;

    size_t hdr_len = (size_t)data_offset * 4;
    if (hdr_len < sizeof(tcp_header_t) || hdr_len > len) {
        return;
    }

    const uint8_t *data = payload + hdr_len;
    size_t data_len = len - hdr_len;

    tcp_conn_t *conn = tcp_find(src_ip, src_port, dst_port);

    if (!conn && (flags & TCP_FLAG_SYN) && dst_port == g_tcp_listen_port) {
        conn = tcp_alloc();
        if (!conn) {
            return;
        }

        conn->active_open = 0;
        conn->remote_ip = src_ip;
        conn->remote_port = src_port;
        conn->local_port = dst_port;
        conn->rcv_nxt = seq + 1;
        conn->snd_nxt = 0x10000000u + ((uint32_t)pit_ticks() & 0xFFFFu);
        memcpy(conn->remote_mac, src_mac, 6);
        conn->state = TCP_STATE_SYN_RCVD;

        tcp_send_segment(conn, TCP_FLAG_SYN | TCP_FLAG_ACK, 0, 0, conn->snd_nxt, conn->rcv_nxt);
        conn->snd_nxt += 1;
        return;
    }

    if (!conn) {
        return;
    }

    if (conn->state == TCP_STATE_SYN_SENT) {
        if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK) && ack == conn->snd_nxt) {
            conn->rcv_nxt = seq + 1;
            memcpy(conn->remote_mac, src_mac, 6);
            tcp_send_segment(conn, TCP_FLAG_ACK, 0, 0, conn->snd_nxt, conn->rcv_nxt);
            conn->state = TCP_STATE_ESTABLISHED;
            conn->established = 1;
        }
        return;
    }

    if (conn->state == TCP_STATE_SYN_RCVD) {
        if ((flags & TCP_FLAG_ACK) && ack == conn->snd_nxt) {
            conn->state = TCP_STATE_ESTABLISHED;
            conn->established = 1;
        }
        return;
    }

    if (conn->state != TCP_STATE_ESTABLISHED) {
        return;
    }

    if (flags & TCP_FLAG_FIN) {
        conn->rcv_nxt = seq + 1;
        tcp_send_segment(conn, TCP_FLAG_ACK, 0, 0, conn->snd_nxt, conn->rcv_nxt);
        tcp_send_segment(conn, TCP_FLAG_FIN | TCP_FLAG_ACK, 0, 0, conn->snd_nxt, conn->rcv_nxt);
        conn->snd_nxt += 1;
        tcp_close(conn);
        return;
    }

    if (data_len > 0) {
        conn->rcv_nxt = seq + (uint32_t)data_len;
        tcp_send_segment(conn, TCP_FLAG_ACK, 0, 0, conn->snd_nxt, conn->rcv_nxt);

        if (conn->active_open) {
            size_t avail = sizeof(conn->rx_data) - 1u;
            if (conn->rx_len < avail) {
                size_t copy = data_len;
                if (copy > avail - conn->rx_len) {
                    copy = avail - conn->rx_len;
                }
                if (copy > 0) {
                    memcpy(conn->rx_data + conn->rx_len, data, copy);
                    conn->rx_len += (uint16_t)copy;
                    conn->rx_data[conn->rx_len] = '\0';
                    conn->rx_ready = 1;
                }
            }
        } else {
            tcp_send_segment(conn, TCP_FLAG_PSH | TCP_FLAG_ACK, data, data_len, conn->snd_nxt, conn->rcv_nxt);
            conn->snd_nxt += (uint32_t)data_len;
        }
    }
}

static void handle_ipv4(const uint8_t src_mac[6], const uint8_t *payload, size_t len) {
    if (len < sizeof(ipv4_header_t)) {
        return;
    }

    const ipv4_header_t *ip = (const ipv4_header_t *)payload;
    uint8_t version = ip->version_ihl >> 4;
    uint8_t ihl = ip->version_ihl & 0x0F;
    if (version != 4 || ihl < 5) {
        return;
    }

    size_t hdr_len = (size_t)ihl * 4;
    uint16_t total_len = ntohs(ip->total_length);
    if (hdr_len > len || total_len < hdr_len || total_len > len) {
        return;
    }

    uint32_t src_ip = ntohl(ip->src_ip);
    uint32_t dst_ip = ntohl(ip->dst_ip);

    arp_update(src_ip, src_mac);

    if (dst_ip != g_ip) {
        return;
    }

    const uint8_t *ip_payload = payload + hdr_len;
    size_t ip_payload_len = total_len - hdr_len;

    if (ip->protocol == IPV4_PROTO_ICMP) {
        handle_icmp(src_ip, src_mac, ip_payload, ip_payload_len);
    } else if (ip->protocol == IPV4_PROTO_TCP) {
        handle_tcp(src_ip, src_mac, ip_payload, ip_payload_len);
    }
}

static void process_frame(const uint8_t *frame, size_t len) {
    if (len < sizeof(eth_header_t)) {
        return;
    }

    const eth_header_t *eth = (const eth_header_t *)frame;
    uint16_t type = ntohs(eth->type);

    if (!mac_equal(eth->dst, g_mac)) {
        static const uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        if (!mac_equal(eth->dst, broadcast)) {
            return;
        }
    }

    const uint8_t *payload = frame + sizeof(eth_header_t);
    size_t payload_len = len - sizeof(eth_header_t);

    if (type == ETH_TYPE_ARP) {
        if (payload_len < sizeof(arp_packet_t)) {
            return;
        }
        const arp_packet_t *arp = (const arp_packet_t *)payload;
        if (ntohs(arp->htype) != 1 || ntohs(arp->ptype) != ETH_TYPE_IPV4 || arp->hlen != 6 || arp->plen != 4) {
            return;
        }

        uint32_t sender_ip = ntohl(arp->sender_ip);
        uint32_t target_ip = ntohl(arp->target_ip);
        arp_update(sender_ip, arp->sender_mac);

        if (ntohs(arp->opcode) == 1 && target_ip == g_ip) {
            send_arp_reply(arp->sender_mac, sender_ip);
        }
        return;
    }

    if (type == ETH_TYPE_IPV4) {
        handle_ipv4(eth->src, payload, payload_len);
    }
}

static void frame_job_run(void *arg) {
    frame_job_t *job = (frame_job_t *)arg;

    spin_lock(&g_net_lock);
    process_frame(job->data, job->len);
    spin_unlock(&g_net_lock);

    kfree(job);
}

void net_init(void) {
    memset(g_arp, 0, sizeof(g_arp));
    memset(g_tcp, 0, sizeof(g_tcp));

    g_net_lock = 0;
    g_tick_lock = 0;
    g_ping_waiting = 0;
    g_ping_result = 0;

    if (!e1000_available()) {
        g_net_available = 0;
        return;
    }

    e1000_get_mac(g_mac);
    g_net_available = 1;
    kprintf("NET: up ip=%u.%u.%u.%u\n",
            (unsigned)((g_ip >> 24) & 0xFF), (unsigned)((g_ip >> 16) & 0xFF),
            (unsigned)((g_ip >> 8) & 0xFF), (unsigned)(g_ip & 0xFF));
}

void net_tick(void) {
    if (!g_net_available) {
        return;
    }
    if (__atomic_test_and_set(&g_tick_lock, __ATOMIC_ACQUIRE)) {
        return;
    }

    uint8_t frame[NET_MAX_FRAME];
    for (int i = 0; i < 16; i++) {
        int n = e1000_poll_receive(frame, sizeof(frame));
        if (n <= 0) {
            break;
        }

        frame_job_t *job = (frame_job_t *)kmalloc(sizeof(frame_job_t) + (size_t)n);
        if (!job) {
            spin_lock(&g_net_lock);
            process_frame(frame, (size_t)n);
            spin_unlock(&g_net_lock);
            continue;
        }

        job->len = (size_t)n;
        memcpy(job->data, frame, (size_t)n);

        if (!mp_submit_work(frame_job_run, job)) {
            frame_job_run(job);
        }
    }

    for (int i = 0; i < 4; i++) {
        if (!mp_service_one_work()) {
            break;
        }
    }

    __atomic_clear(&g_tick_lock, __ATOMIC_RELEASE);
}

bool net_available(void) {
    return g_net_available != 0;
}

uint32_t net_ip_addr(void) {
    return g_ip;
}

void net_get_mac(uint8_t out[6]) {
    memcpy(out, g_mac, 6);
}

bool net_ping(uint32_t ip) {
    if (!g_net_available) {
        return false;
    }

    uint8_t packet[64];
    memset(packet, 0, sizeof(packet));

    icmp_echo_t *icmp = (icmp_echo_t *)packet;
    icmp->type = ICMP_ECHO_REQUEST;
    icmp->code = 0;
    icmp->id = htons(0x4242);

    uint16_t seq;
    spin_lock(&g_net_lock);
    g_ping_seq += 1;
    if (g_ping_seq == 0) {
        g_ping_seq = 1;
    }
    seq = g_ping_seq;
    g_ping_waiting = 1;
    g_ping_ip = ip;
    g_ping_result = 0;
    spin_unlock(&g_net_lock);
    icmp->seq = htons(seq);

    for (size_t i = sizeof(icmp_echo_t); i < sizeof(packet); i++) {
        packet[i] = (uint8_t)i;
    }

    icmp->checksum = 0;
    icmp->checksum = checksum16(packet, sizeof(packet));

    if (send_ipv4(ip, IPV4_PROTO_ICMP, packet, sizeof(packet), (uint16_t)(pit_ticks() & 0xFFFFu), 64) < 0) {
        spin_lock(&g_net_lock);
        g_ping_waiting = 0;
        spin_unlock(&g_net_lock);
        return false;
    }

    uint64_t deadline = pit_ticks() + 300;
    uint64_t last_tick = pit_ticks();
    uint32_t stagnant = 0;
    while (pit_ticks() < deadline) {
        uint64_t now = pit_ticks();
        if (now == last_tick) {
            if (++stagnant > NET_TIMEOUT_STAGNANT_LIMIT) {
                break;
            }
        } else {
            last_tick = now;
            stagnant = 0;
        }
        int waiting;
        int result;
        spin_lock(&g_net_lock);
        waiting = g_ping_waiting;
        result = g_ping_result;
        spin_unlock(&g_net_lock);

        if (!waiting && result == 1) {
            return true;
        }
        net_tick();
    }

    spin_lock(&g_net_lock);
    g_ping_waiting = 0;
    spin_unlock(&g_net_lock);
    return false;
}

bool net_tcp_send_text(uint32_t ip, uint16_t port, const char *text) {
    return net_tcp_request_text(ip, port, text, 0, 0, 0);
}

bool net_tcp_request_text(uint32_t ip, uint16_t port, const char *request,
                          char *response, size_t response_len, uint32_t timeout_ticks) {
    if (!g_net_available || !request || port == 0) {
        return false;
    }
    if (response && response_len > 0) {
        response[0] = '\0';
    }

    uint8_t remote_mac[6];
    if (!resolve_mac(ip, remote_mac, 300)) {
        return false;
    }

    tcp_conn_t *conn = 0;
    uint16_t local_port = 0;
    spin_lock(&g_net_lock);
    conn = tcp_alloc();
    if (!conn) {
        spin_unlock(&g_net_lock);
        return false;
    }

    conn->active_open = 1;
    conn->remote_ip = ip;
    conn->remote_port = port;
    conn->local_port = g_tcp_next_ephemeral++;
    if (g_tcp_next_ephemeral < 49152) {
        g_tcp_next_ephemeral = 49152;
    }
    local_port = conn->local_port;
    conn->snd_nxt = 0x20000000u + ((uint32_t)pit_ticks() & 0xFFFFu);
    conn->rcv_nxt = 0;
    conn->rx_len = 0;
    conn->rx_ready = 0;
    conn->rx_data[0] = '\0';
    memcpy(conn->remote_mac, remote_mac, 6);
    conn->state = TCP_STATE_SYN_SENT;
    spin_unlock(&g_net_lock);

    spin_lock(&g_net_lock);
    if (tcp_send_segment(conn, TCP_FLAG_SYN, 0, 0, conn->snd_nxt, 0) < 0) {
        tcp_close(conn);
        spin_unlock(&g_net_lock);
        return false;
    }
    conn->snd_nxt += 1;
    spin_unlock(&g_net_lock);

    uint64_t deadline = pit_ticks() + 500;
    uint64_t last_tick = pit_ticks();
    uint32_t stagnant = 0;
    while (pit_ticks() < deadline) {
        uint64_t now = pit_ticks();
        if (now == last_tick) {
            if (++stagnant > NET_TIMEOUT_STAGNANT_LIMIT) {
                break;
            }
        } else {
            last_tick = now;
            stagnant = 0;
        }
        int ready = 0;
        spin_lock(&g_net_lock);
        if (conn->used &&
            conn->remote_ip == ip &&
            conn->remote_port == port &&
            conn->local_port == local_port &&
            conn->established) {
            ready = 1;
        }
        spin_unlock(&g_net_lock);
        if (ready) {
            break;
        }
        net_tick();
    }

    spin_lock(&g_net_lock);
    if (!conn->used ||
        conn->remote_ip != ip ||
        conn->remote_port != port ||
        conn->local_port != local_port ||
        !conn->established) {
        tcp_close(conn);
        spin_unlock(&g_net_lock);
        return false;
    }

    size_t len = strlen(request);
    if (len > 1200) {
        len = 1200;
    }

    if (len > 0) {
        if (tcp_send_segment(conn, TCP_FLAG_PSH | TCP_FLAG_ACK, request, len, conn->snd_nxt, conn->rcv_nxt) < 0) {
            tcp_close(conn);
            spin_unlock(&g_net_lock);
            return false;
        }
        conn->snd_nxt += (uint32_t)len;
    }

    if (response && response_len > 1u) {
        spin_unlock(&g_net_lock);

        uint64_t timeout = timeout_ticks != 0 ? (uint64_t)timeout_ticks : 500u;
        uint64_t deadline_rx = pit_ticks() + timeout;
        uint64_t last_rx_tick = pit_ticks();
        uint32_t stagnant_rx = 0;
        int received = 0;
        while (pit_ticks() < deadline_rx) {
            uint64_t now = pit_ticks();
            if (now == last_rx_tick) {
                if (++stagnant_rx > NET_TIMEOUT_STAGNANT_LIMIT) {
                    break;
                }
            } else {
                last_rx_tick = now;
                stagnant_rx = 0;
            }
            spin_lock(&g_net_lock);
            if (conn->used &&
                conn->remote_ip == ip &&
                conn->remote_port == port &&
                conn->local_port == local_port &&
                conn->rx_len > 0) {
                size_t copy = conn->rx_len;
                if (copy >= response_len) {
                    copy = response_len - 1u;
                }
                memcpy(response, conn->rx_data, copy);
                response[copy] = '\0';
                received = 1;
                spin_unlock(&g_net_lock);
                break;
            }
            spin_unlock(&g_net_lock);
            net_tick();
        }

        spin_lock(&g_net_lock);
        if (!received) {
            if (conn->used &&
                conn->remote_ip == ip &&
                conn->remote_port == port &&
                conn->local_port == local_port) {
                (void)tcp_send_segment(conn, TCP_FLAG_FIN | TCP_FLAG_ACK, 0, 0, conn->snd_nxt, conn->rcv_nxt);
                conn->snd_nxt += 1;
                tcp_close(conn);
            }
            spin_unlock(&g_net_lock);
            return false;
        }
    }

    tcp_send_segment(conn, TCP_FLAG_FIN | TCP_FLAG_ACK, 0, 0, conn->snd_nxt, conn->rcv_nxt);
    conn->snd_nxt += 1;
    tcp_close(conn);
    spin_unlock(&g_net_lock);
    return true;
}

void net_set_tcp_listen_port(uint16_t port) {
    if (port == 0) {
        return;
    }
    spin_lock(&g_net_lock);
    g_tcp_listen_port = port;
    spin_unlock(&g_net_lock);
}

uint16_t net_tcp_listen_port(void) {
    uint16_t port;
    spin_lock(&g_net_lock);
    port = g_tcp_listen_port;
    spin_unlock(&g_net_lock);
    return port;
}
