#include <drivers/e1000.h>
#include <drivers/pci.h>
#include <kernel/log.h>
#include <lib/string.h>
#include <memory/heap.h>
#include <memory/vmm.h>

#define E1000_VENDOR_ID 0x8086
#define E1000_MMIO_MAP_BASE 0xffffc20000000000ULL
#define E1000_MMIO_MAP_SIZE 0x20000ULL

#define E1000_REG_CTRL 0x0000
#define E1000_REG_STATUS 0x0008
#define E1000_REG_ICR 0x00C0
#define E1000_REG_IMS 0x00D0
#define E1000_REG_RCTL 0x0100
#define E1000_REG_TCTL 0x0400
#define E1000_REG_TIPG 0x0410
#define E1000_REG_RAL 0x5400
#define E1000_REG_RAH 0x5404
#define E1000_REG_RDBAL 0x2800
#define E1000_REG_RDBAH 0x2804
#define E1000_REG_RDLEN 0x2808
#define E1000_REG_RDH 0x2810
#define E1000_REG_RDT 0x2818
#define E1000_REG_TDBAL 0x3800
#define E1000_REG_TDBAH 0x3804
#define E1000_REG_TDLEN 0x3808
#define E1000_REG_TDH 0x3810
#define E1000_REG_TDT 0x3818

#define E1000_CTRL_RST (1u << 26)

#define E1000_RCTL_EN (1u << 1)
#define E1000_RCTL_UPE (1u << 3)
#define E1000_RCTL_MPE (1u << 4)
#define E1000_RCTL_BAM (1u << 15)
#define E1000_RCTL_SECRC (1u << 26)

#define E1000_TCTL_EN (1u << 1)
#define E1000_TCTL_PSP (1u << 3)

#define E1000_TX_CMD_EOP 0x01
#define E1000_TX_CMD_IFCS 0x02
#define E1000_TX_CMD_RS 0x08
#define E1000_TX_STATUS_DD 0x01
#define E1000_RX_STATUS_DD 0x01

#define E1000_NUM_RX_DESC 32
#define E1000_NUM_TX_DESC 32
#define E1000_BUF_SIZE 2048

typedef struct e1000_rx_desc {
    uint64_t addr;
    uint16_t length;
    uint16_t checksum;
    uint8_t status;
    uint8_t errors;
    uint16_t special;
} __attribute__((packed)) e1000_rx_desc_t;

typedef struct e1000_tx_desc {
    uint64_t addr;
    uint16_t length;
    uint8_t cso;
    uint8_t cmd;
    uint8_t status;
    uint8_t css;
    uint16_t special;
} __attribute__((packed)) e1000_tx_desc_t;

static volatile uint8_t *g_mmio;
static int g_available;
static int g_irq_line = -1;
static volatile uint32_t g_tx_lock;
static pci_device_info_t g_dev;

static e1000_rx_desc_t *g_rx_desc;
static e1000_tx_desc_t *g_tx_desc;
static uint8_t *g_rx_buf[E1000_NUM_RX_DESC];
static uint8_t *g_tx_buf[E1000_NUM_TX_DESC];
static uint32_t g_rx_index;

static void tx_lock(void) {
    while (__atomic_test_and_set(&g_tx_lock, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause");
    }
}

static void tx_unlock(void) {
    __atomic_clear(&g_tx_lock, __ATOMIC_RELEASE);
}

static inline uint32_t mmio_read(uint32_t reg) {
    return *(volatile uint32_t *)(g_mmio + reg);
}

static inline void mmio_write(uint32_t reg, uint32_t value) {
    *(volatile uint32_t *)(g_mmio + reg) = value;
}

static int find_supported_device(pci_device_info_t *out) {
    static const uint16_t dev_ids[] = {0x100E, 0x100F, 0x1010, 0x10D3, 0x10EA, 0x153A};

    for (size_t i = 0; i < sizeof(dev_ids) / sizeof(dev_ids[0]); i++) {
        if (pci_find_device(E1000_VENDOR_ID, dev_ids[i], out)) {
            return 1;
        }
    }
    return 0;
}

static int setup_rx(void) {
    g_rx_desc = (e1000_rx_desc_t *)kmalloc(sizeof(e1000_rx_desc_t) * E1000_NUM_RX_DESC);
    if (!g_rx_desc) {
        return 0;
    }
    memset(g_rx_desc, 0, sizeof(e1000_rx_desc_t) * E1000_NUM_RX_DESC);

    for (uint32_t i = 0; i < E1000_NUM_RX_DESC; i++) {
        g_rx_buf[i] = (uint8_t *)kmalloc(E1000_BUF_SIZE);
        if (!g_rx_buf[i]) {
            return 0;
        }
        memset(g_rx_buf[i], 0, E1000_BUF_SIZE);

        uint64_t phys = vmm_translate((uint64_t)g_rx_buf[i]);
        if (!phys) {
            return 0;
        }
        g_rx_desc[i].addr = phys;
        g_rx_desc[i].status = 0;
    }

    uint64_t ring_phys = vmm_translate((uint64_t)g_rx_desc);
    if (!ring_phys) {
        return 0;
    }

    mmio_write(E1000_REG_RDBAL, (uint32_t)(ring_phys & 0xFFFFFFFFu));
    mmio_write(E1000_REG_RDBAH, (uint32_t)(ring_phys >> 32));
    mmio_write(E1000_REG_RDLEN, E1000_NUM_RX_DESC * sizeof(e1000_rx_desc_t));
    mmio_write(E1000_REG_RDH, 0);
    mmio_write(E1000_REG_RDT, E1000_NUM_RX_DESC - 1);

    mmio_write(E1000_REG_RCTL, E1000_RCTL_EN | E1000_RCTL_UPE | E1000_RCTL_MPE | E1000_RCTL_BAM | E1000_RCTL_SECRC);

    g_rx_index = 0;
    return 1;
}

static int setup_tx(void) {
    g_tx_desc = (e1000_tx_desc_t *)kmalloc(sizeof(e1000_tx_desc_t) * E1000_NUM_TX_DESC);
    if (!g_tx_desc) {
        return 0;
    }
    memset(g_tx_desc, 0, sizeof(e1000_tx_desc_t) * E1000_NUM_TX_DESC);

    for (uint32_t i = 0; i < E1000_NUM_TX_DESC; i++) {
        g_tx_buf[i] = (uint8_t *)kmalloc(E1000_BUF_SIZE);
        if (!g_tx_buf[i]) {
            return 0;
        }
        memset(g_tx_buf[i], 0, E1000_BUF_SIZE);

        uint64_t phys = vmm_translate((uint64_t)g_tx_buf[i]);
        if (!phys) {
            return 0;
        }
        g_tx_desc[i].addr = phys;
        g_tx_desc[i].status = E1000_TX_STATUS_DD;
    }

    uint64_t ring_phys = vmm_translate((uint64_t)g_tx_desc);
    if (!ring_phys) {
        return 0;
    }

    mmio_write(E1000_REG_TDBAL, (uint32_t)(ring_phys & 0xFFFFFFFFu));
    mmio_write(E1000_REG_TDBAH, (uint32_t)(ring_phys >> 32));
    mmio_write(E1000_REG_TDLEN, E1000_NUM_TX_DESC * sizeof(e1000_tx_desc_t));
    mmio_write(E1000_REG_TDH, 0);
    mmio_write(E1000_REG_TDT, 0);

    mmio_write(E1000_REG_TCTL, E1000_TCTL_EN | E1000_TCTL_PSP | (0x10u << 4) | (0x40u << 12));
    mmio_write(E1000_REG_TIPG, 0x0060200A);
    return 1;
}

void e1000_init(void) {
    g_available = 0;
    g_irq_line = -1;
    memset(&g_dev, 0, sizeof(g_dev));

    if (!find_supported_device(&g_dev)) {
        return;
    }

    pci_enable_device(&g_dev);

    uint32_t bar0 = g_dev.bar[0];
    if (bar0 & 0x1u) {
        return;
    }

    uint64_t mmio_phys;
    if ((bar0 & 0x6u) == 0x4u) {
        uint64_t bar1 = (uint64_t)g_dev.bar[1];
        mmio_phys = (bar1 << 32) | (uint64_t)(bar0 & ~0x0Fu);
    } else {
        mmio_phys = (uint64_t)(bar0 & ~0x0Fu);
    }
    if (mmio_phys == 0) {
        return;
    }

    vmm_map_range(E1000_MMIO_MAP_BASE, mmio_phys, E1000_MMIO_MAP_SIZE,
                  VMM_PRESENT | VMM_WRITE | VMM_NX);
    g_mmio = (volatile uint8_t *)E1000_MMIO_MAP_BASE;

    uint32_t ctrl = mmio_read(E1000_REG_CTRL);
    mmio_write(E1000_REG_CTRL, ctrl | E1000_CTRL_RST);
    for (volatile int i = 0; i < 1000000; i++) {
    }

    (void)mmio_read(E1000_REG_STATUS);
    (void)mmio_read(E1000_REG_ICR);
    mmio_write(E1000_REG_IMS, 0);

    if (!setup_rx() || !setup_tx()) {
        return;
    }

    mmio_write(E1000_REG_IMS, (1u << 2) | (1u << 4) | (1u << 7));
    (void)mmio_read(E1000_REG_ICR);

    g_available = 1;
    g_irq_line = (g_dev.irq_line == 0xFFu) ? -1 : (int)g_dev.irq_line;
    kprintf("e1000: enabled at %x:%x.%x irq=%u\n", g_dev.bus, g_dev.slot, g_dev.function, g_dev.irq_line);
}

void e1000_handle_irq(void) {
    if (!g_available) {
        return;
    }
    (void)mmio_read(E1000_REG_ICR);
}

bool e1000_available(void) {
    return g_available != 0;
}

int e1000_irq_line(void) {
    return g_irq_line;
}

void e1000_get_mac(uint8_t out[6]) {
    for (int i = 0; i < 6; i++) {
        out[i] = 0;
    }

    if (!g_available) {
        return;
    }

    uint32_t ral = mmio_read(E1000_REG_RAL);
    uint32_t rah = mmio_read(E1000_REG_RAH);

    out[0] = (uint8_t)(ral & 0xFFu);
    out[1] = (uint8_t)((ral >> 8) & 0xFFu);
    out[2] = (uint8_t)((ral >> 16) & 0xFFu);
    out[3] = (uint8_t)((ral >> 24) & 0xFFu);
    out[4] = (uint8_t)(rah & 0xFFu);
    out[5] = (uint8_t)((rah >> 8) & 0xFFu);
}

int e1000_send_raw(const uint8_t *frame, size_t len) {
    if (!g_available || !frame || len == 0 || len > E1000_BUF_SIZE) {
        return -1;
    }

    tx_lock();

    uint32_t tail = mmio_read(E1000_REG_TDT);
    e1000_tx_desc_t *desc = &g_tx_desc[tail];

    if ((desc->status & E1000_TX_STATUS_DD) == 0) {
        tx_unlock();
        return -1;
    }

    memcpy(g_tx_buf[tail], frame, len);

    desc->length = (uint16_t)len;
    desc->cmd = E1000_TX_CMD_EOP | E1000_TX_CMD_IFCS | E1000_TX_CMD_RS;
    desc->status = 0;

    uint32_t next_tail = (tail + 1) % E1000_NUM_TX_DESC;
    mmio_write(E1000_REG_TDT, next_tail);

    for (uint32_t spin = 0; spin < 1000000; spin++) {
        if (desc->status & E1000_TX_STATUS_DD) {
            tx_unlock();
            return (int)len;
        }
    }

    tx_unlock();
    return -1;
}

int e1000_poll_receive(uint8_t *out, size_t out_len) {
    if (!g_available || !out || out_len == 0) {
        return -1;
    }

    e1000_rx_desc_t *desc = &g_rx_desc[g_rx_index];
    if ((desc->status & E1000_RX_STATUS_DD) == 0) {
        return 0;
    }

    size_t len = desc->length;
    if (len > out_len) {
        len = out_len;
    }

    memcpy(out, g_rx_buf[g_rx_index], len);

    desc->status = 0;
    mmio_write(E1000_REG_RDT, g_rx_index);
    g_rx_index = (g_rx_index + 1) % E1000_NUM_RX_DESC;

    return (int)len;
}
