#include <arch/x86_64/io.h>
#include <drivers/pci.h>
#include <lib/string.h>

#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA 0xCFC

#define PCI_VENDOR_INVALID 0xFFFFu

static uint32_t pci_make_addr(uint8_t bus, uint8_t slot, uint8_t function, uint8_t offset) {
    return (uint32_t)(1u << 31) |
           ((uint32_t)bus << 16) |
           ((uint32_t)slot << 11) |
           ((uint32_t)function << 8) |
           ((uint32_t)offset & 0xFCu);
}

uint32_t pci_config_read32(uint8_t bus, uint8_t slot, uint8_t function, uint8_t offset) {
    outl(PCI_CONFIG_ADDRESS, pci_make_addr(bus, slot, function, offset));
    return inl(PCI_CONFIG_DATA);
}

void pci_config_write32(uint8_t bus, uint8_t slot, uint8_t function, uint8_t offset, uint32_t value) {
    outl(PCI_CONFIG_ADDRESS, pci_make_addr(bus, slot, function, offset));
    outl(PCI_CONFIG_DATA, value);
}

static uint16_t pci_vendor_id(uint8_t bus, uint8_t slot, uint8_t function) {
    return (uint16_t)(pci_config_read32(bus, slot, function, 0x00) & 0xFFFFu);
}

static uint8_t pci_header_type(uint8_t bus, uint8_t slot, uint8_t function) {
    uint32_t value = pci_config_read32(bus, slot, function, 0x0C);
    return (uint8_t)((value >> 16) & 0xFFu);
}

static void pci_fill_device(uint8_t bus, uint8_t slot, uint8_t function, pci_device_info_t *out) {
    memset(out, 0, sizeof(*out));

    uint32_t id = pci_config_read32(bus, slot, function, 0x00);
    uint32_t class_reg = pci_config_read32(bus, slot, function, 0x08);
    uint32_t hdr = pci_config_read32(bus, slot, function, 0x0C);
    uint32_t int_line = pci_config_read32(bus, slot, function, 0x3C);

    out->bus = bus;
    out->slot = slot;
    out->function = function;
    out->vendor_id = (uint16_t)(id & 0xFFFFu);
    out->device_id = (uint16_t)((id >> 16) & 0xFFFFu);
    out->prog_if = (uint8_t)((class_reg >> 8) & 0xFFu);
    out->subclass = (uint8_t)((class_reg >> 16) & 0xFFu);
    out->class_code = (uint8_t)((class_reg >> 24) & 0xFFu);
    out->header_type = (uint8_t)((hdr >> 16) & 0xFFu);
    out->irq_line = (uint8_t)(int_line & 0xFFu);

    uint8_t bar_count = (out->header_type & 0x7F) == 0x00 ? 6 : 2;
    for (uint8_t i = 0; i < bar_count; i++) {
        out->bar[i] = pci_config_read32(bus, slot, function, (uint8_t)(0x10 + i * 4));
    }
}

bool pci_find_device(uint16_t vendor_id, uint16_t device_id, pci_device_info_t *out) {
    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t slot = 0; slot < 32; slot++) {
            uint16_t ven0 = pci_vendor_id((uint8_t)bus, slot, 0);
            if (ven0 == PCI_VENDOR_INVALID) {
                continue;
            }

            uint8_t header = pci_header_type((uint8_t)bus, slot, 0);
            uint8_t max_functions = (header & 0x80) ? 8 : 1;

            for (uint8_t function = 0; function < max_functions; function++) {
                uint32_t id = pci_config_read32((uint8_t)bus, slot, function, 0x00);
                uint16_t ven = (uint16_t)(id & 0xFFFFu);
                uint16_t dev = (uint16_t)((id >> 16) & 0xFFFFu);
                if (ven == PCI_VENDOR_INVALID) {
                    continue;
                }
                if (ven == vendor_id && dev == device_id) {
                    if (out) {
                        pci_fill_device((uint8_t)bus, slot, function, out);
                    }
                    return true;
                }
            }
        }
    }
    return false;
}

void pci_enable_device(const pci_device_info_t *dev) {
    if (!dev) {
        return;
    }

    uint32_t cmd = pci_config_read32(dev->bus, dev->slot, dev->function, 0x04);
    cmd |= 0x00000007u;
    cmd |= (1u << 10);
    pci_config_write32(dev->bus, dev->slot, dev->function, 0x04, cmd);
}

void pci_init(void) {
}
