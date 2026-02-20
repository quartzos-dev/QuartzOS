#ifndef DRIVERS_PCI_H
#define DRIVERS_PCI_H

#include <stdbool.h>
#include <stdint.h>

typedef struct pci_device_info {
    uint8_t bus;
    uint8_t slot;
    uint8_t function;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t class_code;
    uint8_t subclass;
    uint8_t prog_if;
    uint8_t header_type;
    uint8_t irq_line;
    uint32_t bar[6];
} pci_device_info_t;

void pci_init(void);
uint32_t pci_config_read32(uint8_t bus, uint8_t slot, uint8_t function, uint8_t offset);
void pci_config_write32(uint8_t bus, uint8_t slot, uint8_t function, uint8_t offset, uint32_t value);
bool pci_find_device(uint16_t vendor_id, uint16_t device_id, pci_device_info_t *out);
void pci_enable_device(const pci_device_info_t *dev);

#endif
