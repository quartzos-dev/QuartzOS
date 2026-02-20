#ifndef DRIVERS_ATA_H
#define DRIVERS_ATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void ata_init(void);
bool ata_present(void);
bool ata_read28(uint32_t lba, uint8_t sector_count, void *buffer);
bool ata_write28(uint32_t lba, uint8_t sector_count, const void *buffer);

#endif
