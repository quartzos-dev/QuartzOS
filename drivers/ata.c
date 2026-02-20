#include <arch/x86_64/io.h>
#include <drivers/ata.h>
#include <lib/string.h>

#define ATA_PRIMARY_IO 0x1F0
#define ATA_PRIMARY_CTRL 0x3F6

#define ATA_REG_DATA 0
#define ATA_REG_ERROR 1
#define ATA_REG_SECCOUNT0 2
#define ATA_REG_LBA0 3
#define ATA_REG_LBA1 4
#define ATA_REG_LBA2 5
#define ATA_REG_HDDEVSEL 6
#define ATA_REG_COMMAND 7
#define ATA_REG_STATUS 7

#define ATA_CMD_READ_PIO 0x20
#define ATA_CMD_WRITE_PIO 0x30
#define ATA_CMD_CACHE_FLUSH 0xE7
#define ATA_CMD_IDENTIFY 0xEC

#define ATA_SR_BSY 0x80
#define ATA_SR_DRQ 0x08
#define ATA_SR_ERR 0x01

static int g_present;

static bool ata_wait_bsy(void) {
    for (int i = 0; i < 1000000; i++) {
        if ((inb(ATA_PRIMARY_IO + ATA_REG_STATUS) & ATA_SR_BSY) == 0) {
            return true;
        }
    }
    return false;
}

static bool ata_wait_drq(void) {
    for (int i = 0; i < 1000000; i++) {
        uint8_t status = inb(ATA_PRIMARY_IO + ATA_REG_STATUS);
        if (status & ATA_SR_ERR) {
            return false;
        }
        if (status & ATA_SR_DRQ) {
            return true;
        }
    }
    return false;
}

static bool ata_identify(void) {
    outb(ATA_PRIMARY_IO + ATA_REG_HDDEVSEL, 0xA0);
    io_wait();

    outb(ATA_PRIMARY_IO + ATA_REG_SECCOUNT0, 0);
    outb(ATA_PRIMARY_IO + ATA_REG_LBA0, 0);
    outb(ATA_PRIMARY_IO + ATA_REG_LBA1, 0);
    outb(ATA_PRIMARY_IO + ATA_REG_LBA2, 0);
    outb(ATA_PRIMARY_IO + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);

    uint8_t status = inb(ATA_PRIMARY_IO + ATA_REG_STATUS);
    if (status == 0) {
        return false;
    }

    while ((status & ATA_SR_BSY) != 0) {
        status = inb(ATA_PRIMARY_IO + ATA_REG_STATUS);
    }

    uint8_t lba1 = inb(ATA_PRIMARY_IO + ATA_REG_LBA1);
    uint8_t lba2 = inb(ATA_PRIMARY_IO + ATA_REG_LBA2);
    if (lba1 != 0 || lba2 != 0) {
        return false;
    }

    while ((status & ATA_SR_DRQ) == 0 && (status & ATA_SR_ERR) == 0) {
        status = inb(ATA_PRIMARY_IO + ATA_REG_STATUS);
    }

    if (status & ATA_SR_ERR) {
        return false;
    }

    for (int i = 0; i < 256; i++) {
        (void)inw(ATA_PRIMARY_IO + ATA_REG_DATA);
    }
    return true;
}

void ata_init(void) {
    outb(ATA_PRIMARY_CTRL, 0x02);
    g_present = ata_identify() ? 1 : 0;
}

bool ata_present(void) {
    return g_present != 0;
}

bool ata_read28(uint32_t lba, uint8_t sector_count, void *buffer) {
    if (!g_present || sector_count == 0) {
        return false;
    }

    if (!ata_wait_bsy()) {
        return false;
    }

    outb(ATA_PRIMARY_IO + ATA_REG_HDDEVSEL, 0xE0 | ((lba >> 24) & 0x0F));
    outb(ATA_PRIMARY_IO + ATA_REG_SECCOUNT0, sector_count);
    outb(ATA_PRIMARY_IO + ATA_REG_LBA0, lba & 0xFF);
    outb(ATA_PRIMARY_IO + ATA_REG_LBA1, (lba >> 8) & 0xFF);
    outb(ATA_PRIMARY_IO + ATA_REG_LBA2, (lba >> 16) & 0xFF);
    outb(ATA_PRIMARY_IO + ATA_REG_COMMAND, ATA_CMD_READ_PIO);

    uint16_t *dst = (uint16_t *)buffer;
    for (uint8_t s = 0; s < sector_count; s++) {
        if (!ata_wait_bsy() || !ata_wait_drq()) {
            return false;
        }
        for (int i = 0; i < 256; i++) {
            dst[s * 256 + i] = inw(ATA_PRIMARY_IO + ATA_REG_DATA);
        }
    }
    return true;
}

bool ata_write28(uint32_t lba, uint8_t sector_count, const void *buffer) {
    if (!g_present || sector_count == 0) {
        return false;
    }

    if (!ata_wait_bsy()) {
        return false;
    }

    outb(ATA_PRIMARY_IO + ATA_REG_HDDEVSEL, 0xE0 | ((lba >> 24) & 0x0F));
    outb(ATA_PRIMARY_IO + ATA_REG_SECCOUNT0, sector_count);
    outb(ATA_PRIMARY_IO + ATA_REG_LBA0, lba & 0xFF);
    outb(ATA_PRIMARY_IO + ATA_REG_LBA1, (lba >> 8) & 0xFF);
    outb(ATA_PRIMARY_IO + ATA_REG_LBA2, (lba >> 16) & 0xFF);
    outb(ATA_PRIMARY_IO + ATA_REG_COMMAND, ATA_CMD_WRITE_PIO);

    const uint16_t *src = (const uint16_t *)buffer;
    for (uint8_t s = 0; s < sector_count; s++) {
        if (!ata_wait_bsy() || !ata_wait_drq()) {
            return false;
        }
        for (int i = 0; i < 256; i++) {
            outw(ATA_PRIMARY_IO + ATA_REG_DATA, src[s * 256 + i]);
        }
    }

    outb(ATA_PRIMARY_IO + ATA_REG_COMMAND, ATA_CMD_CACHE_FLUSH);
    return ata_wait_bsy();
}
