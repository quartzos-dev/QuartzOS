#ifndef FILESYSTEM_SFS_H
#define FILESYSTEM_SFS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SFS_MAGIC 0x31534653u
#define SFS_MAX_NAME 56
#define SFS_TYPE_DIR 1u
#define SFS_TYPE_FILE 2u

typedef struct sfs_entry {
    char name[SFS_MAX_NAME];
    uint32_t parent;
    uint32_t type;
    uint32_t offset;
    uint32_t size;
    uint32_t reserved;
} sfs_entry_t;

bool sfs_mount(const void *image, size_t size);
void sfs_unmount(void);
int sfs_list(const char *path, char *out, size_t out_len);
bool sfs_read_file(const char *path, void *out, size_t out_len, size_t *read_len);
bool sfs_write_file(const char *path, const void *data, size_t size);
bool sfs_make_dir(const char *path);
bool sfs_exists(const char *path);
bool sfs_attach_block_device(uint32_t start_lba, uint32_t sector_count);
bool sfs_sync(void);
bool sfs_persistence_enabled(void);
bool sfs_check(char *out, size_t out_len);

#endif
