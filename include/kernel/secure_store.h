#ifndef KERNEL_SECURE_STORE_H
#define KERNEL_SECURE_STORE_H

#include <stdbool.h>
#include <stddef.h>

bool secure_store_is_encrypted_blob(const char *text);
bool secure_store_read_text(const char *path, char *out, size_t out_len, size_t *out_read);
bool secure_store_write_text(const char *path, const char *plain, size_t plain_len, bool sync_now);

#endif
