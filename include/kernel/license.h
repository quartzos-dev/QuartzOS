#ifndef KERNEL_LICENSE_H
#define KERNEL_LICENSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LICENSE_MAX_KEY_TEXT 44

typedef enum license_error {
    LICENSE_ERR_NONE = 0,
    LICENSE_ERR_FORMAT = 1,
    LICENSE_ERR_SIGNATURE = 2,
    LICENSE_ERR_NOT_ISSUED = 3,
    LICENSE_ERR_REVOKED = 4,
    LICENSE_ERR_LOCKED = 5,
    LICENSE_ERR_STATE_TAMPER = 6
} license_error_t;

void license_init(void);
void license_reload(void);

bool license_signature_valid(const char *key);
bool license_registered(const char *key);
bool license_key_revoked(const char *key);
bool license_activate(const char *key);
void license_deactivate(void);

bool license_is_active(void);
size_t license_registered_count(void);
size_t license_revoked_count(void);
void license_active_key(char *out, size_t out_len);
uint32_t license_failed_attempts(void);
uint32_t license_lockout_remaining_seconds(void);
license_error_t license_last_error(void);
const char *license_error_text(license_error_t error);

#endif
