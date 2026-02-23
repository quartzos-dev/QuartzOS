#ifndef KERNEL_SECURITY_H
#define KERNEL_SECURITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SECURITY_FEATURE_COUNT 200u

/* Core controls that are actively enforced by kernel policy paths. */
#define SECURITY_FEATURE_ENFORCE_LICENSE_GATE 0u
#define SECURITY_FEATURE_ENFORCE_EXEC_PATH 1u
#define SECURITY_FEATURE_ENFORCE_FS_GUARDS 2u
#define SECURITY_FEATURE_ENFORCE_NET_GUARDS 3u
#define SECURITY_FEATURE_ENFORCE_AUDIT 4u
#define SECURITY_FEATURE_FAILSAFE_INTRUSION 5u
#define SECURITY_FEATURE_FAILSAFE_INTEGRITY 6u
#define SECURITY_FEATURE_FAILSAFE_NET_KILLSWITCH 7u
#define SECURITY_FEATURE_FAILSAFE_APP_KILLSWITCH 8u
#define SECURITY_FEATURE_HARDENED_BOOT_DEFAULT 9u
#define SECURITY_FEATURE_ALLOW_APP_CUSTOM 10u
#define SECURITY_FEATURE_ALLOW_APP_LINUX 11u
#define SECURITY_FEATURE_ALLOW_APP_WINDOWS 12u
#define SECURITY_FEATURE_ALLOW_APP_MACOS 13u
#define SECURITY_FEATURE_REQUIRE_WRAPPER_FOREIGN 14u
#define SECURITY_FEATURE_BLOCK_PRIVILEGED_IN_LOCKDOWN 15u
#define SECURITY_FEATURE_STRICT_SYSWRITE 16u
#define SECURITY_FEATURE_RATE_LIMIT_EVENTS 17u
#define SECURITY_FEATURE_REQUIRE_MANIFEST 18u
#define SECURITY_FEATURE_ALLOW_FAILSAFE_RESET 19u

typedef enum security_mode {
    SECURITY_MODE_NORMAL = 0,
    SECURITY_MODE_HARDENED = 1,
    SECURITY_MODE_LOCKDOWN = 2
} security_mode_t;

typedef enum security_event {
    SECURITY_EVENT_CMD_BLOCKED = 0,
    SECURITY_EVENT_FS_BLOCKED = 1,
    SECURITY_EVENT_NET_BLOCKED = 2,
    SECURITY_EVENT_APP_BLOCKED = 3,
    SECURITY_EVENT_LICENSE_BLOCKED = 4,
    SECURITY_EVENT_INTEGRITY_FAIL = 5,
    SECURITY_EVENT_SYSCALL_BLOCKED = 6,
    SECURITY_EVENT_AUTH_FAIL = 7
} security_event_t;

typedef enum security_app_kind {
    SECURITY_APP_CUSTOM = 0,
    SECURITY_APP_LINUX = 1,
    SECURITY_APP_WINDOWS = 2,
    SECURITY_APP_MACOS = 3,
    SECURITY_APP_UNKNOWN = 4
} security_app_kind_t;

void security_init(void);
bool security_load(void);
bool security_save(void);

security_mode_t security_mode(void);
const char *security_mode_name(security_mode_t mode);
bool security_set_mode(security_mode_t mode);

bool security_lockdown_active(void);
bool security_intrusion_failsafe_active(void);
bool security_integrity_failsafe_active(void);
void security_reset_failsafes(bool intrusion, bool integrity);

void security_note_event(security_event_t event, const char *detail);

size_t security_feature_count(void);
size_t security_feature_enabled_count(void);
bool security_feature_enabled(size_t index);
bool security_feature_set(size_t index, bool enabled);
void security_feature_name(size_t index, char *out, size_t out_len);

bool security_allow_network_ops(void);
bool security_allow_sys_write(size_t len);
bool security_allow_app_launch(security_app_kind_t kind, bool wrapped,
                               char *reason, size_t reason_len);

bool security_verify_integrity_now(char *summary, size_t summary_len);
uint32_t security_intrusion_threshold(void);
bool security_set_intrusion_threshold(uint32_t value);
uint32_t security_recent_suspicious_events(void);
uint32_t security_integrity_checked_entries(void);
uint32_t security_integrity_failure_count(void);

#endif
