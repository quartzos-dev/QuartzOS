#ifndef KERNEL_PLATFORM_H
#define KERNEL_PLATFORM_H

#include <stdbool.h>

void platform_detect(void);
bool platform_is_virtual_machine(void);
const char *platform_vm_vendor(void);
void platform_request_host_license_activation(void);
void platform_clear_host_license_activation_request(void);

#endif
