#ifndef KERNEL_MP_H
#define KERNEL_MP_H

#include <stdbool.h>
#include <stdint.h>

typedef void (*mp_work_fn_t)(void *arg);

void mp_record_bootstrap(uint32_t total, uint32_t online);
uint32_t mp_total_cpus(void);
uint32_t mp_online_cpus(void);
void mp_init_work_queue(void);
bool mp_submit_work(mp_work_fn_t fn, void *arg);
bool mp_service_one_work(void);
void mp_ap_loop(void);

#endif
