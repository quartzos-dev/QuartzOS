#include <drivers/ata.h>
#include <drivers/e1000.h>
#include <drivers/framebuffer.h>
#include <drivers/keyboard.h>
#include <drivers/mouse.h>
#include <drivers/pci.h>
#include <drivers/pic.h>
#include <drivers/pit.h>
#include <drivers/serial.h>
#include <filesystem/sfs.h>
#include <gui/gui.h>
#include <kernel/console.h>
#include <kernel/config.h>
#include <kernel/cron.h>
#include <kernel/gdt.h>
#include <kernel/interrupts.h>
#include <kernel/limine.h>
#include <kernel/audit.h>
#include <kernel/license.h>
#include <kernel/log.h>
#include <kernel/mp.h>
#include <kernel/panic.h>
#include <kernel/shell.h>
#include <kernel/slog.h>
#include <kernel/service.h>
#include <kernel/trace.h>
#include <lib/string.h>
#include <memory/heap.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <net/net.h>
#include <process/task.h>

__attribute__((used, section(".limine_requests")))
static volatile uint64_t limine_base_revision[] = LIMINE_BASE_REVISION(3);

__attribute__((used, section(".limine_requests_start")))
static volatile uint64_t limine_requests_start[] = LIMINE_REQUESTS_START_MARKER;

__attribute__((used, section(".limine_requests_end")))
static volatile uint64_t limine_requests_end[] = LIMINE_REQUESTS_END_MARKER;

__attribute__((used, section(".limine_requests")))
static volatile struct limine_stack_size_request stack_size_request = {
    .id = LIMINE_STACK_SIZE_REQUEST_ID,
    .revision = 0,
    .stack_size = 1024 * 1024
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_framebuffer_request framebuffer_request = {
    .id = LIMINE_FRAMEBUFFER_REQUEST_ID,
    .revision = 0
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_hhdm_request hhdm_request = {
    .id = LIMINE_HHDM_REQUEST_ID,
    .revision = 0
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_memmap_request memmap_request = {
    .id = LIMINE_MEMMAP_REQUEST_ID,
    .revision = 0
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_module_request module_request = {
    .id = LIMINE_MODULE_REQUEST_ID,
    .revision = 0
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_mp_request mp_request = {
    .id = LIMINE_MP_REQUEST_ID,
    .revision = 0,
    .flags = 0
};

static volatile uint32_t g_boot_online_cpus = 1;
static volatile uint32_t g_boot_total_cpus = 1;

static uint32_t atomic_inc_u32(volatile uint32_t *value) {
    uint32_t inc = 1;
    __asm__ volatile("lock xaddl %0, %1" : "+r"(inc), "+m"(*value) : : "memory");
    return inc + 1;
}

static void ap_entry(struct limine_mp_info *info) {
    /*
     * APs run kernel work items only; avoid rewriting shared BSP descriptor
     * tables from multiple CPUs during bring-up.
     */
    (void)atomic_inc_u32(&g_boot_online_cpus);
    info->extra_argument = 1;
    mp_ap_loop();
}

static void bootstrap_smp(void) {
    if (!mp_request.response || mp_request.response->cpu_count < 2) {
        mp_record_bootstrap(1, 1);
        return;
    }

    g_boot_total_cpus = (uint32_t)mp_request.response->cpu_count;
    g_boot_online_cpus = 1;

    for (uint64_t i = 0; i < mp_request.response->cpu_count; i++) {
        struct limine_mp_info *cpu = mp_request.response->cpus[i];
        if (cpu->lapic_id == mp_request.response->bsp_lapic_id) {
            continue;
        }
        cpu->goto_address = ap_entry;
    }

    uint32_t spins = 0;
    while (g_boot_online_cpus < g_boot_total_cpus && spins < 2000000u) {
        __asm__ volatile("pause");
        spins++;
    }

    mp_record_bootstrap(g_boot_total_cpus, g_boot_online_cpus);
}

static const struct limine_file *find_rootfs_module(void) {
    if (!module_request.response) {
        return 0;
    }
    for (uint64_t i = 0; i < module_request.response->module_count; i++) {
        const struct limine_file *mod = module_request.response->modules[i];
        if (mod->string && strcmp(mod->string, "rootfs") == 0) {
            return mod;
        }
    }
    if (module_request.response->module_count > 0) {
        return module_request.response->modules[0];
    }
    return 0;
}

static int parse_u32_dec(const char *s, uint32_t *out) {
    if (!s || !*s || !out) {
        return 0;
    }
    uint32_t value = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
        value = value * 10u + (uint32_t)(*p - '0');
    }
    *out = value;
    return 1;
}

typedef struct boot_profile {
    const char *name;
    uint32_t quantum_ticks;
    int gui_prio;
    int shell_prio;
    int shell_rt;
    int net_prio;
    service_policy_t net_policy;
} boot_profile_t;

static const boot_profile_t PROFILE_NORMAL = {
    .name = "normal",
    .quantum_ticks = 10,
    .gui_prio = 14,
    .shell_prio = 20,
    .shell_rt = 1,
    .net_prio = 12,
    .net_policy = SERVICE_POLICY_ALWAYS
};

static const boot_profile_t PROFILE_SAFE = {
    .name = "safe",
    .quantum_ticks = 18,
    .gui_prio = 10,
    .shell_prio = 22,
    .shell_rt = 0,
    .net_prio = 8,
    .net_policy = SERVICE_POLICY_MANUAL
};

static const boot_profile_t PROFILE_PERF = {
    .name = "perf",
    .quantum_ticks = 4,
    .gui_prio = 18,
    .shell_prio = 20,
    .shell_rt = 1,
    .net_prio = 20,
    .net_policy = SERVICE_POLICY_ALWAYS
};

static void boot_splash(const char *phase, uint32_t step, uint32_t total) {
    uint32_t w = fb_width();
    uint32_t h = fb_height();
    if (w == 0 || h == 0) {
        return;
    }

    for (uint32_t y = 0; y < h; y++) {
        uint32_t c0 = 0x00142539;
        uint32_t c1 = 0x0009121f;
        uint32_t t = (y * 255u) / h;
        uint32_t r = (((c0 >> 16) & 0xFFu) * (255u - t) + ((c1 >> 16) & 0xFFu) * t) / 255u;
        uint32_t g = (((c0 >> 8) & 0xFFu) * (255u - t) + ((c1 >> 8) & 0xFFu) * t) / 255u;
        uint32_t b = ((c0 & 0xFFu) * (255u - t) + (c1 & 0xFFu) * t) / 255u;
        fb_fill_rect(0, (int)y, (int)w, 1, (r << 16) | (g << 8) | b);
    }

    const int card_w = 620;
    const int card_h = 220;
    const int x = ((int)w - card_w) / 2;
    const int y = ((int)h - card_h) / 2;
    fb_fill_rect(x, y, card_w, card_h, 0x00131e2f);
    fb_fill_rect(x, y, card_w, 1, 0x0089b7ea);
    fb_fill_rect(x, y + card_h - 1, card_w, 1, 0x00080f18);

    fb_draw_text(x + 20, y + 24, "QuartzOS Boot", 0x00edf6ff, 0x00131e2f);
    fb_draw_text(x + 20, y + 46, "Initializing desktop services...", 0x00bfd7ee, 0x00131e2f);
    fb_draw_text(x + 20, y + 76, "Current stage:", 0x00b7cde3, 0x00131e2f);
    fb_draw_text(x + 130, y + 76, phase ? phase : "working", 0x00e5f2ff, 0x00131e2f);

    if (total == 0) {
        total = 1;
    }
    if (step > total) {
        step = total;
    }
    int bar_x = x + 20;
    int bar_y = y + 122;
    int bar_w = card_w - 40;
    int bar_h = 28;
    int fill_w = (int)((uint64_t)bar_w * step / total);
    fb_fill_rect(bar_x, bar_y, bar_w, bar_h, 0x001f2e44);
    fb_fill_rect(bar_x, bar_y, fill_w, bar_h, 0x003a83cc);
    fb_fill_rect(bar_x, bar_y, bar_w, 1, 0x0060a6ed);
    fb_fill_rect(bar_x, bar_y + bar_h - 1, bar_w, 1, 0x000a1622);

    char pct[8];
    pct[0] = (char)('0' + ((step * 100u / total) / 100u));
    pct[1] = (char)('0' + (((step * 100u / total) / 10u) % 10u));
    pct[2] = (char)('0' + ((step * 100u / total) % 10u));
    pct[3] = '%';
    pct[4] = '\0';
    if (pct[0] == '0') {
        pct[0] = ' ';
    }
    if (pct[0] == ' ' && pct[1] == '0') {
        pct[1] = ' ';
    }
    fb_draw_text(bar_x + bar_w - 44, bar_y + 10, pct, 0x00f4fbff, 0x001f2e44);

    fb_draw_text(x + 20, y + 170, "If boot is slow, wait for shell and GUI tasks to finish loading.", 0x009eb9d2, 0x00131e2f);
    fb_present();
}

static const boot_profile_t *select_boot_profile(const char *name) {
    if (!name || strcmp(name, "normal") == 0) {
        return &PROFILE_NORMAL;
    }
    if (strcmp(name, "safe") == 0) {
        return &PROFILE_SAFE;
    }
    if (strcmp(name, "perf") == 0) {
        return &PROFILE_PERF;
    }
    return &PROFILE_NORMAL;
}

static void apply_boot_profile(const boot_profile_t *profile,
                               uint64_t gui_id, uint64_t shell_id, uint64_t net_id) {
    if (!profile) {
        profile = &PROFILE_NORMAL;
    }

    task_set_quantum_ticks(profile->quantum_ticks);
    (void)task_set_priority(gui_id, profile->gui_prio);
    (void)task_set_priority(shell_id, profile->shell_prio);
    (void)task_set_realtime(shell_id, profile->shell_rt != 0);
    (void)task_set_priority(net_id, profile->net_prio);
    (void)service_set_policy("net", profile->net_policy);
    if (profile->net_policy == SERVICE_POLICY_MANUAL) {
        (void)service_stop("net");
    } else {
        (void)service_start("net");
    }
}

static void gui_task(void *arg) {
    (void)arg;
    for (;;) {
        gui_tick();
        task_schedule_if_needed();
        __asm__ volatile("hlt");
    }
}

static void shell_task(void *arg) {
    (void)arg;
    for (;;) {
        shell_tick();
        __asm__ volatile("hlt");
    }
}

static void net_task(void *arg) {
    (void)arg;
    for (;;) {
        net_tick();
        task_schedule_if_needed();
        __asm__ volatile("hlt");
    }
}

static task_t *spawn_gui_service(void *arg) {
    (void)arg;
    return task_create("gui", gui_task, 0, 96 * 1024);
}

static task_t *spawn_shell_service(void *arg) {
    (void)arg;
    return task_create("shell", shell_task, 0, 96 * 1024);
}

static task_t *spawn_net_service(void *arg) {
    (void)arg;
    return task_create("net", net_task, 0, 96 * 1024);
}

static void service_task(void *arg) {
    (void)arg;
    for (;;) {
        service_tick();
        cron_tick();
        task_schedule_if_needed();
        __asm__ volatile("hlt");
    }
}

void kernel_main(void) {
    const uint32_t boot_total_steps = 11;
    uint32_t boot_step = 0;

    serial_init();
    console_init();
    trace_init();
    audit_init();
    slog_init();

    if (!LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision)) {
        panic("Unsupported Limine base revision");
    }

    if (!framebuffer_request.response || framebuffer_request.response->framebuffer_count < 1) {
        panic("Framebuffer unavailable");
    }
    if (!hhdm_request.response) {
        panic("HHDM unavailable");
    }
    if (!memmap_request.response) {
        panic("Memory map unavailable");
    }

    struct limine_framebuffer *fb = framebuffer_request.response->framebuffers[0];
    framebuffer_init(fb->address, (uint32_t)fb->width, (uint32_t)fb->height, (uint32_t)fb->pitch, fb->bpp);

    fb_clear(0x00111c26);
    boot_splash("Bootloader handoff", ++boot_step, boot_total_steps);
    kprintf("QuartzOS kernel booting...\n");
    kprintf("FB: %ux%u pitch=%u bpp=%u\n",
            (unsigned)fb->width, (unsigned)fb->height, (unsigned)fb->pitch, (unsigned)fb->bpp);

    gdt_init();
    idt_init();
    boot_splash("CPU descriptors and interrupts", ++boot_step, boot_total_steps);
    mp_init_work_queue();
    bootstrap_smp();
    boot_splash("SMP bring-up", ++boot_step, boot_total_steps);
    kprintf("SMP: online=%u total=%u\n", mp_online_cpus(), mp_total_cpus());

    pic_init();
    for (int i = 0; i < 16; i++) {
        pic_mask_irq((uint8_t)i);
    }
    pic_unmask_irq(0);
    pic_unmask_irq(1);
    pic_unmask_irq(2);
    pic_unmask_irq(12);

    pit_init(100);
    keyboard_init();
    mouse_init((int)fb_width(), (int)fb_height());
    ata_init();
    boot_splash("Core devices", ++boot_step, boot_total_steps);

    pmm_init((struct limine_memmap_response *)memmap_request.response, hhdm_request.response->offset);
    vmm_init(hhdm_request.response->offset);
    heap_init();
    boot_splash("Memory managers", ++boot_step, boot_total_steps);
    if (!fb_enable_backbuffer()) {
        kprintf("FB: backbuffer disabled\n");
    }
    pci_init();
    e1000_init();
    boot_splash("PCI + network discovery", ++boot_step, boot_total_steps);
    if (e1000_available()) {
        int nic_irq = e1000_irq_line();
        if (nic_irq >= 0 && nic_irq < 16) {
            pic_unmask_irq((uint8_t)nic_irq);
            kprintf("NET: unmasked IRQ %u\n", (unsigned)nic_irq);
        }
    }

    const struct limine_file *rootfs = find_rootfs_module();
    if (!rootfs) {
        panic("Root filesystem module missing");
    }
    if (!sfs_mount(rootfs->address, rootfs->size)) {
        panic("Failed to mount rootfs");
    }
    boot_splash("Root filesystem mount", ++boot_step, boot_total_steps);

    if (ata_present()) {
        if (sfs_attach_block_device(0, 131072)) {
            kprintf("SFS: persistence enabled on ATA disk\n");
        } else {
            kprintf("SFS: ATA disk found, persistence attach failed\n");
        }
    } else {
        kprintf("SFS: no ATA disk, running from module image\n");
    }

    size_t sealed_files = 0;
    size_t seal_failures = 0;
    if (sfs_encrypt_plain_files(&sealed_files, &seal_failures)) {
        if (sealed_files > 0) {
            kprintf("SFS: encrypted %u plaintext files\n", (unsigned)sealed_files);
            if (sfs_persistence_enabled() && !sfs_sync()) {
                kprintf("SFS: warning: failed to persist encrypted filesystem\n");
            }
        }
    } else {
        kprintf("SFS: warning: encryption sweep failed (sealed=%u failed=%u)\n",
                (unsigned)sealed_files, (unsigned)seal_failures);
    }
    boot_splash("Disk persistence", ++boot_step, boot_total_steps);

    config_init();
    if (!config_load()) {
        kprintf("CONFIG: no persisted config\n");
    }
    const char *log_level_cfg = config_get("log.level");
    if (log_level_cfg) {
        slog_level_t level = SLOG_LEVEL_DEBUG;
        if (slog_level_from_text(log_level_cfg, &level)) {
            slog_set_min_level(level);
        }
    }
    cron_init();
    if (!cron_load()) {
        kprintf("CRON: no persisted jobs\n");
    }
    service_init();
    boot_splash("Runtime config + cron", ++boot_step, boot_total_steps);

    tasking_init();
    net_init();
    license_init();
    kprintf("LICENSE: loaded=%u revoked=%u active=%s\n",
            (unsigned)license_registered_count(),
            (unsigned)license_revoked_count(),
            license_is_active() ? "yes" : "no");
    gui_init();
    shell_init();
    boot_splash("Shell + desktop services", ++boot_step, boot_total_steps);

    if (!service_register("gui", spawn_gui_service, 0, SERVICE_POLICY_ALWAYS)) {
        panic("Failed to register GUI service");
    }
    if (!service_register("shell", spawn_shell_service, 0, SERVICE_POLICY_ALWAYS)) {
        panic("Failed to register shell service");
    }
    if (!service_register("net", spawn_net_service, 0, SERVICE_POLICY_ALWAYS)) {
        panic("Failed to register net service");
    }

    if (!service_start("gui")) {
        panic("Failed to create GUI task");
    }
    if (!service_start("shell")) {
        panic("Failed to create shell task");
    }
    if (!service_start("net")) {
        panic("Failed to create net task");
    }

    uint64_t gui_id = service_task_id("gui");
    uint64_t shell_id = service_task_id("shell");
    uint64_t net_id = service_task_id("net");
    if (gui_id == 0 || shell_id == 0 || net_id == 0) {
        panic("Missing service task id");
    }

    const char *profile_name = config_get("boot.profile");
    const boot_profile_t *profile = select_boot_profile(profile_name);
    apply_boot_profile(profile, gui_id, shell_id, net_id);
    kprintf("BOOT: profile=%s\n", profile->name);
    boot_splash("Scheduling profile", ++boot_step, boot_total_steps);

    const char *quantum_cfg = config_get("sched.quantum");
    if (quantum_cfg) {
        uint32_t q = 0;
        if (parse_u32_dec(quantum_cfg, &q) && q > 0) {
            task_set_quantum_ticks(q);
            kprintf("SCHED: quantum override=%u\n", (unsigned)q);
        }
    }

    const char *net_policy_cfg = config_get("service.net.policy");
    if (net_policy_cfg) {
        if (strcmp(net_policy_cfg, "manual") == 0) {
            (void)service_set_policy("net", SERVICE_POLICY_MANUAL);
            (void)service_stop("net");
        } else if (strcmp(net_policy_cfg, "always") == 0) {
            (void)service_set_policy("net", SERVICE_POLICY_ALWAYS);
            (void)service_start("net");
        }
    }

    task_t *svc = task_create("service", service_task, 0, 64 * 1024);
    if (!svc) {
        panic("Failed to create service task");
    }
    task_set_priority(svc->id, 18);
    boot_splash("Launching scheduler", ++boot_step, boot_total_steps);
    boot_splash("Done", boot_total_steps, boot_total_steps);

    interrupts_enable();

    for (;;) {
        task_yield();
        __asm__ volatile("hlt");
    }
}
