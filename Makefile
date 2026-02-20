OS_NAME := quartzos
BUILD_DIR := build
ISO_ROOT := $(BUILD_DIR)/iso_root
LIMINE_DIR := $(BUILD_DIR)/limine
LIMINE_TOOL := $(LIMINE_DIR)/limine

CC := x86_64-elf-gcc
LD := x86_64-elf-ld
AS := nasm
PY := python3
TARGET_FLAGS :=

ifeq ($(shell command -v $(CC) >/dev/null 2>&1; echo $$?),1)
CC := clang
LD := ld.lld
TARGET_FLAGS := --target=x86_64-unknown-elf
endif

ifeq ($(shell command -v $(LD) >/dev/null 2>&1; echo $$?),1)
$(error Missing linker '$(LD)'. Install x86_64-elf binutils or LLVM lld.)
endif

ifeq ($(shell command -v $(AS) >/dev/null 2>&1; echo $$?),1)
$(error Missing assembler '$(AS)'. Install NASM.)
endif

CFLAGS := $(TARGET_FLAGS) -std=gnu11 -ffreestanding -fno-stack-protector -fno-pic -fno-pie -m64 -mno-red-zone -mcmodel=kernel -mno-mmx -mno-sse -mno-sse2 -msoft-float -fno-tree-vectorize -Wall -Wextra -Iinclude
LDFLAGS := -nostdlib -z max-page-size=0x1000 -T boot/linker.ld
APP_CFLAGS := $(TARGET_FLAGS) -std=gnu11 -ffreestanding -fno-pic -fno-pie -m64 -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -msoft-float -fno-tree-vectorize -nostdlib -Wall -Wextra

KERNEL_C_SRCS := \
	kernel/main.c \
	kernel/console.c \
	kernel/log.c \
	kernel/panic.c \
	kernel/idt.c \
	kernel/gdt.c \
	kernel/mp.c \
	kernel/syscall.c \
	kernel/shell.c \
	kernel/license.c \
	kernel/trace.c \
	kernel/audit.c \
	kernel/slog.c \
	kernel/service.c \
	kernel/cron.c \
	kernel/config.c \
	drivers/serial.c \
	drivers/framebuffer.c \
	drivers/pic.c \
	drivers/pit.c \
	drivers/keyboard.c \
	drivers/mouse.c \
	drivers/ata.c \
	drivers/pci.c \
	drivers/e1000.c \
	memory/pmm.c \
	memory/vmm.c \
	memory/heap.c \
	process/task.c \
	process/mutex.c \
	process/user.c \
	net/net.c \
	filesystem/sfs.c \
	gui/gui.c \
	lib/string.c

KERNEL_ASM_SRCS := \
	boot/entry.asm \
	kernel/isr.asm \
	process/switch.asm \
	process/user_enter.asm

KERNEL_C_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(KERNEL_C_SRCS))
KERNEL_ASM_OBJS := $(patsubst %.asm,$(BUILD_DIR)/%.o,$(KERNEL_ASM_SRCS))
KERNEL_OBJS := $(KERNEL_C_OBJS) $(KERNEL_ASM_OBJS)

APP_TEMPLATE_SRC := apps/named/named_app.c
APP_NAMES := greeter banner counter fibonacci primes table spinner pulse progress matrix zigzag checker stairs diamond quotes weekdays stats hexview wave heartbeat
NATIVE_APP_ELFS := $(foreach name,$(APP_NAMES),$(BUILD_DIR)/apps/named/$(name).elf)
NATIVE_ROOTFS_APP_MAPS := $(foreach name,$(APP_NAMES),/bin/$(name)=$(BUILD_DIR)/apps/named/$(name).elf)

ECOSYSTEM_SRC := assets/ecosystem/QuartzOS_Ecosystem_Apps_No_Monetization.txt
ECOSYSTEM_GEN_DIR := $(BUILD_DIR)/autogen/ecosystem
ECOSYSTEM_MANIFEST := $(ECOSYSTEM_GEN_DIR)/apps_manifest.mk
ECOSYSTEM_INDEX := $(BUILD_DIR)/autogen/ecosystem_index.csv
ECOSYSTEM_LIST := $(BUILD_DIR)/autogen/ecosystem_index.txt

-include $(ECOSYSTEM_MANIFEST)
ECOSYSTEM_APP_COUNT ?= 0
ECOSYSTEM_APP_NAMES ?=
ECOSYSTEM_APP_SRCS ?=

ECOSYSTEM_APP_ELFS := $(foreach name,$(ECOSYSTEM_APP_NAMES),$(BUILD_DIR)/apps/ecosystem/$(name).elf)
ECOSYSTEM_ROOTFS_APP_MAPS := $(foreach name,$(ECOSYSTEM_APP_NAMES),/bin/$(name)=$(BUILD_DIR)/apps/ecosystem/$(name).elf)

APP_ELFS := $(NATIVE_APP_ELFS) $(ECOSYSTEM_APP_ELFS)
ROOTFS_APP_MAPS := $(NATIVE_ROOTFS_APP_MAPS) $(ECOSYSTEM_ROOTFS_APP_MAPS)

LICENSE_DB_SRC := assets/licenses/licenses.db
LICENSE_NOTICE_SRC := assets/licenses/NOTICE.txt
LICENSE_REVOKED_SRC := assets/licenses/licenses.revoked
GUI_ASSET_MANIFEST := assets/gui/manifest.csv
GUI_ASSETS_DIR := assets/gui
ROOTFS_EXTRA_MAPS := /etc/licenses.db=$(LICENSE_DB_SRC) /etc/licenses.revoked=$(LICENSE_REVOKED_SRC) /etc/license_notice.txt=$(LICENSE_NOTICE_SRC) /etc/ecosystem_apps.txt=$(ECOSYSTEM_SRC) /etc/ecosystem_index.csv=$(ECOSYSTEM_INDEX) /etc/ecosystem_index.txt=$(ECOSYSTEM_LIST)
ROOTFS_IMG := $(BUILD_DIR)/rootfs.sfs
DISK_IMAGE := $(BUILD_DIR)/$(OS_NAME)_disk.img
KERNEL_ELF := $(BUILD_DIR)/kernel.elf
ISO_IMAGE := $(BUILD_DIR)/$(OS_NAME).iso

.PHONY: all clean run iso kernel apps rootfs disk limine gui-assets

all: iso

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: %.asm
	@mkdir -p $(dir $@)
	$(AS) -f elf64 $< -o $@

kernel: $(KERNEL_ELF)

$(KERNEL_ELF): $(KERNEL_OBJS)
	$(LD) $(LDFLAGS) -o $@ $(KERNEL_OBJS)

$(ECOSYSTEM_MANIFEST): tools/generate_ecosystem_apps.py $(ECOSYSTEM_SRC)
	@mkdir -p $(ECOSYSTEM_GEN_DIR) $(BUILD_DIR)/autogen
	$(PY) tools/generate_ecosystem_apps.py \
		--input $(ECOSYSTEM_SRC) \
		--out-dir $(ECOSYSTEM_GEN_DIR) \
		--manifest $(ECOSYSTEM_MANIFEST) \
		--index $(ECOSYSTEM_INDEX) \
		--list $(ECOSYSTEM_LIST)

define APP_RULE
$(BUILD_DIR)/apps/named/$(1).o: $(APP_TEMPLATE_SRC)
	@mkdir -p $$(dir $$@)
	$(CC) $(APP_CFLAGS) -DAPP_NAME=\"$(1)\" -DAPP_KIND=$(2) -c $$< -o $$@

$(BUILD_DIR)/apps/named/$(1).elf: $(BUILD_DIR)/apps/named/$(1).o apps/hello/linker.ld
	@mkdir -p $$(dir $$@)
	$(LD) -nostdlib -T apps/hello/linker.ld -o $$@ $$<
endef

$(eval $(call APP_RULE,greeter,1))
$(eval $(call APP_RULE,banner,2))
$(eval $(call APP_RULE,counter,3))
$(eval $(call APP_RULE,fibonacci,4))
$(eval $(call APP_RULE,primes,5))
$(eval $(call APP_RULE,table,6))
$(eval $(call APP_RULE,spinner,7))
$(eval $(call APP_RULE,pulse,8))
$(eval $(call APP_RULE,progress,9))
$(eval $(call APP_RULE,matrix,10))
$(eval $(call APP_RULE,zigzag,11))
$(eval $(call APP_RULE,checker,12))
$(eval $(call APP_RULE,stairs,13))
$(eval $(call APP_RULE,diamond,14))
$(eval $(call APP_RULE,quotes,15))
$(eval $(call APP_RULE,weekdays,16))
$(eval $(call APP_RULE,stats,17))
$(eval $(call APP_RULE,hexview,18))
$(eval $(call APP_RULE,wave,19))
$(eval $(call APP_RULE,heartbeat,20))

$(BUILD_DIR)/apps/ecosystem/%.o: $(ECOSYSTEM_GEN_DIR)/%.c $(ECOSYSTEM_MANIFEST) apps/ecosystem/template.c
	@mkdir -p $(dir $@)
	$(CC) $(APP_CFLAGS) -c $< -o $@

$(BUILD_DIR)/apps/ecosystem/%.elf: $(BUILD_DIR)/apps/ecosystem/%.o apps/hello/linker.ld
	@mkdir -p $(dir $@)
	$(LD) -nostdlib -T apps/hello/linker.ld -o $@ $<

apps: $(ECOSYSTEM_MANIFEST) $(APP_ELFS)

gui-assets:
	$(PY) tools/generate_gui_assets.py

$(ROOTFS_IMG): tools/mkrootfs.py $(ECOSYSTEM_MANIFEST) $(APP_ELFS) $(LICENSE_DB_SRC) $(LICENSE_REVOKED_SRC) $(LICENSE_NOTICE_SRC) $(ECOSYSTEM_SRC) $(ECOSYSTEM_INDEX) $(ECOSYSTEM_LIST) $(GUI_ASSET_MANIFEST)
	@mkdir -p $(dir $@)
	$(PY) tools/mkrootfs.py $@ \
		$(foreach map,$(ROOTFS_APP_MAPS),--add $(map)) \
		$(foreach map,$(ROOTFS_EXTRA_MAPS),--add $(map)) \
		--add-tree /assets/gui=$(GUI_ASSETS_DIR)

rootfs: $(ROOTFS_IMG)

$(DISK_IMAGE): $(ROOTFS_IMG)
	@mkdir -p $(dir $@)
	dd if=/dev/zero of=$@ bs=1048576 count=64 >/dev/null 2>&1
	dd if=$(ROOTFS_IMG) of=$@ conv=notrunc >/dev/null 2>&1

disk: $(DISK_IMAGE)

$(LIMINE_DIR):
	@if [ ! -d "$(LIMINE_DIR)/.git" ]; then \
		git clone --depth=1 --branch=v10.x-binary https://github.com/limine-bootloader/limine.git $(LIMINE_DIR); \
	fi

$(LIMINE_TOOL): | $(LIMINE_DIR)
	$(CC) -O2 $(LIMINE_DIR)/limine.c -o $(LIMINE_TOOL)

limine: $(LIMINE_TOOL)

$(ISO_IMAGE): $(KERNEL_ELF) $(ROOTFS_IMG) boot/limine.conf | limine
	@mkdir -p $(ISO_ROOT)/boot/limine
	cp $(KERNEL_ELF) $(ISO_ROOT)/boot/kernel.elf
	cp $(ROOTFS_IMG) $(ISO_ROOT)/boot/rootfs.sfs
	cp boot/limine.conf $(ISO_ROOT)/boot/limine.conf
	cp $(LIMINE_DIR)/limine-bios.sys $(ISO_ROOT)/boot/limine/
	cp $(LIMINE_DIR)/limine-bios-cd.bin $(ISO_ROOT)/boot/limine/
	cp $(LIMINE_DIR)/limine-uefi-cd.bin $(ISO_ROOT)/boot/limine/
	xorriso -as mkisofs \
		-b boot/limine/limine-bios-cd.bin \
		-no-emul-boot -boot-load-size 4 -boot-info-table \
		--efi-boot boot/limine/limine-uefi-cd.bin \
		-efi-boot-part --efi-boot-image --protective-msdos-label \
		$(ISO_ROOT) -o $(ISO_IMAGE)
	$(LIMINE_TOOL) bios-install $(ISO_IMAGE)

iso: $(ISO_IMAGE)

run: $(ISO_IMAGE)
run: $(DISK_IMAGE)
	qemu-system-x86_64 -M pc -accel tcg -smp 4 -m 1024 \
		-vga std \
		-cdrom $(ISO_IMAGE) \
		-drive file=$(DISK_IMAGE),format=raw,if=ide,index=0 \
		-netdev user,id=net0 -device e1000,netdev=net0 \
		-serial stdio -no-reboot -no-shutdown

clean:
	rm -rf $(BUILD_DIR)
