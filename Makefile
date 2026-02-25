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

CFLAGS := $(TARGET_FLAGS) -std=gnu11 -ffreestanding -fstack-protector -fno-pic -fno-pie -m64 -mno-red-zone -mcmodel=kernel -mno-mmx -mno-sse -mno-sse2 -msoft-float -fno-tree-vectorize -Wall -Wextra -Iinclude
LDFLAGS := -nostdlib -z max-page-size=0x1000 -T boot/linker.ld
APP_CFLAGS := $(TARGET_FLAGS) -std=gnu11 -ffreestanding -fno-pic -fno-pie -m64 -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -msoft-float -fno-tree-vectorize -nostdlib -Wall -Wextra -Iapps/named/common

GENERATED_DIR := $(BUILD_DIR)/generated/include/generated
GENERATED_SECURITY_KEYS := $(GENERATED_DIR)/security_keys.h
CFLAGS += -I$(BUILD_DIR)/generated/include

KERNEL_C_SRCS := \
	kernel/main.c \
	kernel/console.c \
	kernel/log.c \
	kernel/panic.c \
	kernel/idt.c \
	kernel/gdt.c \
	kernel/cpu_hardening.c \
	kernel/mp.c \
	kernel/stack_protector.c \
	kernel/syscall.c \
	kernel/shell.c \
	kernel/security.c \
	kernel/app_runtime.c \
	kernel/license.c \
	kernel/secure_store.c \
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

APP_NAMES := greeter banner counter fibonacci primes table spinner pulse progress matrix zigzag checker stairs diamond quotes weekdays stats hexview wave heartbeat secdiag devbench hashlab nettrace elfinspect
NATIVE_APP_SRCS := $(foreach name,$(APP_NAMES),apps/named/$(name)/main.c)
NATIVE_APP_OBJS := $(foreach name,$(APP_NAMES),$(BUILD_DIR)/apps/named/$(name)/main.o)
APP_RUNTIME_OBJ := $(BUILD_DIR)/apps/named/common/runtime.o
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
LICENSE_INTEGRITY_SRC := assets/licenses/licenses_integrity.json
LICENSE_TEXT_SRC := LICENSE
SYSTEM_CONFIG_SRC := assets/config/system.cfg
SECURITY_MANIFEST := $(BUILD_DIR)/autogen/security_manifest.txt
SECURITY_MANIFEST_SIG := $(BUILD_DIR)/autogen/security_manifest.sig
GUI_ASSET_MANIFEST := assets/gui/manifest.csv
GUI_ASSETS_DIR := assets/gui
BRANDING_ASSETS_DIR := assets/branding
BRANDING_MARK_SRC := $(BRANDING_ASSETS_DIR)/quartzos-mark.svg
BRANDING_LOGO_SRC := $(BRANDING_ASSETS_DIR)/quartzos-logo.svg
COMPAT_WRAP_DIR := $(BUILD_DIR)/compat
COMPAT_WRAPPERS := $(COMPAT_WRAP_DIR)/secdiag_win.exe $(COMPAT_WRAP_DIR)/secdiag_mac.app $(COMPAT_WRAP_DIR)/secdiag_linux.bin
COMPAT_ROOTFS_MAPS := /bin/secdiag_win.exe=$(COMPAT_WRAP_DIR)/secdiag_win.exe /bin/secdiag_mac.app=$(COMPAT_WRAP_DIR)/secdiag_mac.app /bin/secdiag_linux.bin=$(COMPAT_WRAP_DIR)/secdiag_linux.bin
ROOTFS_EXTRA_MAPS := /etc/LICENSE.txt=$(LICENSE_TEXT_SRC) /etc/licenses.db=$(LICENSE_DB_SRC) /etc/licenses.revoked=$(LICENSE_REVOKED_SRC) /etc/license_notice.txt=$(LICENSE_NOTICE_SRC) /etc/licenses_integrity.json=$(LICENSE_INTEGRITY_SRC) /etc/system.cfg=$(SYSTEM_CONFIG_SRC) /etc/ecosystem_apps.txt=$(ECOSYSTEM_SRC) /etc/ecosystem_index.csv=$(ECOSYSTEM_INDEX) /etc/ecosystem_index.txt=$(ECOSYSTEM_LIST) /etc/security_manifest.txt=$(SECURITY_MANIFEST) /etc/security_manifest.sig=$(SECURITY_MANIFEST_SIG) $(COMPAT_ROOTFS_MAPS)
ROOTFS_IMG := $(BUILD_DIR)/rootfs.sfs
DISK_IMAGE := $(BUILD_DIR)/$(OS_NAME)_disk.img
KERNEL_ELF := $(BUILD_DIR)/kernel.elf
ISO_IMAGE := $(BUILD_DIR)/$(OS_NAME).iso

.PHONY: all clean run iso kernel apps rootfs disk limine gui-assets

all: iso

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(GENERATED_SECURITY_KEYS): tools/generate_security_keys.py | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(PY) tools/generate_security_keys.py --output $@

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: %.asm
	@mkdir -p $(dir $@)
	$(AS) -f elf64 $< -o $@

$(KERNEL_C_OBJS): $(GENERATED_SECURITY_KEYS)

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

$(APP_RUNTIME_OBJ): apps/named/common/runtime.c apps/named/common/runtime.h
	@mkdir -p $(dir $@)
	$(CC) $(APP_CFLAGS) -c $< -o $@

$(NATIVE_APP_OBJS): $(BUILD_DIR)/apps/named/%/main.o: apps/named/%/main.c apps/named/common/runtime.h
	@mkdir -p $(dir $@)
	$(CC) $(APP_CFLAGS) -c $< -o $@

$(BUILD_DIR)/apps/named/%.elf: $(BUILD_DIR)/apps/named/%/main.o $(APP_RUNTIME_OBJ) apps/hello/linker.ld
	@mkdir -p $(dir $@)
	$(LD) -nostdlib -T apps/hello/linker.ld -o $@ $(BUILD_DIR)/apps/named/$*/main.o $(APP_RUNTIME_OBJ)

$(BUILD_DIR)/apps/ecosystem/%.o: $(ECOSYSTEM_GEN_DIR)/%.c $(ECOSYSTEM_MANIFEST) apps/ecosystem/template.c
	@mkdir -p $(dir $@)
	$(CC) $(APP_CFLAGS) -c $< -o $@

$(BUILD_DIR)/apps/ecosystem/%.elf: $(BUILD_DIR)/apps/ecosystem/%.o apps/hello/linker.ld
	@mkdir -p $(dir $@)
	$(LD) -nostdlib -T apps/hello/linker.ld -o $@ $<

apps: $(ECOSYSTEM_MANIFEST) $(APP_ELFS)

$(COMPAT_WRAP_DIR)/secdiag_win.exe: $(BUILD_DIR)/apps/named/secdiag.elf tools/wrap_compat_app.py
	@mkdir -p $(dir $@)
	$(PY) tools/wrap_compat_app.py --input-elf $< --platform windows --output $@

$(COMPAT_WRAP_DIR)/secdiag_mac.app: $(BUILD_DIR)/apps/named/secdiag.elf tools/wrap_compat_app.py
	@mkdir -p $(dir $@)
	$(PY) tools/wrap_compat_app.py --input-elf $< --platform macos --output $@

$(COMPAT_WRAP_DIR)/secdiag_linux.bin: $(BUILD_DIR)/apps/named/secdiag.elf tools/wrap_compat_app.py
	@mkdir -p $(dir $@)
	$(PY) tools/wrap_compat_app.py --input-elf $< --platform linux --output $@

$(SECURITY_MANIFEST): tools/generate_security_manifest.py $(LICENSE_TEXT_SRC) $(LICENSE_DB_SRC) $(LICENSE_REVOKED_SRC) $(LICENSE_NOTICE_SRC) $(LICENSE_INTEGRITY_SRC) $(SYSTEM_CONFIG_SRC) $(GUI_ASSET_MANIFEST) $(BRANDING_MARK_SRC) $(BRANDING_LOGO_SRC) $(ECOSYSTEM_INDEX) $(ECOSYSTEM_LIST)
	@mkdir -p $(dir $@)
	$(PY) tools/generate_security_manifest.py --output $(SECURITY_MANIFEST) \
		--signature $(SECURITY_MANIFEST_SIG) \
		--add /etc/LICENSE.txt=$(LICENSE_TEXT_SRC) \
		--add /etc/licenses.db=$(LICENSE_DB_SRC) \
		--add /etc/licenses.revoked=$(LICENSE_REVOKED_SRC) \
		--add /etc/license_notice.txt=$(LICENSE_NOTICE_SRC) \
		--add /etc/licenses_integrity.json=$(LICENSE_INTEGRITY_SRC) \
		--add /etc/system.cfg=$(SYSTEM_CONFIG_SRC) \
		--add /etc/ecosystem_index.csv=$(ECOSYSTEM_INDEX) \
		--add /etc/ecosystem_index.txt=$(ECOSYSTEM_LIST) \
		--add /assets/branding/quartzos-mark.svg=$(BRANDING_MARK_SRC) \
		--add /assets/branding/quartzos-logo.svg=$(BRANDING_LOGO_SRC) \
		--add /assets/gui/manifest.csv=$(GUI_ASSET_MANIFEST)

$(SECURITY_MANIFEST_SIG): $(SECURITY_MANIFEST)

gui-assets:
	$(PY) tools/generate_gui_assets.py

$(ROOTFS_IMG): tools/mkrootfs.py $(ECOSYSTEM_MANIFEST) $(APP_ELFS) $(COMPAT_WRAPPERS) $(SECURITY_MANIFEST) $(SECURITY_MANIFEST_SIG) $(LICENSE_TEXT_SRC) $(LICENSE_DB_SRC) $(LICENSE_REVOKED_SRC) $(LICENSE_NOTICE_SRC) $(LICENSE_INTEGRITY_SRC) $(SYSTEM_CONFIG_SRC) $(ECOSYSTEM_SRC) $(ECOSYSTEM_INDEX) $(ECOSYSTEM_LIST) $(GUI_ASSET_MANIFEST) $(BRANDING_MARK_SRC) $(BRANDING_LOGO_SRC)
	@mkdir -p $(dir $@)
	$(PY) tools/mkrootfs.py $@ \
		$(foreach map,$(ROOTFS_APP_MAPS),--add $(map)) \
		$(foreach map,$(ROOTFS_EXTRA_MAPS),--add $(map)) \
		--add-tree /assets/gui=$(GUI_ASSETS_DIR) \
		--add-tree /assets/branding=$(BRANDING_ASSETS_DIR)

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
