#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ISO=${1:-"$ROOT_DIR/build/quartzos.iso"}
DISK=${2:-"$ROOT_DIR/build/quartzos_disk.img"}
BOOT_ORDER=${QEMU_BOOT_ORDER:-d}
SERIAL_MODE=${QEMU_SERIAL_MODE:-file}
SERIAL_LOG=${QEMU_SERIAL_LOG:-"$ROOT_DIR/build/qemu-serial.log"}
DISPLAY_MODE=${QEMU_DISPLAY_MODE:-auto}
INPUT_MODE=${QEMU_INPUT_MODE:-auto}

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  echo "error: qemu-system-x86_64 not found in PATH" >&2
  exit 1
fi

if [[ ! -f "$ISO" ]]; then
  echo "error: ISO not found: $ISO" >&2
  echo "hint: run 'cd $ROOT_DIR && make iso disk'" >&2
  exit 1
fi

if [[ ! -f "$DISK" ]]; then
  echo "error: disk image not found: $DISK" >&2
  echo "hint: run 'cd $ROOT_DIR && make disk'" >&2
  exit 1
fi

display_arg=()
if [[ "$DISPLAY_MODE" == "auto" ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    display_arg=(-display cocoa,show-cursor=on)
  fi
elif [[ "$DISPLAY_MODE" != "default" ]]; then
  display_arg=(-display "$DISPLAY_MODE")
fi

serial_arg=()
case "$SERIAL_MODE" in
  stdio)
    serial_arg=(-serial stdio)
    ;;
  none)
    serial_arg=(-serial none)
    ;;
  file)
    mkdir -p "$(dirname "$SERIAL_LOG")"
    serial_arg=(-serial "file:$SERIAL_LOG")
    ;;
  *)
    echo "error: QEMU_SERIAL_MODE must be one of: file, stdio, none" >&2
    exit 1
    ;;
esac

input_arg=()
case "$INPUT_MODE" in
  auto)
    if [[ "$(uname -s)" == "Darwin" ]]; then
      input_arg=(-usb -device usb-kbd -device usb-tablet)
    fi
    ;;
  usb)
    input_arg=(-usb -device usb-kbd -device usb-tablet)
    ;;
  ps2)
    input_arg=()
    ;;
  *)
    echo "error: QEMU_INPUT_MODE must be one of: auto, usb, ps2" >&2
    exit 1
    ;;
esac

echo "Launching QEMU..."
if [[ ${#display_arg[@]} -gt 0 ]]; then
  echo "display: ${display_arg[*]}"
else
  echo "display: default"
fi
if [[ "$SERIAL_MODE" == "file" ]]; then
  echo "serial: file:$SERIAL_LOG"
else
  echo "serial: $SERIAL_MODE"
fi

qemu-system-x86_64 \
  -M pc \
  -accel tcg \
  -smp 4 \
  -m 1024 \
  -vga std \
  "${input_arg[@]}" \
  "${display_arg[@]}" \
  -boot order="$BOOT_ORDER",menu=on \
  -cdrom "$ISO" \
  -drive file="$DISK",format=raw,if=ide,index=0 \
  -netdev user,id=net0 -device e1000,netdev=net0 \
  "${serial_arg[@]}" \
  -no-reboot \
  -no-shutdown
