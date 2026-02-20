#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

show_help() {
  cat <<'EOF'
Usage: ./build_and_launch.sh [--clean] [--serial-only]

Build QuartzOS and launch it in QEMU.

Options:
  --clean        Remove previous build artifacts before building
  --serial-only  Run without GUI output (terminal/serial mode)
  --help         Show this help message
EOF
}

DO_CLEAN=0
SERIAL_ONLY=0

while (($#)); do
  case "$1" in
    --help)
      show_help
      exit 0
      ;;
    --clean)
      DO_CLEAN=1
      ;;
    --serial-only)
      SERIAL_ONLY=1
      ;;
    *)
      echo "Unknown option: $1" >&2
      show_help
      exit 1
      ;;
  esac
  shift
done

if [[ $DO_CLEAN -eq 1 ]]; then
  make clean
fi

make iso disk
if [[ $SERIAL_ONLY -eq 1 ]]; then
  exec qemu-system-x86_64 \
    -M pc \
    -accel tcg \
    -smp 4 \
    -m 1024 \
    -vga std \
    -cdrom build/quartzos.iso \
    -drive file=build/quartzos_disk.img,format=raw,if=ide,index=0 \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -serial stdio \
    -display none \
    -no-reboot \
    -no-shutdown
fi

exec ./tools/run-qemu.sh build/quartzos.iso build/quartzos_disk.img
