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

Environment:
  QEMU_NET_MODE=user|none  QEMU network backend (default: user)
  QEMU_HOST_LICENSE_APP=auto|on|off  auto-open host License Activation app on VM lock mode
  QEMU_HOST_LICENSE_APP_PATH=/path/to/QuartzOS\ License\ Activation.app
  QEMU_HOST_LICENSE_APP_BUILD_SCRIPT=/path/to/build_macos_activation_app.sh
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
  QEMU_SERIAL_MODE=stdio QEMU_DISPLAY_MODE=none exec ./tools/run-qemu.sh build/quartzos.iso build/quartzos_disk.img
fi

exec ./tools/run-qemu.sh build/quartzos.iso build/quartzos_disk.img
