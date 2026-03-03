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
NET_MODE=${QEMU_NET_MODE:-user}
HOST_LICENSE_APP_MODE=${QEMU_HOST_LICENSE_APP:-auto}
HOST_LICENSE_APP_PATH=${QEMU_HOST_LICENSE_APP_PATH:-"$ROOT_DIR/build/QuartzOS License Activation.app"}
HOST_LICENSE_APP_BUILD_SCRIPT=${QEMU_HOST_LICENSE_APP_BUILD_SCRIPT:-"$ROOT_DIR/build_macos_activation_app.sh"}

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

net_arg=()
case "$NET_MODE" in
  user)
    net_arg=(-netdev user,id=net0,ipv6=off -device e1000,netdev=net0)
    ;;
  none)
    net_arg=(-nic none)
    ;;
  *)
    echo "error: QEMU_NET_MODE must be one of: user, none" >&2
    exit 1
    ;;
esac

host_bridge_enabled=0
case "$HOST_LICENSE_APP_MODE" in
  auto)
    if [[ "$(uname -s)" == "Darwin" && "$SERIAL_MODE" == "file" ]]; then
      host_bridge_enabled=1
    fi
    ;;
  on)
    host_bridge_enabled=1
    ;;
  off)
    host_bridge_enabled=0
    ;;
  *)
    echo "error: QEMU_HOST_LICENSE_APP must be one of: auto, on, off" >&2
    exit 1
    ;;
esac

if [[ $host_bridge_enabled -eq 1 && "$(uname -s)" != "Darwin" ]]; then
  echo "warning: host license app bridge currently supports macOS only; disabling" >&2
  host_bridge_enabled=0
fi

if [[ $host_bridge_enabled -eq 1 && "$SERIAL_MODE" != "file" ]]; then
  echo "warning: host license app bridge requires QEMU_SERIAL_MODE=file; disabling" >&2
  host_bridge_enabled=0
fi

host_bridge_pid=""
start_host_license_bridge() {
  if [[ $host_bridge_enabled -ne 1 ]]; then
    return
  fi

  mkdir -p "$(dirname "$SERIAL_LOG")"
  : > "$SERIAL_LOG"

  (
    tail -n 0 -F "$SERIAL_LOG" 2>/dev/null | while IFS= read -r line; do
      case "$line" in
        *HOST_LICENSE_ACTIVATION_REQUIRED*)
          echo "host-bridge: VM requested host license activation app"
          build_script="$HOST_LICENSE_APP_BUILD_SCRIPT"
          if [[ ! -x "$build_script" && -x "$ROOT_DIR/build_macos_activation_app.sh" ]]; then
            build_script="$ROOT_DIR/build_macos_activation_app.sh"
          fi
          if [[ ! -d "$HOST_LICENSE_APP_PATH" && -x "$build_script" ]]; then
            echo "host-bridge: app missing, building host activation app..."
            "$build_script" >/dev/null 2>&1 || true
          fi
          if [[ -d "$HOST_LICENSE_APP_PATH" ]]; then
            if open "$HOST_LICENSE_APP_PATH" >/dev/null 2>&1; then
              echo "host-bridge: opened '$HOST_LICENSE_APP_PATH'"
            else
              echo "host-bridge: failed to open '$HOST_LICENSE_APP_PATH'" >&2
            fi
          else
            echo "host-bridge: app not found: $HOST_LICENSE_APP_PATH" >&2
          fi
          break
          ;;
      esac
    done
  ) &
  host_bridge_pid=$!
}

stop_host_license_bridge() {
  if [[ -n "$host_bridge_pid" ]]; then
    kill "$host_bridge_pid" >/dev/null 2>&1 || true
    host_bridge_pid=""
  fi
}

trap stop_host_license_bridge EXIT INT TERM

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
echo "network: $NET_MODE"
if [[ $host_bridge_enabled -eq 1 ]]; then
  echo "host-license-app: on ($HOST_LICENSE_APP_PATH)"
else
  echo "host-license-app: off"
fi

start_host_license_bridge

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
  "${net_arg[@]}" \
  "${serial_arg[@]}" \
  -no-reboot \
  -no-shutdown
