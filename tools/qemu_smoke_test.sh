#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ISO="${1:-"$ROOT_DIR/build/quartzos.iso"}"
DISK="${2:-"$ROOT_DIR/build/quartzos_disk.img"}"
LOG="${QEMU_SMOKE_LOG:-"$ROOT_DIR/build/qemu-smoke.log"}"
TIMEOUT_SECS="${QEMU_SMOKE_TIMEOUT:-45}"

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  echo "error: qemu-system-x86_64 not found in PATH" >&2
  exit 2
fi

if [[ ! -f "$ISO" ]]; then
  echo "error: ISO not found: $ISO" >&2
  exit 2
fi

if [[ ! -f "$DISK" ]]; then
  echo "error: disk image not found: $DISK" >&2
  exit 2
fi

mkdir -p "$(dirname "$LOG")"
: > "$LOG"

qemu-system-x86_64 \
  -M pc \
  -accel tcg \
  -smp 2 \
  -m 1024 \
  -display none \
  -boot order=d,menu=off \
  -cdrom "$ISO" \
  -drive file="$DISK",format=raw,if=ide,index=0 \
  -nic none \
  -serial "file:$LOG" \
  -no-reboot \
  -no-shutdown &
QEMU_PID=$!

cleanup() {
  if kill -0 "$QEMU_PID" >/dev/null 2>&1; then
    kill "$QEMU_PID" >/dev/null 2>&1 || true
    wait "$QEMU_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

end_ts=$(( $(date +%s) + TIMEOUT_SECS ))
pass=0

while [[ "$(date +%s)" -lt "$end_ts" ]]; do
  if grep -q "QuartzOS shell ready" "$LOG"; then
    pass=1
    break
  fi
  if grep -qi "panic" "$LOG"; then
    break
  fi
  sleep 1
done

cleanup
trap - EXIT INT TERM

if [[ $pass -eq 1 ]]; then
  echo "smoke: PASS (boot reached shell)"
  exit 0
fi

echo "smoke: FAIL (shell readiness marker not observed)" >&2
echo "smoke: log=$LOG" >&2
tail -n 80 "$LOG" >&2 || true
exit 1
