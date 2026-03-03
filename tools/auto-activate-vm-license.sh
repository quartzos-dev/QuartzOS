#!/usr/bin/env bash
set -euo pipefail

KEY_RAW="${1:-}"
KEY="${KEY_RAW^^}"

if [[ -z "$KEY" ]]; then
  echo "usage: $0 <QOS3-license-key>" >&2
  exit 1
fi

if [[ ! "$KEY" =~ ^QOS3-[0-9A-F]{8}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{8}-[0-9A-F]{24}$ ]]; then
  echo "error: invalid QOS3 key format" >&2
  exit 1
fi

if ! pgrep -f "qemu-system-x86_64" >/dev/null 2>&1; then
  echo "error: qemu-system-x86_64 is not running" >&2
  exit 2
fi

# Requires macOS Accessibility permission for Terminal/osascript to send keystrokes.
if ! osascript <<OSA
set targetFound to false

tell application "System Events"
  if exists process "QEMU" then
    set frontmost of process "QEMU" to true
    set targetFound to true
  else if exists process "qemu-system-x86_64" then
    set frontmost of process "qemu-system-x86_64" to true
    set targetFound to true
  end if
end tell

if targetFound is false then
  error "QEMU window not found."
end if

delay 0.45

tell application "System Events"
  keystroke "license terms"
  key code 36
  delay 0.15

  keystroke "license accept"
  key code 36
  delay 0.15

  keystroke "license reload"
  key code 36
  delay 0.15

  keystroke "license activate $KEY"
  key code 36
  delay 0.20

  keystroke "license unlock"
  key code 36
  delay 0.20

  keystroke "license status"
  key code 36
end tell
OSA
then
  echo "error: failed to send keystrokes to QEMU." >&2
  echo "hint: grant Accessibility access to Terminal (or app running this script)." >&2
  exit 3
fi

echo "auto-activate: unlock sequence sent to QEMU"
