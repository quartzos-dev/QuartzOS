#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
"$ROOT_DIR/QuartzOS-license-activation/macos_app/build_macos_activation_app.sh"

echo "Launch with: open \"$ROOT_DIR/build/QuartzOS License Activation.app\""
