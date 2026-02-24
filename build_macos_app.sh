#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
"$ROOT_DIR/QuartzOS-license-issuer/macos_app/build_macos_app.sh"

echo "Launch with: open \"$ROOT_DIR/build/QuartzOS License Issuer.app\""
