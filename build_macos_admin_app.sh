#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
"$ROOT_DIR/QuartzOS-admin-console/macos_app/build_macos_admin_app.sh"

echo "Launch with: open \"$ROOT_DIR/build/QuartzOS Admin Console.app\""
