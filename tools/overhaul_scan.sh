#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"

echo "[1/8] issuer security guard"
python3 tools/check_issuer_security.py

echo "[2/8] license store integrity"
python3 QuartzOS-license-issuer/issue_license.py verify-store --require-manifest

echo "[3/8] python syntax checks"
python3 -m py_compile \
  QuartzOS-license-issuer/issue_license.py \
  server/quartzos_security_server.py \
  tools/generate_security_manifest.py \
  tools/mkrootfs.py \
  tools/wrap_compat_app.py

echo "[4/8] shell script syntax checks"
bash -n \
  tools/run-qemu.sh \
  tools/qemu_smoke_test.sh \
  tools/auto-activate-vm-license.sh \
  build_and_launch.sh \
  build_macos_activation_app.sh \
  build_macos_app.sh

echo "[5/8] build kernel/apps/rootfs"
make -j4 kernel apps rootfs

echo "[6/8] build boot artifacts"
make -j4 iso disk

echo "[7/8] qemu boot smoke test"
bash tools/qemu_smoke_test.sh

echo "[8/8] completed"
echo "overhaul-scan: PASS"
