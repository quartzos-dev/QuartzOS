#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$ROOT_DIR/build"
ISO_PATH="$BUILD_DIR/quartzos.iso"
IMG_PATH="$BUILD_DIR/quartzos_disk.img"
DOWNLOADS_DIR="${DOWNLOADS_DIR:-$HOME/Downloads}"
STAMP="$(date +%Y%m%d-%H%M%S)"
STAGE_DIR="$BUILD_DIR/release-$STAMP"
ZIP_PATH="$DOWNLOADS_DIR/QuartzOS-release-$STAMP.zip"

mkdir -p "$BUILD_DIR" "$DOWNLOADS_DIR" "$STAGE_DIR"

echo "[1/4] Building ISO + IMG..."
make -C "$ROOT_DIR" iso disk

if [[ ! -f "$ISO_PATH" || ! -f "$IMG_PATH" ]]; then
  echo "error: build completed but ISO or IMG is missing" >&2
  exit 1
fi

echo "[2/4] Staging artifacts..."
cp "$ISO_PATH" "$STAGE_DIR/"
cp "$IMG_PATH" "$STAGE_DIR/"

if command -v shasum >/dev/null 2>&1; then
  (
    cd "$STAGE_DIR"
    shasum -a 256 quartzos.iso quartzos_disk.img > SHA256SUMS.txt
  )
fi

echo "[3/4] Creating zip..."
(
  cd "$STAGE_DIR"
  zip -q -9 -r "$ZIP_PATH" .
)

echo "[4/4] Done"
echo "ISO : $ISO_PATH"
echo "IMG : $IMG_PATH"
echo "ZIP : $ZIP_PATH"
