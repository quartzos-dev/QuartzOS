#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
APP_ROOT="$ROOT_DIR/build/QuartzOS License Issuer.app"
MACOS_DIR="$APP_ROOT/Contents/MacOS"
RES_DIR="$APP_ROOT/Contents/Resources"
SRC_DIR="$ROOT_DIR/QuartzOS-license-issuer/macos_app/src"
BIN="$MACOS_DIR/QuartzOS License Issuer"

mkdir -p "$MACOS_DIR" "$RES_DIR"

SOURCES=()
while IFS= read -r file; do
  SOURCES+=("$file")
done < <(find "$SRC_DIR" -maxdepth 1 -name '*.swift' | sort)
if [[ ${#SOURCES[@]} -eq 0 ]]; then
  echo "error: no Swift source files found in $SRC_DIR" >&2
  exit 1
fi

swiftc -O \
  -framework Cocoa \
  -framework Security \
  -framework UniformTypeIdentifiers \
  "${SOURCES[@]}" \
  -o "$BIN"

cat > "$APP_ROOT/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>QuartzOS License Issuer</string>
  <key>CFBundleDisplayName</key>
  <string>QuartzOS License Issuer</string>
  <key>CFBundleExecutable</key>
  <string>QuartzOS License Issuer</string>
  <key>CFBundleIdentifier</key>
  <string>dev.quartzos.licenseissuer</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>CFBundleShortVersionString</key>
  <string>2.0</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST

chmod +x "$BIN"
echo "Built: $APP_ROOT"
