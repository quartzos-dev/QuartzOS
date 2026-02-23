#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
APP_ROOT="$ROOT_DIR/build/QuartzOS License Issuer.app"
MACOS_DIR="$APP_ROOT/Contents/MacOS"
RES_DIR="$APP_ROOT/Contents/Resources"
SRC="$ROOT_DIR/QuartzOS-license-issuer/macos_app/src/main.swift"
BIN="$MACOS_DIR/QuartzOS License Issuer"

mkdir -p "$MACOS_DIR" "$RES_DIR"

swiftc -O -framework Cocoa "$SRC" -o "$BIN"

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
  <string>1.0</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST

chmod +x "$BIN"
echo "Built: $APP_ROOT"
