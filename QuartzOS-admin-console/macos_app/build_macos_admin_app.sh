#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
APP_ROOT="$ROOT_DIR/build/QuartzOS Admin Console.app"
MACOS_DIR="$APP_ROOT/Contents/MacOS"
RES_DIR="$APP_ROOT/Contents/Resources"
SRC_DIR="$ROOT_DIR/QuartzOS-admin-console/macos_app/src"
BIN="$MACOS_DIR/QuartzOS Admin Console"

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
  "${SOURCES[@]}" \
  -o "$BIN"

cat > "$APP_ROOT/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>QuartzOS Admin Console</string>
  <key>CFBundleDisplayName</key>
  <string>QuartzOS Admin Console</string>
  <key>CFBundleExecutable</key>
  <string>QuartzOS Admin Console</string>
  <key>CFBundleIdentifier</key>
  <string>dev.quartzos.adminconsole</string>
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
