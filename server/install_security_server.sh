#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/opt/quartzos-security"
BIN_DIR="$BASE_DIR/bin"
DATA_DIR="$BASE_DIR/data/current"
LOG_DIR="$BASE_DIR/log"
SERVICE_USER="quartzos-sec"
SERVICE_GROUP="quartzos-sec"
ENV_FILE="/etc/default/quartzos-security-server"
UNIT_FILE="/etc/systemd/system/quartzos-security-server.service"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root"
  exit 1
fi

apt-get update
apt-get install -y python3

if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
  groupadd --system "$SERVICE_GROUP"
fi
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --gid "$SERVICE_GROUP" --home-dir "$BASE_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$BASE_DIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$BIN_DIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$LOG_DIR"

install -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$SRC_DIR/quartzos_security_server.py" "$BIN_DIR/quartzos_security_server.py"

if [[ ! -f "$ENV_FILE" ]]; then
  cat > "$ENV_FILE" <<'ENV'
# QuartzOS security server environment
QOS_SECURITY_BIND=0.0.0.0
QOS_SECURITY_AV_PORT=9443
QOS_SECURITY_LICENSE_PORT=9444
QOS_SECURITY_DATA_DIR=/opt/quartzos-security/data/current
QOS_SECURITY_RELOAD_SECONDS=2.5
QOS_SECURITY_REQUIRE_PIN=1
# Comma-separated client IP allowlist. Empty means allow all sources.
QOS_SECURITY_ALLOWED_CLIENTS=
# Must match the QuartzOS build key inputs used for the kernel image.
QOS_BUILD_ROOT_SECRET=QuartzOS-BuildRoot-2026
QOS_BUILD_SALT=quartzos-build-v1
ENV
  chmod 0640 "$ENV_FILE"
  chown root:"$SERVICE_GROUP" "$ENV_FILE"
fi

cat > "$UNIT_FILE" <<'UNIT'
[Unit]
Description=QuartzOS Security Verification Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=quartzos-sec
Group=quartzos-sec
WorkingDirectory=/opt/quartzos-security
EnvironmentFile=-/etc/default/quartzos-security-server
ExecStart=/usr/bin/python3 /opt/quartzos-security/bin/quartzos_security_server.py
Restart=always
RestartSec=1
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/quartzos-security
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now quartzos-security-server.service
systemctl restart quartzos-security-server.service

if command -v ufw >/dev/null 2>&1; then
  if ufw status | grep -q "Status: active"; then
    ufw allow 9443/tcp >/dev/null || true
    ufw allow 9444/tcp >/dev/null || true
  fi
fi

echo "security server installed"
systemctl --no-pager --full status quartzos-security-server.service | sed -n '1,20p'
ss -ltnp | grep -E ':9443|:9444' || true
