#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_TARGET="${1:-root@46.16.131.231}"
REMOTE_STAGE="${2:-/root/quartzos_security_deploy}"
REMOTE_DATA_DIR="/opt/quartzos-security/data/current"

req_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "missing required file: $path" >&2
    exit 1
  fi
}

req_file "$ROOT_DIR/server/quartzos_security_server.py"
req_file "$ROOT_DIR/server/install_security_server.sh"
req_file "$ROOT_DIR/assets/licenses/licenses.db"
req_file "$ROOT_DIR/assets/licenses/licenses.revoked"
req_file "$ROOT_DIR/build/autogen/security_manifest.txt"
req_file "$ROOT_DIR/build/autogen/security_manifest.sig"

echo "[1/4] staging deploy directory on $SERVER_TARGET"
ssh "$SERVER_TARGET" "mkdir -p '$REMOTE_STAGE/data'"

echo "[2/4] uploading server daemon + installer"
scp "$ROOT_DIR/server/quartzos_security_server.py" "$ROOT_DIR/server/install_security_server.sh" "$SERVER_TARGET:$REMOTE_STAGE/"

echo "[3/4] uploading OS security artifacts"
scp \
  "$ROOT_DIR/assets/licenses/licenses.db" \
  "$ROOT_DIR/assets/licenses/licenses.revoked" \
  "$ROOT_DIR/build/autogen/security_manifest.txt" \
  "$ROOT_DIR/build/autogen/security_manifest.sig" \
  "$SERVER_TARGET:$REMOTE_STAGE/data/"

echo "[4/4] installing + activating service"
ssh "$SERVER_TARGET" "
set -euo pipefail
chmod +x '$REMOTE_STAGE/install_security_server.sh'
bash '$REMOTE_STAGE/install_security_server.sh'
install -d -m 0750 -o quartzos-sec -g quartzos-sec '$REMOTE_DATA_DIR'
cp '$REMOTE_STAGE/data/licenses.db' '$REMOTE_DATA_DIR/licenses.db'
cp '$REMOTE_STAGE/data/licenses.revoked' '$REMOTE_DATA_DIR/licenses.revoked'
cp '$REMOTE_STAGE/data/security_manifest.txt' '$REMOTE_DATA_DIR/security_manifest.txt'
cp '$REMOTE_STAGE/data/security_manifest.sig' '$REMOTE_DATA_DIR/security_manifest.sig'
chown quartzos-sec:quartzos-sec '$REMOTE_DATA_DIR/licenses.db' '$REMOTE_DATA_DIR/licenses.revoked' '$REMOTE_DATA_DIR/security_manifest.txt' '$REMOTE_DATA_DIR/security_manifest.sig'
chmod 0640 '$REMOTE_DATA_DIR/licenses.db' '$REMOTE_DATA_DIR/licenses.revoked' '$REMOTE_DATA_DIR/security_manifest.txt' '$REMOTE_DATA_DIR/security_manifest.sig'
systemctl restart quartzos-security-server.service
systemctl --no-pager --full status quartzos-security-server.service | sed -n '1,20p'
"

echo "deploy complete"
