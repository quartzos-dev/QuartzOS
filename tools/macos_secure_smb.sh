#!/usr/bin/env bash
set -euo pipefail

DEFAULT_MOUNT_ROOT="/Volumes"
NSMB_CONF_PATH="$HOME/Library/Preferences/nsmb.conf"

usage() {
  cat <<'EOF'
Secure SMB helper for macOS (IP-based, hardened defaults).

Usage:
  tools/macos_secure_smb.sh mount --ip <IPv4> --share <name> --user <name> [options]
  tools/macos_secure_smb.sh unmount --mount-point <path>
  tools/macos_secure_smb.sh status --mount-point <path>
  tools/macos_secure_smb.sh harden --ip <IPv4>

Commands:
  mount
    Mounts SMB using hardened defaults:
      - IP-only target (no DNS hostname)
      - session/share encryption forced
      - read-only by default
      - private IPv4 required by default

    Options:
      --ip <IPv4>               SMB server IP address (required)
      --share <name>            SMB share name (required)
      --user <name>             SMB username (required)
      --mount-point <path>      Mount point (default: /Volumes/<share>)
      --writable                Allow writes (default is read-only)
      --allow-public-ip         Allow non-private IPs
      --no-harden               Do not update nsmb.conf hardening section
      --help

  unmount
    Options:
      --mount-point <path>      Mount point to unmount (required)
      --help

  status
    Options:
      --mount-point <path>      Mount point to inspect (required)
      --help

  harden
    Writes a scoped hardening section for the target IP to:
      ~/Library/Preferences/nsmb.conf
    Options:
      --ip <IPv4>               SMB server IP address (required)
      --help

Examples:
  tools/macos_secure_smb.sh mount --ip 10.0.2.2 --share quartz --user qian
  tools/macos_secure_smb.sh mount --ip 10.0.2.2 --share quartz --user qian --writable
  tools/macos_secure_smb.sh unmount --mount-point /Volumes/quartz
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

is_valid_ipv4() {
  local ip="$1"
  local IFS=.
  local -a octets
  read -r -a octets <<<"$ip"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  local o
  for o in "${octets[@]}"; do
    [[ "$o" =~ ^[0-9]+$ ]] || return 1
    ((o >= 0 && o <= 255)) || return 1
  done
  return 0
}

is_private_ipv4() {
  local ip="$1"
  local IFS=.
  local -a o
  read -r -a o <<<"$ip"
  if ((o[0] == 10)); then
    return 0
  fi
  if ((o[0] == 172 && o[1] >= 16 && o[1] <= 31)); then
    return 0
  fi
  if ((o[0] == 192 && o[1] == 168)); then
    return 0
  fi
  if ((o[0] == 127)); then
    return 0
  fi
  return 1
}

is_safe_token() {
  local token="$1"
  [[ -n "$token" ]] || return 1
  [[ "$token" =~ ^[A-Za-z0-9._$-]+$ ]]
}

normalize_mount_point() {
  local path="$1"
  [[ -n "$path" ]] || return 1
  [[ "$path" == /* ]] || return 1
  case "$path" in
    *".."*|*"//"*|*":"*|*"\\"*|*"|"*)
      return 1
      ;;
  esac
  printf '%s\n' "$path"
}

append_hardening_block() {
  local ip="$1"
  local begin="# BEGIN QUARTZOS SMB HARDEN $ip"
  local end="# END QUARTZOS SMB HARDEN $ip"
  local tmp

  mkdir -p "$(dirname "$NSMB_CONF_PATH")"
  tmp="$(mktemp "${TMPDIR:-/tmp}/qos-nsmb.XXXXXX")"

  if [[ -f "$NSMB_CONF_PATH" ]]; then
    awk -v b="$begin" -v e="$end" '
      $0 == b {skip=1; next}
      $0 == e {skip=0; next}
      !skip {print}
    ' "$NSMB_CONF_PATH" >"$tmp"
  fi

  {
    if [[ -s "$tmp" ]]; then
      printf '\n'
    fi
    printf '%s\n' "$begin"
    printf '[%s]\n' "$ip"
    printf 'port445=no_netbios\n'
    printf 'minauth=ntlmv2\n'
    printf 'protocol_vers_map=4\n'
    printf 'signing_required=yes\n'
    printf 'signing_req_vers=4\n'
    printf 'validate_neg_off=no\n'
    printf 'force_sess_encrypt=yes\n'
    printf 'force_share_encrypt=yes\n'
    printf 'netBIOS_before_DNS=no\n'
    printf '%s\n' "$end"
  } >>"$tmp"

  mv "$tmp" "$NSMB_CONF_PATH"
  chmod 600 "$NSMB_CONF_PATH"
}

mount_share() {
  need_cmd mount
  need_cmd mount_smbfs

  local ip=""
  local share=""
  local user=""
  local mount_point=""
  local writable=0
  local allow_public_ip=0
  local do_harden=1

  while (($#)); do
    case "$1" in
      --ip)
        ip="${2:-}"; shift 2 ;;
      --share)
        share="${2:-}"; shift 2 ;;
      --user)
        user="${2:-}"; shift 2 ;;
      --mount-point)
        mount_point="${2:-}"; shift 2 ;;
      --writable)
        writable=1; shift ;;
      --allow-public-ip)
        allow_public_ip=1; shift ;;
      --no-harden)
        do_harden=0; shift ;;
      --help)
        usage; exit 0 ;;
      *)
        die "unknown mount option: $1" ;;
    esac
  done

  [[ -n "$ip" ]] || die "--ip is required"
  [[ -n "$share" ]] || die "--share is required"
  [[ -n "$user" ]] || die "--user is required"

  is_valid_ipv4 "$ip" || die "invalid IPv4 address: $ip"
  if ((allow_public_ip == 0)); then
    is_private_ipv4 "$ip" || die "public IP blocked by default; use --allow-public-ip if intentional"
  fi
  is_safe_token "$share" || die "invalid share name; allowed: A-Z a-z 0-9 . _ $ -"
  [[ "$user" =~ ^[-A-Za-z0-9._$]+$ ]] || die "invalid user value"

  if [[ -z "$mount_point" ]]; then
    mount_point="$DEFAULT_MOUNT_ROOT/$share"
  fi
  mount_point="$(normalize_mount_point "$mount_point")" || die "invalid mount point"
  [[ "$mount_point" == "$DEFAULT_MOUNT_ROOT/"* ]] || die "mount point must be under $DEFAULT_MOUNT_ROOT"

  mkdir -p "$mount_point"
  chmod 700 "$mount_point"

  if mount | grep -Fq " on $mount_point ("; then
    die "mount point already in use: $mount_point"
  fi

  if ((do_harden == 1)); then
    append_hardening_block "$ip"
  fi

  local options="nobrowse,sessionencrypt,shareencrypt,forcenewsession"
  if ((writable == 0)); then
    options="$options,rdonly"
  fi

  local target="//${user}@${ip}/${share}"
  echo "Mounting $target -> $mount_point"
  echo "Password is not passed on the command line. macOS will prompt securely if needed."

  mount -t smbfs -o "$options" "$target" "$mount_point"
  echo "Mounted successfully."
}

unmount_share() {
  need_cmd umount
  local mount_point=""
  while (($#)); do
    case "$1" in
      --mount-point)
        mount_point="${2:-}"; shift 2 ;;
      --help)
        usage; exit 0 ;;
      *)
        die "unknown unmount option: $1" ;;
    esac
  done
  [[ -n "$mount_point" ]] || die "--mount-point is required"
  mount_point="$(normalize_mount_point "$mount_point")" || die "invalid mount point"
  umount "$mount_point"
  echo "Unmounted: $mount_point"
}

status_share() {
  local mount_point=""
  while (($#)); do
    case "$1" in
      --mount-point)
        mount_point="${2:-}"; shift 2 ;;
      --help)
        usage; exit 0 ;;
      *)
        die "unknown status option: $1" ;;
    esac
  done
  [[ -n "$mount_point" ]] || die "--mount-point is required"
  mount_point="$(normalize_mount_point "$mount_point")" || die "invalid mount point"
  local line
  line="$(mount | awk -v mp="$mount_point" '$3 == mp {print}')"
  if [[ -z "$line" ]]; then
    echo "not mounted: $mount_point"
    exit 1
  fi
  echo "$line"
}

harden_only() {
  local ip=""
  while (($#)); do
    case "$1" in
      --ip)
        ip="${2:-}"; shift 2 ;;
      --help)
        usage; exit 0 ;;
      *)
        die "unknown harden option: $1" ;;
    esac
  done

  [[ -n "$ip" ]] || die "--ip is required"
  is_valid_ipv4 "$ip" || die "invalid IPv4 address: $ip"
  append_hardening_block "$ip"
  echo "Updated hardening settings in: $NSMB_CONF_PATH"
}

main() {
  [[ $# -ge 1 ]] || { usage; exit 1; }
  case "$1" in
    mount)
      shift
      mount_share "$@"
      ;;
    unmount|umount)
      shift
      unmount_share "$@"
      ;;
    status)
      shift
      status_share "$@"
      ;;
    harden)
      shift
      harden_only "$@"
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      die "unknown command: $1"
      ;;
  esac
}

main "$@"
