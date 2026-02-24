# QuartzOS License Issuer

Hardened issuer/verification tool for QuartzOS licensing.

## Highlights

- Password-protected admin operations.
- Supports `QOS3` keys (modern) and can validate legacy `QOS1/QOS2` keys.
- Legacy deactivation workflow:
  - `deactivate-legacy --purge` revokes and purges all `QOS1/QOS2` from issued DB.
- Tracking database with per-license:
  - `tracking_id` (`QTK-...`)
  - fingerprint
  - status
- Encrypted-at-rest issuer store (`QENC1`) with integrity sealing.

## Admin Password Setup (Required)

Generate an admin hash record first:

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py password-hash \
  --algo scrypt \
  --out /Users/qian/Music/OS/build/issuer_admin_hash.txt
```

Then use it for commands:

```bash
export QOS_ISSUER_ADMIN_HASH="$(cat /Users/qian/Music/OS/build/issuer_admin_hash.txt)"
```

## Common Commands

Issue modern license:

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py issue \
  --owner "Acme" --tier consumer --version qos3 --count 1
```

List issued/revoked licenses:

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py list --show
```

Verify a key:

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py verify --key QOS3-... --strict
```

Lookup by tracking id:

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py lookup --tracking-id QTK-...
```

Deactivate all QOS1/QOS2 licenses:

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py deactivate-legacy --purge --actor admin
```

Verify/seal store integrity:

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py verify-store --require-manifest
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py seal-store
```

## Password via Environment (Safer)

To avoid exposing password in process args, pass:

```bash
export QOS_ISSUER_PASSWORD='your-admin-password'
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py \
  --password-env QOS_ISSUER_PASSWORD list --show
```

## macOS App

Native app wrapper is in:

- `/Users/qian/Music/OS/QuartzOS-license-issuer/macos_app`

Advanced app features:

- Multi-tab workflow (`Issue`, `Verify`, `Revocation`, `Store`).
- Live output console with export.
- Dashboard cards (issued, active, revoked, integrity).
- Keychain integration for issuer password.
- Batch key verify + key extraction.
- Command history + rerun.
- Store hardening tools from UI (`verify-store`, `seal-store`, `harden-store`, `password-hash`).

Build:

```bash
cd /Users/qian/Music/OS
./QuartzOS-license-issuer/macos_app/build_macos_app.sh
```

or:

```bash
cd /Users/qian/Music/OS
./build_macos_app.sh
```

Launch:

```bash
open "/Users/qian/Music/OS/build/QuartzOS License Issuer.app"
```
