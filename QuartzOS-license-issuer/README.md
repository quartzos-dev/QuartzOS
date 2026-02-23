# QuartzOS License Issuer (Security Overhaul)

Password-protected issuer and verifier for `QOS1`, `QOS2`, and `QOS3` keys.

## What Changed
- Added hardened `QOS3` key format:
  - `QOS3-<id8>-<tier2>-<policy2>-<nonce8>-<sig24>`
  - HMAC-SHA256 signature truncated to 96 bits (`sig24` hex chars).
- Kept compatibility with existing `QOS1` and `QOS2` keys.
- Reworked tier model to match `LICENSE`:
  - `consumer`, `enterprise`, `educational`, `server`
  - `dev_standard`, `student_dev`, `startup_dev`, `open_lab`, `oem`
- Added metadata-aware verification checks (`verify --strict`).
- Added tamper-evident store integrity manifest:
  - `assets/licenses/licenses_integrity.json`
  - signed by HMAC with `QOS_ISSUER_INTEGRITY_SECRET`.
- Added encrypted-at-rest issuer store (`QENC1`) for db/revoked/meta/audit/integrity files.
- Added `verify-store`, `seal-store`, and `harden-store` commands.
- Legacy key issuance (`QOS1`/`QOS2`) is disabled by default.

## Paths
- Issuer: `/Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py`
- Issued DB: `/Users/qian/Music/OS/assets/licenses/licenses.db`
- Revoked DB: `/Users/qian/Music/OS/assets/licenses/licenses.revoked`
- Metadata CSV: `/Users/qian/Music/OS/assets/licenses/licenses_meta.csv`
- Audit CSV: `/Users/qian/Music/OS/assets/licenses/licenses_audit.csv`
- Integrity manifest: `/Users/qian/Music/OS/assets/licenses/licenses_integrity.json`

## Default Admin Password
`QuartzOS-Admin-2026!`

Set a custom admin hash with env var `QOS_ISSUER_ADMIN_HASH`:

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py password-hash \
  --out /Users/qian/Music/OS/build/issuer_admin_hash.txt
export QOS_ISSUER_ADMIN_HASH="$(cat /Users/qian/Music/OS/build/issuer_admin_hash.txt)"
```

## Usage
Interactive mode:

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py
```

Issue `QOS3` keys:

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py issue \
  --owner "Acme Corp" --tier enterprise --version qos3 --count 3
```

Verify key status (strict mode checks metadata/integrity too):

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py verify --key QOS3-... --strict
```

List keys:

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py list --show
```

Revoke / unrevoke:

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py revoke --key QOS3-...
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py revoke-all
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py unrevoke --key QOS3-...
```

Verify/seal store integrity:

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py verify-store --require-manifest
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py seal-store
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py harden-store
```

Legacy issuance override (only when explicitly needed):

```bash
python3 /Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py issue \
  --owner "Legacy Lab" --tier consumer --version qos2 --allow-legacy --count 1
```

## Environment Variables
- `QOS_ISSUER_ADMIN_HASH`: PBKDF2 admin password record.
- `QOS_ISSUER_HMAC_SECRET_V2`: override `QOS2` signing secret.
- `QOS_ISSUER_HMAC_SECRET_V3`: override `QOS3` signing secret.
- `QOS_ISSUER_INTEGRITY_SECRET`: integrity manifest HMAC secret.
- `QOS_ISSUER_FILE_ENC_KEY`: encryption key for critical issuer files.

## Build Note
After issuing/revoking keys, rebuild image:

```bash
cd /Users/qian/Music/OS
make iso disk
```
