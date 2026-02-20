# QuartzOS License Issuer (Major Security Update)

Password-protected issuer for both legacy `QOS1` and hardened `QOS2` keys.

## What Changed
- Added **QOS2 key format** with HMAC-SHA256 signature (`QOS2-...-...-...-...`).
- Added **revocation database** support (`assets/licenses/licenses.revoked`).
- Added **audit trail CSV** for issue/revoke/unrevoke operations.
- Upgraded admin password handling to **PBKDF2-SHA256** records.
- Kept compatibility with existing QOS1 keys.

## Paths
- Issuer: `/Users/qian/Music/OS/license_issuer/issue_license.py`
- Issued DB: `/Users/qian/Music/OS/assets/licenses/licenses.db`
- Revoked DB: `/Users/qian/Music/OS/assets/licenses/licenses.revoked`
- Issue metadata CSV: `/Users/qian/Music/OS/assets/licenses/licenses_meta.csv`
- Audit CSV: `/Users/qian/Music/OS/assets/licenses/licenses_audit.csv`

## Default Admin Password
`QuartzOS-Admin-2026!`

Set a custom admin hash with env var `QOS_ISSUER_ADMIN_HASH`:

```bash
python3 /Users/qian/Music/OS/license_issuer/issue_license.py password-hash
```

Use the output record as `QOS_ISSUER_ADMIN_HASH`.

## Usage
Interactive menu (run with no subcommand):

```bash
python3 /Users/qian/Music/OS/license_issuer/issue_license.py
```

Issue QOS2 keys:

```bash
python3 /Users/qian/Music/OS/license_issuer/issue_license.py issue \
  --owner "Acme Corp" --tier enterprise --version qos2 --count 3
```

Verify key status:

```bash
python3 /Users/qian/Music/OS/license_issuer/issue_license.py verify --key QOS2-...
```

List keys:

```bash
python3 /Users/qian/Music/OS/license_issuer/issue_license.py list --show
```

Revoke / unrevoke:

```bash
python3 /Users/qian/Music/OS/license_issuer/issue_license.py revoke --key QOS2-...
python3 /Users/qian/Music/OS/license_issuer/issue_license.py unrevoke --key QOS2-...
```

## Build Note
After issuing/revoking keys, rebuild image:

```bash
cd /Users/qian/Music/OS
make iso disk
```
