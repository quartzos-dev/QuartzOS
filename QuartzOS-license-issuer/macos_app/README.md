# QuartzOS License Issuer Pro (macOS)

Native AppKit front-end for:

- `/Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py`

## What Was Upgraded

- Full multi-tab workflow:
  - `Issue`
  - `Verify`
  - `Revocation`
  - `Store`
- Dashboard cards for issued/active/revoked/integrity.
- Secure password handling:
  - Password is passed with `--password-env`, never in command args.
  - Keychain support: save/load/clear issuer password.
- Batch verification from pasted text (extracts valid `QOS1/QOS2/QOS3` keys).
- Command history with one-click rerun.
- Real-time output console + log export.
- Stop/cancel active command support.
- Store/security operations integrated into UI:
  - `verify-store`
  - `seal-store`
  - `harden-store`
  - `password-hash`

## Build

```bash
cd /Users/qian/Music/OS
./QuartzOS-license-issuer/macos_app/build_macos_app.sh
```

Shortcut wrapper from repo root:

```bash
cd /Users/qian/Music/OS
./build_macos_app.sh
```

## Launch

```bash
open "/Users/qian/Music/OS/build/QuartzOS License Issuer.app"
```

## Quick Start

1. Set `Repo Path` to `/Users/qian/Music/OS` (auto-detected by default).
2. Set `Issuer Password` (or load from Keychain).
3. (Optional) set `Admin Hash File` for privileged operations.
4. Use tabs to run operations.
5. Use `Refresh Dashboard` in Store tab after changes.
