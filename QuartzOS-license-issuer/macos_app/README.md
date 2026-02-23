# QuartzOS License Issuer macOS App

This folder contains a native macOS AppKit application wrapper around:

- `/Users/qian/Music/OS/QuartzOS-license-issuer/issue_license.py`

## Build

```bash
cd /Users/qian/Music/OS
./QuartzOS-license-issuer/macos_app/build_macos_app.sh
```

## Launch

```bash
open "/Users/qian/Music/OS/build/QuartzOS License Issuer.app"
```

## Notes

- The app executes issuer commands using `python3`.
- Passwords are passed via environment variable (`--password-env`) instead of command-line args.
- The app can generate a secure admin hash file (`password-hash`) and then use it for all privileged actions.
- `deactivate-legacy` revokes and purges all `QOS1/QOS2` licenses.
