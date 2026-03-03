# QuartzOS Admin Console

Security-first all-in-one admin application for QuartzOS.

Core features:
- Baseline security audit (`tools/admin_security_audit.py`).
- One-click `health`, `smoke`, and `overhaul` pipelines.
- Privileged license administration (issue/list/revoke/deactivate legacy).
- Operational helpers (build activation app, build issuer app, open security policy, export report).

Security controls:
- Password is never passed on argv; privileged actions use env-only injection.
- No arbitrary shell execution from UI; only allowlisted operations are exposed.
- Destructive operations require explicit confirmation dialogs.

Build and run:

```bash
cd /Users/qian/Music/OS
./build_macos_admin_app.sh
open "/Users/qian/Music/OS/build/QuartzOS Admin Console.app"
```
