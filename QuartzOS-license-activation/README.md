# QuartzOS License Activation (Public App)

This app is for end users to activate QuartzOS.

Scope:
- Verify a QOS3 key using the project verifier.
- Enforce Consumer Monthly tier check before unlock command export.
- Generate unlock command sequence for locked QuartzOS sessions.
- One-click auto activation for a running QEMU VM (macOS keystroke automation).

Out of scope:
- Issuing/revoking licenses.
- Admin password workflows.
- License store mutation.

Build:

```bash
cd /Users/qian/Music/OS
./build_macos_activation_app.sh
open "/Users/qian/Music/OS/build/QuartzOS License Activation.app"
```

The existing `QuartzOS License Issuer.app` remains dev/admin-only.

CLI automation helper:

```bash
cd /Users/qian/Music/OS
./tools/auto-activate-vm-license.sh QOS3-...-...-...-...
```
