# QuartzOS License Activation (macOS)

Build the app bundle:

```bash
cd /Users/qian/Music/OS
./QuartzOS-license-activation/macos_app/build_macos_activation_app.sh
```

Open it:

```bash
open "/Users/qian/Music/OS/build/QuartzOS License Activation.app"
```

The app includes `Activate Running VM`, which sends the full unlock sequence to
the active QEMU window after key verification.
