# QuartzOS Security Server

This folder contains the server-side implementation used by QuartzOS kernel security checks.

## Components

- `quartzos_security_server.py`
  - TCP security daemon for:
    - antivirus manifest checks on port `9443`
    - license verification checks on port `9444`
  - validates kernel request HMAC pin (`QOS_KEY_SECURITY_SERVER_PIN` derivation)
  - verifies license signatures and enforces minimum `QOS3` monthly/subscription tier

- `install_security_server.sh`
  - installs and hardens the daemon as a `systemd` service:
    - `quartzos-security-server.service`
  - service user: `quartzos-sec`
  - data dir: `/opt/quartzos-security/data/current`

## Required data files on server

- `/opt/quartzos-security/data/current/security_manifest.txt`
- `/opt/quartzos-security/data/current/security_manifest.sig`
- `/opt/quartzos-security/data/current/licenses.db`
- `/opt/quartzos-security/data/current/licenses.revoked`

## Deployment from macOS workspace

Use:

```bash
/Users/qian/Music/OS/tools/deploy_security_server_bundle.sh root@46.16.131.231
```

(Requires SSH access to the server.)
