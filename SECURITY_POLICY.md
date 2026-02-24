# QuartzOS Security Policy

Version: 1.0
Effective date: February 24, 2026

## 1. Purpose
This document defines security controls, verification requirements, and reporting expectations for QuartzOS.

## 2. Security principles
- Fail closed for integrity and license verification.
- Minimize trust at user level.
- Enforce critical security in kernel space.
- Audit security-relevant events.

## 3. Verification architecture
- Kernel integrity checks validate critical files against a signed manifest.
- Critical file hashes are additionally checked against a remote antivirus validation service.
- License activation and active license state are verified against a remote license database service.
- If remote verification is unavailable or rejects data, QuartzOS may restrict or deny operation.

## 4. Server access model
- Verification endpoints are kernel-only security channels.
- End users and userland tools are not permitted to directly access verification server endpoints.
- Attempts to bypass this model may trigger lock or failsafe behavior.

## 5. Security controls
- Memory and execution controls (kernel/user separation, syscall gates, policy checks).
- Security feature flags and lockdown mode.
- Integrity and intrusion failsafes.
- Encrypted and signed critical security/license state.

## 6. Incident response
QuartzOS may:
- block operations,
- disable selected services,
- require re-verification,
- or enforce lock mode,
when security integrity cannot be established.

## 7. Vulnerability reporting
For responsible disclosure, report security issues with:
- clear reproduction steps,
- impact analysis,
- and affected versions/components.

If no dedicated reporting address is published, open a private security issue in the project channel used by maintainers.

## 8. Supported policy behavior
Security behavior may change between releases. The latest release policy applies.

## 9. Disclaimer
This policy is an operational security document, not legal advice.
