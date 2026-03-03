#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class CheckResult:
    name: str
    status: str
    severity: str
    message: str


def run_command(repo: Path, args: List[str]) -> tuple[int, str]:
    proc = subprocess.run(
        args,
        cwd=str(repo),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc.returncode, proc.stdout.strip()


def not_world_writable(path: Path) -> bool:
    mode = path.stat().st_mode
    return (mode & stat.S_IWOTH) == 0 and (mode & stat.S_IWGRP) == 0


def secure_hash_file(path: Path) -> bool:
    mode = path.stat().st_mode
    # Password hash file should not be readable by group/other.
    return (mode & stat.S_IRGRP) == 0 and (mode & stat.S_IROTH) == 0


def load_cfg(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def audit(repo: Path) -> list[CheckResult]:
    results: list[CheckResult] = []

    required = [
        repo / "Makefile",
        repo / "tools" / "check_issuer_security.py",
        repo / "QuartzOS-license-issuer" / "issue_license.py",
        repo / "server" / "quartzos_security_server.py",
        repo / "assets" / "licenses" / "licenses.db",
        repo / "assets" / "licenses" / "licenses.revoked",
        repo / "assets" / "licenses" / "licenses_integrity.json",
        repo / "assets" / "config" / "system.cfg",
    ]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        results.append(
            CheckResult(
                "required-files",
                "FAIL",
                "critical",
                "missing required files: " + ", ".join(missing),
            )
        )
    else:
        results.append(CheckResult("required-files", "PASS", "info", "all required security files present"))

    sensitive = [
        repo / "assets" / "licenses" / "licenses.db",
        repo / "assets" / "licenses" / "licenses.revoked",
        repo / "assets" / "licenses" / "licenses_integrity.json",
        repo / "assets" / "licenses" / "licenses_meta.csv",
        repo / "assets" / "licenses" / "licenses_audit.csv",
        repo / "assets" / "licenses" / "licenses_tracking.csv",
        repo / "assets" / "config" / "system.cfg",
        repo / "server" / "quartzos_security_server.py",
        repo / "QuartzOS-license-issuer" / "issue_license.py",
    ]
    weak_perms = [str(p) for p in sensitive if p.exists() and not not_world_writable(p)]
    if weak_perms:
        results.append(
            CheckResult(
                "file-permissions",
                "WARN",
                "high",
                "group/other writable sensitive files: " + ", ".join(weak_perms),
            )
        )
    else:
        results.append(CheckResult("file-permissions", "PASS", "info", "sensitive files not world/group writable"))

    hash_path = repo / "build" / "issuer_admin_hash.txt"
    if hash_path.exists():
        if secure_hash_file(hash_path):
            results.append(CheckResult("admin-hash-permissions", "PASS", "info", "issuer_admin_hash.txt permissions are restricted"))
        else:
            results.append(
                CheckResult(
                    "admin-hash-permissions",
                    "WARN",
                    "high",
                    "issuer_admin_hash.txt is readable by group/other; set mode 600",
                )
            )
    else:
        results.append(CheckResult("admin-hash-permissions", "WARN", "medium", "build/issuer_admin_hash.txt not found"))

    cfg = load_cfg(repo / "assets" / "config" / "system.cfg")
    ip_text = cfg.get("security.server.ip", "")
    av_port_text = cfg.get("security.server.av_port", "")
    lic_port_text = cfg.get("security.server.license_port", "")

    cfg_errors: list[str] = []
    try:
        ipaddress.ip_address(ip_text)
    except ValueError:
        cfg_errors.append("security.server.ip invalid")

    try:
        av_port = int(av_port_text)
        if av_port <= 0 or av_port > 65535:
            raise ValueError
    except ValueError:
        cfg_errors.append("security.server.av_port invalid")

    try:
        lic_port = int(lic_port_text)
        if lic_port <= 0 or lic_port > 65535:
            raise ValueError
    except ValueError:
        cfg_errors.append("security.server.license_port invalid")

    if not cfg_errors and av_port == lic_port:
        cfg_errors.append("security server ports must be different")

    if cfg_errors:
        results.append(CheckResult("server-config", "FAIL", "critical", "; ".join(cfg_errors)))
    else:
        results.append(CheckResult("server-config", "PASS", "info", f"server={ip_text} av={av_port_text} license={lic_port_text}"))

    code, output = run_command(repo, [sys.executable, "tools/check_issuer_security.py"])
    if code == 0:
        results.append(CheckResult("issuer-security-guard", "PASS", "info", output or "passed"))
    else:
        results.append(CheckResult("issuer-security-guard", "FAIL", "critical", output or "failed"))

    code, output = run_command(
        repo,
        [
            sys.executable,
            "QuartzOS-license-issuer/issue_license.py",
            "verify-store",
            "--require-manifest",
        ],
    )
    if code == 0:
        results.append(CheckResult("license-store-verify", "PASS", "info", output or "clean"))
    else:
        results.append(CheckResult("license-store-verify", "FAIL", "critical", output or "verify-store failed"))

    # Basic encrypted-at-rest signal: known store files should start with QENC1| in hardened mode.
    encrypted_targets = [
        repo / "assets" / "licenses" / "licenses.db",
        repo / "assets" / "licenses" / "licenses.revoked",
        repo / "assets" / "licenses" / "licenses_meta.csv",
        repo / "assets" / "licenses" / "licenses_audit.csv",
        repo / "assets" / "licenses" / "licenses_tracking.csv",
    ]
    plaintext = []
    for path in encrypted_targets:
        if not path.exists():
            continue
        head = path.read_text(encoding="utf-8", errors="ignore")[:8]
        if not head.startswith("QENC1|"):
            plaintext.append(str(path))

    if plaintext:
        results.append(
            CheckResult(
                "encrypted-store-format",
                "WARN",
                "high",
                "store files not in QENC1 format: " + ", ".join(plaintext),
            )
        )
    else:
        results.append(CheckResult("encrypted-store-format", "PASS", "info", "license store files are in QENC1 format"))

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="QuartzOS admin security baseline audit")
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent), help="QuartzOS repo root")
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    results = audit(repo)

    fail_count = sum(1 for r in results if r.status == "FAIL")
    warn_count = sum(1 for r in results if r.status == "WARN")

    if args.json:
        payload = {
            "repo": str(repo),
            "summary": {
                "total": len(results),
                "fail": fail_count,
                "warn": warn_count,
                "pass": len(results) - fail_count - warn_count,
            },
            "results": [r.__dict__ for r in results],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(f"QuartzOS Admin Security Audit: {repo}")
        for r in results:
            print(f"[{r.status}] {r.name}: {r.message}")
        print(
            "summary: "
            f"total={len(results)} pass={len(results) - fail_count - warn_count} warn={warn_count} fail={fail_count}"
        )

    return 1 if fail_count > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
