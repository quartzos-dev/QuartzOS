#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import getpass
import hashlib
import hmac
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT_DIR / "assets" / "licenses" / "licenses.db"
DEFAULT_REVOKED = ROOT_DIR / "assets" / "licenses" / "licenses.revoked"
DEFAULT_META = ROOT_DIR / "assets" / "licenses" / "licenses_meta.csv"
DEFAULT_AUDIT = ROOT_DIR / "assets" / "licenses" / "licenses_audit.csv"

LEGACY_ADMIN_SALT = "QOS-ISSUER-SALT-V1"
DEFAULT_ADMIN_PASSWORD = "QuartzOS-Admin-2026!"
DEFAULT_ADMIN_ITERATIONS = 240_000
DEFAULT_ADMIN_SALT_HEX = "6f11717bf77eb6fd6808d4df576c02f6"
DEFAULT_ADMIN_HASH_HEX = hashlib.pbkdf2_hmac(
    "sha256",
    DEFAULT_ADMIN_PASSWORD.encode("utf-8"),
    bytes.fromhex(DEFAULT_ADMIN_SALT_HEX),
    DEFAULT_ADMIN_ITERATIONS,
).hex()
DEFAULT_ADMIN_RECORD = (
    f"pbkdf2_sha256${DEFAULT_ADMIN_ITERATIONS}"
    f"${DEFAULT_ADMIN_SALT_HEX}${DEFAULT_ADMIN_HASH_HEX}"
)
DEFAULT_LEGACY_ADMIN_HASH = hashlib.sha256(
    (DEFAULT_ADMIN_PASSWORD + LEGACY_ADMIN_SALT).encode("utf-8")
).hexdigest()

DEFAULT_HMAC_SECRET = "QuartzOS-Licensing-HMAC-Key-V2-2026"

TIERS = {
    "community": 0x0001,
    "pro": 0x0002,
    "enterprise": 0x0004,
    "ultimate": 0x0008,
    "all": 0x000F,
}


@dataclass(frozen=True)
class ParsedKey:
    key: str
    version: str
    key_id: int
    feature_bits: int
    nonce: int
    signature: int


def fnv1a32(text: str) -> int:
    h = 2166136261
    for b in text.encode("ascii", "strict"):
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def signature_for_v1(key_id: int, feature_bits: int) -> int:
    payload = f"QOS1:{key_id:08X}:{feature_bits:04X}:QUARTZOS-LICENSE-V1"
    return fnv1a32(payload)


def signature_for_v2(key_id: int, feature_bits: int, nonce: int, secret: str) -> int:
    payload = f"QOS2:{key_id:08X}:{feature_bits:04X}:{nonce:08X}:QUARTZOS-LICENSE-V2"
    digest = hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()
    return int.from_bytes(digest[:8], "big")


def make_key_v1(key_id: int, feature_bits: int) -> str:
    sig = signature_for_v1(key_id, feature_bits)
    return f"QOS1-{key_id:08X}-{feature_bits:04X}-{sig:08X}"


def make_key_v2(key_id: int, feature_bits: int, nonce: int, secret: str) -> str:
    sig = signature_for_v2(key_id, feature_bits, nonce, secret)
    return f"QOS2-{key_id:08X}-{feature_bits:04X}-{nonce:08X}-{sig:016X}"


def normalize_key(raw: str) -> str:
    key = raw.strip().upper()
    if len(key) == 27:
        if not key.startswith("QOS1-") or key[13] != "-" or key[18] != "-":
            raise ValueError("invalid QOS1 key format")
        parts = (key[5:13], key[14:18], key[19:27])
    elif len(key) == 44:
        if not key.startswith("QOS2-") or key[13] != "-" or key[18] != "-" or key[27] != "-":
            raise ValueError("invalid QOS2 key format")
        parts = (key[5:13], key[14:18], key[19:27], key[28:44])
    else:
        raise ValueError("unsupported key length")

    for block in parts:
        int(block, 16)
    return key


def parse_key(raw: str) -> ParsedKey:
    key = normalize_key(raw)
    if key.startswith("QOS1-"):
        return ParsedKey(
            key=key,
            version="qos1",
            key_id=int(key[5:13], 16),
            feature_bits=int(key[14:18], 16),
            nonce=0,
            signature=int(key[19:27], 16),
        )
    return ParsedKey(
        key=key,
        version="qos2",
        key_id=int(key[5:13], 16),
        feature_bits=int(key[14:18], 16),
        nonce=int(key[19:27], 16),
        signature=int(key[28:44], 16),
    )


def is_signature_valid(raw: str, secret: str) -> bool:
    try:
        parsed = parse_key(raw)
    except ValueError:
        return False
    if parsed.version == "qos1":
        return parsed.signature == signature_for_v1(parsed.key_id, parsed.feature_bits)
    return parsed.signature == signature_for_v2(parsed.key_id, parsed.feature_bits, parsed.nonce, secret)


def read_key_file(path: Path, secret: str) -> list[str]:
    if not path.exists():
        return []
    out: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#") or text.startswith(";"):
            continue
        token = text.split()[0]
        try:
            key = normalize_key(token)
        except ValueError:
            continue
        if not is_signature_valid(key, secret):
            continue
        if key not in seen:
            out.append(key)
            seen.add(key)
    return out


def write_key_file(path: Path, title: str, keys: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = [
        f"# {title}",
        "# Format: one signed key per line (QOS1 or QOS2).",
    ]
    body = sorted(set(keys))
    path.write_text("\n".join(header + body) + "\n", encoding="utf-8")


def read_db(path: Path, secret: str) -> list[str]:
    return read_key_file(path, secret)


def write_db(path: Path, keys: list[str]) -> None:
    write_key_file(path, "QuartzOS License Database (v2)", keys)


def read_revoked(path: Path, secret: str) -> list[str]:
    return read_key_file(path, secret)


def write_revoked(path: Path, keys: list[str]) -> None:
    write_key_file(path, "QuartzOS Revoked License Database", keys)


def append_meta(meta_path: Path, rows: list[tuple[str, str, str, str, str, str, str, str]]) -> None:
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not meta_path.exists()
    with meta_path.open("a", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        if needs_header:
            w.writerow(
                [
                    "issued_at_utc",
                    "owner",
                    "tier",
                    "version",
                    "key_id_hex",
                    "feature_bits_hex",
                    "nonce_hex",
                    "key",
                ]
            )
        for row in rows:
            w.writerow(row)


def append_audit(audit_path: Path, rows: list[tuple[str, str, str, str, str]]) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not audit_path.exists()
    with audit_path.open("a", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        if needs_header:
            w.writerow(["timestamp_utc", "action", "key", "actor", "note"])
        for row in rows:
            w.writerow(row)


def make_password_record(password: str, iterations: int = DEFAULT_ADMIN_ITERATIONS, salt: bytes | None = None) -> str:
    if iterations < 100_000:
        raise ValueError("iterations must be >= 100000")
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, record: str) -> bool:
    text = record.strip()
    if text.startswith("pbkdf2_sha256$"):
        parts = text.split("$")
        if len(parts) != 4:
            return False
        _, iter_text, salt_hex, hash_hex = parts
        try:
            iterations = int(iter_text)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
        except ValueError:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(digest, expected)

    legacy = hashlib.sha256((password + LEGACY_ADMIN_SALT).encode("utf-8")).hexdigest()
    return hmac.compare_digest(legacy, text.lower())


def verify_admin_password(password: str) -> bool:
    configured = os.getenv("QOS_ISSUER_ADMIN_HASH", DEFAULT_ADMIN_RECORD)
    if verify_password(password, configured):
        return True
    return verify_password(password, DEFAULT_LEGACY_ADMIN_HASH)


def require_password(supplied: str | None) -> None:
    if supplied is None:
        supplied = getpass.getpass("Issuer password: ")
    if not verify_admin_password(supplied):
        print("error: invalid issuer password", file=sys.stderr)
        raise SystemExit(1)


def key_secret() -> str:
    return os.getenv("QOS_ISSUER_HMAC_SECRET", DEFAULT_HMAC_SECRET)


def key_status(db_keys: set[str], revoked_keys: set[str], key: str) -> str:
    if key in revoked_keys:
        return "revoked"
    if key in db_keys:
        return "issued"
    return "unknown"


def cmd_issue(args: argparse.Namespace) -> None:
    require_password(args.password)
    secret = key_secret()

    db_keys = set(read_db(args.db, secret))
    revoked_keys = set(read_revoked(args.revoked, secret))
    created: list[str] = []
    tier_bits = TIERS[args.tier]
    version = args.version.lower()

    while len(created) < args.count:
        key_id = secrets.randbits(32)
        if version == "qos1":
            key = make_key_v1(key_id, tier_bits)
            nonce_hex = ""
        else:
            nonce = secrets.randbits(32)
            key = make_key_v2(key_id, tier_bits, nonce, secret)
            nonce_hex = f"{nonce:08X}"
        if key in db_keys or key in created:
            continue
        created.append(key)
        db_keys.add(key)
        revoked_keys.discard(key)

    write_db(args.db, sorted(db_keys))
    write_revoked(args.revoked, sorted(revoked_keys))

    ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    meta_rows: list[tuple[str, str, str, str, str, str, str, str]] = []
    audit_rows: list[tuple[str, str, str, str, str]] = []
    for key in created:
        parsed = parse_key(key)
        meta_rows.append(
            (
                ts,
                args.owner,
                args.tier,
                parsed.version,
                f"{parsed.key_id:08X}",
                f"{parsed.feature_bits:04X}",
                f"{parsed.nonce:08X}" if parsed.version == "qos2" else "",
                key,
            )
        )
        audit_rows.append((ts, "ISSUE", key, args.owner, args.tier))

    append_meta(args.meta, meta_rows)
    append_audit(args.audit, audit_rows)

    print(
        f"issued {len(created)} key(s) owner='{args.owner}' "
        f"tier='{args.tier}' version='{version}'"
    )
    for key in created:
        print(key)


def cmd_verify(args: argparse.Namespace) -> None:
    secret = key_secret()
    try:
        parsed = parse_key(args.key)
    except ValueError as exc:
        print(f"invalid: {exc}")
        raise SystemExit(1)

    sig_ok = is_signature_valid(parsed.key, secret)
    db_keys = set(read_db(args.db, secret))
    revoked_keys = set(read_revoked(args.revoked, secret))
    issued = parsed.key in db_keys
    revoked = parsed.key in revoked_keys

    print(f"key: {parsed.key}")
    print(f"version: {parsed.version}")
    print(f"signature: {'valid' if sig_ok else 'invalid'}")
    print(f"issued: {'yes' if issued else 'no'}")
    print(f"revoked: {'yes' if revoked else 'no'}")
    print(f"feature_bits: 0x{parsed.feature_bits:04X}")
    if parsed.version == "qos2":
        print(f"nonce: 0x{parsed.nonce:08X}")

    ok = sig_ok and issued and not revoked
    raise SystemExit(0 if ok else 1)


def cmd_list(args: argparse.Namespace) -> None:
    require_password(args.password)
    secret = key_secret()
    db_keys = sorted(set(read_db(args.db, secret)))
    revoked = set(read_revoked(args.revoked, secret))
    active = [k for k in db_keys if k not in revoked]

    print(f"total issued keys: {len(db_keys)}")
    print(f"active keys: {len(active)}")
    print(f"revoked keys: {len(revoked)}")

    if args.show:
        for key in db_keys:
            print(f"{key} [{key_status(set(db_keys), revoked, key)}]")


def cmd_revoke(args: argparse.Namespace) -> None:
    require_password(args.password)
    secret = key_secret()

    try:
        key = normalize_key(args.key)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if not is_signature_valid(key, secret):
        print("error: key signature is invalid", file=sys.stderr)
        raise SystemExit(1)

    db_keys = set(read_db(args.db, secret))
    revoked = set(read_revoked(args.revoked, secret))
    if key not in db_keys:
        print("error: key not found in issued database", file=sys.stderr)
        raise SystemExit(1)
    if key in revoked:
        print("already revoked")
        return

    revoked.add(key)
    write_revoked(args.revoked, sorted(revoked))
    ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    append_audit(args.audit, [(ts, "REVOKE", key, args.actor, args.note or "")])
    print(f"revoked: {key}")


def cmd_unrevoke(args: argparse.Namespace) -> None:
    require_password(args.password)
    secret = key_secret()

    try:
        key = normalize_key(args.key)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if not is_signature_valid(key, secret):
        print("error: key signature is invalid", file=sys.stderr)
        raise SystemExit(1)

    revoked = set(read_revoked(args.revoked, secret))
    if key not in revoked:
        print("key is not revoked")
        return
    revoked.remove(key)
    write_revoked(args.revoked, sorted(revoked))
    ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    append_audit(args.audit, [(ts, "UNREVOKE", key, args.actor, args.note or "")])
    print(f"unrevoked: {key}")


def cmd_password_hash(args: argparse.Namespace) -> None:
    password = args.password
    if password is None:
        password = getpass.getpass("New issuer password: ")
    record = make_password_record(password, iterations=args.iterations)
    print(record)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="QuartzOS License Issuer (password protected, revocation-aware, QOS1/QOS2)"
    )
    p.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"license db path (default: {DEFAULT_DB})")
    p.add_argument(
        "--revoked",
        type=Path,
        default=DEFAULT_REVOKED,
        help=f"revoked db path (default: {DEFAULT_REVOKED})",
    )
    p.add_argument("--meta", type=Path, default=DEFAULT_META, help=f"metadata csv path (default: {DEFAULT_META})")
    p.add_argument("--audit", type=Path, default=DEFAULT_AUDIT, help=f"audit csv path (default: {DEFAULT_AUDIT})")

    sub = p.add_subparsers(dest="cmd", required=True)

    issue = sub.add_parser("issue", help="issue new license keys (password required)")
    issue.add_argument("--owner", required=True, help="owner name")
    issue.add_argument("--tier", choices=sorted(TIERS.keys()), default="community")
    issue.add_argument("--version", choices=["qos2", "qos1"], default="qos2")
    issue.add_argument("--count", type=int, default=1)
    issue.add_argument("--password", help="issuer password (optional; prompt if omitted)")
    issue.set_defaults(func=cmd_issue)

    verify = sub.add_parser("verify", help="verify signature + issuance + revocation status")
    verify.add_argument("--key", required=True, help="license key")
    verify.set_defaults(func=cmd_verify)

    list_cmd = sub.add_parser("list", help="list issued/revoked keys (password required)")
    list_cmd.add_argument("--show", action="store_true", help="print all issued keys")
    list_cmd.add_argument("--password", help="issuer password (optional; prompt if omitted)")
    list_cmd.set_defaults(func=cmd_list)

    revoke = sub.add_parser("revoke", help="revoke an issued key (password required)")
    revoke.add_argument("--key", required=True, help="license key")
    revoke.add_argument("--actor", default="admin", help="operator name for audit log")
    revoke.add_argument("--note", default="", help="optional audit note")
    revoke.add_argument("--password", help="issuer password (optional; prompt if omitted)")
    revoke.set_defaults(func=cmd_revoke)

    unrevoke = sub.add_parser("unrevoke", help="remove key from revocation list (password required)")
    unrevoke.add_argument("--key", required=True, help="license key")
    unrevoke.add_argument("--actor", default="admin", help="operator name for audit log")
    unrevoke.add_argument("--note", default="", help="optional audit note")
    unrevoke.add_argument("--password", help="issuer password (optional; prompt if omitted)")
    unrevoke.set_defaults(func=cmd_unrevoke)

    pwhash = sub.add_parser("password-hash", help="generate QOS_ISSUER_ADMIN_HASH value")
    pwhash.add_argument("--password", help="password (optional; prompt if omitted)")
    pwhash.add_argument("--iterations", type=int, default=DEFAULT_ADMIN_ITERATIONS)
    pwhash.set_defaults(func=cmd_password_hash)

    return p


def prompt_text(label: str, default: str | None = None, required: bool = False) -> str:
    while True:
        suffix = f" [{default}]" if default is not None else ""
        value = input(f"{label}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        if not required:
            return ""
        print("value is required")


def prompt_int(label: str, default: int, minimum: int, maximum: int) -> int:
    while True:
        raw = prompt_text(label, str(default), required=True)
        try:
            value = int(raw)
        except ValueError:
            print("enter a valid integer")
            continue
        if value < minimum or value > maximum:
            print(f"value must be between {minimum} and {maximum}")
            continue
        return value


def prompt_yes_no(label: str, default: bool = False) -> bool:
    default_text = "y" if default else "n"
    while True:
        value = prompt_text(f"{label} (y/n)", default_text, required=True).lower()
        if value in ("y", "yes"):
            return True
        if value in ("n", "no"):
            return False
        print("enter y or n")


def prompt_tier(default: str = "community") -> str:
    choices = "/".join(sorted(TIERS.keys()))
    while True:
        value = prompt_text(f"tier ({choices})", default, required=True).lower()
        if value in TIERS:
            return value
        print("invalid tier")


def prompt_version(default: str = "qos2") -> str:
    while True:
        value = prompt_text("version (qos2/qos1)", default, required=True).lower()
        if value in ("qos2", "qos1"):
            return value
        print("invalid version")


def interactive_args() -> list[str] | None:
    print("QuartzOS License Issuer interactive mode")
    print("  1) issue")
    print("  2) verify")
    print("  3) list")
    print("  4) revoke")
    print("  5) unrevoke")
    print("  6) password-hash")
    print("  q) quit")
    while True:
        choice = prompt_text("select command", required=True).lower()
        if choice in ("q", "quit", "exit"):
            return None
        if choice in ("1", "issue"):
            owner = prompt_text("owner", required=True)
            tier = prompt_tier("community")
            version = prompt_version("qos2")
            count = prompt_int("count", 1, 1, 1000)
            return [
                "issue",
                "--owner",
                owner,
                "--tier",
                tier,
                "--version",
                version,
                "--count",
                str(count),
            ]
        if choice in ("2", "verify"):
            key = prompt_text("license key", required=True)
            return ["verify", "--key", key]
        if choice in ("3", "list"):
            show = prompt_yes_no("show all keys", default=False)
            out = ["list"]
            if show:
                out.append("--show")
            return out
        if choice in ("4", "revoke"):
            key = prompt_text("license key", required=True)
            actor = prompt_text("actor", "admin", required=True)
            note = prompt_text("note", "", required=False)
            out = ["revoke", "--key", key, "--actor", actor]
            if note:
                out.extend(["--note", note])
            return out
        if choice in ("5", "unrevoke"):
            key = prompt_text("license key", required=True)
            actor = prompt_text("actor", "admin", required=True)
            note = prompt_text("note", "", required=False)
            out = ["unrevoke", "--key", key, "--actor", actor]
            if note:
                out.extend(["--note", note])
            return out
        if choice in ("6", "password-hash"):
            iterations = prompt_int("iterations", DEFAULT_ADMIN_ITERATIONS, 100000, 2000000)
            return ["password-hash", "--iterations", str(iterations)]
        print("invalid selection")


def run_args(parser: argparse.ArgumentParser, argv: list[str]) -> int:
    args = parser.parse_args(argv)
    if args.cmd == "issue" and (args.count < 1 or args.count > 1000):
        print("error: --count must be between 1 and 1000", file=sys.stderr)
        return 1
    try:
        args.func(args)
        return 0
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        return 1


def main() -> None:
    parser = build_parser()
    if len(sys.argv) == 1:
        try:
            argv = interactive_args()
        except (EOFError, KeyboardInterrupt):
            print("\naborted")
            raise SystemExit(1)
        if argv is None:
            print("bye")
            return
        code = run_args(parser, argv)
        raise SystemExit(code)

    code = run_args(parser, sys.argv[1:])
    raise SystemExit(code)


if __name__ == "__main__":
    main()
