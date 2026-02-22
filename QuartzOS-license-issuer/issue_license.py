#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import getpass
import hashlib
import hmac
import io
import json
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
DEFAULT_INTEGRITY = ROOT_DIR / "assets" / "licenses" / "licenses_integrity.json"
DEFAULT_PASSWORD_HASH_OUT = ROOT_DIR / "build" / "issuer_admin_hash.txt"

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

DEFAULT_HMAC_SECRET_V2 = "QuartzOS-Licensing-HMAC-Key-V2-2026"
DEFAULT_HMAC_SECRET_V3 = "QuartzOS-Licensing-HMAC-Key-V3-2026"
DEFAULT_INTEGRITY_SECRET = "QuartzOS-License-Store-Integrity-V1-2026"
DEFAULT_FILE_ENC_SECRET = "QuartzOS-SecureStore-ENC-V1-2026"
SECURE_PREFIX = "QENC1|"
SECURE_NONCE_BYTES = 8
SECURE_TAG_BYTES = 32
ALLOW_LEGACY_ISSUE_DEFAULT = False

POLICY_DEVELOPMENT_ONLY = 0x01
POLICY_NON_COMMERCIAL = 0x02
POLICY_ACADEMIC_ONLY = 0x04
POLICY_SERVER_ONLY = 0x08
POLICY_OEM_ONLY = 0x10
POLICY_AUDIT_REQUIRED = 0x20
POLICY_SUBSCRIPTION = 0x40


@dataclass(frozen=True)
class TierSpec:
    name: str
    code: int
    legacy_feature_bits: int
    policy_bits: int
    summary: str


@dataclass(frozen=True)
class ParsedKey:
    key: str
    version: str
    key_id: int
    feature_bits: int
    tier_code: int
    policy_bits: int
    nonce: int
    signature_hex: str


@dataclass(frozen=True)
class MetaRecord:
    issued_at_utc: str
    owner: str
    tier: str
    version: str
    key_id_hex: str
    feature_bits_hex: str
    nonce_hex: str
    key: str


TIERS: dict[str, TierSpec] = {
    "consumer": TierSpec(
        "consumer",
        code=0x01,
        legacy_feature_bits=0x0001,
        policy_bits=POLICY_NON_COMMERCIAL | POLICY_SUBSCRIPTION,
        summary="Personal non-commercial single-device use",
    ),
    "enterprise": TierSpec(
        "enterprise",
        code=0x02,
        legacy_feature_bits=0x0002,
        policy_bits=POLICY_SUBSCRIPTION,
        summary="Internal commercial use",
    ),
    "educational": TierSpec(
        "educational",
        code=0x03,
        legacy_feature_bits=0x0003,
        policy_bits=POLICY_ACADEMIC_ONLY | POLICY_SUBSCRIPTION,
        summary="Accredited institutions",
    ),
    "server": TierSpec(
        "server",
        code=0x04,
        legacy_feature_bits=0x0004,
        policy_bits=POLICY_SERVER_ONLY | POLICY_SUBSCRIPTION,
        summary="Server deployments",
    ),
    "dev_standard": TierSpec(
        "dev_standard",
        code=0x05,
        legacy_feature_bits=0x0005,
        policy_bits=POLICY_DEVELOPMENT_ONLY,
        summary="Development-only standard license",
    ),
    "student_dev": TierSpec(
        "student_dev",
        code=0x06,
        legacy_feature_bits=0x0006,
        policy_bits=POLICY_DEVELOPMENT_ONLY | POLICY_ACADEMIC_ONLY | POLICY_NON_COMMERCIAL,
        summary="Student development use",
    ),
    "startup_dev": TierSpec(
        "startup_dev",
        code=0x07,
        legacy_feature_bits=0x0007,
        policy_bits=POLICY_DEVELOPMENT_ONLY,
        summary="Startup internal development use",
    ),
    "open_lab": TierSpec(
        "open_lab",
        code=0x08,
        legacy_feature_bits=0x0008,
        policy_bits=POLICY_DEVELOPMENT_ONLY | POLICY_NON_COMMERCIAL,
        summary="Open lab non-commercial research",
    ),
    "oem": TierSpec(
        "oem",
        code=0x09,
        legacy_feature_bits=0x0009,
        policy_bits=POLICY_OEM_ONLY | POLICY_AUDIT_REQUIRED,
        summary="OEM preinstalled deployment",
    ),
}

LEGACY_TIER_ALIASES: dict[str, str] = {
    "community": "consumer",
    "pro": "enterprise",
    "ultimate": "server",
}


def policy_labels(bits: int) -> list[str]:
    out: list[str] = []
    if bits & POLICY_DEVELOPMENT_ONLY:
        out.append("development_only")
    if bits & POLICY_NON_COMMERCIAL:
        out.append("non_commercial")
    if bits & POLICY_ACADEMIC_ONLY:
        out.append("academic_only")
    if bits & POLICY_SERVER_ONLY:
        out.append("server_only")
    if bits & POLICY_OEM_ONLY:
        out.append("oem_only")
    if bits & POLICY_AUDIT_REQUIRED:
        out.append("audit_required")
    if bits & POLICY_SUBSCRIPTION:
        out.append("subscription")
    return out


def normalize_tier_name(raw: str) -> str:
    value = raw.strip().lower().replace("-", "_")
    if value in LEGACY_TIER_ALIASES:
        return LEGACY_TIER_ALIASES[value]
    return value


def tier_from_code(code: int) -> TierSpec | None:
    for spec in TIERS.values():
        if spec.code == code:
            return spec
    return None


def tier_from_feature_bits(feature_bits: int) -> TierSpec | None:
    for spec in TIERS.values():
        if spec.legacy_feature_bits == feature_bits:
            return spec
    return None


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


def signature_for_v3(key_id: int, tier_code: int, policy_bits: int, nonce: int, secret: str) -> str:
    payload = f"QOS3:{key_id:08X}:{tier_code:02X}:{policy_bits:02X}:{nonce:08X}:QUARTZOS-LICENSE-V3"
    digest = hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()
    return digest[:12].hex().upper()


def make_key_v1(key_id: int, feature_bits: int) -> str:
    sig = signature_for_v1(key_id, feature_bits)
    return f"QOS1-{key_id:08X}-{feature_bits:04X}-{sig:08X}"


def make_key_v2(key_id: int, feature_bits: int, nonce: int, secret: str) -> str:
    sig = signature_for_v2(key_id, feature_bits, nonce, secret)
    return f"QOS2-{key_id:08X}-{feature_bits:04X}-{nonce:08X}-{sig:016X}"


def make_key_v3(key_id: int, tier_code: int, policy_bits: int, nonce: int, secret: str) -> str:
    sig = signature_for_v3(key_id, tier_code, policy_bits, nonce, secret)
    return f"QOS3-{key_id:08X}-{tier_code:02X}-{policy_bits:02X}-{nonce:08X}-{sig}"


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
    elif len(key) == 53:
        if (
            not key.startswith("QOS3-")
            or key[13] != "-"
            or key[16] != "-"
            or key[19] != "-"
            or key[28] != "-"
        ):
            raise ValueError("invalid QOS3 key format")
        parts = (key[5:13], key[14:16], key[17:19], key[20:28], key[29:53])
    else:
        raise ValueError("unsupported key length")

    for block in parts:
        int(block, 16)
    return key


def parse_key(raw: str) -> ParsedKey:
    key = normalize_key(raw)
    if key.startswith("QOS1-"):
        feature = int(key[14:18], 16)
        tier = tier_from_feature_bits(feature)
        return ParsedKey(
            key=key,
            version="qos1",
            key_id=int(key[5:13], 16),
            feature_bits=feature,
            tier_code=tier.code if tier else 0,
            policy_bits=0,
            nonce=0,
            signature_hex=key[19:27],
        )
    if key.startswith("QOS2-"):
        feature = int(key[14:18], 16)
        tier = tier_from_feature_bits(feature)
        return ParsedKey(
            key=key,
            version="qos2",
            key_id=int(key[5:13], 16),
            feature_bits=feature,
            tier_code=tier.code if tier else 0,
            policy_bits=0,
            nonce=int(key[19:27], 16),
            signature_hex=key[28:44],
        )
    return ParsedKey(
        key=key,
        version="qos3",
        key_id=int(key[5:13], 16),
        feature_bits=((int(key[14:16], 16) << 8) | int(key[17:19], 16)),
        tier_code=int(key[14:16], 16),
        policy_bits=int(key[17:19], 16),
        nonce=int(key[20:28], 16),
        signature_hex=key[29:53],
    )


def is_signature_valid(raw: str, secret_v2: str, secret_v3: str) -> bool:
    try:
        parsed = parse_key(raw)
    except ValueError:
        return False
    if parsed.version == "qos1":
        expected = f"{signature_for_v1(parsed.key_id, parsed.feature_bits):08X}"
        return hmac.compare_digest(parsed.signature_hex, expected)
    if parsed.version == "qos2":
        expected = f"{signature_for_v2(parsed.key_id, parsed.feature_bits, parsed.nonce, secret_v2):016X}"
        return hmac.compare_digest(parsed.signature_hex, expected)
    expected = signature_for_v3(parsed.key_id, parsed.tier_code, parsed.policy_bits, parsed.nonce, secret_v3)
    return hmac.compare_digest(parsed.signature_hex, expected)


def read_key_file(path: Path, secret_v2: str, secret_v3: str) -> list[str]:
    if not path.exists():
        return []
    out: list[str] = []
    seen: set[str] = set()
    for line in read_text_secure(path).splitlines():
        text = line.strip()
        if not text or text.startswith("#") or text.startswith(";"):
            continue
        token = text.split()[0]
        try:
            key = normalize_key(token)
        except ValueError:
            continue
        if not is_signature_valid(key, secret_v2, secret_v3):
            continue
        if key not in seen:
            out.append(key)
            seen.add(key)
    return out


def scan_key_file(path: Path, secret_v2: str, secret_v3: str) -> tuple[list[str], list[str], list[str]]:
    valid: list[str] = []
    invalid: list[str] = []
    duplicates: list[str] = []
    seen: set[str] = set()

    if not path.exists():
        return valid, invalid, duplicates

    try:
        lines = read_text_secure(path).splitlines()
    except ValueError as exc:
        return valid, [f"decrypt error: {exc}"], duplicates

    for n, line in enumerate(lines, start=1):
        text = line.strip()
        if not text or text.startswith("#") or text.startswith(";"):
            continue
        token = text.split()[0]
        try:
            key = normalize_key(token)
        except ValueError:
            invalid.append(f"line {n}: invalid format ({token})")
            continue
        if not is_signature_valid(key, secret_v2, secret_v3):
            invalid.append(f"line {n}: invalid signature ({key})")
            continue
        if key in seen:
            duplicates.append(key)
            continue
        seen.add(key)
        valid.append(key)
    return valid, invalid, duplicates


def write_key_file(path: Path, title: str, keys: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = [
        f"# {title}",
        "# Format: one signed key per line (QOS1, QOS2, or QOS3).",
    ]
    body = sorted(set(keys))
    write_text_secure(path, "\n".join(header + body) + "\n")


def read_db(path: Path, secret_v2: str, secret_v3: str) -> list[str]:
    return read_key_file(path, secret_v2, secret_v3)


def write_db(path: Path, keys: list[str]) -> None:
    write_key_file(path, "QuartzOS License Database (v3)", keys)


def read_revoked(path: Path, secret_v2: str, secret_v3: str) -> list[str]:
    return read_key_file(path, secret_v2, secret_v3)


def write_revoked(path: Path, keys: list[str]) -> None:
    write_key_file(path, "QuartzOS Revoked License Database", keys)


def append_meta(meta_path: Path, rows: list[tuple[str, str, str, str, str, str, str, str]]) -> None:
    header = [
        "issued_at_utc",
        "owner",
        "tier",
        "version",
        "key_id_hex",
        "feature_bits_hex",
        "nonce_hex",
        "key",
    ]
    existing = read_csv_rows_secure(meta_path)
    if not existing or existing[0] != header:
        existing = [header]
    for row in rows:
        existing.append(list(row))
    write_csv_rows_secure(meta_path, existing)


def append_audit(audit_path: Path, rows: list[tuple[str, str, str, str, str]]) -> None:
    header = ["timestamp_utc", "action", "key", "actor", "note"]
    existing = read_csv_rows_secure(audit_path)
    if not existing or existing[0] != header:
        existing = [header]
    for row in rows:
        existing.append(list(row))
    write_csv_rows_secure(audit_path, existing)


def load_meta_key(meta_path: Path, key: str) -> MetaRecord | None:
    if not meta_path.exists():
        return None
    text = read_text_secure(meta_path)
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        if not row:
            continue
        if (row.get("key") or "").strip().upper() != key:
            continue
        return MetaRecord(
            issued_at_utc=(row.get("issued_at_utc") or "").strip(),
            owner=(row.get("owner") or "").strip(),
            tier=(row.get("tier") or "").strip(),
            version=(row.get("version") or "").strip().lower(),
            key_id_hex=(row.get("key_id_hex") or "").strip().upper(),
            feature_bits_hex=(row.get("feature_bits_hex") or "").strip().upper(),
            nonce_hex=(row.get("nonce_hex") or "").strip().upper(),
            key=(row.get("key") or "").strip().upper(),
        )
    return None


def parse_int_arg(raw: str, bit_limit: int) -> int:
    text = raw.strip().lower()
    base = 16 if text.startswith("0x") else 10
    value = int(text, base)
    mask = (1 << bit_limit) - 1
    return value & mask


def make_password_record(password: str, iterations: int = DEFAULT_ADMIN_ITERATIONS, salt: bytes | None = None) -> str:
    if iterations < 100_000:
        raise ValueError("iterations must be >= 100000")
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, record: str) -> bool:
    text = record.strip()
    if not text.startswith("pbkdf2_sha256$"):
        return False

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


def verify_admin_password(password: str) -> bool:
    configured = os.getenv("QOS_ISSUER_ADMIN_HASH", DEFAULT_ADMIN_RECORD)
    if not configured.strip().startswith("pbkdf2_sha256$"):
        print(
            "error: QOS_ISSUER_ADMIN_HASH must use pbkdf2_sha256 format. "
            "Generate one with: issue_license.py password-hash",
            file=sys.stderr,
        )
        return False
    return verify_password(password, configured)


def require_password(supplied: str | None) -> None:
    if supplied is None:
        supplied = getpass.getpass("Issuer password: ")
    if not verify_admin_password(supplied):
        print("error: invalid issuer password", file=sys.stderr)
        raise SystemExit(1)


def key_secret_v2() -> str:
    return os.getenv("QOS_ISSUER_HMAC_SECRET_V2", os.getenv("QOS_ISSUER_HMAC_SECRET", DEFAULT_HMAC_SECRET_V2))


def key_secret_v3() -> str:
    return os.getenv("QOS_ISSUER_HMAC_SECRET_V3", os.getenv("QOS_ISSUER_HMAC_SECRET", DEFAULT_HMAC_SECRET_V3))


def integrity_secret() -> str:
    return os.getenv("QOS_ISSUER_INTEGRITY_SECRET", DEFAULT_INTEGRITY_SECRET)


def file_enc_secret() -> bytes:
    return os.getenv("QOS_ISSUER_FILE_ENC_KEY", DEFAULT_FILE_ENC_SECRET).encode("utf-8")


def _stream_xor(data: bytes, nonce: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    counter = 0
    pos = 0
    while pos < len(data):
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        take = min(len(block), len(data) - pos)
        for i in range(take):
            out[pos + i] = data[pos + i] ^ block[i]
        pos += take
        counter += 1
    return bytes(out)


def encrypt_text_secure(text: str) -> str:
    key = file_enc_secret()
    nonce = secrets.token_bytes(SECURE_NONCE_BYTES)
    plain = text.encode("utf-8")
    cipher = _stream_xor(plain, nonce, key)
    tag = hmac.new(key, SECURE_PREFIX.encode("ascii") + nonce + cipher, hashlib.sha256).hexdigest().upper()
    return f"{SECURE_PREFIX}{nonce.hex().upper()}|{cipher.hex().upper()}|{tag}\n"


def decrypt_text_secure(raw: str) -> str:
    text = raw.strip()
    if not text.startswith(SECURE_PREFIX):
        return raw
    parts = text.split("|")
    if len(parts) != 4:
        raise ValueError("invalid encrypted file format")
    _, nonce_hex, cipher_hex, tag_hex = parts
    if len(nonce_hex) != SECURE_NONCE_BYTES * 2:
        raise ValueError("invalid encrypted nonce length")
    if len(tag_hex) != SECURE_TAG_BYTES * 2:
        raise ValueError("invalid encrypted tag length")
    if len(cipher_hex) % 2 != 0:
        raise ValueError("invalid encrypted payload length")

    nonce = bytes.fromhex(nonce_hex)
    cipher = bytes.fromhex(cipher_hex)
    file_tag = bytes.fromhex(tag_hex)
    key = file_enc_secret()

    expected = hmac.new(key, SECURE_PREFIX.encode("ascii") + nonce + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(file_tag, expected):
        raise ValueError("encrypted file tag mismatch")

    plain = _stream_xor(cipher, nonce, key)
    return plain.decode("utf-8")


def read_text_secure(path: Path) -> str:
    if not path.exists():
        return ""
    raw = path.read_text(encoding="utf-8")
    return decrypt_text_secure(raw)


def write_text_secure(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(encrypt_text_secure(text), encoding="utf-8")


def read_csv_rows_secure(path: Path) -> list[list[str]]:
    text = read_text_secure(path)
    if not text.strip():
        return []
    return list(csv.reader(io.StringIO(text)))


def write_csv_rows_secure(path: Path, rows: list[list[str]]) -> None:
    buf = io.StringIO()
    writer = csv.writer(buf)
    for row in rows:
        writer.writerow(row)
    write_text_secure(path, buf.getvalue())


def file_sha256(path: Path) -> str:
    if not path.exists():
        return ""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def compute_integrity_payload(db: Path, revoked: Path, meta: Path, audit: Path) -> dict:
    return {
        "schema": "qos-license-store-v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "files": {
            "db": {
                "path": str(db),
                "sha256": file_sha256(db),
                "size": db.stat().st_size if db.exists() else 0,
            },
            "revoked": {
                "path": str(revoked),
                "sha256": file_sha256(revoked),
                "size": revoked.stat().st_size if revoked.exists() else 0,
            },
            "meta": {
                "path": str(meta),
                "sha256": file_sha256(meta),
                "size": meta.stat().st_size if meta.exists() else 0,
            },
            "audit": {
                "path": str(audit),
                "sha256": file_sha256(audit),
                "size": audit.stat().st_size if audit.exists() else 0,
            },
        },
    }


def write_integrity_manifest(path: Path, db: Path, revoked: Path, meta: Path, audit: Path, secret: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = compute_integrity_payload(db, revoked, meta, audit)
    signature = hmac.new(secret.encode("utf-8"), canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()
    wrapped = {"payload": payload, "hmac_sha256": signature}
    write_text_secure(path, json.dumps(wrapped, indent=2, sort_keys=True) + "\n")


def verify_integrity_manifest(
    path: Path,
    db: Path,
    revoked: Path,
    meta: Path,
    audit: Path,
    secret: str,
    require_manifest: bool,
) -> tuple[bool, list[str]]:
    issues: list[str] = []
    if not path.exists():
        if require_manifest:
            issues.append("integrity manifest missing")
            return False, issues
        return True, issues

    try:
        text = read_text_secure(path)
        loaded = json.loads(text)
    except Exception as exc:
        return False, [f"integrity manifest parse error: {exc}"]

    payload = loaded.get("payload")
    stored_sig = (loaded.get("hmac_sha256") or "").strip().lower()
    if not isinstance(payload, dict) or not stored_sig:
        return False, ["integrity manifest missing payload/signature"]

    expected_sig = hmac.new(secret.encode("utf-8"), canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(stored_sig, expected_sig):
        issues.append("integrity manifest HMAC mismatch")

    expected_payload = compute_integrity_payload(db, revoked, meta, audit)
    payload_files = payload.get("files") if isinstance(payload.get("files"), dict) else {}
    expected_files = expected_payload["files"]

    for name in ("db", "revoked", "meta", "audit"):
        current = expected_files[name]
        recorded = payload_files.get(name) if isinstance(payload_files, dict) else None
        if not isinstance(recorded, dict):
            issues.append(f"integrity missing file section: {name}")
            continue
        if str(recorded.get("sha256", "")).lower() != str(current.get("sha256", "")).lower():
            issues.append(f"integrity hash mismatch: {name}")
        if int(recorded.get("size", -1)) != int(current.get("size", -2)):
            issues.append(f"integrity size mismatch: {name}")

    return len(issues) == 0, issues


def seal_integrity(args: argparse.Namespace) -> None:
    write_integrity_manifest(args.integrity, args.db, args.revoked, args.meta, args.audit, integrity_secret())


def key_status(db_keys: set[str], revoked_keys: set[str], key: str) -> str:
    if key in revoked_keys:
        return "revoked"
    if key in db_keys:
        return "issued"
    return "unknown"


def resolve_issue_profile(tier_name: str, version: str, feature_bits_override: str | None, policy_mask: str | None) -> tuple[str, int, int, int]:
    normalized = normalize_tier_name(tier_name)
    if normalized == "all":
        if version == "qos3":
            raise ValueError("tier 'all' is legacy-only and unsupported for qos3")
        feature_bits = 0x000F
        if feature_bits_override:
            feature_bits = parse_int_arg(feature_bits_override, 16)
        return "all", 0x00, 0x00, feature_bits

    spec = TIERS.get(normalized)
    if spec is None:
        raise ValueError(f"unknown tier '{tier_name}'")

    if version == "qos3":
        policy = spec.policy_bits
        if policy_mask is not None:
            policy = parse_int_arg(policy_mask, 8)
        feature_bits = (spec.code << 8) | policy
        return spec.name, spec.code, policy, feature_bits

    feature_bits = spec.legacy_feature_bits
    if feature_bits_override:
        feature_bits = parse_int_arg(feature_bits_override, 16)
    return spec.name, spec.code, 0x00, feature_bits


def cmd_issue(args: argparse.Namespace) -> None:
    require_password(args.password)
    secret_v2 = key_secret_v2()
    secret_v3 = key_secret_v3()

    db_keys = set(read_db(args.db, secret_v2, secret_v3))
    revoked_keys = set(read_revoked(args.revoked, secret_v2, secret_v3))
    created: list[str] = []
    version = args.version.lower()
    if version in ("qos1", "qos2") and not args.allow_legacy:
        print(
            "error: issuing legacy qos1/qos2 keys is disabled by default; "
            "re-run with --allow-legacy to override",
            file=sys.stderr,
        )
        raise SystemExit(1)

    try:
        tier_name, tier_code, policy_bits, feature_bits = resolve_issue_profile(
            args.tier,
            version,
            args.feature_bits,
            args.policy_mask,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)

    while len(created) < args.count:
        key_id = secrets.randbits(32)
        if version == "qos1":
            key = make_key_v1(key_id, feature_bits)
            nonce_hex = ""
        elif version == "qos2":
            nonce = secrets.randbits(32)
            key = make_key_v2(key_id, feature_bits, nonce, secret_v2)
            nonce_hex = f"{nonce:08X}"
        else:
            nonce = secrets.randbits(32)
            key = make_key_v3(key_id, tier_code, policy_bits, nonce, secret_v3)
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
                tier_name,
                parsed.version,
                f"{parsed.key_id:08X}",
                f"{parsed.feature_bits:04X}",
                f"{parsed.nonce:08X}" if parsed.version != "qos1" else "",
                key,
            )
        )
        note = tier_name
        if parsed.version == "qos3":
            labels = policy_labels(parsed.policy_bits)
            if labels:
                note += f" policies={','.join(labels)}"
        audit_rows.append((ts, "ISSUE", key, args.owner, note))

    append_meta(args.meta, meta_rows)
    append_audit(args.audit, audit_rows)
    seal_integrity(args)

    print(
        f"issued {len(created)} key(s) owner='{args.owner}' "
        f"tier='{tier_name}' version='{version}'"
    )
    if version == "qos3":
        labels = policy_labels(policy_bits)
        print(f"qos3 profile: tier_code=0x{tier_code:02X} policy_bits=0x{policy_bits:02X} ({','.join(labels) if labels else 'none'})")
    for key in created:
        print(key)


def cmd_verify(args: argparse.Namespace) -> None:
    secret_v2 = key_secret_v2()
    secret_v3 = key_secret_v3()

    try:
        parsed = parse_key(args.key)
    except ValueError as exc:
        print(f"invalid: {exc}")
        raise SystemExit(1)

    sig_ok = is_signature_valid(parsed.key, secret_v2, secret_v3)
    db_keys = set(read_db(args.db, secret_v2, secret_v3))
    revoked_keys = set(read_revoked(args.revoked, secret_v2, secret_v3))
    issued = parsed.key in db_keys
    revoked = parsed.key in revoked_keys

    meta = load_meta_key(args.meta, parsed.key)
    meta_ok = meta is not None
    meta_note = "not found"
    if meta is not None:
        expected_key_id = f"{parsed.key_id:08X}"
        expected_feature = f"{parsed.feature_bits:04X}"
        expected_nonce = f"{parsed.nonce:08X}" if parsed.version != "qos1" else ""
        checks = [
            meta.version == parsed.version,
            meta.key_id_hex == expected_key_id,
            meta.feature_bits_hex == expected_feature,
            meta.nonce_hex == expected_nonce,
        ]
        meta_ok = all(checks)
        meta_note = f"owner={meta.owner or 'unknown'} issued_at={meta.issued_at_utc or 'unknown'} tier={meta.tier or 'unknown'}"

    integrity_ok, integrity_issues = verify_integrity_manifest(
        args.integrity,
        args.db,
        args.revoked,
        args.meta,
        args.audit,
        integrity_secret(),
        require_manifest=args.strict,
    )

    print(f"key: {parsed.key}")
    print(f"version: {parsed.version}")
    print(f"legacy: {'yes (deprecated)' if parsed.version in ('qos1', 'qos2') else 'no'}")
    print(f"signature: {'valid' if sig_ok else 'invalid'}")
    print(f"issued: {'yes' if issued else 'no'}")
    print(f"revoked: {'yes' if revoked else 'no'}")

    if parsed.version == "qos3":
        spec = tier_from_code(parsed.tier_code)
        tier_name = spec.name if spec else "unknown"
        labels = policy_labels(parsed.policy_bits)
        print(f"tier_code: 0x{parsed.tier_code:02X} ({tier_name})")
        print(f"policy_bits: 0x{parsed.policy_bits:02X} ({','.join(labels) if labels else 'none'})")
        print(f"nonce: 0x{parsed.nonce:08X}")
    else:
        spec = tier_from_feature_bits(parsed.feature_bits)
        tier_name = spec.name if spec else "legacy-custom"
        print(f"feature_bits: 0x{parsed.feature_bits:04X} ({tier_name})")
        if parsed.version == "qos2":
            print(f"nonce: 0x{parsed.nonce:08X}")

    print(f"metadata: {'ok' if meta_ok else 'mismatch'} ({meta_note})")
    if args.integrity.exists():
        print(f"integrity: {'ok' if integrity_ok else 'failed'}")
        for issue in integrity_issues:
            print(f"  - {issue}")
    else:
        print("integrity: manifest not present")

    ok = sig_ok and issued and not revoked
    if args.strict:
        ok = ok and meta_ok and integrity_ok
    raise SystemExit(0 if ok else 1)


def cmd_list(args: argparse.Namespace) -> None:
    require_password(args.password)
    secret_v2 = key_secret_v2()
    secret_v3 = key_secret_v3()

    db_keys = sorted(set(read_db(args.db, secret_v2, secret_v3)))
    revoked = set(read_revoked(args.revoked, secret_v2, secret_v3))
    active = [k for k in db_keys if k not in revoked]

    print(f"total issued keys: {len(db_keys)}")
    print(f"active keys: {len(active)}")
    print(f"revoked keys: {len(revoked)}")

    if args.show:
        db_lookup = set(db_keys)
        for key in db_keys:
            parsed = parse_key(key)
            if parsed.version == "qos3":
                spec = tier_from_code(parsed.tier_code)
                tier = spec.name if spec else "unknown"
            else:
                spec = tier_from_feature_bits(parsed.feature_bits)
                tier = spec.name if spec else "legacy-custom"
            print(f"{key} [{key_status(db_lookup, revoked, key)}] tier={tier}")


def cmd_revoke(args: argparse.Namespace) -> None:
    require_password(args.password)
    secret_v2 = key_secret_v2()
    secret_v3 = key_secret_v3()

    try:
        key = normalize_key(args.key)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if not is_signature_valid(key, secret_v2, secret_v3):
        print("error: key signature is invalid", file=sys.stderr)
        raise SystemExit(1)

    db_keys = set(read_db(args.db, secret_v2, secret_v3))
    revoked = set(read_revoked(args.revoked, secret_v2, secret_v3))
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
    seal_integrity(args)
    print(f"revoked: {key}")


def cmd_unrevoke(args: argparse.Namespace) -> None:
    require_password(args.password)
    secret_v2 = key_secret_v2()
    secret_v3 = key_secret_v3()

    try:
        key = normalize_key(args.key)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if not is_signature_valid(key, secret_v2, secret_v3):
        print("error: key signature is invalid", file=sys.stderr)
        raise SystemExit(1)

    revoked = set(read_revoked(args.revoked, secret_v2, secret_v3))
    if key not in revoked:
        print("key is not revoked")
        return
    revoked.remove(key)
    write_revoked(args.revoked, sorted(revoked))
    ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    append_audit(args.audit, [(ts, "UNREVOKE", key, args.actor, args.note or "")])
    seal_integrity(args)
    print(f"unrevoked: {key}")


def cmd_verify_store(args: argparse.Namespace) -> None:
    secret_v2 = key_secret_v2()
    secret_v3 = key_secret_v3()

    db_valid, db_invalid, db_duplicates = scan_key_file(args.db, secret_v2, secret_v3)
    rv_valid, rv_invalid, rv_duplicates = scan_key_file(args.revoked, secret_v2, secret_v3)

    issues: list[str] = []
    issues.extend([f"db: {msg}" for msg in db_invalid])
    issues.extend([f"revoked: {msg}" for msg in rv_invalid])
    if db_duplicates:
        issues.append(f"db duplicate keys: {len(set(db_duplicates))}")
    if rv_duplicates:
        issues.append(f"revoked duplicate keys: {len(set(rv_duplicates))}")

    db_set = set(db_valid)
    for key in rv_valid:
        if key not in db_set:
            issues.append(f"revoked key missing from db: {key}")

    integrity_ok, integrity_issues = verify_integrity_manifest(
        args.integrity,
        args.db,
        args.revoked,
        args.meta,
        args.audit,
        integrity_secret(),
        require_manifest=args.require_manifest,
    )
    issues.extend(integrity_issues)

    print(f"db valid keys: {len(db_valid)}")
    print(f"revoked valid keys: {len(rv_valid)}")
    print(f"integrity manifest: {'ok' if integrity_ok else 'failed'}")

    if issues:
        print("store issues:")
        for item in issues:
            print(f"- {item}")
    else:
        print("store verification: clean")

    raise SystemExit(0 if not issues else 1)


def cmd_seal_store(args: argparse.Namespace) -> None:
    require_password(args.password)
    seal_integrity(args)
    print(f"sealed integrity manifest: {args.integrity}")


def cmd_harden_store(args: argparse.Namespace) -> None:
    require_password(args.password)
    secret_v2 = key_secret_v2()
    secret_v3 = key_secret_v3()

    db_keys = read_db(args.db, secret_v2, secret_v3)
    revoked_keys = read_revoked(args.revoked, secret_v2, secret_v3)
    write_db(args.db, db_keys)
    write_revoked(args.revoked, revoked_keys)

    for path in (args.meta, args.audit):
        if path.exists():
            write_text_secure(path, read_text_secure(path))

    seal_integrity(args)
    print("harden-store: encrypted db/revoked/meta/audit/integrity")


def cmd_password_hash(args: argparse.Namespace) -> None:
    password = args.password
    if password is None:
        password = getpass.getpass("New issuer password: ")
    record = make_password_record(password, iterations=args.iterations)
    out_path = args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(record + "\n", encoding="utf-8")
    print(f"password hash record written to: {out_path}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "QuartzOS License Issuer (password protected, revocation-aware, "
            "QOS1/QOS2/QOS3 + integrity verification)"
        )
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
    p.add_argument(
        "--integrity",
        type=Path,
        default=DEFAULT_INTEGRITY,
        help=f"integrity manifest path (default: {DEFAULT_INTEGRITY})",
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    issue = sub.add_parser("issue", help="issue new license keys (password required)")
    issue.add_argument("--owner", required=True, help="owner name")
    issue.add_argument(
        "--tier",
        choices=sorted(list(TIERS.keys()) + ["community", "pro", "ultimate", "all"]),
        default="consumer",
    )
    issue.add_argument("--version", choices=["qos3", "qos2", "qos1"], default="qos3")
    issue.add_argument("--count", type=int, default=1)
    issue.add_argument("--feature-bits", help="override feature bits for qos1/qos2 (decimal or 0xHEX)")
    issue.add_argument("--policy-mask", help="override policy bits for qos3 (decimal or 0xHEX)")
    issue.add_argument(
        "--allow-legacy",
        action="store_true",
        default=ALLOW_LEGACY_ISSUE_DEFAULT,
        help="allow issuing deprecated qos1/qos2 keys",
    )
    issue.add_argument("--password", help="issuer password (optional; prompt if omitted)")
    issue.set_defaults(func=cmd_issue)

    verify = sub.add_parser("verify", help="verify signature + issuance + revocation + metadata")
    verify.add_argument("--key", required=True, help="license key")
    verify.add_argument("--strict", action="store_true", help="fail if metadata/integrity checks fail")
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

    verify_store = sub.add_parser("verify-store", help="verify db/revocation files + integrity manifest")
    verify_store.add_argument("--require-manifest", action="store_true", help="fail if integrity manifest is missing")
    verify_store.set_defaults(func=cmd_verify_store)

    seal_store = sub.add_parser("seal-store", help="rebuild integrity manifest (password required)")
    seal_store.add_argument("--password", help="issuer password (optional; prompt if omitted)")
    seal_store.set_defaults(func=cmd_seal_store)

    harden_store = sub.add_parser(
        "harden-store",
        help="encrypt security-critical issuer files (password required)",
    )
    harden_store.add_argument("--password", help="issuer password (optional; prompt if omitted)")
    harden_store.set_defaults(func=cmd_harden_store)

    pwhash = sub.add_parser("password-hash", help="generate QOS_ISSUER_ADMIN_HASH value")
    pwhash.add_argument("--password", help="password (optional; prompt if omitted)")
    pwhash.add_argument("--iterations", type=int, default=DEFAULT_ADMIN_ITERATIONS)
    pwhash.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_PASSWORD_HASH_OUT,
        help=f"write hash record to file (default: {DEFAULT_PASSWORD_HASH_OUT})",
    )
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


def prompt_tier(default: str = "consumer") -> str:
    choices = "/".join(sorted(list(TIERS.keys()) + ["community", "pro", "ultimate", "all"]))
    while True:
        value = prompt_text(f"tier ({choices})", default, required=True).lower()
        if value in TIERS or value in LEGACY_TIER_ALIASES or value == "all":
            return value
        print("invalid tier")


def prompt_version(default: str = "qos3") -> str:
    while True:
        value = prompt_text("version (qos3/qos2/qos1)", default, required=True).lower()
        if value in ("qos3", "qos2", "qos1"):
            return value
        print("invalid version")


def interactive_args() -> list[str] | None:
    print("QuartzOS License Issuer interactive mode")
    print("  1) issue")
    print("  2) verify")
    print("  3) list")
    print("  4) revoke")
    print("  5) unrevoke")
    print("  6) verify-store")
    print("  7) seal-store")
    print("  8) harden-store")
    print("  9) password-hash")
    print("  q) quit")
    while True:
        choice = prompt_text("select command", required=True).lower()
        if choice in ("q", "quit", "exit"):
            return None
        if choice in ("1", "issue"):
            owner = prompt_text("owner", required=True)
            tier = prompt_tier("consumer")
            version = prompt_version("qos3")
            count = prompt_int("count", 1, 1, 1000)
            out = [
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
            if version in ("qos1", "qos2"):
                if prompt_yes_no("allow legacy issue", default=False):
                    out.append("--allow-legacy")
            return out
        if choice in ("2", "verify"):
            key = prompt_text("license key", required=True)
            strict = prompt_yes_no("strict verify", default=False)
            out = ["verify", "--key", key]
            if strict:
                out.append("--strict")
            return out
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
        if choice in ("6", "verify-store"):
            require_manifest = prompt_yes_no("require integrity manifest", default=True)
            out = ["verify-store"]
            if require_manifest:
                out.append("--require-manifest")
            return out
        if choice in ("7", "seal-store"):
            return ["seal-store"]
        if choice in ("8", "harden-store"):
            return ["harden-store"]
        if choice in ("9", "password-hash"):
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
