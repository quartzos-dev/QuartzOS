#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import logging
import os
import signal
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional, Set, Tuple

DEFAULT_BUILD_ROOT_SECRET = "QuartzOS-BuildRoot-2026"
DEFAULT_BUILD_SALT = "quartzos-build-v1"
DEFAULT_FILE_ENC_SECRET = "QuartzOS-SecureStore-ENC-V1-2026"
DEFAULT_FILE_ENC_SECRET_PREV = "QuartzOS-SecureStore-ENC-V1-2026"
DEFAULT_HMAC_SECRET_V2 = "QuartzOS-Licensing-HMAC-Key-V2-2026"
DEFAULT_HMAC_SECRET_V3 = "QuartzOS-Licensing-HMAC-Key-V3-2026"

SECURE_PREFIX = "QENC1|"
SECURE_VERSION_V2 = "v2"
SECURE_KID_CURRENT = 0x01
SECURE_KID_PREVIOUS = 0x02
SECURE_NONCE_BYTES = 8
SECURE_TAG_BYTES = 32

POLICY_DEVELOPMENT_ONLY = 0x01
POLICY_SUBSCRIPTION = 0x40


@dataclass(frozen=True)
class FileKeyPair:
    kid: int
    enc_key: bytes
    mac_key: bytes
    legacy_raw: bytes


def derive_bytes(root_secret: bytes, salt: str, label: str, size: int = 32) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        msg = f"{salt}|{label}|{counter}".encode("utf-8")
        out.extend(hmac.new(root_secret, msg, hashlib.sha256).digest())
        counter += 1
    return bytes(out[:size])


def stream_xor(data: bytes, nonce: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    pos = 0
    counter = 0
    while pos < len(data):
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        take = min(len(block), len(data) - pos)
        for i in range(take):
            out[pos + i] = data[pos + i] ^ block[i]
        pos += take
        counter += 1
    return bytes(out)


def tag_v1_legacy(mac_key: bytes, nonce: bytes, cipher: bytes) -> bytes:
    return hmac.new(mac_key, SECURE_PREFIX.encode("ascii") + nonce + cipher, hashlib.sha256).digest()


def tag_v2(mac_key: bytes, kid: int, nonce: bytes, cipher: bytes) -> bytes:
    aad = (
        SECURE_PREFIX.encode("ascii")
        + f"{SECURE_VERSION_V2}|".encode("ascii")
        + bytes([kid])
        + len(cipher).to_bytes(4, "little")
    )
    return hmac.new(mac_key, aad + nonce + cipher, hashlib.sha256).digest()


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip().lower()
    return value in {"1", "true", "yes", "on", "y"}


def parse_port(text: str, fallback: int) -> int:
    try:
        value = int(text, 10)
    except ValueError:
        return fallback
    if value <= 0 or value > 65535:
        return fallback
    return value


def parse_u32_hex(text: str) -> int:
    return int(text, 16)


def fnv1a32(text: str) -> int:
    value = 2166136261
    for b in text.encode("ascii", "strict"):
        value ^= b
        value = (value * 16777619) & 0xFFFFFFFF
    return value


def signature_for_v1(key_id: int, feature_bits: int) -> int:
    payload = f"QOS1:{key_id:08X}:{feature_bits:04X}:QUARTZOS-LICENSE-V1"
    return fnv1a32(payload)


def signature_for_v2(key_id: int, feature_bits: int, nonce: int, key_v2: bytes) -> int:
    payload = f"QOS2:{key_id:08X}:{feature_bits:04X}:{nonce:08X}:QUARTZOS-LICENSE-V2".encode("ascii")
    digest = hmac.new(key_v2, payload, hashlib.sha256).digest()
    return int.from_bytes(digest[:8], "big")


def signature_for_v3(key_id: int, tier_code: int, policy_bits: int, nonce: int, key_v3: bytes) -> str:
    payload = f"QOS3:{key_id:08X}:{tier_code:02X}:{policy_bits:02X}:{nonce:08X}:QUARTZOS-LICENSE-V3".encode("ascii")
    digest = hmac.new(key_v3, payload, hashlib.sha256).digest()
    return digest[:12].hex().upper()


def normalize_key(raw: str) -> str:
    key = raw.strip().upper()
    if len(key) == 27:
        if not key.startswith("QOS1-") or key[13] != "-" or key[18] != "-":
            raise ValueError("invalid QOS1 format")
        parts = (key[5:13], key[14:18], key[19:27])
    elif len(key) == 44:
        if not key.startswith("QOS2-") or key[13] != "-" or key[18] != "-" or key[27] != "-":
            raise ValueError("invalid QOS2 format")
        parts = (key[5:13], key[14:18], key[19:27], key[28:44])
    elif len(key) == 53:
        if (
            not key.startswith("QOS3-")
            or key[13] != "-"
            or key[16] != "-"
            or key[19] != "-"
            or key[28] != "-"
        ):
            raise ValueError("invalid QOS3 format")
        parts = (key[5:13], key[14:16], key[17:19], key[20:28], key[29:53])
    else:
        raise ValueError("unsupported key length")

    for block in parts:
        int(block, 16)
    return key


def key_signature_valid(key: str, key_v2: bytes, key_v3: bytes, legacy_v2: bytes, legacy_v3: bytes) -> bool:
    try:
        norm = normalize_key(key)
    except ValueError:
        return False

    if norm.startswith("QOS1-"):
        key_id = parse_u32_hex(norm[5:13])
        feature_bits = int(norm[14:18], 16)
        sig = norm[19:27]
        expected = f"{signature_for_v1(key_id, feature_bits):08X}"
        return hmac.compare_digest(sig, expected)

    if norm.startswith("QOS2-"):
        key_id = parse_u32_hex(norm[5:13])
        feature_bits = int(norm[14:18], 16)
        nonce = parse_u32_hex(norm[19:27])
        sig = norm[28:44]
        expected = f"{signature_for_v2(key_id, feature_bits, nonce, key_v2):016X}"
        if hmac.compare_digest(sig, expected):
            return True
        legacy_expected = f"{signature_for_v2(key_id, feature_bits, nonce, legacy_v2):016X}"
        return hmac.compare_digest(sig, legacy_expected)

    key_id = parse_u32_hex(norm[5:13])
    tier_code = int(norm[14:16], 16)
    policy_bits = int(norm[17:19], 16)
    nonce = parse_u32_hex(norm[20:28])
    sig = norm[29:53]
    expected = signature_for_v3(key_id, tier_code, policy_bits, nonce, key_v3)
    if hmac.compare_digest(sig, expected):
        return True
    legacy_expected = signature_for_v3(key_id, tier_code, policy_bits, nonce, legacy_v3)
    return hmac.compare_digest(sig, legacy_expected)


def minimum_consumer_monthly(key: str) -> bool:
    try:
        norm = normalize_key(key)
    except ValueError:
        return False
    if not norm.startswith("QOS3-"):
        return False
    tier_code = int(norm[14:16], 16)
    policy_bits = int(norm[17:19], 16)
    if tier_code not in {0x01, 0x02, 0x03, 0x04, 0x09}:
        return False
    if (policy_bits & POLICY_SUBSCRIPTION) == 0:
        return False
    if (policy_bits & POLICY_DEVELOPMENT_ONLY) != 0:
        return False
    return True


def normalize_path(path: str) -> Optional[str]:
    if not path or path[0] != "/":
        return None
    if "\\" in path or "|" in path or ":" in path:
        return None

    out_parts = []
    for part in path.split("/"):
        if part == "" or part == ".":
            continue
        if part == "..":
            return None
        for ch in part:
            if ord(ch) < 32:
                return None
        out_parts.append(part)

    if not out_parts:
        return "/"
    return "/" + "/".join(out_parts)


def parse_token_map(tokens: Iterable[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        out[key.strip().lower()] = value.strip()
    return out


def is_hex(text: str, expected_len: int) -> bool:
    if len(text) != expected_len:
        return False
    try:
        int(text, 16)
    except ValueError:
        return False
    return True


class SecurityDataStore:
    def __init__(self, data_dir: Path, root_secret: bytes, build_salt: str, logger: logging.Logger) -> None:
        self.data_dir = data_dir
        self.root_secret = root_secret
        self.build_salt = build_salt
        self.logger = logger

        self.server_pin_key = derive_bytes(self.root_secret, self.build_salt, "security.server.pin")
        self.license_hmac_v2 = derive_bytes(self.root_secret, self.build_salt, "license.hmac.v2")
        self.license_hmac_v3 = derive_bytes(self.root_secret, self.build_salt, "license.hmac.v3")
        self.manifest_sign_key = derive_bytes(self.root_secret, self.build_salt, "security.manifest.sign")
        self.legacy_hmac_v2 = os.getenv("QOS_LEGACY_LICENSE_HMAC_V2", DEFAULT_HMAC_SECRET_V2).encode("utf-8")
        self.legacy_hmac_v3 = os.getenv("QOS_LEGACY_LICENSE_HMAC_V3", DEFAULT_HMAC_SECRET_V3).encode("utf-8")

        self._secure_pairs = self._build_secure_key_pairs()
        self._lock = threading.Lock()
        self._last_loaded = 0.0
        self.manifest: Dict[str, str] = {}
        self.issued_keys: Set[str] = set()
        self.revoked_keys: Set[str] = set()
        self.quarantine_hashes: Set[str] = set()
        self.manifest_signature_ok = False

    def _build_secure_key_pairs(self) -> Tuple[FileKeyPair, ...]:
        current_legacy = os.getenv("QOS_ISSUER_FILE_ENC_KEY", DEFAULT_FILE_ENC_SECRET).encode("utf-8")
        prev_legacy = os.getenv("QOS_ISSUER_FILE_ENC_KEY_PREV", DEFAULT_FILE_ENC_SECRET_PREV).encode("utf-8")
        return (
            FileKeyPair(
                kid=SECURE_KID_CURRENT,
                enc_key=derive_bytes(self.root_secret, self.build_salt, "securestore.enc"),
                mac_key=derive_bytes(self.root_secret, self.build_salt, "securestore.mac"),
                legacy_raw=current_legacy,
            ),
            FileKeyPair(
                kid=SECURE_KID_PREVIOUS,
                enc_key=derive_bytes(self.root_secret, self.build_salt, "securestore.enc.prev"),
                mac_key=derive_bytes(self.root_secret, self.build_salt, "securestore.mac.prev"),
                legacy_raw=prev_legacy,
            ),
        )

    def _decrypt_text_secure(self, raw: str) -> str:
        text = raw.strip()
        if not text.startswith(SECURE_PREFIX):
            return raw

        parts = text.split("|")
        if len(parts) == 6 and parts[1].lower() == SECURE_VERSION_V2:
            _, _, kid_hex, nonce_hex, cipher_hex, tag_hex = parts
            if len(kid_hex) != 2:
                raise ValueError("invalid encrypted key id")
            if len(nonce_hex) != SECURE_NONCE_BYTES * 2:
                raise ValueError("invalid encrypted nonce")
            if len(tag_hex) != SECURE_TAG_BYTES * 2:
                raise ValueError("invalid encrypted tag")
            if len(cipher_hex) % 2 != 0:
                raise ValueError("invalid encrypted payload")

            kid = int(kid_hex, 16)
            nonce = bytes.fromhex(nonce_hex)
            cipher = bytes.fromhex(cipher_hex)
            file_tag = bytes.fromhex(tag_hex)

            pair = None
            for candidate in self._secure_pairs:
                if candidate.kid == kid:
                    pair = candidate
                    break
            if pair is None:
                raise ValueError("unknown encrypted key id")

            expected = tag_v2(pair.mac_key, pair.kid, nonce, cipher)
            if not hmac.compare_digest(file_tag, expected):
                raise ValueError("encrypted tag mismatch")
            plain = stream_xor(cipher, nonce, pair.enc_key)
            return plain.decode("utf-8")

        if len(parts) == 4:
            _, nonce_hex, cipher_hex, tag_hex = parts
            if len(nonce_hex) != SECURE_NONCE_BYTES * 2:
                raise ValueError("invalid legacy nonce")
            if len(tag_hex) != SECURE_TAG_BYTES * 2:
                raise ValueError("invalid legacy tag")
            if len(cipher_hex) % 2 != 0:
                raise ValueError("invalid legacy payload")

            nonce = bytes.fromhex(nonce_hex)
            cipher = bytes.fromhex(cipher_hex)
            file_tag = bytes.fromhex(tag_hex)

            for pair in self._secure_pairs:
                expected = tag_v1_legacy(pair.legacy_raw, nonce, cipher)
                if not hmac.compare_digest(file_tag, expected):
                    continue
                plain = stream_xor(cipher, nonce, pair.legacy_raw)
                return plain.decode("utf-8")
            raise ValueError("legacy encrypted tag mismatch")

        raise ValueError("invalid encrypted file format")

    def _read_text(self, path: Path) -> str:
        if not path.exists():
            return ""
        raw = path.read_text(encoding="utf-8")
        return self._decrypt_text_secure(raw)

    def _manifest_signature_valid(self, manifest_text: str) -> bool:
        sig_path = self.data_dir / "security_manifest.sig"
        if not sig_path.exists():
            return False
        sig_text = sig_path.read_text(encoding="utf-8").strip().lower()
        if not is_hex(sig_text, 64):
            return False
        expected = hmac.new(self.manifest_sign_key, manifest_text.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig_text, expected)

    def _read_manifest(self) -> Tuple[Dict[str, str], bool]:
        manifest_path = self.data_dir / "security_manifest.txt"
        out: Dict[str, str] = {}
        raw = manifest_path.read_text(encoding="utf-8") if manifest_path.exists() else ""
        sig_ok = self._manifest_signature_valid(raw)
        if not sig_ok:
            return out, False
        for line in raw.splitlines():
            text = line.strip()
            if not text or text.startswith("#") or "|" not in text:
                continue
            path_text, digest = text.split("|", 1)
            norm_path = normalize_path(path_text.strip())
            digest = digest.strip().lower()
            if not norm_path or not is_hex(digest, 64):
                continue
            out[norm_path] = digest
        return out, True

    def _read_key_set(self, path: Path) -> Set[str]:
        out: Set[str] = set()
        text = self._read_text(path)
        for line in text.splitlines():
            item = line.strip()
            if not item or item.startswith("#") or item.startswith(";"):
                continue
            token = item.split()[0]
            try:
                key = normalize_key(token)
            except ValueError:
                continue
            if not key_signature_valid(
                key,
                self.license_hmac_v2,
                self.license_hmac_v3,
                self.legacy_hmac_v2,
                self.legacy_hmac_v3,
            ):
                continue
            out.add(key)
        return out

    def _read_hash_set(self, path: Path) -> Set[str]:
        out: Set[str] = set()
        if not path.exists():
            return out
        for line in path.read_text(encoding="utf-8").splitlines():
            value = line.strip().lower()
            if not value or value.startswith("#"):
                continue
            if is_hex(value, 64):
                out.add(value)
        return out

    def reload(self, force: bool = False, min_interval: float = 2.0) -> None:
        with self._lock:
            now = time.monotonic()
            if not force and now - self._last_loaded < min_interval:
                return

            manifest, manifest_sig_ok = self._read_manifest()
            issued = self._read_key_set(self.data_dir / "licenses.db")
            revoked = self._read_key_set(self.data_dir / "licenses.revoked")
            quarantine = self._read_hash_set(self.data_dir / "quarantine_hashes.txt")

            self.manifest = manifest
            self.issued_keys = issued
            self.revoked_keys = revoked
            self.quarantine_hashes = quarantine
            self.manifest_signature_ok = manifest_sig_ok
            self._last_loaded = now
            self.logger.info(
                "data loaded: manifest=%d sig=%s issued=%d revoked=%d quarantine=%d",
                len(self.manifest),
                "ok" if self.manifest_signature_ok else "invalid",
                len(self.issued_keys),
                len(self.revoked_keys),
                len(self.quarantine_hashes),
            )

    def pin_hex(self, channel: str, nonce_hex: str, payload: str) -> str:
        msg = f"{channel}|{nonce_hex}|{payload}".encode("utf-8")
        return hmac.new(self.server_pin_key, msg, hashlib.sha256).hexdigest()

    def pin_valid(self, channel: str, nonce_hex: str, payload: str, mac_hex: str) -> bool:
        if not is_hex(nonce_hex, 16) or not is_hex(mac_hex, 64):
            return False
        expected = self.pin_hex(channel, nonce_hex.lower(), payload)
        return hmac.compare_digest(mac_hex.lower(), expected)


class QuartzSecurityServer:
    def __init__(
        self,
        bind_ip: str,
        av_port: int,
        license_port: int,
        require_pin: bool,
        allowed_clients: Set[str],
        store: SecurityDataStore,
        reload_interval: float,
    ) -> None:
        self.bind_ip = bind_ip
        self.av_port = av_port
        self.license_port = license_port
        self.require_pin = require_pin
        self.allowed_clients = allowed_clients
        self.store = store
        self.reload_interval = reload_interval
        self.stop_event = threading.Event()
        self.logger = logging.getLogger("quartzos-security")

    def _client_allowed(self, ip: str) -> bool:
        if not self.allowed_clients:
            return True
        return ip in self.allowed_clients

    def _response_ok(self, channel: str, nonce_hex: str, payload: str) -> str:
        mac = self.store.pin_hex(channel, nonce_hex.lower(), payload)
        return f"OK nonce={nonce_hex.lower()} mac={mac}"

    def _handle_av(self, fields: Dict[str, str]) -> str:
        path_raw = fields.get("path", "")
        sha256_hex = fields.get("sha256", "").lower()
        nonce_hex = fields.get("nonce", "").lower()
        mac_hex = fields.get("mac", "").lower()

        norm_path = normalize_path(path_raw)
        if not norm_path or not is_hex(sha256_hex, 64):
            return "DENY reason=format"

        payload = f"path={norm_path} sha256={sha256_hex}"
        if self.require_pin and not self.store.pin_valid("av", nonce_hex, payload, mac_hex):
            return "DENY reason=mac"
        if not self.store.manifest_signature_ok:
            return "DENY reason=manifest-signature"

        expected = self.store.manifest.get(norm_path)
        if expected is None:
            return "DENY reason=manifest-missing"
        if expected != sha256_hex:
            return "DENY reason=manifest-mismatch"
        if sha256_hex in self.store.quarantine_hashes:
            return "DENY reason=quarantine"

        return self._response_ok("av", nonce_hex, payload)

    def _handle_license(self, fields: Dict[str, str]) -> str:
        key_raw = fields.get("key", "")
        nonce_hex = fields.get("nonce", "").lower()
        mac_hex = fields.get("mac", "").lower()

        try:
            key = normalize_key(key_raw)
        except ValueError:
            return "DENY reason=format"

        payload = f"key={key}"
        if self.require_pin and not self.store.pin_valid("lic", nonce_hex, payload, mac_hex):
            return "DENY reason=mac"

        if not key_signature_valid(
            key,
            self.store.license_hmac_v2,
            self.store.license_hmac_v3,
            self.store.legacy_hmac_v2,
            self.store.legacy_hmac_v3,
        ):
            return "DENY reason=signature"
        if key not in self.store.issued_keys:
            return "DENY reason=not-issued"
        if key in self.store.revoked_keys:
            return "DENY reason=revoked"
        if not minimum_consumer_monthly(key):
            return "DENY reason=min-tier"

        return self._response_ok("lic", nonce_hex, payload)

    def _dispatch(self, role: str, line: str, client_ip: str) -> str:
        if not self._client_allowed(client_ip):
            return "DENY reason=client"

        parts = line.strip().split()
        if not parts:
            return "DENY reason=empty"

        cmd = parts[0].strip().upper()
        fields = parse_token_map(parts[1:])

        if cmd == "QOS_SERVER_PING":
            return "OK"

        if role == "av" and cmd == "QOS_AV_VERIFY":
            return self._handle_av(fields)

        if role == "license" and cmd == "QOS_LICENSE_VERIFY":
            return self._handle_license(fields)

        return "DENY reason=command"

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int], role: str) -> None:
        client_ip, client_port = addr
        conn.settimeout(4.0)
        try:
            data = b""
            while len(data) < 4096:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk
                if b"\n" in chunk:
                    break
            line = data.decode("utf-8", errors="ignore").strip()
            self.store.reload(force=False, min_interval=self.reload_interval)
            response = self._dispatch(role, line, client_ip)
            conn.sendall((response + "\n").encode("utf-8"))
            self.logger.info("%s request from %s:%d -> %s", role, client_ip, client_port, response.split()[0])
        except Exception as exc:  # noqa: BLE001
            self.logger.warning("%s request from %s:%d failed: %s", role, client_ip, client_port, exc)
            try:
                conn.sendall(b"DENY reason=error\n")
            except Exception:  # noqa: BLE001
                pass
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass

    def _serve(self, role: str, port: int) -> None:
        family = socket.AF_INET6 if ":" in self.bind_ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.bind_ip, port))
        sock.listen(64)
        sock.settimeout(1.0)
        self.logger.info("listening role=%s bind=%s port=%d", role, self.bind_ip, port)

        while not self.stop_event.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_client, args=(conn, addr, role), daemon=True)
            t.start()

        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass

    def run(self) -> None:
        self.store.reload(force=True, min_interval=0.0)

        threads = [
            threading.Thread(target=self._serve, args=("av", self.av_port), daemon=True),
            threading.Thread(target=self._serve, args=("license", self.license_port), daemon=True),
        ]
        for t in threads:
            t.start()

        while not self.stop_event.is_set():
            time.sleep(0.25)

    def stop(self) -> None:
        self.stop_event.set()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="QuartzOS security verification server")
    parser.add_argument("--bind", default=os.getenv("QOS_SECURITY_BIND", "0.0.0.0"), help="bind IP")
    parser.add_argument(
        "--av-port",
        type=int,
        default=parse_port(os.getenv("QOS_SECURITY_AV_PORT", "9443"), 9443),
        help="antivirus verification TCP port",
    )
    parser.add_argument(
        "--license-port",
        type=int,
        default=parse_port(os.getenv("QOS_SECURITY_LICENSE_PORT", "9444"), 9444),
        help="license verification TCP port",
    )
    parser.add_argument(
        "--data-dir",
        default=os.getenv("QOS_SECURITY_DATA_DIR", "/opt/quartzos-security/data/current"),
        help="directory containing security_manifest.txt/licenses.db/licenses.revoked",
    )
    parser.add_argument(
        "--reload-seconds",
        type=float,
        default=float(os.getenv("QOS_SECURITY_RELOAD_SECONDS", "2.5")),
        help="minimum seconds between data reload checks",
    )
    parser.add_argument(
        "--require-pin",
        dest="require_pin",
        action="store_true",
        default=env_bool("QOS_SECURITY_REQUIRE_PIN", True),
        help="require HMAC request pin validation",
    )
    parser.add_argument(
        "--no-require-pin",
        dest="require_pin",
        action="store_false",
        help="disable HMAC request pin validation",
    )
    parser.add_argument(
        "--allowed-client",
        action="append",
        default=[],
        help="optional allowlisted client IPv4/IPv6 (repeatable)",
    )
    parser.add_argument(
        "--log-level",
        default=os.getenv("QOS_SECURITY_LOG_LEVEL", "INFO"),
        help="logging level",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger("quartzos-security")

    root_secret = os.getenv("QOS_BUILD_ROOT_SECRET", DEFAULT_BUILD_ROOT_SECRET).encode("utf-8")
    build_salt = os.getenv("QOS_BUILD_SALT", DEFAULT_BUILD_SALT)

    allowed = {item.strip() for item in args.allowed_client if item.strip()}
    env_allowed = os.getenv("QOS_SECURITY_ALLOWED_CLIENTS", "")
    if env_allowed.strip():
        for item in env_allowed.split(","):
            item = item.strip()
            if item:
                allowed.add(item)

    store = SecurityDataStore(Path(args.data_dir), root_secret, build_salt, logger)
    server = QuartzSecurityServer(
        bind_ip=args.bind,
        av_port=args.av_port,
        license_port=args.license_port,
        require_pin=args.require_pin,
        allowed_clients=allowed,
        store=store,
        reload_interval=max(0.5, args.reload_seconds),
    )

    def _signal_handler(signum: int, _frame: object) -> None:
        logger.info("signal %d received, stopping", signum)
        server.stop()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    logger.info(
        "starting: bind=%s av_port=%d license_port=%d data_dir=%s require_pin=%s allowlist=%d",
        args.bind,
        args.av_port,
        args.license_port,
        args.data_dir,
        "yes" if args.require_pin else "no",
        len(allowed),
    )
    server.run()
    logger.info("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
