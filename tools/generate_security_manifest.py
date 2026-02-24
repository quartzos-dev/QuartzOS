#!/usr/bin/env python3
"""Generate QuartzOS integrity manifest for critical rootfs files."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
from pathlib import Path

DEFAULT_ROOT_SECRET = "QuartzOS-BuildRoot-2026"
DEFAULT_BUILD_SALT = "quartzos-build-v1"


def parse_add_mapping(item: str) -> tuple[str, Path]:
    if "=" not in item:
        raise argparse.ArgumentTypeError(f"invalid mapping '{item}', expected ROOT=HOST")
    root, host = item.split("=", 1)
    root = root.strip()
    host_path = Path(host.strip())
    if not root.startswith("/"):
        raise argparse.ArgumentTypeError(f"rootfs path must start with '/': {root}")
    return root, host_path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def derive_manifest_sign_key(root_secret: str, build_salt: str) -> bytes:
    seed = root_secret.encode("utf-8")
    out = bytearray()
    counter = 0
    while len(out) < 32:
        msg = f"{build_salt}|security.manifest.sign|{counter}".encode("utf-8")
        out.extend(hmac.new(seed, msg, hashlib.sha256).digest())
        counter += 1
    return bytes(out[:32])


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate QuartzOS security integrity manifest")
    parser.add_argument("--output", required=True, help="output manifest path")
    parser.add_argument(
        "--add",
        action="append",
        default=[],
        metavar="ROOT=HOST",
        help="add a rootfs path to hash from a host file",
    )
    parser.add_argument(
        "--signature",
        default="",
        help="optional path to write HMAC signature for the manifest",
    )
    args = parser.parse_args()

    pairs: list[tuple[str, Path]] = [parse_add_mapping(item) for item in args.add]
    if not pairs:
        parser.error("at least one --add ROOT=HOST mapping is required")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    lines.append("# QuartzOS security manifest")
    lines.append("# format: <rootfs-path>|<sha256-hex>")
    for root, host in pairs:
        if not host.exists():
            raise SystemExit(f"missing input file: {host}")
        lines.append(f"{root}|{sha256_file(host)}")

    manifest_text = "\n".join(lines) + "\n"
    output_path.write_text(manifest_text, encoding="utf-8")

    if args.signature:
        sig_path = Path(args.signature)
        sig_path.parent.mkdir(parents=True, exist_ok=True)
        root_secret = os.getenv("QOS_BUILD_ROOT_SECRET", DEFAULT_ROOT_SECRET)
        build_salt = os.getenv("QOS_BUILD_SALT", DEFAULT_BUILD_SALT)
        key = derive_manifest_sign_key(root_secret, build_salt)
        sig = hmac.new(key, manifest_text.encode("utf-8"), hashlib.sha256).hexdigest()
        sig_path.write_text(sig + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
