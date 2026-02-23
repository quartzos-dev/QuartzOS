#!/usr/bin/env python3
"""Generate QuartzOS integrity manifest for critical rootfs files."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


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

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
