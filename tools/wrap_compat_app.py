#!/usr/bin/env python3
"""Wrap a QuartzOS ELF as a Windows/macOS/Linux compatibility container."""

from __future__ import annotations

import argparse
from pathlib import Path

WRAP_MAGIC = b"QZWRAP1"


def windows_prefix() -> bytes:
    buf = bytearray(0x100)
    buf[0:2] = b"MZ"
    pe_off = 0x80
    buf[0x3C:0x40] = pe_off.to_bytes(4, "little")
    buf[pe_off : pe_off + 4] = b"PE\0\0"
    buf[pe_off + 4 : pe_off + 6] = (0x8664).to_bytes(2, "little")
    return bytes(buf)


def macos_prefix() -> bytes:
    buf = bytearray(0x100)
    buf[0:4] = b"\xcf\xfa\xed\xfe"
    buf[4:8] = (0x01000007).to_bytes(4, "little")
    buf[8:12] = (3).to_bytes(4, "little")
    return bytes(buf)


def linux_prefix() -> bytes:
    buf = bytearray(0x80)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2  # 64-bit
    buf[5] = 1  # little-endian
    buf[6] = 1  # version
    buf[7] = 3  # linux osabi
    return bytes(buf)


def custom_prefix() -> bytes:
    return b"QAPP\0\0\0\0"


def make_wrapper(payload: bytes, platform: str) -> bytes:
    if platform == "windows":
        prefix = windows_prefix()
        kind = b"W"
    elif platform == "macos":
        prefix = macos_prefix()
        kind = b"M"
    elif platform == "linux":
        prefix = linux_prefix()
        kind = b"L"
    elif platform == "custom":
        prefix = custom_prefix()
        kind = b"Q"
    else:
        raise ValueError(f"unsupported platform: {platform}")

    trailer = WRAP_MAGIC + kind + len(payload).to_bytes(8, "little")
    return prefix + payload + trailer


def main() -> int:
    parser = argparse.ArgumentParser(description="Wrap QuartzOS ELF in compat container")
    parser.add_argument("--input-elf", required=True)
    parser.add_argument("--platform", choices=["windows", "macos", "linux", "custom"], required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    src = Path(args.input_elf)
    out = Path(args.output)
    payload = src.read_bytes()

    wrapper = make_wrapper(payload, args.platform)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(wrapper)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
