#!/usr/bin/env python3
from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "QuartzOS-license-issuer" / "issue_license.py"


def is_name(node: ast.AST, name: str) -> bool:
    return isinstance(node, ast.Name) and node.id == name


def call_name(node: ast.Call) -> str:
    fn = node.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
        return f"{fn.value.id}.{fn.attr}"
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return ""


def expr_contains_sensitive(node: ast.AST) -> bool:
    sensitive_tokens = ("password", "passwd", "secret", "token", "record")

    if isinstance(node, ast.Name):
        text = node.id.lower()
        return any(tok in text for tok in sensitive_tokens)
    if isinstance(node, ast.Attribute):
        text = node.attr.lower()
        if any(tok in text for tok in sensitive_tokens):
            return True
        return expr_contains_sensitive(node.value)
    for child in ast.iter_child_nodes(node):
        if expr_contains_sensitive(child):
            return True
    return False


def iter_calls(tree: ast.AST) -> Iterable[ast.Call]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def main() -> int:
    if not TARGET.exists():
        print(f"error: missing target file: {TARGET}", file=sys.stderr)
        return 2

    source = TARGET.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(TARGET))
    findings: list[str] = []

    weak_hash_names = {"hashlib.sha1", "hashlib.sha224", "hashlib.sha256", "hashlib.md5"}
    log_like_names = {
        "print",
        "debug",
        "info",
        "warning",
        "error",
        "critical",
        "exception",
        "logger.debug",
        "logger.info",
        "logger.warning",
        "logger.error",
        "logger.critical",
        "logger.exception",
    }

    for call in iter_calls(tree):
        cname = call_name(call)

        if cname in weak_hash_names:
            if any(expr_contains_sensitive(arg) for arg in call.args):
                findings.append(
                    f"{TARGET}:{call.lineno}:{call.col_offset + 1}: weak hash used with sensitive input ({cname})"
                )

        if cname in log_like_names:
            if any(expr_contains_sensitive(arg) for arg in call.args):
                findings.append(
                    f"{TARGET}:{call.lineno}:{call.col_offset + 1}: sensitive data in clear-text output ({cname})"
                )

        # Explicit regression check from previous incidents.
        if cname == "print" and call.args and is_name(call.args[0], "record"):
            findings.append(
                f"{TARGET}:{call.lineno}:{call.col_offset + 1}: printing raw password hash record is forbidden"
            )

    if findings:
        print("Issuer security guard failed:")
        for line in findings:
            print(f"- {line}")
        return 1

    print("Issuer security guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
