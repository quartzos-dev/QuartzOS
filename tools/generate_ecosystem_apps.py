#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path

FIELD_ORDER = [
    "Domain",
    "Category",
    "Focus Area",
    "Designed For",
    "Primary Users",
    "Target Environment",
    "Overview",
    "Concept Summary",
    "System Description",
    "Core Capabilities",
    "Key Modules",
    "MVP Scope",
    "Architecture",
    "Technical Foundation",
    "Stack Alignment",
]

ENTRY_RE = re.compile(r"(?ms)^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s+|\Z)")
TITLE_RE = re.compile(r"^(.*?)\s+(Domain|Category|Focus Area):\s*(.*)$")
FIELD_RE = re.compile(
    r"(Domain|Category|Focus Area|Designed For|Primary Users|Target Environment|"
    r"Overview|Concept Summary|System Description|Core Capabilities|Key Modules|"
    r"MVP Scope|Architecture|Technical Foundation|Stack Alignment):"
)


@dataclass
class Entry:
    app_id: int
    slug: str
    title: str
    profile: str
    summary: str
    capabilities: str
    technical: str


def collapse_ws(text: str) -> str:
    return " ".join(text.split())


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    slug = re.sub(r"_+", "_", slug)
    return slug or "app"


def c_lit(text: str) -> str:
    return json.dumps(text, ensure_ascii=True)


def parse_fields(rest: str) -> dict[str, str]:
    matches = list(FIELD_RE.finditer(rest))
    if not matches:
        return {}

    fields: dict[str, str] = {}
    for i, match in enumerate(matches):
        key = match.group(1)
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(rest)
        value = collapse_ws(rest[start:end]).strip()
        if value:
            fields[key] = value
    return fields


def first_present(fields: dict[str, str], keys: list[str]) -> tuple[str, str] | None:
    for key in keys:
        value = fields.get(key)
        if value:
            return key, value
    return None


def make_profile(fields: dict[str, str]) -> str:
    parts: list[str] = []

    primary = first_present(fields, ["Domain", "Category", "Focus Area"])
    audience = first_present(fields, ["Designed For", "Primary Users", "Target Environment"])

    if primary:
        parts.append(f"{primary[0]}: {primary[1]}")
    if audience:
        parts.append(f"{audience[0]}: {audience[1]}")

    if parts:
        return " | ".join(parts)
    return "QuartzOS ecosystem profile"


def parse_entries(text: str) -> list[Entry]:
    out: list[Entry] = []

    for match in ENTRY_RE.finditer(text):
        app_id = int(match.group(1))
        body = collapse_ws(match.group(2))

        title = f"Ecosystem App {app_id}"
        rest = body

        title_match = TITLE_RE.match(body)
        if title_match:
            title = collapse_ws(title_match.group(1)).strip()
            rest = f"{title_match.group(2)}: {title_match.group(3)}"

        fields = parse_fields(rest)

        profile = make_profile(fields)
        summary = (
            fields.get("Overview")
            or fields.get("Concept Summary")
            or fields.get("System Description")
            or rest
        )
        capabilities = (
            fields.get("Core Capabilities")
            or fields.get("Key Modules")
            or fields.get("MVP Scope")
            or "QuartzOS ecosystem capability set."
        )
        technical = (
            fields.get("Architecture")
            or fields.get("Technical Foundation")
            or fields.get("Stack Alignment")
            or "QuartzOS native integration stack."
        )

        base = slugify(title)
        if len(base) > 36:
            base = base[:36].rstrip("_")
            if not base:
                base = "app"
        slug = f"eco{app_id:03d}_{base}"

        out.append(
            Entry(
                app_id=app_id,
                slug=slug,
                title=title,
                profile=profile,
                summary=summary,
                capabilities=capabilities,
                technical=technical,
            )
        )

    out.sort(key=lambda e: e.app_id)
    return out


def render_wrapper(entry: Entry) -> str:
    return (
        f"#define APP_ID {entry.app_id}\n"
        f"#define APP_SLUG {c_lit(entry.slug)}\n"
        f"#define APP_TITLE {c_lit(entry.title)}\n"
        f"#define APP_PROFILE {c_lit(entry.profile)}\n"
        f"#define APP_SUMMARY {c_lit(entry.summary)}\n"
        f"#define APP_CAPABILITIES {c_lit(entry.capabilities)}\n"
        f"#define APP_TECH {c_lit(entry.technical)}\n"
        "#include \"../../../apps/ecosystem/template.c\"\n"
    )


def write_manifest(entries: list[Entry], out_dir: Path, manifest_path: Path) -> None:
    names = [e.slug for e in entries]
    srcs = [f"{out_dir.as_posix()}/{e.slug}.c" for e in entries]

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", encoding="utf-8") as f:
        f.write("# Auto-generated by tools/generate_ecosystem_apps.py\n")
        f.write(f"ECOSYSTEM_APP_COUNT := {len(entries)}\n")
        f.write("ECOSYSTEM_APP_NAMES := \\\n")
        for i, name in enumerate(names):
            suffix = " \\\n" if i + 1 < len(names) else "\n"
            f.write(f"\t{name}{suffix}")

        f.write("ECOSYSTEM_APP_SRCS := \\\n")
        for i, src in enumerate(srcs):
            suffix = " \\\n" if i + 1 < len(srcs) else "\n"
            f.write(f"\t{src}{suffix}")


def write_index(entries: list[Entry], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "slug", "title", "profile", "summary", "capabilities", "technical"])
        for e in entries:
            w.writerow(
                [
                    e.app_id,
                    e.slug,
                    e.title,
                    e.profile,
                    e.summary,
                    e.capabilities,
                    e.technical,
                ]
            )


def write_list(entries: list[Entry], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write("QuartzOS Ecosystem App Index\n")
        f.write("============================\n")
        for e in entries:
            f.write(f"{e.app_id:03d} {e.slug} | {e.title}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate QuartzOS ecosystem apps from catalog text")
    parser.add_argument("--input", required=True, type=Path, help="source catalog text file")
    parser.add_argument("--out-dir", required=True, type=Path, help="generated C files directory")
    parser.add_argument("--manifest", required=True, type=Path, help="generated makefile fragment")
    parser.add_argument("--index", required=True, type=Path, help="generated CSV index path")
    parser.add_argument("--list", required=True, type=Path, help="generated plain-text index path")
    args = parser.parse_args()

    text = args.input.read_text(encoding="utf-8", errors="ignore")
    entries = parse_entries(text)
    if not entries:
        raise SystemExit("no entries parsed from ecosystem input")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for old in args.out_dir.glob("eco*.c"):
        old.unlink()

    for entry in entries:
        (args.out_dir / f"{entry.slug}.c").write_text(render_wrapper(entry), encoding="utf-8")

    write_manifest(entries, args.out_dir, args.manifest)
    write_index(entries, args.index)
    write_list(entries, args.list)

    print(f"generated {len(entries)} ecosystem apps")


if __name__ == "__main__":
    main()
