#!/usr/bin/env python3
"""Generate a large QuartzOS GUI asset pack (detailed unique SVG icons/wallpapers)."""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import shutil
from pathlib import Path


PALETTES = [
    ("#10243A", "#1F4E79", "#4E8FC5", "#D9EEFF"),
    ("#0F2A2E", "#1E5A61", "#2E8D96", "#D5F8FA"),
    ("#1C2435", "#35517D", "#5E86C9", "#EEF4FF"),
    ("#1E2032", "#3E4F88", "#6C7CC5", "#EEF1FF"),
    ("#1A2B22", "#356B54", "#5AA47F", "#E2FFF2"),
    ("#27201B", "#7A4C28", "#B37A46", "#FFF2E6"),
    ("#1A2630", "#2A5E6D", "#4B91A3", "#E3F8FF"),
    ("#271E2A", "#6B3F7A", "#9A6BB4", "#F6E8FF"),
    ("#1E2E3A", "#275F88", "#3C8FC1", "#E7F7FF"),
    ("#1B2630", "#2D4C6F", "#4F79A7", "#EAF2FF"),
    ("#1D2F45", "#2A618E", "#58A3D8", "#E7F8FF"),
    ("#122A3D", "#236890", "#4BA7D0", "#E9F7FF"),
]

ADJECTIVES = [
    "aero",
    "nova",
    "quartz",
    "swift",
    "bright",
    "zen",
    "pixel",
    "core",
    "lumen",
    "tidal",
    "vivid",
    "alpha",
    "neon",
    "crisp",
    "solid",
    "magnet",
    "stellar",
    "vector",
    "prime",
    "solar",
]

NOUNS = [
    "editor",
    "studio",
    "board",
    "player",
    "mail",
    "cloud",
    "camera",
    "viewer",
    "terminal",
    "charts",
    "notes",
    "calendar",
    "gallery",
    "browser",
    "settings",
    "monitor",
    "builder",
    "designer",
    "manager",
    "inspector",
]

SYSTEM_NAMES = [
    "network",
    "battery",
    "volume",
    "bluetooth",
    "display",
    "cpu",
    "memory",
    "storage",
    "clock",
    "mail",
    "wifi",
    "security",
    "update",
    "theme",
    "accessibility",
    "privacy",
    "downloads",
    "uploads",
    "input",
    "power",
]


class SeedRng:
    """Small deterministic RNG for stable asset generation."""

    def __init__(self, seed: int):
        self.state = (seed ^ 0x9E3779B9) & 0xFFFFFFFF

    def next_u32(self) -> int:
        self.state = (1664525 * self.state + 1013904223) & 0xFFFFFFFF
        return self.state

    def randf(self) -> float:
        return self.next_u32() / 4294967295.0

    def randint(self, low: int, high: int) -> int:
        span = high - low + 1
        return low + int(self.randf() * span)


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def polygon_points(
    rng: SeedRng, cx: float, cy: float, r_min: float, r_max: float, count: int
) -> str:
    start = rng.randf() * math.tau
    pts = []
    for i in range(count):
        angle = start + (math.tau * i / count) + (rng.randf() - 0.5) * (math.pi / count)
        radius = r_min + (r_max - r_min) * rng.randf()
        x = cx + math.cos(angle) * radius
        y = cy + math.sin(angle) * radius
        pts.append(f"{x:.1f},{y:.1f}")
    return " ".join(pts)


def wave_path(
    rng: SeedRng,
    x0: float,
    y0: float,
    width: float,
    amplitude: float,
    segments: int,
    stroke_w: float,
    color: str,
    opacity: float,
) -> str:
    seg_w = width / segments
    x = x0
    d = f"M{x0:.1f} {y0:.1f}"
    phase = rng.randf() * math.pi * 2.0
    for i in range(segments):
        x1 = x + seg_w
        c1x = x + seg_w * 0.30
        c2x = x + seg_w * 0.72
        y_amp = amplitude * math.sin(phase + i * 0.8)
        c1y = y0 + y_amp * (0.6 + rng.randf() * 0.8)
        c2y = y0 - y_amp * (0.3 + rng.randf() * 0.9)
        y1 = y0 + amplitude * math.sin(phase + (i + 1) * 0.8)
        d += f" C {c1x:.1f} {c1y:.1f}, {c2x:.1f} {c2y:.1f}, {x1:.1f} {y1:.1f}"
        x = x1
    return (
        f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{stroke_w:.1f}" '
        f'stroke-linecap="round" stroke-opacity="{opacity:.3f}" />'
    )


def hex_grid_overlay(
    rng: SeedRng,
    x0: float,
    y0: float,
    width: float,
    height: float,
    cell: float,
    color: str,
    opacity: float,
    stroke: float,
) -> str:
    cell = max(8.0, cell)
    step_x = cell * 1.5
    step_y = cell * 0.8660254
    cols = int(width / step_x) + 4
    rows = int(height / step_y) + 4
    polys = []
    for row in range(rows):
        cy = y0 + row * step_y
        shift = cell * 0.75 if (row & 1) else 0.0
        for col in range(cols):
            if rng.randf() < 0.22:
                continue
            cx = x0 + col * step_x + shift
            if cx < x0 - cell or cx > x0 + width + cell:
                continue
            if cy < y0 - cell or cy > y0 + height + cell:
                continue
            pts = []
            for k in range(6):
                angle = (math.pi / 3.0) * k + (math.pi / 6.0)
                radius = cell * (0.48 + (rng.randf() - 0.5) * 0.10)
                px = cx + math.cos(angle) * radius
                py = cy + math.sin(angle) * radius
                pts.append(f"{px:.1f},{py:.1f}")
            op = opacity * (0.55 + 0.65 * rng.randf())
            sw = stroke * (0.85 + 0.55 * rng.randf())
            polys.append(
                f'<polygon points="{" ".join(pts)}" fill="none" stroke="{color}" '
                f'stroke-width="{sw:.2f}" stroke-opacity="{op:.3f}" />'
            )
    return "".join(polys)


def circuit_overlay(
    rng: SeedRng,
    x0: float,
    y0: float,
    width: float,
    height: float,
    trace_count: int,
    color: str,
    node_color: str,
    stroke: float,
    opacity: float,
    node_radius: float,
) -> str:
    traces = []
    nodes = []
    for _ in range(trace_count):
        x = x0 + rng.randf() * width
        y = y0 + rng.randf() * height
        d = [f"M {x:.1f} {y:.1f}"]
        segments = 3 + rng.randint(0, 4)
        for i in range(segments):
            span = 0.15 + rng.randf() * 0.32
            if i & 1:
                y += (rng.randf() - 0.5) * height * span
            else:
                x += (rng.randf() - 0.5) * width * span
            x = clamp(x, x0, x0 + width)
            y = clamp(y, y0, y0 + height)
            d.append(f"L {x:.1f} {y:.1f}")
            if rng.randf() < 0.64:
                nr = node_radius * (0.8 + rng.randf() * 0.8)
                nodes.append(
                    f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{nr:.2f}" fill="{node_color}" '
                    f'fill-opacity="{0.25 + 0.55 * rng.randf():.3f}" />'
                )
        sw = stroke * (0.8 + rng.randf() * 0.7)
        op = opacity * (0.55 + rng.randf() * 0.65)
        traces.append(
            f'<path d="{" ".join(d)}" fill="none" stroke="{color}" stroke-width="{sw:.2f}" '
            f'stroke-linejoin="round" stroke-linecap="round" stroke-opacity="{op:.3f}" />'
        )
    return "".join(traces) + "".join(nodes)


def hud_arc_overlay(
    rng: SeedRng,
    cx: float,
    cy: float,
    r_min: float,
    r_max: float,
    arc_count: int,
    color: str,
    stroke: float,
    opacity: float,
) -> str:
    arcs = []
    for _ in range(arc_count):
        r = r_min + (r_max - r_min) * rng.randf()
        start = rng.randf() * math.tau
        span = math.pi * (0.18 + rng.randf() * 0.72)
        end = start + span
        x1 = cx + math.cos(start) * r
        y1 = cy + math.sin(start) * r
        x2 = cx + math.cos(end) * r
        y2 = cy + math.sin(end) * r
        large = 1 if span > math.pi else 0
        sw = stroke * (0.75 + rng.randf() * 0.85)
        op = opacity * (0.45 + rng.randf() * 0.75)
        arcs.append(
            f'<path d="M {x1:.1f} {y1:.1f} A {r:.1f} {r:.1f} 0 {large} 1 {x2:.1f} {y2:.1f}" '
            f'fill="none" stroke="{color}" stroke-width="{sw:.2f}" stroke-opacity="{op:.3f}" '
            f'stroke-linecap="round" />'
        )
    return "".join(arcs)


def perspective_grid_overlay(
    rng: SeedRng, w: int, h: int, horizon: float, color: str, opacity: float, stroke: float
) -> str:
    vx = w * (0.22 + rng.randf() * 0.56)
    vy = horizon
    lines = []
    rays = 34
    for i in range(rays + 1):
        x = w * i / rays
        op = opacity * (0.45 + rng.randf() * 0.6)
        sw = stroke * (0.8 + rng.randf() * 0.5)
        lines.append(
            f'<line x1="{vx:.1f}" y1="{vy:.1f}" x2="{x:.1f}" y2="{h:.1f}" '
            f'stroke="{color}" stroke-opacity="{op:.3f}" stroke-width="{sw:.2f}" />'
        )
    bands = 18
    for i in range(1, bands + 1):
        t = i / bands
        k = t * t
        y = vy + (h - vy) * k
        left = vx + (0.0 - vx) * k
        right = vx + (w - vx) * k
        op = opacity * (0.42 + 0.65 * (1.0 - t))
        sw = stroke * (0.75 + 0.3 * (1.0 - t))
        lines.append(
            f'<line x1="{left:.1f}" y1="{y:.1f}" x2="{right:.1f}" y2="{y:.1f}" '
            f'stroke="{color}" stroke-opacity="{op:.3f}" stroke-width="{sw:.2f}" />'
        )
    return "".join(lines)


def symbol_svg(symbol_kind: int, x: int, y: int, size: int, fg: str) -> str:
    cx = x + size // 2
    cy = y + size // 2
    s = size
    stroke = max(10, s // 17)
    if symbol_kind == 0:
        return (
            f'<circle cx="{cx}" cy="{cy}" r="{s // 5}" fill="none" stroke="{fg}" stroke-width="{stroke}" />'
            f'<line x1="{cx + s // 7}" y1="{cy + s // 7}" x2="{x + s}" y2="{y + s}" '
            f'stroke="{fg}" stroke-width="{stroke}" stroke-linecap="round" />'
        )
    if symbol_kind == 1:
        return (
            f'<rect x="{x + s // 7}" y="{y + s // 6}" width="{s // 2}" height="{s // 2}" '
            f'rx="{s // 12}" fill="none" stroke="{fg}" stroke-width="{stroke}" />'
            f'<path d="M{x + s // 7} {y + s // 2} L{x + s // 2} {y + s // 2 - s // 7} '
            f'L{x + s - s // 7} {y + s // 2} L{x + s // 2} {y + s - s // 6} Z" '
            f'fill="none" stroke="{fg}" stroke-width="{stroke}" stroke-linejoin="round" />'
        )
    if symbol_kind == 2:
        return (
            f'<path d="M{x + s // 8} {y + s // 2} L{x + s // 3} {y + s - s // 7} '
            f'L{x + s - s // 8} {y + s // 5}" fill="none" stroke="{fg}" stroke-width="{stroke}" '
            f'stroke-linecap="round" stroke-linejoin="round" />'
            f'<circle cx="{x + s // 8}" cy="{y + s // 2}" r="{stroke // 2 + 2}" fill="{fg}" />'
            f'<circle cx="{x + s // 3}" cy="{y + s - s // 7}" r="{stroke // 2 + 2}" fill="{fg}" />'
            f'<circle cx="{x + s - s // 8}" cy="{y + s // 5}" r="{stroke // 2 + 2}" fill="{fg}" />'
        )
    if symbol_kind == 3:
        return (
            f'<rect x="{x + s // 6}" y="{y + s // 6}" width="{s // 7}" height="{s - s // 3}" fill="{fg}" />'
            f'<rect x="{x + s // 3}" y="{y + s // 3}" width="{s // 7}" height="{s // 2}" fill="{fg}" />'
            f'<rect x="{x + s // 2}" y="{y + s // 4}" width="{s // 7}" height="{s // 2 + s // 10}" fill="{fg}" />'
            f'<rect x="{x + s - s // 3}" y="{y + s // 7}" width="{s // 7}" height="{s - s // 4}" fill="{fg}" />'
        )
    if symbol_kind == 4:
        return (
            f'<path d="M{cx} {y + s // 8} L{x + s - s // 8} {cy} L{cx} {y + s - s // 8} '
            f'L{x + s // 8} {cy} Z" fill="none" stroke="{fg}" stroke-width="{stroke}" '
            f'stroke-linejoin="round" />'
            f'<circle cx="{cx}" cy="{cy}" r="{s // 10}" fill="{fg}" />'
        )
    if symbol_kind == 5:
        return (
            f'<rect x="{x + s // 7}" y="{y + s // 5}" width="{s - s // 4}" height="{s - s // 3}" '
            f'rx="{s // 10}" fill="none" stroke="{fg}" stroke-width="{stroke}" />'
            f'<line x1="{x + s // 7}" y1="{y + s // 3}" x2="{x + s - s // 8}" y2="{y + s // 3}" '
            f'stroke="{fg}" stroke-width="{stroke}" />'
            f'<line x1="{x + s // 3}" y1="{y + s // 7}" x2="{x + s // 3}" y2="{y + s // 5}" stroke="{fg}" stroke-width="{stroke}" />'
            f'<line x1="{x + s - s // 3}" y1="{y + s // 7}" x2="{x + s - s // 3}" y2="{y + s // 5}" '
            f'stroke="{fg}" stroke-width="{stroke}" />'
        )
    if symbol_kind == 6:
        return (
            f'<path d="M{x + s // 8} {cy} Q{cx} {y + s // 8}, {x + s - s // 8} {cy}" fill="none" '
            f'stroke="{fg}" stroke-width="{stroke}" />'
            f'<path d="M{x + s // 8} {cy + s // 7} Q{cx} {y + s // 4}, {x + s - s // 8} {cy + s // 7}" '
            f'fill="none" stroke="{fg}" stroke-width="{max(6, stroke - 2)}" opacity="0.9" />'
            f'<path d="M{x + s // 8} {cy + s // 4} Q{cx} {y + s // 3}, {x + s - s // 8} {cy + s // 4}" '
            f'fill="none" stroke="{fg}" stroke-width="{max(5, stroke - 3)}" opacity="0.75" />'
        )
    if symbol_kind == 7:
        return (
            f'<circle cx="{cx}" cy="{cy}" r="{s // 4}" fill="none" stroke="{fg}" stroke-width="{stroke}" />'
            f'<circle cx="{cx}" cy="{cy}" r="{s // 10}" fill="{fg}" />'
            f'<line x1="{cx}" y1="{y + s // 10}" x2="{cx}" y2="{y + s // 4}" stroke="{fg}" stroke-width="{stroke}" />'
            f'<line x1="{cx}" y1="{y + s - s // 10}" x2="{cx}" y2="{y + s - s // 4}" stroke="{fg}" stroke-width="{stroke}" />'
            f'<line x1="{x + s // 10}" y1="{cy}" x2="{x + s // 4}" y2="{cy}" stroke="{fg}" stroke-width="{stroke}" />'
            f'<line x1="{x + s - s // 10}" y1="{cy}" x2="{x + s - s // 4}" y2="{cy}" stroke="{fg}" stroke-width="{stroke}" />'
        )
    if symbol_kind == 8:
        return (
            f'<path d="M{x + s // 7} {y + s // 3} L{x + s // 2} {y + s // 6} L{x + s - s // 7} {y + s // 3} '
            f'L{x + s - s // 7} {y + s - s // 5} L{x + s // 7} {y + s - s // 5} Z" '
            f'fill="none" stroke="{fg}" stroke-width="{stroke}" stroke-linejoin="round" />'
            f'<line x1="{x + s // 2}" y1="{y + s // 6}" x2="{x + s // 2}" y2="{y + s - s // 5}" '
            f'stroke="{fg}" stroke-width="{max(6, stroke - 2)}" />'
        )
    if symbol_kind == 9:
        return (
            f'<rect x="{x + s // 6}" y="{y + s // 6}" width="{s - s // 3}" height="{s - s // 3}" '
            f'rx="{s // 10}" fill="none" stroke="{fg}" stroke-width="{stroke}" />'
            f'<line x1="{x + s // 3}" y1="{y + s // 3}" x2="{x + s - s // 3}" y2="{y + s - s // 3}" '
            f'stroke="{fg}" stroke-width="{stroke}" stroke-linecap="round" />'
            f'<line x1="{x + s - s // 3}" y1="{y + s // 3}" x2="{x + s // 3}" y2="{y + s - s // 3}" '
            f'stroke="{fg}" stroke-width="{stroke}" stroke-linecap="round" />'
        )
    if symbol_kind == 10:
        return (
            f'<path d="M{x + s // 8} {y + s // 2} C{x + s // 3} {y + s // 8}, {x + s // 2} {y + s - s // 8}, '
            f'{x + s - s // 8} {y + s // 2}" fill="none" stroke="{fg}" stroke-width="{stroke}" />'
            f'<circle cx="{x + s // 4}" cy="{cy}" r="{s // 14}" fill="{fg}" />'
            f'<circle cx="{x + s // 2}" cy="{cy}" r="{s // 14}" fill="{fg}" />'
            f'<circle cx="{x + s - s // 4}" cy="{cy}" r="{s // 14}" fill="{fg}" />'
        )
    return (
        f'<path d="M{x + s // 8} {y + s // 8} L{x + s - s // 8} {y + s // 8} '
        f'L{x + s - s // 8} {y + s - s // 8} L{x + s // 8} {y + s - s // 8} Z" '
        f'fill="none" stroke="{fg}" stroke-width="{stroke}" />'
        f'<path d="M{x + s // 8} {y + s // 2} L{x + s - s // 8} {y + s // 2}" stroke="{fg}" stroke-width="{stroke}" />'
        f'<path d="M{cx} {y + s // 8} L{cx} {y + s - s // 8}" stroke="{fg}" stroke-width="{stroke}" />'
    )


def icon_svg(seed: int, title: str, size: int = 3072) -> str:
    rng = SeedRng(seed)
    deep, base, accent, text = PALETTES[seed % len(PALETTES)]
    symbol_kind = seed % 12

    vivid = [
        "#36D1FF",
        "#3B82FF",
        "#8A5CFF",
        "#FF6AB3",
        "#FF9F43",
        "#FFD84D",
        "#53E3A6",
    ]
    v0 = vivid[seed % len(vivid)]
    v1 = vivid[(seed + 2) % len(vivid)]
    v2 = vivid[(seed + 4) % len(vivid)]
    v3 = vivid[(seed + 5) % len(vivid)]

    corner = int(size * 0.205)
    pad = int(size * 0.045)
    inner = int(size * 0.088)
    cx = size / 2.0
    cy = size / 2.0
    orb_rx = size * 0.242
    orb_ry = size * 0.212
    orb_depth = size * 0.062
    symbol_box = int(size * 0.50)
    symbol_x = int((size - symbol_box) / 2)
    symbol_y = int((size - symbol_box) / 2)

    defs = [
        f'<linearGradient id="bg{seed}" x1="0%" y1="0%" x2="100%" y2="100%">'
        f'<stop offset="0%" stop-color="{v0}" />'
        f'<stop offset="26%" stop-color="{v1}" />'
        f'<stop offset="56%" stop-color="{v2}" />'
        f'<stop offset="78%" stop-color="{accent}" />'
        f'<stop offset="100%" stop-color="{deep}" />'
        f"</linearGradient>",
        f'<radialGradient id="sun{seed}" cx="{18 + int(rng.randf() * 44)}%" cy="{8 + int(rng.randf() * 34)}%" r="88%">'
        f'<stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.62" />'
        f'<stop offset="30%" stop-color="{v3}" stop-opacity="0.35" />'
        f'<stop offset="100%" stop-color="{v3}" stop-opacity="0" />'
        f"</radialGradient>",
        f'<linearGradient id="glass{seed}" x1="0%" y1="0%" x2="0%" y2="100%">'
        f'<stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.70" />'
        f'<stop offset="46%" stop-color="#FFFFFF" stop-opacity="0.26" />'
        f'<stop offset="100%" stop-color="#FFFFFF" stop-opacity="0.00" />'
        f"</linearGradient>",
        f'<linearGradient id="ribbon{seed}" x1="0%" y1="0%" x2="100%" y2="0%">'
        f'<stop offset="0%" stop-color="{v0}" stop-opacity="0.18" />'
        f'<stop offset="34%" stop-color="{v1}" stop-opacity="0.72" />'
        f'<stop offset="66%" stop-color="{v2}" stop-opacity="0.72" />'
        f'<stop offset="100%" stop-color="{v3}" stop-opacity="0.18" />'
        f"</linearGradient>",
        f'<radialGradient id="orb{seed}" cx="34%" cy="27%" r="74%">'
        f'<stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.84" />'
        f'<stop offset="30%" stop-color="{v0}" stop-opacity="0.52" />'
        f'<stop offset="68%" stop-color="{v1}" stop-opacity="0.42" />'
        f'<stop offset="100%" stop-color="{v2}" stop-opacity="0.20" />'
        f"</radialGradient>",
        f'<linearGradient id="extrude{seed}" x1="0%" y1="0%" x2="0%" y2="100%">'
        f'<stop offset="0%" stop-color="#15283C" stop-opacity="0.45" />'
        f'<stop offset="100%" stop-color="#08131D" stop-opacity="0.06" />'
        f"</linearGradient>",
        f'<linearGradient id="symbol{seed}" x1="0%" y1="0%" x2="100%" y2="100%">'
        f'<stop offset="0%" stop-color="#FFFFFF" />'
        f'<stop offset="100%" stop-color="{v3}" />'
        f"</linearGradient>",
        f'<filter id="shadow{seed}" x="-40%" y="-40%" width="180%" height="180%">'
        f'<feDropShadow dx="0" dy="{int(size * 0.016)}" stdDeviation="{int(size * 0.028)}" flood-color="#06111A" flood-opacity="0.54" />'
        f"</filter>",
        f'<filter id="soft{seed}" x="-40%" y="-40%" width="180%" height="180%">'
        f'<feDropShadow dx="0" dy="0" stdDeviation="{max(2, int(size * 0.0046))}" flood-color="{v0}" flood-opacity="0.45" />'
        f"</filter>",
        f'<filter id="grain{seed}">'
        f'<feTurbulence type="fractalNoise" baseFrequency="{0.62 + rng.randf() * 0.46:.3f}" numOctaves="2" seed="{seed % 4096}" />'
        f'<feColorMatrix type="saturate" values="0" />'
        f'<feComponentTransfer><feFuncA type="table" tableValues="0 0.09" /></feComponentTransfer>'
        f"</filter>",
    ]

    bokeh = []
    for _ in range(28):
        bx = int(size * (0.12 + rng.randf() * 0.76))
        by = int(size * (0.10 + rng.randf() * 0.78))
        br = int(size * (0.012 + rng.randf() * 0.040))
        op = 0.06 + rng.randf() * 0.18
        bokeh.append(f'<circle cx="{bx}" cy="{by}" r="{br}" fill="#FFFFFF" opacity="{op:.3f}" />')

    glass_panels = []
    for i in range(8):
        y0 = size * (0.20 + i * 0.085) + (rng.randf() - 0.5) * size * 0.03
        x0 = inner + (rng.randf() - 0.5) * size * 0.08
        x1 = size - inner + (rng.randf() - 0.5) * size * 0.08
        y1 = y0 + size * (0.046 + rng.randf() * 0.026)
        op = 0.08 + rng.randf() * 0.16
        glass_panels.append(
            f'<path d="M {x0:.1f} {y0:.1f} L {x1:.1f} {y0 - size * 0.09:.1f} L {x1:.1f} {y1:.1f} L {x0:.1f} {y1 + size * 0.09:.1f} Z" fill="#FFFFFF" opacity="{op:.3f}" />'
        )

    ribbons = []
    base_angle = -24.0 + rng.randf() * 20.0
    for i in range(12):
        stroke_w = size * (0.019 - i * 0.0013)
        if stroke_w <= size * 0.004:
            stroke_w = size * 0.004
        path = wave_path(
            rng,
            x0=-size * 0.12,
            y0=size * (0.17 + i * 0.063) + (rng.randf() - 0.5) * size * 0.04,
            width=size * 1.24,
            amplitude=size * (0.018 + i * 0.0023),
            segments=8 + (i % 5),
            stroke_w=stroke_w,
            color=f"url(#ribbon{seed})",
            opacity=0.12 + i * 0.026,
        )
        ribbons.append(f'<g transform="rotate({base_angle + i * 0.58:.2f} {cx:.1f} {cy:.1f})">{path}</g>')

    glints = []
    for _ in range(26):
        gx = int(size * (0.10 + rng.randf() * 0.82))
        gy = int(size * (0.08 + rng.randf() * 0.82))
        gs = int(size * (0.004 + rng.randf() * 0.010))
        op = 0.30 + rng.randf() * 0.55
        glints.append(
            f'<rect x="{gx - gs}" y="{gy - 1}" width="{gs * 2}" height="2" fill="#FFFFFF" opacity="{op:.3f}" />'
            f'<rect x="{gx - 1}" y="{gy - gs}" width="2" height="{gs * 2}" fill="#FFFFFF" opacity="{op:.3f}" />'
        )

    extrusion = []
    depth_steps = 12
    for i in range(depth_steps):
        dy = orb_depth * (i + 1) / depth_steps
        op = 0.18 * (1.0 - (i / depth_steps)) + 0.04
        extrusion.append(
            f'<ellipse cx="{cx:.1f}" cy="{cy + dy:.1f}" rx="{orb_rx * (0.98 + 0.01 * i):.1f}" ry="{orb_ry * (0.93 + 0.008 * i):.1f}" '
            f'fill="url(#extrude{seed})" opacity="{op:.3f}" />'
        )

    symbol_shadow = symbol_svg(symbol_kind, symbol_x + int(size * 0.012), symbol_y + int(size * 0.015), symbol_box, "#0C2030")
    symbol = symbol_svg(symbol_kind, symbol_x, symbol_y, symbol_box, "url(#symbol" + str(seed) + ")")

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}">
  <title>{title}</title>
  <defs>{''.join(defs)}</defs>
  <rect x="{pad}" y="{pad}" width="{size - pad * 2}" height="{size - pad * 2}" rx="{corner}" fill="url(#bg{seed})" filter="url(#shadow{seed})" />
  <rect x="{pad}" y="{pad}" width="{size - pad * 2}" height="{size - pad * 2}" rx="{corner}" fill="url(#sun{seed})" />
  <g>{''.join(bokeh)}</g>
  <g>{''.join(glass_panels)}</g>
  <g filter="url(#soft{seed})">{''.join(ribbons)}</g>
  <g>{''.join(extrusion)}</g>
  <ellipse cx="{cx:.1f}" cy="{cy + orb_depth:.1f}" rx="{orb_rx * 1.04:.1f}" ry="{orb_ry * 0.33:.1f}" fill="#0B1D2D" opacity="0.24" />
  <ellipse cx="{cx:.1f}" cy="{cy:.1f}" rx="{orb_rx:.1f}" ry="{orb_ry:.1f}" fill="url(#orb{seed})" stroke="#FFFFFF" stroke-opacity="0.42" stroke-width="{max(3, int(size * 0.0023))}" />
  <ellipse cx="{cx - orb_rx * 0.14:.1f}" cy="{cy - orb_ry * 0.22:.1f}" rx="{orb_rx * 0.68:.1f}" ry="{orb_ry * 0.46:.1f}" fill="#FFFFFF" opacity="0.25" />
  <path d="M {pad + size * 0.02:.1f} {size * 0.13:.1f} C {size * 0.33:.1f} {size * -0.01:.1f}, {size * 0.67:.1f} {size * 0.25:.1f}, {size - pad - size * 0.02:.1f} {size * 0.07:.1f} L {size - pad - size * 0.02:.1f} {size * 0.32:.1f} C {size * 0.68:.1f} {size * 0.40:.1f}, {size * 0.33:.1f} {size * 0.10:.1f}, {pad + size * 0.02:.1f} {size * 0.38:.1f} Z" fill="url(#glass{seed})" />
  <rect x="{inner}" y="{inner}" width="{size - inner * 2}" height="{size - inner * 2}" rx="{corner - int(size * 0.065)}" fill="none" stroke="#FFFFFF" stroke-opacity="0.30" stroke-width="{max(2, int(size * 0.0017))}" />
  <rect x="{inner + size * 0.006:.1f}" y="{inner + size * 0.006:.1f}" width="{size - (inner + size * 0.006) * 2:.1f}" height="{size - (inner + size * 0.006) * 2:.1f}" rx="{corner - int(size * 0.075)}" fill="none" stroke="{v0}" stroke-opacity="0.35" stroke-width="{max(1, int(size * 0.0010))}" />
  <g filter="url(#soft{seed})">{''.join(glints)}</g>
  <g opacity="0.52">{symbol_shadow}</g>
  <g filter="url(#soft{seed})">{symbol}</g>
  <rect x="{pad}" y="{pad}" width="{size - pad * 2}" height="{size - pad * 2}" rx="{corner}" fill="#FFFFFF" filter="url(#grain{seed})" opacity="0.18" />
</svg>
"""


def layered_ridge_points(
    rng: SeedRng, w: int, h: int, base_ratio: float, amp_ratio: float, count: int
) -> str:
    pts = []
    for i in range(count + 1):
        x = int((w / count) * i)
        normalized = i / max(1, count)
        phase = normalized * math.pi * (1.5 + rng.randf() * 2.2)
        y = int(h * (base_ratio + amp_ratio * math.sin(phase) + (rng.randf() - 0.5) * 0.04))
        y = int(clamp(y, h * 0.14, h * 0.94))
        pts.append(f"{x},{y}")
    return " ".join(pts)


def wallpaper_svg(seed: int, title: str, w: int = 8192, h: int = 4608) -> str:
    rng = SeedRng(seed)
    deep, base, accent, text = PALETTES[seed % len(PALETTES)]
    sky = PALETTES[(seed + 2) % len(PALETTES)][3]
    aqua = PALETTES[(seed + 5) % len(PALETTES)][2]
    glow = PALETTES[(seed + 7) % len(PALETTES)][3]

    g_bg = f"wp{seed}bg"
    g_sun = f"wp{seed}sun"
    g_glass = f"wp{seed}glass"
    g_ribbon = f"wp{seed}ribbon"
    g_haze = f"wp{seed}haze"
    noise = f"wp{seed}noise"
    soft = f"wp{seed}soft"

    sun_x = w * (0.14 + rng.randf() * 0.28)
    sun_y = h * (0.10 + rng.randf() * 0.16)

    rays = []
    for i in range(74):
        angle = -1.18 + (2.40 * i / 73.0) + (rng.randf() - 0.5) * 0.05
        dist = h * (1.6 + rng.randf() * 0.8)
        x2 = sun_x + math.cos(angle) * dist
        y2 = sun_y + math.sin(angle) * dist
        sw = h * (0.012 + rng.randf() * 0.018)
        op = 0.015 + rng.randf() * 0.040
        rays.append(
            f'<line x1="{sun_x:.1f}" y1="{sun_y:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="#FFFFFF" stroke-width="{sw:.1f}" stroke-opacity="{op:.3f}" '
            f'stroke-linecap="round" />'
        )

    ribbons = []
    tilt = -15.0 + rng.randf() * 12.0
    for i in range(18):
        sw = h * (0.021 - i * 0.00085)
        if sw < h * 0.004:
            sw = h * 0.004
        path = wave_path(
            rng,
            x0=-w * 0.10,
            y0=h * (0.16 + i * 0.043) + (rng.randf() - 0.5) * h * 0.04,
            width=w * 1.24,
            amplitude=h * (0.010 + i * 0.0024),
            segments=9 + (i % 5),
            stroke_w=sw,
            color=f"url(#{g_ribbon})",
            opacity=0.11 + i * 0.022,
        )
        ribbons.append(
            f'<g transform="rotate({tilt + i * 0.42:.2f} {w/2:.1f} {h/2:.1f})">{path}</g>'
        )

    bokeh = []
    for _ in range(340):
        bx = int(w * (0.03 + rng.randf() * 0.94))
        by = int(h * (0.03 + rng.randf() * 0.90))
        br = int(h * (0.002 + rng.randf() * 0.020))
        op = 0.04 + rng.randf() * 0.20
        bokeh.append(
            f'<circle cx="{bx}" cy="{by}" r="{br}" fill="#FFFFFF" opacity="{op:.3f}" />'
        )

    panes = []
    for _ in range(72):
        px = int(w * (0.04 + rng.randf() * 0.90))
        py = int(h * (0.10 + rng.randf() * 0.74))
        pw = int(w * (0.015 + rng.randf() * 0.080))
        ph = int(h * (0.006 + rng.randf() * 0.028))
        rot = -18 + int(rng.randf() * 36)
        op = 0.05 + rng.randf() * 0.15
        panes.append(
            f'<rect x="{px}" y="{py}" width="{pw}" height="{ph}" rx="{max(2, ph // 3)}" '
            f'fill="#FFFFFF" opacity="{op:.3f}" transform="rotate({rot} {px + pw/2:.1f} {py + ph/2:.1f})" />'
        )

    orbs = []
    for _ in range(46):
        ox = int(w * (0.06 + rng.randf() * 0.88))
        oy = int(h * (0.06 + rng.randf() * 0.76))
        orad = int(h * (0.010 + rng.randf() * 0.048))
        op = 0.05 + rng.randf() * 0.16
        orbs.append(
            f'<circle cx="{ox}" cy="{oy}" r="{orad}" fill="{glow}" opacity="{op:.3f}" />'
            f'<circle cx="{ox - orad*0.28:.1f}" cy="{oy - orad*0.33:.1f}" r="{orad*0.26:.1f}" fill="#FFFFFF" opacity="{op*0.75:.3f}" />'
        )

    lower1 = layered_ridge_points(rng, w, h, 0.77, 0.033, 30)
    lower2 = layered_ridge_points(rng, w, h, 0.85, 0.028, 34)

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
  <title>{title}</title>
  <defs>
    <linearGradient id="{g_bg}" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="{sky}" />
      <stop offset="38%" stop-color="{base}" />
      <stop offset="100%" stop-color="{deep}" />
    </linearGradient>
    <radialGradient id="{g_sun}" cx="{(sun_x / w) * 100:.2f}%" cy="{(sun_y / h) * 100:.2f}%" r="62%">
      <stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.82" />
      <stop offset="28%" stop-color="{glow}" stop-opacity="0.46" />
      <stop offset="100%" stop-color="{glow}" stop-opacity="0" />
    </radialGradient>
    <linearGradient id="{g_glass}" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.52" />
      <stop offset="45%" stop-color="#FFFFFF" stop-opacity="0.16" />
      <stop offset="100%" stop-color="#FFFFFF" stop-opacity="0.00" />
    </linearGradient>
    <linearGradient id="{g_ribbon}" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.02" />
      <stop offset="48%" stop-color="{aqua}" stop-opacity="0.62" />
      <stop offset="100%" stop-color="#FFFFFF" stop-opacity="0.02" />
    </linearGradient>
    <linearGradient id="{g_haze}" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="{accent}" stop-opacity="0.00" />
      <stop offset="100%" stop-color="{deep}" stop-opacity="0.56" />
    </linearGradient>
    <filter id="{soft}" x="-30%" y="-30%" width="160%" height="160%">
      <feDropShadow dx="0" dy="0" stdDeviation="{max(2, int(h * 0.0020))}" flood-color="{sky}" flood-opacity="0.42" />
    </filter>
    <filter id="{noise}">
      <feTurbulence type="fractalNoise" baseFrequency="{0.38 + rng.randf() * 0.30:.4f}" numOctaves="2" seed="{seed % 4096}" />
      <feColorMatrix type="saturate" values="0" />
      <feComponentTransfer><feFuncA type="table" tableValues="0 0.10" /></feComponentTransfer>
    </filter>
  </defs>
  <rect width="{w}" height="{h}" fill="url(#{g_bg})" />
  <rect width="{w}" height="{h}" fill="url(#{g_sun})" />
  <g>{''.join(rays)}</g>
  <g>{''.join(orbs)}</g>
  <g>{''.join(bokeh)}</g>
  <g>{''.join(panes)}</g>
  <g filter="url(#{soft})">{''.join(ribbons)}</g>
  <path d="M 0 {h * 0.20:.1f} C {w * 0.27:.1f} {h * 0.03:.1f}, {w * 0.62:.1f} {h * 0.34:.1f}, {w:.1f} {h * 0.12:.1f} L {w:.1f} {h * 0.39:.1f} C {w * 0.67:.1f} {h * 0.49:.1f}, {w * 0.31:.1f} {h * 0.11:.1f}, 0 {h * 0.44:.1f} Z" fill="url(#{g_glass})" />
  <polygon points="0,{h} {lower1} {w},{h}" fill="{accent}" opacity="0.34" />
  <polygon points="0,{h} {lower2} {w},{h}" fill="{base}" opacity="0.42" />
  <rect width="{w}" height="{h}" fill="url(#{g_haze})" />
  <rect width="{w}" height="{h}" fill="#FFFFFF" filter="url(#{noise})" opacity="0.16" />
</svg>
"""


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def make_name(idx: int) -> str:
    adj = ADJECTIVES[idx % len(ADJECTIVES)]
    noun = NOUNS[(idx // len(ADJECTIVES)) % len(NOUNS)]
    return f"{adj}_{noun}_{idx + 1:03d}"


def make_system_name(idx: int) -> str:
    base = SYSTEM_NAMES[idx % len(SYSTEM_NAMES)]
    variant = 1 + (idx // len(SYSTEM_NAMES))
    return f"{base}_{variant:02d}"


def unique_content(
    seen_hashes: set[str], base_seed: int, render_fn
) -> tuple[str, str, int]:
    salt = 0
    while salt < 1000:
        seed = base_seed + salt * 1000003
        content = render_fn(seed)
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if digest not in seen_hashes:
            seen_hashes.add(digest)
            return content, digest, seed
        salt += 1
    raise RuntimeError("Unable to generate unique asset content after many attempts")


def build_assets(
    root: Path,
    app_count: int,
    system_count: int,
    wallpaper_count: int,
    icon_size: int,
    wallpaper_w: int,
    wallpaper_h: int,
) -> int:
    gui_root = root / "assets" / "gui"
    icons_apps = gui_root / "icons" / "apps"
    icons_system = gui_root / "icons" / "system"
    wallpapers = gui_root / "wallpapers"
    for folder in (icons_apps, icons_system, wallpapers):
        if folder.exists():
            shutil.rmtree(folder)
        folder.mkdir(parents=True, exist_ok=True)

    manifest_rows = []
    seen_hashes: set[str] = set()

    for i in range(app_count):
        name = make_name(i)
        filename = f"{name}.svg"
        rel = f"icons/apps/{filename}"
        title = f"QuartzOS App Icon {i + 1:03d} - {name}"
        content, digest, used_seed = unique_content(
            seen_hashes,
            i,
            lambda s, t=title: icon_svg(s, t, size=icon_size),
        )
        path = icons_apps / filename
        write_text(path, content)
        manifest_rows.append(
            ("icon-app", name, rel, f"{icon_size}x{icon_size}", digest, path.stat().st_size, used_seed)
        )

    for i in range(system_count):
        name = make_system_name(i)
        filename = f"{name}.svg"
        rel = f"icons/system/{filename}"
        title = f"QuartzOS System Icon {i + 1:03d} - {name}"
        content, digest, used_seed = unique_content(
            seen_hashes,
            1000 + i,
            lambda s, t=title: icon_svg(s, t, size=icon_size),
        )
        path = icons_system / filename
        write_text(path, content)
        manifest_rows.append(
            ("icon-system", name, rel, f"{icon_size}x{icon_size}", digest, path.stat().st_size, used_seed)
        )

    for i in range(wallpaper_count):
        name = f"wallpaper_{i + 1:03d}"
        filename = f"{name}.svg"
        rel = f"wallpapers/{filename}"
        title = f"QuartzOS Wallpaper {i + 1:03d}"
        content, digest, used_seed = unique_content(
            seen_hashes,
            2000 + i,
            lambda s, t=title: wallpaper_svg(s, t, w=wallpaper_w, h=wallpaper_h),
        )
        path = wallpapers / filename
        write_text(path, content)
        manifest_rows.append(
            ("wallpaper", name, rel, f"{wallpaper_w}x{wallpaper_h}", digest, path.stat().st_size, used_seed)
        )

    manifest = gui_root / "manifest.csv"
    with manifest.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "name", "path", "size", "sha256", "bytes", "seed"])
        writer.writerows(manifest_rows)

    readme = gui_root / "README.md"
    total = app_count + system_count + wallpaper_count
    summary = [
        "# QuartzOS GUI Asset Pack",
        "",
        "- Style: Aero-inspired production vector art (bright multicolor gradients, glass bloom, ribbons, pseudo-3D depth)",
        "- Duplicate policy: SHA-256 uniqueness enforced across all generated files",
        f"- App icons: {app_count} ({icon_size}x{icon_size})",
        f"- System icons: {system_count} ({icon_size}x{icon_size})",
        f"- Wallpapers: {wallpaper_count} ({wallpaper_w}x{wallpaper_h})",
        f"- Total files: {total}",
        "",
        "Generated via `tools/generate_gui_assets.py`.",
        "",
        "Regenerate:",
        "```bash",
        "python3 tools/generate_gui_assets.py",
        "```",
        "",
        "Manifest columns: type,name,path,size,sha256,bytes,seed",
    ]
    write_text(readme, "\n".join(summary) + "\n")
    return total


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate QuartzOS GUI assets")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="Repo root")
    parser.add_argument("--app-icons", type=int, default=360, help="Number of app icons")
    parser.add_argument("--system-icons", type=int, default=120, help="Number of system icons")
    parser.add_argument("--wallpapers", type=int, default=60, help="Number of wallpapers")
    parser.add_argument("--icon-size", type=int, default=3072, help="Square icon size")
    parser.add_argument("--wallpaper-width", type=int, default=8192, help="Wallpaper width")
    parser.add_argument("--wallpaper-height", type=int, default=4608, help="Wallpaper height")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    total = build_assets(
        args.root,
        args.app_icons,
        args.system_icons,
        args.wallpapers,
        args.icon_size,
        args.wallpaper_width,
        args.wallpaper_height,
    )
    print(f"Generated {total} GUI assets in {args.root / 'assets' / 'gui'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
