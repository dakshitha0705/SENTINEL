"""Streamlit presentation layer: palette, small HTML helpers. Logic lives in sentinel/*.py modules."""
from __future__ import annotations

import html

import pandas as pd

# Muted pastel-dark palette (see theme.py for the full token set)
TOKENS = {
    "bg": "#070F0C", "obsidian": "#0D1513", "graphite": "#141D1A", "sage": "#86A091", "mint": "#B5D3C0",
    "ivory": "#EFE6D2", "copper": "#B87A55", "amber": "#D9A35B", "red": "#C0574B", "muted": "#93A39B",
}
SEV_COLOR = {"Critical": "#D06B5E", "High": "#D9A35B", "Medium": "#9FC2AE", "Low": "#8A9A94"}
RULE_SHORT = {"R1": "Brute force", "R2": "Spraying", "R3": "Logon after failures", "R4": "Unusual time",
              "R5": "New device/IP", "R6": "Privilege change", "R7": "Suspicious process", "R8": "Log cleared",
              "R9": "Lateral movement", "R10": "Bulk copy", "R11": "USB device", "R12": "Sustained brute force",
              "R13": "Small spray", "R14": "Group discovery", "CTX": "4672 context"}


def esc(x) -> str:
    return html.escape(str(x))


def pill(level: str, text: str | None = None) -> str:
    return (f'<span class="sn-pill" style="--c:{SEV_COLOR.get(level, "#8A938F")}">'
            f'<i></i>{esc(text or level)}</span>')


def tag(text, kind: str = "") -> str:
    return f'<span class="sn-tag {kind}">{esc(text)}</span>'


def kpi(label, value, sub: str = "", small: bool = False) -> str:
    return (f'<div class="sn-kpi{" sm" if small else ""}"><div class="l">{esc(label)}</div><div class="v">{esc(value)}</div>'
            + (f'<div class="s">{esc(sub)}</div>' if sub else "") + "</div>")


def ts(x) -> str:
    return pd.Timestamp(x).strftime("%Y-%m-%d %H:%M:%S")


def duration(a, b) -> str:
    s = int((pd.Timestamp(b) - pd.Timestamp(a)).total_seconds())
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {(s % 3600) // 60:02d}m"


def section(title: str, sub: str = "") -> str:
    return (f'<div class="sn-section"><div class="t">{esc(title)}</div>'
            + (f'<div class="d">{esc(sub)}</div>' if sub else "") + "</div>")
