"""Streamlit presentation helpers (styling and small HTML components). No logic lives here."""
from __future__ import annotations

import html

import pandas as pd

SEV_COLOR = {"Critical": "#C2413A", "High": "#C8773A", "Medium": "#B39B3A", "Low": "#5E8AA8"}
RULE_SHORT = {"R1": "Brute force", "R2": "Spraying", "R3": "Logon after failures", "R4": "Unusual time",
              "R5": "New device/IP", "R6": "Privilege change", "R7": "Suspicious process", "R8": "Log cleared",
              "R9": "Lateral movement", "R10": "Bulk copy", "R11": "USB device", "CTX": "4672 context"}

CSS = """
<style>
html, body, [class*="css"] { font-family: "Segoe UI", system-ui, -apple-system, sans-serif; }
.block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1400px; }
h1, h2, h3 { letter-spacing: .2px; font-weight: 600; }
h1 { font-size: 1.55rem !important; } h2 { font-size: 1.2rem !important; } h3 { font-size: 1.02rem !important; }
[data-testid="stSidebar"] { background: #121A22; border-right: 1px solid #223040; }
.sn-brand { font-weight: 700; font-size: 1.15rem; letter-spacing: 3px; color: #E3E9EF; }
.sn-sub { color: #7F8EA0; font-size: .78rem; margin-top: -2px; }
.sn-kpi { background: #17202A; border: 1px solid #243242; border-radius: 6px; padding: 10px 14px; }
.sn-kpi .v { font-size: 1.45rem; font-weight: 600; color: #E3E9EF; font-variant-numeric: tabular-nums; }
.sn-kpi .l { font-size: .74rem; color: #8695A7; text-transform: uppercase; letter-spacing: .6px; }
.sn-pill { display: inline-block; padding: 1px 9px; border-radius: 3px; font-size: .74rem; font-weight: 600;
           color: #fff; letter-spacing: .3px; }
.sn-tag { display: inline-block; padding: 1px 7px; margin: 1px 3px 1px 0; border-radius: 3px; font-size: .72rem;
          background: #1E2A37; border: 1px solid #2B3B4D; color: #A9B7C6; font-family: Consolas, monospace; }
.sn-step { border-left: 3px solid #5B8DB8; background: #141C25; padding: 8px 12px; margin: 0 0 8px 6px;
           border-radius: 0 5px 5px 0; }
.sn-step.weak { border-left: 3px dashed #6B7785; opacity: .85; }
.sn-step.ctx { border-left-color: #4E6578; }
.sn-step .t { font-family: Consolas, monospace; font-size: .78rem; color: #8FA0B3; }
.sn-step .r { font-weight: 600; color: #DDE5EC; }
.sn-step .why { font-size: .86rem; color: #C3CDD8; margin-top: 2px; }
.sn-step .link { font-size: .78rem; color: #8FA0B3; margin-top: 4px; }
.sn-claim { padding: 6px 10px; border-bottom: 1px solid #1F2B38; font-size: .9rem; }
.sn-ok { color: #5FAF7F; font-weight: 600; font-size: .76rem; }
.sn-bad { color: #D9665E; font-weight: 600; font-size: .76rem; }
.sn-hyp { color: #C9A44E; font-weight: 600; font-size: .76rem; }
.sn-cite { font-family: Consolas, monospace; font-size: .74rem; color: #7F8EA0; }
.sn-muted { color: #7F8EA0; font-size: .82rem; }
.sn-box { background: #141C25; border: 1px solid #223040; border-radius: 6px; padding: 10px 14px; margin-bottom: 10px; }
.sn-box h4 { margin: 0 0 6px 0; font-size: .86rem; color: #9FB1C4; text-transform: uppercase; letter-spacing: .7px; }
div[data-testid="stMetricValue"] { font-variant-numeric: tabular-nums; }
</style>
"""


def esc(x) -> str:
    return html.escape(str(x))


def pill(level: str, text: str | None = None) -> str:
    return f'<span class="sn-pill" style="background:{SEV_COLOR.get(level, "#555")}">{esc(text or level)}</span>'


def tag(text) -> str:
    return f'<span class="sn-tag">{esc(text)}</span>'


def kpi(label, value) -> str:
    return f'<div class="sn-kpi"><div class="v">{esc(value)}</div><div class="l">{esc(label)}</div></div>'


def ts(x) -> str:
    return pd.Timestamp(x).strftime("%Y-%m-%d %H:%M:%S")


def duration(a, b) -> str:
    s = int((pd.Timestamp(b) - pd.Timestamp(a)).total_seconds())
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {(s % 3600) // 60:02d}m"
