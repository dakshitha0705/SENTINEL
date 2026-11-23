"""Threat hunting over normalised events: prepared hunts, hunt categories and custom regex searches.

Used by the Threat Hunting page. Every hunt is a real query over `analysis.events` (plus the event ids of the
detection rules' own alerts for the category hunts), so the counts shown are counts of logged records.
"""
from __future__ import annotations

import re
import warnings

import pandas as pd

PRIVATE = r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)"

# Prepared hunts: name -> (field or kind, regex / value)
HUNTS = {
    "Encoded or hidden PowerShell": ("command_line", r"powershell.*\s-(e|en|enc|encodedcommand)\s|-w(indowstyle)?\s+hidden"),
    "Credential dumping tools / LSASS access": ("command_line", r"mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs.*minidump"),
    "Privileged group enumeration": ("command_line", r"net1?(\.exe)?\s+(local)?group\b.*admin|get-adgroupmember"),
    "Downloads via LOLBins (certutil, bitsadmin)": ("command_line", r"certutil.*-urlcache|bitsadmin.*/transfer"),
    "Failed logons from external addresses": ("auth_fail_external", ""),
    "Log clearing": ("action", "log_cleared"),
    "Logons outside 07:00-19:00 UTC": ("offhours", ""),
}

# Hunt categories shown as cards: plain-language description, prepared hunts, event actions and rules whose alert
# events are included.
CATEGORIES = {
    "Credential Attacks": {
        "desc": "Brute force, password spraying and successful logons that follow failures.",
        "hunts": ["Failed logons from external addresses"], "actions": ["login_failure"],
        "rules": ["R1", "R2", "R3", "R12", "R13"], "icon": "key"},
    "Suspicious Execution": {
        "desc": "Encoded PowerShell, credential-dumping tools and download utilities.",
        "hunts": ["Encoded or hidden PowerShell", "Credential dumping tools / LSASS access",
                  "Downloads via LOLBins (certutil, bitsadmin)"], "actions": [], "rules": ["R7", "R10"],
        "icon": "terminal"},
    "Privilege Activity": {
        "desc": "Accounts added to privileged groups and enumeration of those groups.",
        "hunts": ["Privileged group enumeration"], "actions": ["group_add", "group_enum"], "rules": ["R6", "R14"],
        "icon": "admin_panel_settings"},
    "Evidence Tampering": {
        "desc": "Audit logs being cleared, especially after other suspicious activity.",
        "hunts": ["Log clearing"], "actions": ["log_cleared"], "rules": ["R8"], "icon": "delete_sweep"},
    "Unusual Access": {
        "desc": "Logons at unusual hours, from new devices or addresses, or across many hosts.",
        "hunts": ["Logons outside 07:00-19:00 UTC"], "actions": [], "rules": ["R4", "R5", "R9", "R11"],
        "icon": "travel_explore"},
}


def prepared(ev: pd.DataFrame, name: str) -> pd.DataFrame:
    kind, rx = HUNTS[name]
    if kind == "auth_fail_external":
        return ev[(ev["action"] == "login_failure") & (ev["src_ip"] != "") & ~ev["src_ip"].str.match(PRIVATE)]
    if kind == "offhours":
        return ev[(ev["action"] == "login_success") & ~ev["timestamp"].dt.hour.between(7, 18)]
    if kind == "action":
        return ev[ev["action"] == rx]
    with warnings.catch_warnings():              # groups in the patterns are only for alternation
        warnings.simplefilter("ignore", UserWarning)
        return ev[ev[kind].astype(str).str.contains(rx, case=False, regex=True, na=False)]


def custom(ev: pd.DataFrame, field: str, pattern: str) -> pd.DataFrame:
    re.compile(pattern)                       # raises re.error for the caller to report
    return ev[ev[field].astype(str).str.contains(pattern, case=False, regex=True, na=False)]


def category(analysis, name: str) -> pd.DataFrame:
    """Union of the category's prepared hunts, event actions and its rules' alert events."""
    c = CATEGORIES[name]
    ev = analysis.events
    ids = set()
    for h in c["hunts"]:
        ids |= set(prepared(ev, h)["event_id"])
    if c["actions"]:
        ids |= set(ev.loc[ev["action"].isin(c["actions"]), "event_id"])
    for al in analysis.alerts:
        if al["rule"] in c["rules"]:
            ids |= set(al["event_ids"])
    return ev[ev["event_id"].isin(ids)].sort_values("timestamp")


def summarise(analysis, hits: pd.DataFrame) -> dict:
    """Counts and pivots for a hunt result."""
    in_inc = {e: i["incident_id"] for i in analysis.incidents for e in i["event_ids"]}
    incs = sorted({in_inc[e] for e in hits["event_id"] if e in in_inc}) if len(hits) else []
    piv = {}
    for col in ("user", "host", "src_ip"):
        vc = hits[col][hits[col] != ""].value_counts() if len(hits) else pd.Series(dtype=int)
        piv[col] = vc
    return {"events": len(hits), "incidents": incs, "in_incidents": sum(1 for e in hits["event_id"] if e in in_inc) if len(hits) else 0,
            "pivots": piv, "incident_of": in_inc}


def category_counts(analysis) -> dict:
    return {n: len(category(analysis, n)) for n in CATEGORIES}
