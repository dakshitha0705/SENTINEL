"""Naive baseline detector used only for comparison (docs/evaluation.md, "Naive-detector comparison").

What it deliberately lacks, compared with SENTINEL:
* no behavioural baselines (a fixed 08:00-18:00 UTC business-hours rule instead of per-user history);
* no allowlists, change windows or context suppression;
* no storyline correlation: every alert is a separate item for the analyst to review.

It reuses SENTINEL's fixed thresholds where they exist (R1/R2/R3 numbers, the same process regexes) so
that the comparison isolates the design elements above instead of better or worse thresholds.
"""
from __future__ import annotations

import re
from datetime import timedelta

import pandas as pd

from .rules import _clusters, _max_in_window


def _item(rule, sub: pd.DataFrame, reason: str) -> dict:
    return {"rule": rule, "event_ids": list(sub["event_id"]), "start": sub["timestamp"].min(),
            "end": sub["timestamp"].max(), "reason": reason}


def run_naive(ev: pd.DataFrame, cfg: dict) -> list[dict]:
    d = cfg["detection"]
    out = []
    fails = ev[(ev["action"] == "login_failure") & (ev["user"] != "")]
    # N1 brute force: same thresholds as R1, per user (any source)
    win = timedelta(minutes=d["brute_force"]["window_minutes"])
    for user, g in fails.groupby("user"):
        g = g.sort_values("timestamp")
        times = list(g["timestamp"])
        for idx in _clusters(times, win):
            if _max_in_window([times[i] for i in idx], win) >= d["brute_force"]["min_failures"]:
                out.append(_item("N1", g.iloc[idx], f"{len(idx)} failures for {user}"))
    # N2 spraying: same thresholds as R2
    win = timedelta(minutes=d["password_spray"]["window_minutes"])
    for ip, g in fails[fails["src_ip"] != ""].groupby("src_ip"):
        g = g.sort_values("timestamp")
        times, users = list(g["timestamp"]), list(g["user"])
        for idx in _clusters(times, win):
            k = _max_in_window([times[i] for i in idx], win, keys=[users[i] for i in idx])
            if k >= d["password_spray"]["min_distinct_users"]:
                out.append(_item("N2", g.iloc[idx], f"{ip} failed against {k} accounts"))
    # N3 any success within 15 min after any failure for the same user
    k = timedelta(minutes=15)
    succ = ev[ev["action"] == "login_success"]
    last_fail = fails.groupby("user")["timestamp"].apply(list).to_dict()
    for i, r in succ.iterrows():
        ft = last_fail.get(r["user"], [])
        if any(r["timestamp"] - k <= t < r["timestamp"] for t in ft):
            out.append(_item("N3", succ.loc[[i]], f"{r['user']} success after failure"))
    # N4 logon outside fixed business hours (no per-user baseline, no service-account exception)
    for i, r in succ.iterrows():
        if not (8 <= r["timestamp"].hour < 18):
            out.append(_item("N4", succ.loc[[i]], f"{r['user']} logon at {r['timestamp']:%H:%M}"))
    # N5 every privileged group addition (no allowlist / change window)
    priv = {g.lower() for g in d["privileged_groups"]}
    ga = ev[(ev["action"] == "group_add") & (ev["group"].str.lower().isin(priv))]
    for i in ga.index:
        out.append(_item("N5", ev.loc[[i]], "privileged group change"))
    # N6 the same suspicious-process regexes as R7
    pats = [re.compile(p["pattern"], re.I) for p in d["suspicious_processes"] if p.get("field") != "parent_child"]
    procs = ev[ev["action"] == "process_start"]
    for i, r in procs.iterrows():
        text = f"{r['process']} {r['command_line']}"
        if any(p.search(text) for p in pats):
            out.append(_item("N6", ev.loc[[i]], "suspicious process"))
    # N7 every audit-log clear
    for i in ev.index[ev["action"] == "log_cleared"]:
        out.append(_item("N7", ev.loc[[i]], "audit log cleared"))
    out.sort(key=lambda x: x["start"])
    for n, x in enumerate(out, 1):
        x["incident_id"] = f"NAIVE-{n:04d}"
    return out
