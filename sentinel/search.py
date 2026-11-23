"""Global search over the current analysis (incidents, alerts and normalised events)."""
from __future__ import annotations

import re

import pandas as pd

EVENT_COLS = ["user", "actor", "target_user", "host", "src_ip", "process", "command_line", "group", "event_code",
              "event_id", "src_geo"]


def search(analysis, query: str, limit: int = 200) -> dict:
    q = (query or "").strip()
    if not q or analysis is None:
        return {"query": q, "incidents": [], "alerts": [], "events": pd.DataFrame(), "total_events": 0}
    rx = re.compile(re.escape(q), re.I)
    incs = []
    for i in analysis.incidents:
        hay = " ".join([i["incident_id"], i["title"], *i["users"], *i["hosts"], *i["ips"], *i["mitre"], *i["rules"]])
        if rx.search(hay):
            incs.append(i)
    alerts = [a for a in analysis.alerts if a["rule"] != "CTX" and rx.search(f"{a['alert_id']} {a['rule']} {a['name']} {a['reason']}")]
    ev = analysis.events
    mask = pd.Series(False, index=ev.index)
    for c in EVENT_COLS:
        if c in ev:
            mask |= ev[c].astype(str).str.contains(q, case=False, regex=False, na=False)
    hits = ev[mask]
    return {"query": q, "incidents": incs, "alerts": alerts[:limit], "events": hits.head(limit),
            "total_events": int(mask.sum())}
