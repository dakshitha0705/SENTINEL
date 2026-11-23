"""Attack Storyline Engine: groups alerts into incidents with explained links.

Linking policy
--------------
* Alerts are processed in time order. An alert may join an open incident if it starts no more than
  ``max_gap_minutes`` after the incident's last activity and the incident would not exceed
  ``max_span_hours``.
* Keys compared against every alert already in the incident: user identity (user/actor/member),
  host, source IP.
* STRONG link: >= 2 keys match.  WEAK link: exactly 1 key matches and that key is the user identity.
  A shared host or IP alone (e.g. a busy domain controller or NAT address) never links alerts.
* Weak links are displayed but weak-only alerts never add to severity (see severity.py).
* Context alerts (R4, R5, 4672) never start an incident on their own. The single exception is an
  "anomalous logon": R4 (unusual time) and R5 (new device/IP) firing on the same logon with a
  confident baseline - two independent anomalies on one event.
"""
from __future__ import annotations

from datetime import timedelta

import pandas as pd

from .rules import CONTEXT_RULES

STAGE_LABEL = {"R1": "Brute force", "R2": "Password spraying", "R3": "Logon after failures",
               "R6": "Privilege change", "R7": "Suspicious execution", "R8": "Log clearing",
               "R9": "Lateral movement", "R10": "Data staging", "R12": "Sustained brute force",
               "R13": "Small password spray", "R14": "Group discovery",
               "ANOM": "Off-hours logon from new device/IP"}


def _keys(a):
    return {"user": set(a["users"]), "host": set(a["hosts"]), "ip": set(a["ips"])}


def _match(a, b):
    ka, kb = _keys(a), _keys(b)
    return [k for k in ("user", "host", "ip") if ka[k] & kb[k]]


def _describe(a, b, matched):
    ka, kb = _keys(a), _keys(b)
    parts = []
    for k in matched:
        vals = sorted(ka[k] & kb[k])
        label = {"user": "same account", "host": "same host", "ip": "same source IP"}[k]
        parts.append(f"{label} ({', '.join(vals[:3])})")
    delta = (a["start"] - b["end"]).total_seconds() / 60
    when = f"{delta:.1f} min after" if delta >= 0 else f"{-delta:.1f} min before the end of"
    return f"{' + '.join(parts)}; {when} {b['alert_id']} ({b['rule']})"


def _best_link(alert, inc, alerts_by_id):
    best = None
    for aid in inc["alert_ids"]:
        other = alerts_by_id[aid]
        m = _match(alert, other)
        if not m:
            continue
        strength = "strong" if len(m) >= 2 else ("weak" if m == ["user"] else None)
        if strength is None:
            continue
        rank = (len(m), other["end"])
        if best is None or rank > best[0]:
            best = (rank, other, m, strength)
    if best is None:
        return None
    _, other, m, strength = best
    return {"from": other["alert_id"], "to": alert["alert_id"], "strength": strength, "keys": m,
            "reason": _describe(alert, other, m)}


def _anchor(a, gap):
    """Start time used for the span limit. A long-running alert (e.g. a brute force spread over hours)
    counts from shortly before its last event, so it can still be followed by the next attack stage."""
    return max(a["start"], a["end"] - gap)


def _fits(alert, inc, cfg, slack_before=False):
    gap = timedelta(minutes=cfg["correlation"]["max_gap_minutes"])
    span = timedelta(hours=cfg["correlation"]["max_span_hours"])
    start, end = inc["start"], inc["end"]
    if alert["start"] > end + gap:
        return False
    if slack_before and alert["end"] < start - gap:
        return False
    return max(end, alert["end"]) - min(inc.get("anchor", start), _anchor(alert, gap)) <= span


def _new_incident(alert, kind="primary", gap=timedelta(minutes=30)):
    return {"alert_ids": [alert["alert_id"]], "start": alert["start"], "end": alert["end"],
            "anchor": _anchor(alert, gap), "links": [], "membership": {alert["alert_id"]: "seed"},
            "seed_kind": kind}


def _add(inc, alert, link, gap=timedelta(minutes=30)):
    inc["alert_ids"].append(alert["alert_id"])
    inc["anchor"] = min(inc.get("anchor", inc["start"]), _anchor(alert, gap))
    inc["start"] = min(inc["start"], alert["start"])
    inc["end"] = max(inc["end"], alert["end"])
    inc["links"].append(link)
    inc["membership"][alert["alert_id"]] = link["strength"]


def _attach(alert, incidents, alerts_by_id, cfg, slack_before):
    best = None
    for inc in incidents:
        if not _fits(alert, inc, cfg, slack_before=slack_before):
            continue
        link = _best_link(alert, inc, alerts_by_id)
        if link is None:
            continue
        rank = (len(link["keys"]), inc["end"])
        if best is None or rank > best[0]:
            best = (rank, inc, link)
    if best:
        _add(best[1], alert, best[2])
        return True
    return False


def correlate(alerts: list[dict], events: pd.DataFrame, cfg: dict) -> list[dict]:
    by_id = {a["alert_id"]: a for a in alerts}
    gap = timedelta(minutes=cfg["correlation"]["max_gap_minutes"])
    primary = [a for a in alerts if not a["context"]]
    context = [a for a in alerts if a["context"]]
    incidents: list[dict] = []
    home: dict = {}

    # Pass 1: primary alerts form incidents. A logon-after-failures alert (R3) always joins the incident
    # of the burst it was derived from (causal link), even when the success came later than max_gap.
    for a in sorted(primary, key=lambda x: x["start"]):
        prior = a["details"].get("prior_alert_id")
        if prior and prior in home:
            p = by_id[prior]
            link = {"from": prior, "to": a["alert_id"], "strength": "strong", "keys": _match(a, p) or ["user"],
                    "reason": f"successful logon by the targeted account from the same source "
                              f"{a['details'].get('minutes_after')} min after the {p['rule']} failures "
                              f"({prior}); derived link"}
            _add(home[prior], a, link, gap)
            home[a["alert_id"]] = home[prior]
            continue
        if not _attach(a, incidents, by_id, cfg, slack_before=False):
            incidents.append(_new_incident(a, gap=gap))
        home[a["alert_id"]] = next(i for i in incidents if a["alert_id"] in i["alert_ids"])

    # Pass 2: context alerts attach to existing incidents (may precede them by up to max_gap).
    leftover = []
    for a in sorted(context, key=lambda x: x["start"]):
        if not _attach(a, incidents, by_id, cfg, slack_before=True):
            leftover.append(a)

    # Pass 3: anomalous logon = R4 + R5 (confident baseline) on the same event seeds an incident.
    by_event: dict = {}
    for a in leftover:
        if a["rule"] in ("R4", "R5"):
            by_event.setdefault(a["event_ids"][0], []).append(a)
    seeds = set()
    for eid, group in by_event.items():
        rules = {g["rule"] for g in group}
        if {"R4", "R5"} <= rules and all(g["confidence"] == "high" for g in group):
            seeds.update(g["alert_id"] for g in group)
    anom_incidents: list[dict] = []
    for a in sorted(leftover, key=lambda x: x["start"]):
        if a["alert_id"] in seeds:
            if not _attach(a, anom_incidents, by_id, cfg, slack_before=True):
                anom_incidents.append(_new_incident(a, kind="anomalous_logon", gap=gap))
        elif anom_incidents:
            _attach(a, anom_incidents, by_id, cfg, slack_before=True)
    # second sweep: context that occurred *before* a later anomalous seed
    attached = {aid for inc in anom_incidents for aid in inc["alert_ids"]}
    for a in leftover:
        if a["alert_id"] not in attached and a["alert_id"] not in seeds and anom_incidents:
            _attach(a, anom_incidents, by_id, cfg, slack_before=True)
    incidents += anom_incidents

    # Build incident records.
    ev_time = events.set_index("event_id")["timestamp"]
    out = []
    for inc in incidents:
        members = sorted((by_id[i] for i in inc["alert_ids"]), key=lambda x: (x["start"], x["alert_id"]))
        eids = sorted({e for m in members for e in m["event_ids"]}, key=lambda e: (ev_time[e], e))
        scored = [m for m in members if inc["membership"][m["alert_id"]] in ("seed", "strong")]
        stages = []
        for m in scored:
            lab = STAGE_LABEL.get(m["rule"])
            if inc["seed_kind"] == "anomalous_logon" and m["rule"] in ("R4", "R5"):
                lab = STAGE_LABEL["ANOM"]
            if lab and lab not in stages:
                stages.append(lab)
        users = sorted({u for m in members for u in m["users"]})
        hosts = sorted({h for m in members for h in m["hosts"]})
        ips = sorted({i for m in members for i in m["ips"]})
        prim_users = [u for m in scored if not m["context"] for u in m["users"]] or users
        prim_hosts = [h for m in scored if not m["context"] for h in m["hosts"]] or hosts
        focus_u = max(set(prim_users), key=prim_users.count) if prim_users else "unknown"
        focus_h = max(set(prim_hosts), key=prim_hosts.count) if prim_hosts else "unknown"
        if len(set(prim_users)) > 3:
            focus_u = f"{len(set(prim_users))} accounts"
        title = " -> ".join(stages) + f" ({focus_u} on {focus_h})"
        mitre = []
        for m in members:
            for t in m["mitre"]:
                if t not in mitre:
                    mitre.append(t)
        out.append({
            "alert_ids": [m["alert_id"] for m in members],
            "membership": inc["membership"], "links": inc["links"], "seed_kind": inc["seed_kind"],
            "start": min(m["start"] for m in members), "end": max(m["end"] for m in members),
            "event_ids": eids, "users": users, "hosts": hosts, "ips": ips,
            "rules": sorted({m["rule"] for m in members}), "mitre": mitre, "stages": stages, "title": title,
        })
    out.sort(key=lambda i: i["start"])
    for n, inc in enumerate(out, start=1):
        inc["incident_id"] = f"INC-{n:04d}"
    return out


def storyline(incident: dict, alerts_by_id: dict) -> list[dict]:
    """Ordered storyline steps with the link that brought each alert into the incident."""
    link_to = {l["to"]: l for l in incident["links"]}
    steps = []
    for aid in incident["alert_ids"]:
        a = alerts_by_id[aid]
        steps.append({"alert_id": aid, "time": a["start"], "end": a["end"], "rule": a["rule"], "name": a["name"],
                      "reason": a["reason"], "event_ids": a["event_ids"], "context": a["context"],
                      "membership": incident["membership"][aid], "link": link_to.get(aid)})
    return steps
