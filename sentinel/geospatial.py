"""Globe data adapter: geographic markers and connections, ONLY from coordinates present in the logs.

SENTINEL never invents locations and never calls an online geolocation service. A marker exists only
where events carry explicit latitude/longitude columns, mapped by the column mapper to
``src_lat/src_lon`` (where the activity came from, e.g. a SIEM's source geo-enrichment) and/or
``dst_lat/dst_lon`` (where the target device is). Without such columns the globe runs in
*exploration mode* and shows no security data.

Markers group events by rounded coordinate and record whether the location appears as a source, a
device site, or both. A connection is drawn only for an event of a correlated incident that has BOTH a
source and a device location that differ - so every arc is one logged event, not an inference.
"""
from __future__ import annotations

import hashlib

import pandas as pd

LEVEL_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def has_geo(events: pd.DataFrame) -> bool:
    return any(c in events and bool(events[c].notna().any()) for c in ("src_lat", "dst_lat"))


def geo_provenance(analysis) -> str:
    cols = []
    for f in analysis.dataset.files:
        mp = analysis.dataset.mappings.get(f["name"], {})
        parts = [f"'{mp[a]}'/'{mp[b]}'" for a, b in (("src_lat", "src_lon"), ("dst_lat", "dst_lon"))
                 if mp.get(a) and mp.get(b)]
        if parts:
            cols.append(f"{f['name']}: {', '.join(parts)}")
    return ("coordinates from log columns " + "; ".join(cols)) if cols else "no location fields in these logs"


def _mid(lat, lon) -> str:
    return "GEO-" + hashlib.sha1(f"{lat:.2f},{lon:.2f}".encode()).hexdigest()[:8]


def markers(analysis, incidents=None, time_range=None) -> dict:
    """{'mode': 'intel'|'explore', 'markers': [...], 'arcs': [...], 'provenance', 'located_events', ...}"""
    ev = analysis.events
    incidents = analysis.incidents if incidents is None else incidents
    base = {"provenance": geo_provenance(analysis), "total_events": int(len(ev))}
    if not has_geo(ev):
        return {"mode": "explore", "markers": [], "arcs": [], "located_events": 0, **base}
    if time_range:
        lo, hi = time_range
        ev = ev[(ev["timestamp"] >= lo) & (ev["timestamp"] <= hi)]
    ev_inc: dict = {}
    for inc in incidents:
        for e in inc["event_ids"]:
            ev_inc.setdefault(e, []).append(inc)
    rows = []
    for role, la, lo_, lab in (("source", "src_lat", "src_lon", "src_geo"), ("device", "dst_lat", "dst_lon", "dst_geo")):
        if la not in ev:
            continue
        sub = ev[ev[la].notna() & ev[lo_].notna()]
        rows.append(pd.DataFrame({"event_id": sub["event_id"], "lat": sub[la].round(2), "lng": sub[lo_].round(2),
                                  "label": sub[lab], "role": role, "timestamp": sub["timestamp"],
                                  "src_ip": sub["src_ip"]}))
    loc = pd.concat(rows, ignore_index=True) if rows else pd.DataFrame()
    if loc.empty:
        return {"mode": "explore", "markers": [], "arcs": [], "located_events": 0, **base}
    out = []
    for (lat, lng), grp in loc.groupby(["lat", "lng"], sort=False):
        labels = [x for x in grp["label"].unique() if x]
        eids = list(dict.fromkeys(grp["event_id"]))
        incs = {i["incident_id"]: i for e in eids for i in ev_inc.get(e, [])}
        level = min((i["severity"]["level"] for i in incs.values()), key=lambda x: LEVEL_RANK[x], default="none")
        out.append({"id": _mid(lat, lng), "lat": float(lat), "lng": float(lng),
                    "label": ", ".join(labels[:2]) or f"{lat:.2f}, {lng:.2f}", "count": len(eids),
                    "roles": sorted(set(grp["role"])), "incidents": sorted(incs), "level": level,
                    "ips": sorted({x for x in grp.loc[grp["role"] == "source", "src_ip"] if x})[:20],
                    "first": grp["timestamp"].min().strftime("%Y-%m-%d %H:%M"),
                    "last": grp["timestamp"].max().strftime("%Y-%m-%d %H:%M"), "event_ids": eids})
    by_id = {m["id"]: m for m in out}
    arcs, seen = [], {}
    gi = ev.set_index("event_id")
    for inc in incidents:
        for e in inc["event_ids"]:
            if e not in gi.index:
                continue
            r = gi.loc[e]
            if pd.isna(r.get("src_lat")) or pd.isna(r.get("dst_lat")):
                continue
            a, b = _mid(round(r["src_lat"], 2), round(r["src_lon"], 2)), _mid(round(r["dst_lat"], 2), round(r["dst_lon"], 2))
            if a == b or a not in by_id or b not in by_id:
                continue
            k = (inc["incident_id"], a, b)
            if k in seen:
                seen[k]["n"] += 1
                seen[k]["last"] = r["timestamp"]
                continue
            seen[k] = {"n": 1, "first": r["timestamp"], "last": r["timestamp"], "inc": inc, "a": by_id[a], "b": by_id[b]}
    for (iid, _, _), v in seen.items():
        m1, m2 = v["a"], v["b"]
        arcs.append({"startLat": m1["lat"], "startLng": m1["lng"], "endLat": m2["lat"], "endLng": m2["lng"],
                     "incident": iid, "level": v["inc"]["severity"]["level"], "events": v["n"],
                     "label": f"{iid} ({v['inc']['severity']['level']}): {v['n']} event(s) from {m1['label']} to a device at "
                              f"{m2['label']}, {v['first']:%m-%d %H:%M}-{v['last']:%H:%M} UTC"})
    out.sort(key=lambda m: (LEVEL_RANK.get(m["level"], 9), -m["count"]))
    located = int(loc["event_id"].nunique())
    return {"mode": "intel", "markers": out, "arcs": arcs, "located_events": located, **base}


def for_component(geo: dict) -> dict:
    """Strip per-marker event lists before sending to the browser (kept server-side for lookups)."""
    return {**geo, "markers": [{k: v for k, v in m.items() if k != "event_ids"} for m in geo["markers"]]}


def marker_records(analysis, geo: dict, marker_ids) -> pd.DataFrame:
    ids = [marker_ids] if isinstance(marker_ids, str) else list(marker_ids)
    eids = list(dict.fromkeys(e for m in geo["markers"] if m["id"] in ids for e in m["event_ids"]))
    if not eids:
        return pd.DataFrame()
    cols = ["event_id", "timestamp", "action", "user", "host", "src_ip", "src_geo", "dst_geo", "event_code",
            "source_file", "source_row"]
    return analysis.events.set_index("event_id", drop=False).loc[eids, cols].reset_index(drop=True)
