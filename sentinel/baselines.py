"""Per-user behavioural baselines.

For every successful logon, the baseline is built *only from that user's earlier successful logons*
(strictly before the event). An attack can therefore never become part of its own baseline, and
data from other datasets (e.g. test seeds) is never used.
"""
from __future__ import annotations

import pandas as pd


def _hour_dist(a: int, b: int) -> int:
    d = abs(a - b) % 24
    return min(d, 24 - d)


def compute_login_baselines(events: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Return one row per login_success event with the user's prior-history snapshot."""
    bcfg = cfg["detection"]["baseline"]
    tol = int(bcfg.get("hour_tolerance", 1))
    # Learning lag: a logon only enters the baseline once it is older than the maximum incident span,
    # so activity inside one incident can never make itself look normal.
    lag = pd.Timedelta(hours=cfg["correlation"]["max_span_hours"])
    logins = events[(events["action"] == "login_success") & (events["user"] != "")]
    rows = []
    for user, grp in logins.groupby("user", sort=False):
        hours: list[int] = []
        days: set = set()
        hosts: dict = {}
        ips: dict = {}
        pending: list = []
        for ev in grp.sort_values("timestamp").itertuples():
            while pending and pending[0].timestamp <= ev.timestamp - lag:
                old = pending.pop(0)
                hours.append(old.timestamp.hour)
                days.add(old.timestamp.date())
                if old.host:
                    hosts[old.host] = hosts.get(old.host, 0) + 1
                if old.src_ip:
                    ips[old.src_ip] = ips.get(old.src_ip, 0) + 1
            n_prior = len(hours)
            h = ev.timestamp.hour
            confident = n_prior >= bcfg["min_logins"] and len(days) >= bcfg["min_days"]
            usual = any(_hour_dist(h, p) <= tol for p in set(hours)) if hours else None
            rows.append({
                "event_id": ev.event_id, "user": user, "n_prior": n_prior, "days_prior": len(days),
                "confident": confident, "hour": h, "hour_usual": usual,
                "host_known": ev.host in hosts if ev.host else None,
                "ip_known": ev.src_ip in ips if ev.src_ip else None,
                "usual_hours": sorted(set(hours)),
                "known_hosts": sorted(hosts, key=hosts.get, reverse=True)[:5],
                "known_ips": sorted(ips, key=ips.get, reverse=True)[:5],
            })
            pending.append(ev)
    cols = ["event_id", "user", "n_prior", "days_prior", "confident", "hour", "hour_usual", "host_known",
            "ip_known", "usual_hours", "known_hosts", "known_ips"]
    return pd.DataFrame(rows, columns=cols).set_index("event_id") if rows else pd.DataFrame(columns=cols).set_index("event_id")


def user_profiles(events: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Whole-dataset summary per user (for display only; detection uses compute_login_baselines)."""
    bcfg = cfg["detection"]["baseline"]
    logins = events[(events["action"] == "login_success") & (events["user"] != "")]
    out = []
    for user, g in logins.groupby("user"):
        hrs = g["timestamp"].dt.hour
        out.append({
            "user": user, "logins": len(g), "days": g["timestamp"].dt.date.nunique(),
            "typical_hours": f"{int(hrs.quantile(0.1)):02d}-{int(hrs.quantile(0.9)):02d}h",
            "hosts": g["host"].nunique(), "source_ips": g["src_ip"].replace("", pd.NA).nunique(),
            "baseline": "confident" if len(g) >= bcfg["min_logins"] and g["timestamp"].dt.date.nunique() >= bcfg["min_days"] else "low confidence",
        })
    return pd.DataFrame(out)
