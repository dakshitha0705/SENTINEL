"""Deterministic detection rules R1-R8 (plus supporting 4672 context).

Every alert records: rule ID and name, the exact triggering event IDs, time range, users, hosts,
source IPs, a human-readable reason, confidence, MITRE techniques and its severity weight class.
Context-only alerts (R4, R5, 4672) never create an incident on their own.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import timedelta

import pandas as pd

from .baselines import compute_login_baselines

RULES = {
    "R1": ("Brute force", ["T1110.001"], "medium"),
    "R2": ("Password spraying", ["T1110.003"], "high"),
    "R3": ("Successful logon after failures", ["T1078"], "high"),
    "R4": ("Unusual login time for this user", ["T1078"], "low"),
    "R5": ("New device or source IP for this user", ["T1078"], "low"),
    "R6": ("Unauthorised privileged group change", ["T1098"], "high"),
    "R7": ("Suspicious process execution", ["T1059.001"], "high"),
    "R8": ("Audit log cleared", ["T1070.001"], "high"),
    # R9 is context-only: in stress seed 1001 it fired on an administrator visiting 3 new servers.
    "R9": ("Lateral movement to several new hosts", ["T1021"], "low"),
    "R10": ("Bulk copy / archive staging to removable or remote location", ["T1039", "T1074"], "medium"),
    "R11": ("USB storage device connected", ["T1052.001"], "low"),
    # R12-R14 were added in the upgrade after the stress-seed failure analysis (docs/evaluation.md).
    "R12": ("Sustained brute force (longer window)", ["T1110.001"], "medium"),
    "R13": ("Small password spray", ["T1110.003"], "medium"),
    # R14 is context-only: administrators legitimately enumerate groups.
    "R14": ("Privileged group discovery", ["T1069"], "low"),
    "CTX": ("Special privileges assigned at logon (4672)", [], "none"),
}
CONTEXT_RULES = {"R4", "R5", "R9", "R11", "R14", "CTX"}
PRIMARY_RULES = {"R1", "R2", "R3", "R6", "R7", "R8", "R10", "R12", "R13"}
BURST_RULES = {"R1", "R2", "R12", "R13"}


def _fmt(ts) -> str:
    return pd.Timestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _alert(rule, events: pd.DataFrame, reason, confidence="high", details=None, mitre=None,
           users=None, hosts=None, ips=None, context=None):
    name, default_mitre, weight = RULES[rule]
    return {
        "rule": rule, "name": name, "mitre": mitre or default_mitre, "weight": weight,
        "context": rule in CONTEXT_RULES if context is None else context,
        "start": events["timestamp"].min(), "end": events["timestamp"].max(),
        "event_ids": list(events["event_id"]),
        "users": sorted(set(users if users is not None else [u for u in events["user"] if u])),
        "hosts": sorted(set(hosts if hosts is not None else [h for h in events["host"] if h])),
        "ips": sorted(set(ips if ips is not None else [i for i in events["src_ip"] if i])),
        "reason": reason, "confidence": confidence, "details": details or {},
    }


def in_change_window(ts, cfg) -> bool:
    """Recurring windows {weekday, start "HH:MM", end "HH:MM"} or approved change tickets with absolute
    {start, end} ISO timestamps (e.g. registered by a change-management feed)."""
    ts = pd.Timestamp(ts)
    minutes = ts.hour * 60 + ts.minute
    for w in cfg["allowlists"]["change_windows"]:
        if "weekday" not in w:
            lo, hi = pd.Timestamp(w["start"]), pd.Timestamp(w["end"])
            t = ts if ts.tzinfo else ts.tz_localize("UTC")
            if lo <= t <= hi:
                return True
            continue
        if ts.weekday() != int(w["weekday"]):
            continue
        sh, sm = map(int, w["start"].split(":"))
        eh, em = map(int, w["end"].split(":"))
        if sh * 60 + sm <= minutes <= eh * 60 + em:
            return True
    return False


def _clusters(times: list, gap: timedelta) -> list[list[int]]:
    """Split a sorted time list into index clusters where consecutive gaps <= gap."""
    out, cur = [], []
    for i, t in enumerate(times):
        if cur and t - times[cur[-1]] > gap:
            out.append(cur)
            cur = []
        cur.append(i)
    if cur:
        out.append(cur)
    return out


def _max_in_window(times: list, window: timedelta, keys=None) -> int:
    """Max number of events (or distinct keys) in any sliding window."""
    best, lo = 0, 0
    counter: Counter = Counter()
    for hi, t in enumerate(times):
        if keys is not None:
            counter[keys[hi]] += 1
        while t - times[lo] > window:
            if keys is not None:
                counter[keys[lo]] -= 1
                if counter[keys[lo]] == 0:
                    del counter[keys[lo]]
            lo += 1
        best = max(best, len(counter) if keys is not None else hi - lo + 1)
    return best


# --------------------------------------------------------------------------- R1 / R2 / R3

def rule_bruteforce(ev, cfg):
    c = cfg["detection"]["brute_force"]
    win = timedelta(minutes=c["window_minutes"])
    fails = ev[(ev["action"] == "login_failure") & (ev["user"] != "")].copy()
    fails["src"] = fails["src_ip"].where(fails["src_ip"] != "", "host:" + fails["host"])
    alerts = []
    for (user, src), g in fails.groupby(["user", "src"], sort=False):
        g = g.sort_values("timestamp")
        times = list(g["timestamp"])
        for idx in _clusters(times, win):
            sub = g.iloc[idx]
            peak = _max_in_window([times[i] for i in idx], win)
            if peak >= c["min_failures"]:
                span = (sub["timestamp"].max() - sub["timestamp"].min()).total_seconds() / 60
                alerts.append(_alert("R1", sub,
                    f"{len(sub)} failed logons for {user} from {src.replace('host:', 'host ')} in {span:.1f} min "
                    f"(peak {peak} within {c['window_minutes']} min; threshold {c['min_failures']})",
                    confidence="high" if peak >= 2 * c["min_failures"] else "medium",
                    details={"failures": len(sub), "peak_in_window": peak, "source": src, "target_user": user,
                             "threshold": c["min_failures"]}))
    return alerts


def rule_spray(ev, cfg):
    c = cfg["detection"]["password_spray"]
    win = timedelta(minutes=c["window_minutes"])
    fails = ev[(ev["action"] == "login_failure") & (ev["user"] != "") & (ev["src_ip"] != "")]
    alerts = []
    for ip, g in fails.groupby("src_ip", sort=False):
        g = g.sort_values("timestamp")
        times, users = list(g["timestamp"]), list(g["user"])
        for idx in _clusters(times, win):
            sub = g.iloc[idx]
            distinct = _max_in_window([times[i] for i in idx], win, keys=[users[i] for i in idx])
            per_user = sub["user"].value_counts()
            if distinct >= c["min_distinct_users"] and per_user.median() <= c["max_attempts_per_user"]:
                alerts.append(_alert("R2", sub,
                    f"{ip} failed against {sub['user'].nunique()} distinct accounts with {len(sub)} attempts "
                    f"(max {per_user.max()} per account) - spraying pattern (threshold {c['min_distinct_users']} accounts)",
                    confidence="high", details={"source_ip": ip, "accounts": int(sub["user"].nunique()),
                                                "attempts": len(sub), "max_per_account": int(per_user.max())}))
    return alerts


def r3_decay(minutes: float, cfg) -> float:
    """Severity contribution of a logon-after-failures link: 1.0 up to full_weight_minutes, then linear
    down to min_factor at max_minutes_after_burst. A delayed success is weaker evidence of compromise."""
    c = cfg["detection"]["failure_then_success"]
    k = float(c["max_minutes_after_burst"])
    full = float(c.get("full_weight_minutes", k))
    lo = float(c.get("min_factor", 1.0))
    if minutes <= full or k <= full:
        return 1.0
    return round(max(lo, 1.0 - (1.0 - lo) * (minutes - full) / (k - full)), 2)


def rule_fail_then_success(ev, cfg, burst_alerts):
    c = cfg["detection"]["failure_then_success"]
    k = timedelta(minutes=c["max_minutes_after_burst"])
    full = c.get("full_weight_minutes", c["max_minutes_after_burst"])
    succ = ev[ev["action"] == "login_success"]
    by_id = ev.set_index("event_id", drop=False)
    alerts, used = [], set()
    for b in burst_alerts:
        bev = by_id.loc[b["event_ids"]]
        for user, ug in bev.groupby("user"):
            last_fail = ug["timestamp"].max()
            src_ips = set(ug["src_ip"]) - {""}
            hosts = set(ug["host"]) - {""}
            cand = succ[(succ["user"] == user) & (succ["timestamp"] > last_fail) & (succ["timestamp"] <= last_fail + k)]
            if src_ips:
                cand = cand[cand["src_ip"].isin(src_ips)]
            else:
                cand = cand[cand["host"].isin(hosts)]
            cand = cand[~cand["event_id"].isin(used)]
            if cand.empty:
                continue
            s = cand.sort_values("timestamp").iloc[[0]]
            used.add(s["event_id"].iloc[0])
            mins = (s["timestamp"].iloc[0] - last_fail).total_seconds() / 60
            src = next(iter(src_ips), None) or next(iter(hosts))
            decay = r3_decay(mins, cfg)
            late = mins > full
            alerts.append(_alert("R3", s,
                f"{user} logged on successfully from {src} {mins:.1f} min after {len(ug)} failed attempts "
                f"from the same source ({b['rule']} burst)"
                + (f"; delayed success, so its severity contribution is reduced to {decay:.2f}x "
                   "(not confirmed compromise)" if late else ""),
                confidence="medium" if late else "high",
                details={"prior_rule": b["rule"], "prior_failures": len(ug), "minutes_after": round(mins, 1),
                         "prior_event_ids": list(ug["event_id"]), "decay": decay, "late": late,
                         "_prior": b}))
    return alerts


def _first_success(ev) -> dict:
    """(user, source) -> time of the first successful logon. Source = src IP, else 'host:<host>'."""
    s = ev[(ev["action"] == "login_success") & (ev["user"] != "")]
    if s.empty:
        return {}
    src = s["src_ip"].where(s["src_ip"] != "", "host:" + s["host"])
    return s.assign(src=src).groupby(["user", "src"])["timestamp"].min().to_dict()


def rule_sustained_bruteforce(ev, cfg, fast_alerts, first_success, use_baseline=True):
    """R12: failures against one account from one source spread over longer windows.

    Fires for any configured (min_failures, window_minutes) pair on failures that R1 did not already
    cover. A source that had already logged on successfully as this account before the failures began
    (e.g. a stale saved password on the user's own workstation) is excluded when baselines are enabled.
    """
    c = cfg["detection"].get("sustained_brute_force", {})
    windows = c.get("windows", [])
    if not windows:
        return []
    covered = {e for a in fast_alerts for e in a["event_ids"]}
    fails = ev[(ev["action"] == "login_failure") & (ev["user"] != "")].copy()
    fails["src"] = fails["src_ip"].where(fails["src_ip"] != "", "host:" + fails["host"])
    alerts = []
    for (user, src), g in fails.groupby(["user", "src"], sort=False):
        g = g[~g["event_id"].isin(covered)].sort_values("timestamp")
        if len(g) < min(w["min_failures"] for w in windows):
            continue
        times = list(g["timestamp"])
        best = None
        for w in windows:
            win = timedelta(minutes=w["window_minutes"])
            for idx in _clusters(times, win):
                peak = _max_in_window([times[i] for i in idx], win)
                if peak >= w["min_failures"] and (best is None or len(idx) > len(best[0])):
                    best = (idx, peak, w)
        if not best:
            continue
        idx, peak, w = best
        sub = g.iloc[idx]
        known = first_success.get((user, src))
        if use_baseline and known is not None and known < sub["timestamp"].min():
            continue
        span = (sub["timestamp"].max() - sub["timestamp"].min()).total_seconds() / 60
        alerts.append(_alert("R12", sub,
            f"{len(sub)} failed logons for {user} from {src.replace('host:', 'host ')} over {span:.1f} min "
            f"(peak {peak} within {w['window_minutes']} min; threshold {w['min_failures']})"
            + ("; this source had never logged on successfully as this account" if use_baseline else ""),
            confidence="medium",
            details={"failures": len(sub), "peak_in_window": peak, "source": src, "target_user": user,
                     "threshold": w["min_failures"], "window_minutes": w["window_minutes"]}))
    return alerts


def rule_small_spray(ev, cfg, spray_alerts, first_success, use_baseline=True):
    """R13: one source failing against a few (>= min_distinct_users) accounts, below the R2 threshold.

    Requires a high failure proportion from that source in the window (a shared PC where people mistype
    and then log on is not a spray) and, with baselines enabled, that most targeted accounts never logged
    on successfully from that source before.
    """
    c = cfg["detection"].get("small_spray")
    if not c:
        return []
    win = timedelta(minutes=c["window_minutes"])
    covered = {e for a in spray_alerts for e in a["event_ids"]}
    auth = ev[(ev["action"].isin(["login_failure", "login_success"])) & (ev["user"] != "") & (ev["src_ip"] != "")]
    alerts = []
    for ip, g in auth.groupby("src_ip", sort=False):
        f = g[(g["action"] == "login_failure") & ~g["event_id"].isin(covered)].sort_values("timestamp")
        if f["user"].nunique() < c["min_distinct_users"]:
            continue
        times, users = list(f["timestamp"]), list(f["user"])
        for idx in _clusters(times, win):
            sub = f.iloc[idx]
            distinct = _max_in_window([times[i] for i in idx], win, keys=[users[i] for i in idx])
            if distinct < c["min_distinct_users"]:
                continue
            t0, t1 = sub["timestamp"].min(), sub["timestamp"].max() + win
            succ = g[(g["action"] == "login_success") & (g["timestamp"] >= t0) & (g["timestamp"] <= t1)]
            ratio = len(sub) / (len(sub) + len(succ))
            if ratio < c["min_failure_ratio"]:
                continue
            targets = sorted(sub["user"].unique())
            if use_baseline:
                known = [u for u in targets if first_success.get((u, ip)) is not None
                         and first_success[(u, ip)] < t0]
                if len(known) > len(targets) * c.get("max_known_fraction", 0.5):
                    continue
            alerts.append(_alert("R13", sub,
                f"{ip} failed against {len(targets)} distinct accounts with {len(sub)} attempts in "
                f"{(sub['timestamp'].max() - t0).total_seconds() / 60:.1f} min; {ratio:.0%} of its logon "
                f"attempts in the window failed (small-spray threshold {c['min_distinct_users']} accounts)",
                confidence="medium", details={"source_ip": ip, "accounts": len(targets), "attempts": len(sub),
                                              "failure_ratio": round(ratio, 2)}))
    return alerts


# --------------------------------------------------------------------------- R4 / R5

def rule_baseline(ev, cfg, base: pd.DataFrame):
    bcfg = cfg["detection"]["baseline"]
    svc = set(cfg["allowlists"]["service_accounts"])
    logins = ev[ev["action"] == "login_success"].set_index("event_id", drop=False)
    alerts = []
    for eid, b in base.iterrows():
        fire_r4 = b["confident"] and b["hour_usual"] is False and b["user"] not in svc
        fire_r5 = b["n_prior"] >= bcfg["min_logins_for_new_context"] and (b["host_known"] is False or b["ip_known"] is False)
        if not (fire_r4 or fire_r5):
            continue
        row = logins.loc[eid]
        one = logins.loc[[eid]]
        conf_label = "high" if b["confident"] else "low"
        if fire_r4:
            hrs = ", ".join(f"{h:02d}" for h in b["usual_hours"])
            alerts.append(_alert("R4", one,
                f"{b['user']} logged on at {row['timestamp']:%H:%M} UTC; no prior logon within "
                f"+-{bcfg['hour_tolerance']}h of this hour in {b['n_prior']} earlier logons (usual hours: {hrs})",
                confidence=conf_label,
                details={"hour": int(b["hour"]), "usual_hours": b["usual_hours"], "prior_logins": int(b["n_prior"]),
                         "baseline": "confident", "in_change_window": in_change_window(row["timestamp"], cfg)}))
        if b["n_prior"] >= bcfg["min_logins_for_new_context"]:
            new = []
            if b["host_known"] is False:
                new.append(f"host {row['host']}")
            if b["ip_known"] is False:
                new.append(f"source IP {row['src_ip']}")
            if new:
                alerts.append(_alert("R5", one,
                    f"First time {b['user']} logged on from/to {' and '.join(new)} in {b['n_prior']} earlier logons"
                    + ("" if b["confident"] else " (LOW-CONFIDENCE baseline: limited history)"),
                    confidence=conf_label,
                    details={"new": new, "prior_logins": int(b["n_prior"]), "known_hosts": b["known_hosts"],
                             "known_ips": b["known_ips"], "baseline": "confident" if b["confident"] else "low confidence",
                             "new_host": b["host_known"] is False, "new_ip": b["ip_known"] is False}))
    return alerts


def rule_ctx_4672(ev, cfg):
    sp = ev[ev["action"] == "privilege_logon"]
    return [_alert("CTX", sp.loc[[i]], f"Special privileges assigned to logon of {r.user} on {r.host} "
                   "(context only; not evidence of escalation)", confidence="high")
            for i, r in sp.iterrows()]


# --------------------------------------------------------------------------- R6 / R7 / R8

def rule_priv_group(ev, cfg):
    priv = {g.lower() for g in cfg["detection"]["privileged_groups"]}
    admins = set(cfg["allowlists"]["authorized_admins"])
    ga = ev[(ev["action"] == "group_add")]
    alerts = []
    for i, r in ga.iterrows():
        if r["group"].strip().lower() not in priv:
            continue
        actor = r["actor"] or r["user"]
        authorised = actor in admins
        window = in_change_window(r["timestamp"], cfg)
        if authorised and window:
            continue
        why = []
        if not authorised:
            why.append(f"actor {actor or 'unknown'} is not an authorised administrator")
        if not window:
            why.append("change made outside any approved change window")
        self_add = actor and actor == r["target_user"]
        alerts.append(_alert("R6", ev.loc[[i]],
            f"{r['target_user'] or 'an account'} added to privileged group '{r['group']}' on {r['host']} by "
            f"{actor or 'unknown'}" + (" (self-added)" if self_add else "") + "; " + "; ".join(why),
            confidence="high" if not authorised else "medium",
            users=[u for u in {actor, r["target_user"]} if u],
            details={"group": r["group"], "actor": actor, "member": r["target_user"], "authorised_actor": authorised,
                     "in_change_window": window, "self_add": bool(self_add), "event_code": r["event_code"]}))
    return alerts


def rule_process(ev, cfg):
    pats = cfg["detection"]["suspicious_processes"]
    compiled = {p["id"]: re.compile(p["pattern"], re.I) for p in pats if p.get("field") != "parent_child"}
    procs = ev[ev["action"] == "process_start"]
    alerts = []
    for i, r in procs.iterrows():
        hits, mitre = [], []
        cmd = r["command_line"] or ""
        for p in pats:
            f = p.get("field")
            if f == "parent_child":
                ok = r["parent_process"] in p["parents"] and r["process"] in p["children"]
            elif f == "any":
                ok = bool(compiled[p["id"]].search(f"{r['process']} {cmd}"))
            else:
                ok = bool(compiled[p["id"]].search(cmd))
            if ok:
                hits.append(p["name"])
                mitre.extend(t for t in p["mitre"] if t not in mitre)
        if hits:
            shown = cmd if len(cmd) <= 160 else cmd[:157] + "..."
            alerts.append(_alert("R7", ev.loc[[i]],
                f"{r['process'] or 'process'} (parent {r['parent_process'] or 'unknown'}) by {r['user']} on "
                f"{r['host']} matched: {', '.join(hits)}. Command: {shown}",
                confidence="high", mitre=mitre,
                details={"patterns": hits, "process": r["process"], "parent": r["parent_process"]}))
    return alerts


def rule_log_cleared(ev, cfg, prior_alerts):
    lc = ev[ev["action"] == "log_cleared"]
    alerts = []
    for i, r in lc.iterrows():
        t = r["timestamp"]
        before = [a for a in prior_alerts if a["rule"] in PRIMARY_RULES and a["rule"] != "R8"
                  and t - timedelta(hours=4) <= a["end"] <= t
                  and (r["host"] in a["hosts"] or r["user"] in a["users"])]
        alerts.append(_alert("R8", ev.loc[[i]],
            f"Audit log cleared on {r['host']} by {r['user'] or 'unknown'}"
            + (f"; preceded by {len(before)} suspicious alert(s) on the same host/user within 4 h "
               f"({', '.join(sorted({a['rule'] for a in before}))})" if before else "; no preceding suspicious activity found"),
            confidence="high", details={"preceded_by_suspicious": bool(before),
                                        "preceding_rules": sorted({a["rule"] for a in before})}))
    return alerts


# --------------------------------------------------------------------------- R9 / R10 / R11 (additional)

def rule_lateral(ev, cfg, base: pd.DataFrame):
    """>= min_hosts distinct hosts NEW for the account (confident-enough history) within the window."""
    c = cfg["detection"].get("lateral_movement", {"min_new_hosts": 3, "window_minutes": 30})
    svc = set(cfg["allowlists"]["service_accounts"])
    win = timedelta(minutes=c["window_minutes"])
    if base.empty:
        return []
    new = base[(base["host_known"] == False) & (base["n_prior"] >= cfg["detection"]["baseline"]["min_logins_for_new_context"])]  # noqa: E712
    logins = ev.set_index("event_id", drop=False)
    alerts = []
    for user, g in new.groupby("user"):
        if user in svc:
            continue
        rows = logins.loc[g.index].sort_values("timestamp")
        times, hosts = list(rows["timestamp"]), list(rows["host"])
        lo, used = 0, set()
        for hi in range(len(rows)):
            while times[hi] - times[lo] > win:
                lo += 1
            window_hosts = set(hosts[lo:hi + 1])
            if len(window_hosts) >= c["min_new_hosts"] and not (set(rows["event_id"].iloc[lo:hi + 1]) & used):
                sub = rows.iloc[lo:hi + 1]
                used |= set(sub["event_id"])
                alerts.append(_alert("R9", sub,
                    f"{user} logged on to {len(window_hosts)} hosts never used before by this account within "
                    f"{(times[hi] - times[lo]).total_seconds() / 60:.1f} min: {', '.join(sorted(window_hosts))}",
                    confidence="medium", details={"new_hosts": sorted(window_hosts), "logons": len(sub)}))
    return alerts


BULK_RE = re.compile(r"(robocopy\b.*\s/(mir|e|s)\b|xcopy\b.*\s/(s|e)\b|\b7z(\.exe)?\s+a\b|\brar(\.exe)?\s+a\b|"
                     r"compress-archive\b|\btar(\.exe)?\s+-?c)", re.I)
DEST_RE = re.compile(r"(?<![a-z])([d-z]):\\|\\\\[\w.-]+\\", re.I)


def rule_bulk_copy(ev, cfg):
    procs = ev[(ev["action"] == "process_start") & (ev["command_line"] != "")]
    alerts = []
    for i, r in procs.iterrows():
        cmd = r["command_line"]
        if BULK_RE.search(cmd) and DEST_RE.search(cmd):
            alerts.append(_alert("R10", ev.loc[[i]],
                f"{r['user']} on {r['host']} ran a recursive copy/archive command writing to a removable drive or "
                f"network location: {cmd[:160]}", confidence="medium", details={"command": cmd[:300]}))
    return alerts


def rule_usb(ev, cfg):
    dev = ev[ev["action"] == "device_connected"]
    alerts = []
    for i, r in dev.iterrows():
        raw = r["raw"].lower()
        if any(k in raw for k in ("usb", "mass storage", "diskdrive", "disk drive", "removable")):
            alerts.append(_alert("R11", ev.loc[[i]], f"External storage device recognised on {r['host']}"
                                 + (f" during {r['user']}'s session" if r["user"] else ""), confidence="high"))
    return alerts


DISCOVERY = [
    (re.compile(r"\bnet1?(\.exe)?\s+localgroup\b.*\badmin", re.I), "local Administrators group enumerated", "T1069.001"),
    (re.compile(r"\bnet1?(\.exe)?\s+group\b.*(admins|operators)", re.I), "domain privileged group enumerated", "T1069.002"),
    (re.compile(r"get-(ad|net|domain)groupmember\b.*(admin|operator)", re.I), "privileged group members listed (PowerShell)", "T1069.002"),
    (re.compile(r"get-localgroupmember\b.*admin", re.I), "local Administrators listed (PowerShell)", "T1069.001"),
    (re.compile(r"\bdsquery(\.exe)?\s+group\b.*admin", re.I), "privileged group queried (dsquery)", "T1069.002"),
]


def rule_discovery(ev, cfg):
    """R14 (context only): enumeration of privileged groups, e.g. net group "Domain Admins" /domain."""
    admins = set(cfg["allowlists"]["authorized_admins"])
    procs = ev[(ev["action"] == "process_start") & (ev["command_line"] != "")]
    alerts = []
    for i, r in procs.iterrows():
        for rx, what, tech in DISCOVERY:
            if rx.search(r["command_line"]):
                admin = r["user"] in admins
                alerts.append(_alert("R14", ev.loc[[i]],
                    f"{r['user'] or 'unknown'} on {r['host']}: {what}. Command: {r['command_line'][:140]}"
                    + (" (authorised administrator; routine for admins)" if admin else ""),
                    confidence="low" if admin else "medium", mitre=[tech],
                    details={"command": r["command_line"][:300], "authorised_admin": admin}))
                break
    # 4799: membership of a security-enabled local group was enumerated. Only privileged groups, and only
    # when the caller is an interactive tool (net/PowerShell/cmd/wmic) - Windows services do this all the time.
    priv = {g.lower() for g in cfg["detection"]["privileged_groups"]}
    tools = {"net.exe", "net1.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe"}
    enum = ev[(ev["action"] == "group_enum") & (ev["group"].str.lower().isin(priv)) & (ev["process"].isin(tools))]
    for i, r in enum.iterrows():
        admin = r["user"] in admins
        alerts.append(_alert("R14", ev.loc[[i]],
            f"{r['user'] or 'unknown'} enumerated members of '{r['group']}' on {r['host']} using {r['process']} (4799)"
            + (" (authorised administrator; routine for admins)" if admin else ""),
            confidence="low" if admin else "medium", mitre=["T1069.001"],
            details={"group": r["group"], "caller": r["process"], "authorised_admin": admin}))
    return alerts


# --------------------------------------------------------------------------- driver

def rule_coverage(ev: pd.DataFrame) -> dict:
    """Which rules could be evaluated on this data (missing fields => 'not evaluated')."""
    has = lambda a: bool((ev["action"] == a).any())
    fails = ev[ev["action"] == "login_failure"]
    status = {
        "R1": (has("login_failure") and (fails["user"] != "").any(), "needs failed logons with user"),
        "R2": (has("login_failure") and (fails["src_ip"] != "").any(), "needs failed logons with source IP"),
        "R3": (has("login_failure") and has("login_success"), "needs failed and successful logons"),
        "R4": (has("login_success"), "needs successful logons with timestamps"),
        "R5": (has("login_success") and ((ev["host"] != "") | (ev["src_ip"] != "")).any(), "needs logons with host/IP"),
        "R6": (has("group_add") and (ev.loc[ev["action"] == "group_add", "group"] != "").any(), "needs group membership events (4728/4732/4756)"),
        "R7": (has("process_start") and ((ev["command_line"] != "") | (ev["process"] != "")).any(), "needs process creation events (4688)"),
        "R8": (has("log_cleared"), "needs audit-log-cleared events (1102)"),
        "R9": (has("login_success") and (ev["host"] != "").any(), "needs successful logons with destination host"),
        "R10": (has("process_start") and (ev["command_line"] != "").any(), "needs process command lines"),
        "R11": (has("device_connected"), "needs device-recognised events (6416, PnP auditing)"),
        "R12": (has("login_failure") and (fails["user"] != "").any(), "needs failed logons with user"),
        "R13": (has("login_failure") and (fails["src_ip"] != "").any(), "needs failed logons with source IP"),
        "R14": ((has("process_start") and (ev["command_line"] != "").any()) or has("group_enum"),
                "needs process command lines or 4799 group-enumeration events"),
    }
    return {k: {"evaluated": bool(v[0]), "requirement": v[1]} for k, v in status.items()}


FEATURE_DEFAULTS = {"baselines": True, "context": True, "allowlists": True}


def run_rules(ev: pd.DataFrame, cfg: dict):
    """Run all rules. Returns (alerts sorted by time with IDs, rule coverage, login baselines).

    ``cfg["features"]`` switches design elements off for the ablation study (all default True):
    ``baselines``  - R4/R5/R9 are not run and R12/R13 skip their known-source checks;
    ``context``    - context-only alerts are treated as ordinary detections (they may start incidents);
    ``allowlists`` - authorised admins, service accounts and change windows are emptied.
    """
    feats = {**FEATURE_DEFAULTS, **(cfg.get("features") or {})}
    if not feats["allowlists"]:
        cfg = {**cfg, "allowlists": {**cfg["allowlists"], "authorized_admins": [], "service_accounts": [],
                                     "change_windows": []}}
    coverage = rule_coverage(ev)
    base = compute_login_baselines(ev, cfg)
    first = _first_success(ev)
    alerts = []
    r1 = rule_bruteforce(ev, cfg) if coverage["R1"]["evaluated"] else []
    r2 = rule_spray(ev, cfg) if coverage["R2"]["evaluated"] else []
    r12 = rule_sustained_bruteforce(ev, cfg, r1, first, feats["baselines"]) if coverage["R12"]["evaluated"] else []
    r13 = rule_small_spray(ev, cfg, r2, first, feats["baselines"]) if coverage["R13"]["evaluated"] else []
    alerts += r1 + r2 + r12 + r13
    if coverage["R3"]["evaluated"]:
        alerts += rule_fail_then_success(ev, cfg, r1 + r2 + r12 + r13)
    if feats["baselines"]:
        alerts += rule_baseline(ev, cfg, base)
    alerts += rule_ctx_4672(ev, cfg)
    if coverage["R6"]["evaluated"]:
        alerts += rule_priv_group(ev, cfg)
    if coverage["R7"]["evaluated"]:
        alerts += rule_process(ev, cfg)
    if coverage["R9"]["evaluated"] and feats["baselines"]:
        alerts += rule_lateral(ev, cfg, base)
    if coverage["R10"]["evaluated"]:
        alerts += rule_bulk_copy(ev, cfg)
    if coverage["R11"]["evaluated"]:
        alerts += rule_usb(ev, cfg)
    if coverage["R14"]["evaluated"]:
        alerts += rule_discovery(ev, cfg)
    if coverage["R8"]["evaluated"]:
        alerts += rule_log_cleared(ev, cfg, alerts)
    if not feats["context"]:
        for a in alerts:
            if a["rule"] != "CTX":
                a["context"] = False
    alerts.sort(key=lambda a: (a["start"], a["rule"]))
    for n, a in enumerate(alerts, start=1):
        a["alert_id"] = f"ALR-{n:04d}"
    for a in alerts:
        prior = a["details"].pop("_prior", None)
        if prior is not None:
            a["details"]["prior_alert_id"] = prior["alert_id"]
    counts = Counter(a["rule"] for a in alerts)
    for k in coverage:
        coverage[k]["alerts"] = counts.get(k, 0)
    if not feats["baselines"]:
        for k in ("R4", "R5", "R9"):
            coverage[k].update(evaluated=False, requirement="disabled (ablation: no behavioural baselines)")
    return alerts, coverage, base
