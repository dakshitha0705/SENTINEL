"""Evidence pack builder.

Code (never the SLM) turns an incident into numbered facts F1..Fn. Each fact carries structured
fields (event IDs, counts, times, users, hosts, IPs) used by the verifier. Supporting and
contradicting evidence are computed here from the logs and baselines.
"""
from __future__ import annotations

import hashlib
import json
from datetime import timedelta

import pandas as pd

from .playbooks import candidates_for
from .rules import CONTEXT_RULES

MAX_TEXT = 320


def _t(ts) -> str:
    return pd.Timestamp(ts).strftime("%H:%M:%S")


def _d(ts) -> str:
    return pd.Timestamp(ts).strftime("%Y-%m-%d")


def _span(a, b) -> str:
    a, b = pd.Timestamp(a), pd.Timestamp(b)
    if a == b:
        return f"{_d(a)} {_t(a)} UTC"
    if _d(a) == _d(b):
        return f"{_d(a)} {_t(a)}-{_t(b)} UTC"
    return f"{_d(a)} {_t(a)} to {_d(b)} {_t(b)} UTC"


def _ids(eids, n=4) -> str:
    if len(eids) <= n:
        return ", ".join(eids)
    return f"{eids[0]} ... {eids[-1]} ({len(eids)} events)"


def _sanitize(text: str) -> str:
    """Log content is untrusted: collapse whitespace, cap length, neutralise prompt-like markers."""
    t = " ".join(str(text).split())
    t = t.replace("```", "'''")
    return t if len(t) <= MAX_TEXT else t[: MAX_TEXT - 3] + "..."


def build_evidence_pack(inc: dict, alerts_by_id: dict, ds, cfg: dict) -> dict:
    events = ds.events
    ev = events.set_index("event_id")
    facts: list[dict] = []

    def add(kind, text, event_ids=(), numbers=(), times=(), users=(), hosts=(), ips=(), ref=None):
        fid = f"F{len(facts) + 1}"
        facts.append({"id": fid, "kind": kind, "text": _sanitize(text), "event_ids": list(event_ids),
                      "numbers": [float(n) for n in numbers], "times": sorted(set(times)),
                      "users": sorted(set(users)), "hosts": sorted(set(hosts)), "ips": sorted(set(ips)),
                      "ref": ref})
        return fid

    members = [alerts_by_id[a] for a in inc["alert_ids"]]
    sev = inc["severity"]
    scope = add("scope",
                f"Incident {inc['incident_id']} spans {_span(inc['start'], inc['end'])} with {len(members)} alerts "
                f"over {len(inc['event_ids'])} log events. Accounts: {', '.join(inc['users']) or 'none'}. "
                f"Hosts: {', '.join(inc['hosts']) or 'none'}. Source IPs: {', '.join(inc['ips']) or 'none'}.",
                event_ids=inc["event_ids"], numbers=[len(members), len(inc["event_ids"])],
                times=[pd.Timestamp(inc["start"]).strftime("%H:%M"), pd.Timestamp(inc["end"]).strftime("%H:%M")],
                users=inc["users"], hosts=inc["hosts"], ips=inc["ips"], ref=inc["incident_id"])

    alert_fact = {}
    for a in members:
        nums = [len(a["event_ids"])] + [v for v in a["details"].values() if isinstance(v, (int, float)) and not isinstance(v, bool)]
        ev_times = [t.strftime("%H:%M") for t in ev.loc[a["event_ids"], "timestamp"]]
        role = "context" if a["context"] else "detection"
        member = inc["membership"][a["alert_id"]]
        tag = "" if member in ("seed", "strong") else " [weak link: shown, not scored]"
        fid = add(role,
                  f"{_span(a['start'], a['end'])}: {a['rule']} {a['name']} - {a['reason']}. "
                  f"Events: {_ids(a['event_ids'])}.{tag}",
                  event_ids=a["event_ids"], numbers=nums, times=ev_times,
                  users=a["users"], hosts=a["hosts"], ips=a["ips"], ref=a["alert_id"])
        alert_fact[a["alert_id"]] = fid

    for l in inc["links"]:
        a, b = alerts_by_id[l["to"]], alerts_by_id[l["from"]]
        add("link", f"{l['to']} ({a['rule']}) linked to {l['from']} ({b['rule']}) by a {l['strength']} link: {l['reason']}.",
            event_ids=[], users=set(a["users"]) & set(b["users"]), hosts=set(a["hosts"]) & set(b["hosts"]),
            ips=set(a["ips"]) & set(b["ips"]),
            numbers=[round(abs((a["start"] - b["end"]).total_seconds()) / 60, 1)], ref=l["to"])

    sev_text = "; ".join(f"{l['factor']} {l['points']:+d}" for l in sev["breakdown"])
    sev_fid = add("severity", f"Severity {sev['level']} (score {sev['score']}/100): {sev_text}. "
                  f"Confidence that the activity is malicious: {sev['confidence']['level']} ({sev['confidence']['reason']}).",
                  numbers=[sev["score"], sev["raw_score"]] + [l["points"] for l in sev["breakdown"]], ref="severity")

    supporting, contradicting = [], []
    # Supporting: the scored primary detections themselves
    for a in members:
        if not a["context"] and inc["membership"][a["alert_id"]] in ("seed", "strong"):
            supporting.append(alert_fact[a["alert_id"]])
        if a["rule"] in ("R4", "R5") and a["confidence"] == "high" and inc["membership"][a["alert_id"]] in ("seed", "strong"):
            supporting.append(alert_fact[a["alert_id"]])

    # Contradicting evidence (code-computed)
    base = None
    try:
        from .baselines import compute_login_baselines
        base = compute_login_baselines(events[events["user"].isin(inc["users"])], cfg)
    except Exception:
        base = None
    inc_logins = [e for e in inc["event_ids"] if ev.at[e, "action"] == "login_success"]
    if base is not None:
        for e in inc_logins:
            if e not in base.index:
                continue
            b = base.loc[e]
            r = ev.loc[e]
            if b["host_known"] and b["ip_known"]:
                contradicting.append(add("contradicting",
                    f"Logon {e} by {r['user']} at {_t(r['timestamp'])} came from a host ({r['host']}) and source IP "
                    f"({r['src_ip'] or 'n/a'}) already seen in {b['n_prior']} earlier logons by this account.",
                    event_ids=[e], numbers=[b["n_prior"]], times=[r["timestamp"].strftime("%H:%M")],
                    users=[r["user"]], hosts=[r["host"]], ips=[r["src_ip"]] if r["src_ip"] else []))
            if b["hour_usual"] and b["confident"]:
                contradicting.append(add("contradicting",
                    f"Logon {e} by {r['user']} at {_t(r['timestamp'])} falls within the account's usual logon hours.",
                    event_ids=[e], times=[r["timestamp"].strftime("%H:%M")], users=[r["user"]], hosts=[r["host"]]))
            if not b["confident"]:
                contradicting.append(add("contradicting",
                    f"Baseline for {r['user']} is LOW confidence: only {b['n_prior']} earlier logons over "
                    f"{b['days_prior']} days, so 'unusual' judgements are weak.",
                    event_ids=[e], numbers=[b["n_prior"], b["days_prior"]], users=[r["user"]]))
    k = cfg["detection"]["failure_then_success"]["max_minutes_after_burst"]
    for a in members:
        if a["rule"] in ("R1", "R2") and "R3" not in inc["rules"]:
            contradicting.append(add("contradicting",
                f"No successful logon from {', '.join(a['ips']) or 'the same source'} followed the failed attempts of "
                f"{a['alert_id']} within {k} minutes, so the logs show attempts, not access.",
                event_ids=a["event_ids"][-1:], numbers=[k], users=a["users"], ips=a["ips"]))
        if a["rule"] == "R6":
            d = a["details"]
            if d.get("authorised_actor"):
                contradicting.append(add("contradicting",
                    f"The group change in {a['alert_id']} was made by {d['actor']}, an authorised administrator.",
                    event_ids=a["event_ids"], users=[d["actor"]]))
            if d.get("in_change_window"):
                contradicting.append(add("contradicting",
                    f"The group change in {a['alert_id']} happened inside an approved change window.",
                    event_ids=a["event_ids"]))
        if a["rule"] == "R8" and not a["details"].get("preceded_by_suspicious"):
            contradicting.append(add("contradicting",
                f"No other suspicious activity was found on {', '.join(a['hosts'])} in the 4 hours before the log clear.",
                event_ids=a["event_ids"], numbers=[4], hosts=a["hosts"]))
        if a["rule"] == "CTX":
            pass
    if any(a["rule"] == "CTX" for a in members):
        ctx = [a for a in members if a["rule"] == "CTX"]
        add("caveat", f"Event 4672 (special privileges at logon) appears {len(ctx)} time(s); it shows a privileged "
            "session, not that privileges were escalated.", event_ids=[e for a in ctx for e in a["event_ids"]],
            numbers=[len(ctx)], users={u for a in ctx for u in a["users"]})

    limitations = ["Logs record authentication outcomes and process starts; they cannot prove who was at the keyboard "
                   "or whether an action was authorised."]
    if "R3" in inc["rules"] or inc.get("seed_kind") == "anomalous_logon":
        limitations.append("A successful logon does not by itself prove the account was compromised.")
    endpoint_hosts = set(events.loc[events["log_type"] == "endpoint", "host"])
    no_edr = [h for h in inc["hosts"] if h not in endpoint_hosts]
    if no_edr:
        limitations.append(f"No endpoint (process) telemetry was supplied for: {', '.join(no_edr)}.")
    if any(a["rule"] == "R8" for a in members):
        limitations.append("The audit log was cleared, so events before the clearing on that host may be missing.")
    if any(a["confidence"] != "high" for a in members if a["rule"] in ("R4", "R5")):
        limitations.append("Some behavioural judgements rely on a low-confidence baseline (limited history).")

    playbooks = candidates_for(inc)
    pack = {
        "incident_id": inc["incident_id"], "title": inc["title"],
        "severity": {"level": sev["level"], "score": sev["score"], "fact_id": sev_fid},
        "confidence": sev["confidence"], "mitre": inc["mitre"],
        "facts": facts, "scope_fact": scope,
        "supporting_fact_ids": sorted(set(supporting), key=lambda x: int(x[1:])),
        "contradicting_fact_ids": contradicting,
        "limitations": limitations,
        "playbooks": [{"id": p["id"], "title": p["title"]} for p in playbooks],
        "entities": sorted(set(inc["users"]) | set(inc["hosts"]) | set(inc["ips"])),
    }
    pack["hash"] = pack_hash(pack)
    return pack


def pack_hash(pack: dict) -> str:
    core = {k: pack[k] for k in ("incident_id", "title", "severity", "facts", "playbooks")}
    return hashlib.sha256(json.dumps(core, sort_keys=True, default=str).encode()).hexdigest()[:16]


def slm_view(pack: dict) -> dict:
    """Compact pack sent to the SLM (no raw logs, no internal indexes)."""
    return {
        "incident_id": pack["incident_id"], "title": pack["title"], "severity": pack["severity"],
        "confidence": pack["confidence"], "mitre_techniques": pack["mitre"],
        "facts": [{"id": f["id"], "kind": f["kind"], "text": f["text"]} for f in pack["facts"]],
        "supporting_fact_ids": pack["supporting_fact_ids"],
        "contradicting_fact_ids": pack["contradicting_fact_ids"],
        "allowed_playbooks": pack["playbooks"], "limitations": pack["limitations"],
    }


def known_entities(events: pd.DataFrame) -> set:
    ents = set()
    for c in ("user", "actor", "target_user", "host", "src_ip"):
        ents |= set(events[c].dropna().astype(str))
    return {e for e in ents if e and len(e) >= 3}
