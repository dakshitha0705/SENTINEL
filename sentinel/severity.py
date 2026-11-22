"""Explainable 0-100 severity score.

Severity = potential impact if the activity is malicious (how urgently to look).
Confidence = how strongly the evidence indicates malicious activity (separate field).

Only alerts that are incident seeds or joined by a STRONG link are scored. Each rule counts once per
incident (no double counting of repeated alerts of the same rule). Every factor is returned as a
line in the breakdown so the UI and report can show exactly how the number was formed.
"""
from __future__ import annotations

from .rules import CONTEXT_RULES

ACCESS, ESCALATION, ACTION = "access", "escalation", "action"


def level_for(score: int, cfg: dict) -> str:
    lv = cfg["severity"]["levels"]
    if score >= lv["critical"]:
        return "Critical"
    if score >= lv["high"]:
        return "High"
    if score >= lv["medium"]:
        return "Medium"
    return "Low"


def score_incident(inc: dict, alerts_by_id: dict, cfg: dict) -> dict:
    s = cfg["severity"]
    w = s["rule_weights"]
    members = [alerts_by_id[a] for a in inc["alert_ids"]]
    scored = [a for a in members if inc["membership"][a["alert_id"]] in ("seed", "strong")]
    weak = [a for a in members if inc["membership"][a["alert_id"]] == "weak"]
    lines = []

    # 1. Rule weights (once per rule)
    seen = set()
    for a in scored:
        if a["rule"] in seen or a["rule"] == "CTX":
            continue
        seen.add(a["rule"])
        same = [x for x in scored if x["rule"] == a["rule"]]
        label = f"{a['rule']} {a['name']}"
        if a["rule"] in ("R4", "R5") and all(x["confidence"] != "high" for x in same):
            # Reduced weight: an anomaly judged against a low-confidence baseline adds nothing.
            lines.append({"factor": label + " (low-confidence baseline)", "points": 0,
                          "detail": "baseline history too short; shown but not scored"})
            continue
        lines.append({"factor": label, "points": w.get(a["weight"], 0), "detail": f"{a['weight']} weight rule"})
    for r in sorted({a["rule"] for a in weak} - seen - {"CTX"}):
        lines.append({"factor": f"{r} (weak link only)", "points": 0,
                      "detail": "joined by a single shared key; shown but not scored"})

    # 2. Log clearing after suspicious activity
    if any(a["rule"] == "R8" and a["details"].get("preceded_by_suspicious") for a in scored):
        lines.append({"factor": "Log cleared after suspicious activity", "points": s["log_clear_after_activity"],
                      "detail": "R8 preceded by other alerts on the same host/user"})

    # 3. Privileged account involvement
    priv_accounts = set(cfg["allowlists"]["privileged_accounts"])
    priv_groups = {g.lower() for g in cfg["detection"]["privileged_groups"]}
    reasons = set()
    for a in scored:
        reasons.update(f"{u} is a privileged account" for u in a["users"] if u in priv_accounts)
        if a["rule"] == "CTX":
            reasons.add(f"special privileges assigned at logon ({', '.join(a['users'])})")
        if a["rule"] == "R6" and a["details"].get("group", "").lower() in priv_groups:
            reasons.add(f"{a['details'].get('member')} added to {a['details'].get('group')}")
    if reasons:
        lines.append({"factor": "Privileged account involved", "points": s["privileged_account"],
                      "detail": "; ".join(sorted(reasons))})
    tier0 = {g.lower() for g in s.get("tier0_groups", [])}
    t0 = [a for a in scored if a["rule"] == "R6" and a["details"].get("group", "").lower() in tier0]
    if t0:
        lines.append({"factor": "Domain-wide admin group targeted", "points": s["tier0_group"],
                      "detail": ", ".join(sorted({a['details']['group'] for a in t0}))})

    # 4. Critical asset
    crit = {h.upper() for h in cfg["assets"]["critical"]}
    hit = sorted({h for a in scored for h in a["hosts"] if h.upper() in crit})
    if hit:
        lines.append({"factor": "Critical asset involved", "points": s["critical_asset"], "detail": ", ".join(hit)})

    # 5. Chain completeness (ordered stages)
    first = {}
    rules = {a["rule"] for a in scored}
    for a in scored:
        st = None
        if a["rule"] == "R3" or (a["rule"] in ("R4", "R5") and {"R4", "R5"} <= rules):
            st = ACCESS
        elif a["rule"] == "R6":
            st = ESCALATION
        elif a["rule"] in ("R7", "R8"):
            st = ACTION
        if st and (st not in first or a["start"] < first[st]):
            first[st] = a["start"]
    if len(first) == 3 and first[ACCESS] <= first[ESCALATION] <= first[ACTION]:
        lines.append({"factor": "Full attack chain", "points": s["chain_full"],
                      "detail": "access -> privilege change -> execution/log clearing, in order"})
    elif len(first) >= 2:
        lines.append({"factor": "Partial attack chain", "points": s["chain_two_stages"],
                      "detail": " + ".join(sorted(first))})

    # 6. Low-confidence baseline
    # Penalty only when the incident's evidence rests on behavioural baselines (no primary detection).
    low = [a for a in scored if a["rule"] in ("R4", "R5") and a["confidence"] != "high"]
    baseline_driven = not any(a["rule"] not in CONTEXT_RULES for a in scored)
    if low and baseline_driven:
        lines.append({"factor": "Low-confidence baseline", "points": s["low_confidence_baseline"],
                      "detail": f"limited history for {', '.join(sorted({u for a in low for u in a['users']}))}"})

    # 7. Benign context (capped)
    benign = []
    for a in members:
        if a["rule"] == "R6" and a["details"].get("in_change_window"):
            benign.append("privileged change made inside an approved change window")
        if a["rule"] == "R4" and a["details"].get("in_change_window"):
            benign.append("off-hours logon inside an approved change window")
    admins = set(cfg["allowlists"]["authorized_admins"])
    all_users = {u for a in scored for u in a["users"]}
    if all_users and all_users <= admins and not any(a["rule"] == "R5" for a in members):
        benign.append("activity by authorised administrator(s) from known devices")
    if benign:
        pts = max(s["benign_context_max"], s["benign_context_each"] * len(benign))
        lines.append({"factor": "Benign context", "points": pts, "detail": "; ".join(sorted(set(benign)))})

    raw = sum(l["points"] for l in lines)
    score = max(0, min(100, raw))
    level = level_for(score, cfg)
    return {"score": score, "raw_score": raw, "level": level, "breakdown": lines,
            "confidence": confidence_for(scored, benign)}


def confidence_for(scored: list, benign: list) -> dict:
    """Confidence that the activity is malicious - separate from severity."""
    primary = [a for a in scored if a["rule"] not in CONTEXT_RULES]
    strong_signals = {"R3", "R6", "R7", "R8"} & {a["rule"] for a in primary}
    if len(strong_signals) >= 2:
        lvl, why = "High", "multiple independent high-signal detections"
    elif strong_signals or any(a["confidence"] == "high" for a in primary):
        lvl, why = "Medium", "one high-signal detection; intent not established by logs"
    else:
        lvl, why = "Low", "behavioural anomalies only"
    if benign and lvl != "Low":
        lvl = {"High": "Medium", "Medium": "Low"}[lvl]
        why += "; lowered by benign context"
    return {"level": lvl, "reason": why}


def score_all(incidents: list, alerts_by_id: dict, cfg: dict) -> list:
    for inc in incidents:
        inc["severity"] = score_incident(inc, alerts_by_id, cfg)
    return incidents
