"""Comparison, ablation and workload metrics (docs/evaluation.md sections 5-8).

Two matching protocols are reported for every system, so that a detector without correlation is not
penalised just for producing small items:

* strict  - the SENTINEL protocol: an item matches an attack when it contains >= 50% of the attack's
            events (metrics.py).
* lenient - an item is a true positive when it contains ANY event of an attack; an attack is detected
            when ANY item touches it. Benign look-alikes are flagged on any overlap in both protocols.
"""
from __future__ import annotations

import copy
from collections import defaultdict

from .metrics import load_ground_truth  # noqa: F401  (re-export for scripts)


def _gt_sets(events, gt):
    rid = events.set_index("event_id")["record_id"].astype(str)
    rec_to_eid = {r: e for e, r in rid.items()}
    conv = lambda g: {**g, "eids": {rec_to_eid[str(r)] for r in g["record_ids"] if str(r) in rec_to_eid}}
    return [conv(g) for g in gt["incidents"]], [conv(g) for g in gt["benign"]]


def evaluate_items(items: list[dict], events, gt: dict) -> dict:
    attacks, benign = _gt_sets(events, gt)
    out = {}
    for proto in ("strict", "lenient"):
        tp_items, hit = 0, set()
        for it in items:
            es = set(it["event_ids"])
            matched = False
            for g in attacks:
                if not g["eids"]:
                    continue
                ov = len(es & g["eids"])
                ok = ov / len(g["eids"]) >= 0.5 if proto == "strict" else ov > 0
                if ok:
                    matched = True
                    hit.add(g["scenario_id"])
            tp_items += matched
        n = len(items)
        p = tp_items / n if n else 0.0
        r = len(hit) / len(attacks) if attacks else 0.0
        out[proto] = {"items": n, "true_positive_items": tp_items, "false_positive_items": n - tp_items,
                      "attacks": len(attacks), "attacks_detected": len(hit),
                      "precision": round(p, 3), "recall": round(r, 3),
                      "f1": round(2 * p * r / (p + r), 3) if p + r else 0.0}
    flagged = [b["scenario_id"] for b in benign if any(set(i["event_ids"]) & b["eids"] for i in items)]
    out["benign_flagged"] = flagged
    out["false_positive_rate"] = round(len(flagged) / len(benign), 3) if benign else None
    return out


def aggregate_items(rows: list[dict]) -> dict:
    agg = {}
    for proto in ("strict", "lenient"):
        t = defaultdict(int)
        for r in rows:
            for k in ("items", "true_positive_items", "false_positive_items", "attacks", "attacks_detected"):
                t[k] += r[proto][k]
        p = t["true_positive_items"] / t["items"] if t["items"] else 0.0
        rc = t["attacks_detected"] / t["attacks"] if t["attacks"] else 0.0
        agg[proto] = {**t, "precision": round(p, 3), "recall": round(rc, 3),
                      "f1": round(2 * p * rc / (p + rc), 3) if p + rc else 0.0}
    fl = sum(len(r["benign_flagged"]) for r in rows)
    ben = sum(r.get("benign_total", 0) for r in rows)
    agg["benign_flagged"] = fl
    agg["false_positive_rate"] = round(fl / ben, 3) if ben else None
    return agg


def compression(analysis) -> dict:
    """Alert-to-incident compression. Measures analyst workload reduction, NOT detection accuracy.

    Raw detections = every rule alert except the informational 4672 records (CTX)."""
    raw = [a for a in analysis.alerts if a["rule"] != "CTX"]
    n_alert, n_inc = len(raw), len(analysis.incidents)
    in_inc = {a for i in analysis.incidents for a in i["alert_ids"]}
    return {"alerts": n_alert, "primary_alerts": sum(1 for a in raw if not a["context"]),
            "incidents": n_inc, "alerts_in_incidents": sum(1 for a in raw if a["alert_id"] in in_inc),
            "compression_pct": round((1 - n_inc / n_alert) * 100, 1) if n_alert else None}


def per_scenario_jaccard(results: list[dict]) -> dict:
    """Scenario -> per-dataset Jaccard (None = missed), mean/min over matched runs and the miss count."""
    table = defaultdict(list)
    for m in results:
        for r in m.get("per_scenario", []):
            table[r["scenario_id"]].append({"dataset": m["dataset"], "name": r["name"], "jaccard": r["jaccard"],
                                            "incident_id": r["incident_id"]})
    out = {}
    for sid, rows in sorted(table.items(), key=lambda kv: int(kv[0][1:]) if kv[0][1:].isdigit() else 0):
        js = [r["jaccard"] for r in rows if r["jaccard"] is not None]
        out[sid] = {"name": rows[0]["name"].split(" with ")[0], "runs": rows, "matched": len(js),
                    "missed": len(rows) - len(js), "mean_jaccard": round(sum(js) / len(js), 3) if js else None,
                    "min_jaccard": min(js) if js else None}
    return out


ABLATIONS = {
    "full": ({}, "Complete SENTINEL"),
    "no_baselines": ({"baselines": False}, "R4/R5/R9 off; R12/R13 no known-source check; no R4+R5 composite"),
    "no_context": ({"context": False}, "context-only alerts may start incidents; benign-context discount off"),
    "no_allowlists": ({"allowlists": False}, "no authorised admins, service accounts or change windows"),
}


def ablation_cfg(cfg: dict, name: str) -> dict:
    new = copy.deepcopy(cfg)
    new["features"] = {**(new.get("features") or {}), **ABLATIONS[name][0]}
    return new
