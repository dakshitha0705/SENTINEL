"""Incident-level evaluation against generator ground truth.

Matching procedure (fixed before evaluation, documented in docs/evaluation.md):
* Each event is mapped to its ground-truth scenario through its source record ID (EventRecordID).
* A detected incident MATCHES a ground-truth malicious incident when it contains at least 50% of that
  incident's events. A detected incident that matches no malicious incident is a false positive.
* A benign look-alike scenario is FLAGGED when any detected incident contains any of its events.
* Precision = matched detected incidents / all detected incidents.
* Recall    = ground-truth incidents matched by at least one detection / all ground-truth incidents.
* FPR       = flagged benign look-alikes / all benign look-alikes.
* Correlation quality = Jaccard overlap between a matched incident's events and the ground-truth events.
* Severity agreement = detected level == expected level for matched incidents.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

from .rules import PRIMARY_RULES

LEVELS = ["Critical", "High", "Medium", "Low"]


def load_ground_truth(folder) -> dict:
    with open(Path(folder) / "ground_truth.json", encoding="utf-8") as fh:
        return json.load(fh)


def evaluate(analysis, gt: dict) -> dict:
    ev = analysis.events
    rid = ev.set_index("event_id")["record_id"].astype(str)
    rec_to_eid = {r: e for e, r in rid.items()}
    gt_inc = [{**g, "eids": {rec_to_eid[str(r)] for r in g["record_ids"] if str(r) in rec_to_eid}} for g in gt["incidents"]]
    gt_ben = [{**g, "eids": {rec_to_eid[str(r)] for r in g["record_ids"] if str(r) in rec_to_eid}} for g in gt["benign"]]
    detected = analysis.incidents

    rows, matched_gt = [], {}
    for inc in detected:
        es = set(inc["event_ids"])
        best = None
        for g in gt_inc:
            if not g["eids"]:
                continue
            cov = len(es & g["eids"]) / len(g["eids"])
            if cov >= 0.5 and (best is None or cov > best[1]):
                best = (g, cov)
        benign_hit = [b["scenario_id"] for b in gt_ben if es & b["eids"]]
        row = {"incident_id": inc["incident_id"], "title": inc["title"], "level": inc["severity"]["level"],
               "score": inc["severity"]["score"], "events": len(es), "benign_overlap": benign_hit}
        if best:
            g, cov = best
            jac = len(es & g["eids"]) / len(es | g["eids"])
            row.update({"matched": g["scenario_id"], "coverage": round(cov, 3), "jaccard": round(jac, 3),
                        "expected_level": g["expected_severity"]})
            matched_gt.setdefault(g["scenario_id"], []).append(row)
        else:
            row.update({"matched": None})
        rows.append(row)

    tp_det = sum(1 for r in rows if r["matched"])
    n_det = len(rows)
    recall_hits = [g["scenario_id"] for g in gt_inc if g["scenario_id"] in matched_gt]
    misses = [{"scenario_id": g["scenario_id"], "name": g["name"],
               "best_coverage": round(max((len(set(i["event_ids"]) & g["eids"]) / max(1, len(g["eids"]))
                                           for i in detected), default=0.0), 3)} for g in gt_inc
              if g["scenario_id"] not in matched_gt]
    flagged = [b["scenario_id"] for b in gt_ben if any(set(i["event_ids"]) & b["eids"] for i in detected)]
    precision = tp_det / n_det if n_det else 0.0
    recall = len(recall_hits) / len(gt_inc) if gt_inc else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    best_rows = [max(v, key=lambda r: r["coverage"]) for v in matched_gt.values()]
    sev_pairs = [(r["expected_level"], r["level"]) for r in best_rows if r.get("expected_level")]

    # Event-level (alert) metrics: per rule, using generator labels.
    labels = _event_labels(analysis, gt)
    per_rule = {}
    for rule in sorted(PRIMARY_RULES | {"R4", "R5"}):
        al = [a for a in analysis.alerts if a["rule"] == rule]
        flagged_e = {e for a in al for e in a["event_ids"]}
        tp = sum(1 for e in flagged_e if labels.get(e) == 1)
        per_rule[rule] = {"alerts": len(al), "flagged_events": len(flagged_e), "malicious_events": tp,
                          "precision": round(tp / len(flagged_e), 3) if flagged_e else None}
    # incident-level confusion over (malicious scenario events): event-in-incident vs label
    y_true = [labels.get(e, 0) for e in ev["event_id"]]
    in_inc = {e for i in detected for e in i["event_ids"]}
    y_pred = [1 if e in in_inc else 0 for e in ev["event_id"]]
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()
    return {
        "dataset": gt["dataset"],
        "events": int(len(ev)),
        "gt_incidents": len(gt_inc), "gt_benign": len(gt_ben), "detected_incidents": n_det,
        "incident_precision": round(precision, 3), "incident_recall": round(recall, 3), "f1": round(f1, 3),
        "false_positive_rate": round(len(flagged) / len(gt_ben), 3) if gt_ben else None,
        "flagged_benign": flagged,
        "false_positive_incidents": [r for r in rows if not r["matched"]],
        "missed_incidents": misses,
        "correlation_jaccard_mean": round(sum(r["jaccard"] for r in best_rows) / len(best_rows), 3) if best_rows else None,
        "severity_agreement": round(sum(1 for e, d in sev_pairs if e == d) / len(sev_pairs), 3) if sev_pairs else None,
        "severity_pairs": sev_pairs,
        "incidents": rows,
        "per_rule": per_rule,
        "event_confusion": {"labels": ["benign", "malicious"], "matrix": cm,
                            "event_precision": round(precision_score(y_true, y_pred, zero_division=0), 3),
                            "event_recall": round(recall_score(y_true, y_pred, zero_division=0), 3),
                            "event_f1": round(f1_score(y_true, y_pred, zero_division=0), 3)},
    }


def _event_labels(analysis, gt) -> dict:
    ev = analysis.events
    rid = ev.set_index("event_id")["record_id"].astype(str)
    rec_to_eid = {r: e for e, r in rid.items()}
    labels = {}
    for g in gt["incidents"]:
        for r in g["record_ids"]:
            if str(r) in rec_to_eid:
                labels[rec_to_eid[str(r)]] = 1
    return labels


def aggregate(results: list[dict]) -> dict:
    tp = sum(sum(1 for r in x["incidents"] if r["matched"]) for x in results)
    det = sum(x["detected_incidents"] for x in results)
    gt_hit = sum(x["gt_incidents"] - len(x["missed_incidents"]) for x in results)
    gt = sum(x["gt_incidents"] for x in results)
    fl = sum(len(x["flagged_benign"]) for x in results)
    ben = sum(x["gt_benign"] for x in results)
    p = tp / det if det else 0.0
    r = gt_hit / gt if gt else 0.0
    jac = [x["correlation_jaccard_mean"] for x in results if x["correlation_jaccard_mean"] is not None]
    pairs = [tuple(p_) for x in results for p_ in x["severity_pairs"]]
    return {"datasets": [x["dataset"] for x in results], "detected_incidents": det, "matched_detected": tp,
            "gt_incidents": gt, "gt_detected": gt_hit, "benign_lookalikes": ben, "benign_flagged": fl,
            "incident_precision": round(p, 3), "incident_recall": round(r, 3),
            "f1": round(2 * p * r / (p + r), 3) if p + r else 0.0,
            "false_positive_rate": round(fl / ben, 3) if ben else None,
            "correlation_jaccard_mean": round(sum(jac) / len(jac), 3) if jac else None,
            "severity_agreement": round(sum(1 for e, d in pairs if e == d) / len(pairs), 3) if pairs else None,
            "severity_pairs": pairs}
