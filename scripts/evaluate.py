"""Evaluate SENTINEL on synthetic datasets with ground truth.

    python scripts/evaluate.py            # regenerate datasets, evaluate everything, write results/metrics.json
    python scripts/evaluate.py --dev      # dev seed only (use while tuning; never tune on held-out output)

Dataset roles (docs/evaluation.md):
  dev      seed 7 (+ the same seed with the extra look-alikes B8-B10): the only tuning sets
  test     seeds 101/202/303: held out since the first freeze (22 Nov)
  stress   seeds 1001-1010: held out at the first freeze; their failure analysis motivated R12/R13/R3-decay,
           so after the upgrade they are DIAGNOSTIC, not held out
  fresh    seeds 5001-5010: generated after the upgrade's detector freeze (23 Nov); the held-out set for
           the upgrade

Also computed: naive-detector comparison, ablation study, alert compression and per-scenario Jaccard.
The SLM is not involved: detection, correlation and severity are deterministic.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "data"))

from generator import DEV, FRESH, STRESS, TEST, generate  # noqa: E402
from sentinel.comparison import (ABLATIONS, ablation_cfg, aggregate_items, compression,  # noqa: E402
                                 evaluate_items, per_scenario_jaccard)
from sentinel.config import load_config  # noqa: E402
from sentinel.ingest import ingest_paths  # noqa: E402
from sentinel.metrics import aggregate, evaluate, load_ground_truth  # noqa: E402
from sentinel.naive import run_naive  # noqa: E402
from sentinel.pipeline import analyze_dataset  # noqa: E402

SAMPLES = ROOT / "data" / "samples"
RESULTS = ROOT / "results"
DEV_EXT = dataclasses.replace(DEV, name="dev_ext_seed7", extended=True,
                              description="Development seed 7 with the extra look-alikes B8-B10 (tuning only).")
FILES = {"mixed": ["auth_logs.csv", "endpoint_logs.json"],
         "json": ["auth_logs.json", "endpoint_logs.json"],
         "csv": ["auth_logs.csv", "endpoint_logs.csv"]}
_DS_CACHE: dict = {}


def dataset(params, fmt="mixed"):
    key = (params.name, fmt)
    if key not in _DS_CACHE:
        _DS_CACHE[key] = ingest_paths([SAMPLES / params.name / f for f in FILES[fmt]])
    return _DS_CACHE[key]


def run(params, cfg, fmt="mixed", with_analysis=False):
    ds = dataset(params, fmt)
    a = analyze_dataset(ds, cfg)
    m = evaluate(a, load_ground_truth(SAMPLES / params.name))
    m["input_files"] = FILES[fmt]
    m["timings_s"] = {k: round(v, 4) for k, v in a.timings.items()}
    m["compression"] = compression(a)
    return (m, a) if with_analysis else m


def show(m):
    print(f"  {m['dataset']}: events={m['events']} detected={m['detected_incidents']} "
          f"P={m['incident_precision']} R={m['incident_recall']} F1={m['f1']} FPR={m['false_positive_rate']} "
          f"Jaccard={m['correlation_jaccard_mean']} SevAgree={m['severity_agreement']}")
    for r in m["incidents"]:
        print(f"     {r['incident_id']} {r['level']:<8} {r['score']:>3} matched={r['matched']} "
              f"exp={r.get('expected_level')} cov={r.get('coverage')} | {r['title']}")
    for x in m["missed_incidents"]:
        print(f"     MISSED {x['scenario_id']} {x['name']} (best coverage {x['best_coverage']})")
    if m["flagged_benign"]:
        print(f"     FLAGGED BENIGN: {m['flagged_benign']}")


def comparison(param_sets, cfg) -> dict:
    """SENTINEL variants and the naive detector on identical data, both matching protocols."""
    out = {}
    variants = {name: ablation_cfg(cfg, name) for name in ABLATIONS}
    for name, vcfg in variants.items():
        rows, strict_rows, comp = [], [], []
        for p in param_sets:
            m, a = run(p, vcfg, with_analysis=True)
            gt = load_ground_truth(SAMPLES / p.name)
            r = evaluate_items(a.incidents, a.events, gt)
            r["benign_total"] = len(gt["benign"])
            rows.append(r)
            strict_rows.append(m)
            comp.append(m["compression"])
        agg = aggregate_items(rows)
        full_agg = aggregate(strict_rows)
        out[name] = {"description": ABLATIONS[name][1], "items_to_review": agg["strict"]["items"],
                     "strict": agg["strict"], "lenient": agg["lenient"],
                     "false_positive_rate": agg["false_positive_rate"],
                     "correlation_jaccard_mean": full_agg["correlation_jaccard_mean"],
                     "severity_agreement": full_agg["severity_agreement"],
                     "alerts": sum(c["alerts"] for c in comp)}
    rows, n_alerts = [], 0
    for p in param_sets:
        ds = dataset(p)
        items = run_naive(ds.events, cfg)
        gt = load_ground_truth(SAMPLES / p.name)
        r = evaluate_items(items, ds.events, gt)
        r["benign_total"] = len(gt["benign"])
        rows.append(r)
        n_alerts += len(items)
    agg = aggregate_items(rows)
    out["naive"] = {"description": "fixed thresholds, fixed business hours, no baselines/allowlists/context, "
                                   "no correlation (each alert reviewed separately)",
                    "items_to_review": agg["strict"]["items"], "strict": agg["strict"], "lenient": agg["lenient"],
                    "false_positive_rate": agg["false_positive_rate"], "correlation_jaccard_mean": None,
                    "severity_agreement": None, "alerts": n_alerts}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", action="store_true", help="development seeds only")
    ap.add_argument("--no-generate", action="store_true")
    args = ap.parse_args()
    cfg = load_config()
    seeds = [DEV, DEV_EXT] if args.dev else [DEV, DEV_EXT, *TEST, *STRESS, *FRESH]
    if not args.no_generate:
        for p in seeds:
            generate(p, SAMPLES)
    print("Development seeds (used for tuning):")
    dev = [run(p, cfg) for p in (DEV, DEV_EXT)]
    for m in dev:
        show(m)
    if args.dev:
        return
    groups = {}
    for label, ps in (("test", TEST), ("stress", STRESS), ("fresh", FRESH)):
        print(f"{label} seeds:")
        res = []
        for p in ps:
            m = run(p, cfg)
            show(m)
            res.append(m)
        agg = aggregate(res)
        print(f"{label.upper()} AGGREGATE:", json.dumps({k: v for k, v in agg.items() if k != "severity_pairs"}))
        groups[label] = (res, agg)
    fmt_checks = {}
    for fmt in ("json", "csv"):
        m = run(TEST[0], cfg, fmt)
        fmt_checks[fmt] = {k: m[k] for k in ("incident_precision", "incident_recall", "f1", "false_positive_rate")}
    print("Format robustness (test_seed101):", fmt_checks)
    print("Comparison / ablation (held-out: test + fresh) ...")
    held_out = [*TEST, *FRESH]
    comp = comparison(held_out, cfg)
    for k, v in comp.items():
        print(f"  {k:<14} items={v['items_to_review']:>4} strict P/R/F1={v['strict']['precision']}/"
              f"{v['strict']['recall']}/{v['strict']['f1']} lenient P/R/F1={v['lenient']['precision']}/"
              f"{v['lenient']['recall']}/{v['lenient']['f1']} FPR={v['false_positive_rate']}")
    all_held = groups["test"][0] + groups["fresh"][0]
    comp_rows = [m["compression"] for m in all_held]
    n_al, n_inc = sum(c["alerts"] for c in comp_rows), sum(c["incidents"] for c in comp_rows)
    compress = {"datasets": [m["dataset"] for m in all_held], "per_dataset": comp_rows, "alerts": n_al,
                "incidents": n_inc, "compression_pct": round((1 - n_inc / n_al) * 100, 1) if n_al else None,
                "note": "workload reduction (alerts an analyst would otherwise triage one by one), not accuracy"}
    print("Compression:", compress["alerts"], "alerts ->", compress["incidents"], "incidents =",
          compress["compression_pct"], "%")
    RESULTS.mkdir(exist_ok=True)
    out = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "matching_rule": ">=50% of ground-truth event IDs; benign flagged on any overlap",
           "dataset_roles": {"dev": "tuning", "test": "held out since the first freeze",
                             "stress": "diagnostic since the upgrade (motivated R12/R13/R3 decay)",
                             "fresh": "held out since the upgrade freeze"},
           "dev": dev[0], "dev_ext": dev[1],
           "test": groups["test"][0], "test_aggregate": groups["test"][1], "format_robustness": fmt_checks,
           "stress": groups["stress"][0], "stress_aggregate": groups["stress"][1],
           "fresh": groups["fresh"][0], "fresh_aggregate": groups["fresh"][1],
           "comparison": {"datasets": [p.name for p in held_out], **comp},
           "compression": compress,
           "per_scenario_jaccard": {"test": per_scenario_jaccard(groups["test"][0]),
                                    "fresh": per_scenario_jaccard(groups["fresh"][0]),
                                    "stress": per_scenario_jaccard(groups["stress"][0])}}
    with open(RESULTS / "metrics.json", "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, default=str)
    print(f"wrote {RESULTS / 'metrics.json'}")


if __name__ == "__main__":
    main()
