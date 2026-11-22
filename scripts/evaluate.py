"""Evaluate SENTINEL on the development seed and the held-out test seeds.

    python scripts/evaluate.py            # regenerate datasets, evaluate dev + test, write results/
    python scripts/evaluate.py --dev      # dev seed only (use while tuning; never tune on test output)

The SLM is not involved: detection, correlation and severity are deterministic.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "data"))

from generator import DEV, STRESS, TEST, generate  # noqa: E402
from sentinel.config import load_config  # noqa: E402
from sentinel.metrics import aggregate, evaluate, load_ground_truth  # noqa: E402
from sentinel.pipeline import analyze_paths  # noqa: E402

SAMPLES = ROOT / "data" / "samples"
RESULTS = ROOT / "results"


def run(params, cfg, fmt="mixed"):
    folder = SAMPLES / params.name
    files = {"mixed": ["auth_logs.csv", "endpoint_logs.json"],
             "json": ["auth_logs.json", "endpoint_logs.json"],
             "csv": ["auth_logs.csv", "endpoint_logs.csv"]}[fmt]
    a = analyze_paths([folder / f for f in files], cfg)
    m = evaluate(a, load_ground_truth(folder))
    m["input_files"] = files
    m["timings_s"] = {k: round(v, 4) for k, v in a.timings.items()}
    return m


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", action="store_true", help="development seed only")
    ap.add_argument("--no-generate", action="store_true")
    args = ap.parse_args()
    cfg = load_config()
    seeds = [DEV] if args.dev else [DEV, *TEST, *STRESS]
    if not args.no_generate:
        for p in seeds:
            generate(p, SAMPLES)
    print("Development seed (used for tuning):")
    dev = run(DEV, cfg)
    show(dev)
    if args.dev:
        return
    print("Held-out test seeds (reported):")
    tests = []
    for p in TEST:
        m = run(p, cfg)
        show(m)
        tests.append(m)
    # format robustness: same test seed via JSON-only and CSV-only inputs
    fmt_checks = {}
    for fmt in ("json", "csv"):
        m = run(TEST[0], cfg, fmt)
        fmt_checks[fmt] = {k: m[k] for k in ("incident_precision", "incident_recall", "f1", "false_positive_rate")}
    agg = aggregate(tests)
    print("TEST AGGREGATE:", json.dumps({k: v for k, v in agg.items() if k != "severity_pairs"}))
    print("Format robustness (test_seed101):", fmt_checks)
    print("Stress seeds (out-of-envelope, never tuned on):")
    stress = []
    for p in STRESS:
        m = run(p, cfg)
        show(m)
        stress.append(m)
    sagg = aggregate(stress)
    print("STRESS AGGREGATE:", json.dumps({k: v for k, v in sagg.items() if k != "severity_pairs"}))
    RESULTS.mkdir(exist_ok=True)
    out = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "matching_rule": ">=50% of ground-truth event IDs; benign flagged on any overlap",
           "dev": dev, "test": tests, "test_aggregate": agg, "format_robustness": fmt_checks,
           "stress": stress, "stress_aggregate": sagg}
    with open(RESULTS / "metrics.json", "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, default=str)
    print(f"wrote {RESULTS / 'metrics.json'}")


if __name__ == "__main__":
    main()
