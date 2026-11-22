"""Run the local SLM on every incident of a dataset, verify outputs, and record measured performance.

    python scripts/slm_benchmark.py                           # dev seed, qwen2.5:3b, no cache
    python scripts/slm_benchmark.py --dataset test_seed101 --model qwen2.5:7b

Writes results/slm_benchmark_<dataset>_<model>.json with per-incident latency, tokens/s and
verification results. Nothing here is estimated: all numbers come from Ollama's response metadata.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinel.config import load_config, override  # noqa: E402
from sentinel.evidence import known_entities  # noqa: E402
from sentinel.pipeline import analyze_paths  # noqa: E402
from sentinel.slm import explain, status  # noqa: E402
from sentinel.verifier import verify_output  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="dev_seed7")
    ap.add_argument("--model", default=None)
    ap.add_argument("--cache", action="store_true", help="allow cached explanations")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    cfg = load_config()
    if a.model:
        cfg = override(cfg, **{"slm.model": a.model})
    d = ROOT / "data" / "samples" / a.dataset
    an = analyze_paths([d / "auth_logs.csv", d / "endpoint_logs.json"], cfg)
    ke = known_entities(an.events)
    rows = []
    for inc in an.incidents:
        p = an.packs[inc["incident_id"]]
        t0 = time.perf_counter()
        r = explain(p, cfg, use_cache=a.cache)
        wall = time.perf_counter() - t0
        v = verify_output(r["output"], p, ke)
        rows.append({"incident_id": inc["incident_id"], "level": inc["severity"]["level"], "source": r["source"],
                     "error": r.get("error"), "wall_s": round(wall, 2), **{k: r.get("stats", {}).get(k) for k in
                     ("tokens_per_s", "output_tokens", "prompt_tokens", "load_s")}, **v["stats"],
                     "unverified": [{"text": c["text"], "problems": c["problems"]}
                                    for c in v["summary"] + v["conclusions"] if c["status"] != "Verified"]})
        print(f"{inc['incident_id']} {inc['severity']['level']:<8} src={r['source']} wall={wall:.1f}s "
              f"tok/s={r.get('stats', {}).get('tokens_per_s')} verified={v['stats']['verified']}/"
              f"{v['stats']['factual_claims']} hyp={v['stats']['grounded_hypotheses']}/{v['stats']['hypotheses']} "
              f"actions={v['stats']['actions_accepted']} rejected={v['stats']['actions_rejected']}")
        if a.verbose:
            for c in v["summary"] + v["conclusions"]:
                print(f"   [{c['status']}] {c['fact_ids']} {c['text']}  {c['problems'] or ''}")
            for h in v["hypotheses"]:
                print(f"   [{h['status']}] {h['text']} | confirm: {h['how_to_confirm']}")
            for x in v["actions"]:
                print(f"   [{x['playbook_id']}] {x['adaptation']}")
    claims = sum(r["factual_claims"] for r in rows)
    ver = sum(r["verified"] for r in rows)
    slm_rows = [r for r in rows if r["source"] == "slm"]
    summary = {"dataset": a.dataset, "model": cfg["slm"]["model"], "incidents": len(rows),
               "slm_answers": len(slm_rows), "fallbacks": sum(1 for r in rows if r["source"] == "template"),
               "factual_claims": claims, "verified": ver,
               "verification_rate": round(ver / claims, 3) if claims else None,
               "mean_wall_s": round(sum(r["wall_s"] for r in slm_rows) / len(slm_rows), 2) if slm_rows else None,
               "mean_tokens_per_s": round(sum(r["tokens_per_s"] or 0 for r in slm_rows) / len(slm_rows), 1) if slm_rows else None,
               "ollama": status(cfg)}
    print(json.dumps({k: v for k, v in summary.items() if k != "ollama"}))
    out = ROOT / "results" / f"slm_benchmark_{a.dataset}_{cfg['slm']['model'].replace(':', '-')}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"summary": summary, "incidents": rows}, indent=1, default=str), encoding="utf-8")
    print("wrote", out)


if __name__ == "__main__":
    main()
