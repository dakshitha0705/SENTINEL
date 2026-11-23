"""Run the local SLM on every incident of one or more datasets, verify outputs, record measured performance.

    python scripts/slm_benchmark.py                                   # test seeds, qwen2.5:3b, GPU, self-repair on
    python scripts/slm_benchmark.py --model qwen2.5:7b
    python scripts/slm_benchmark.py --cpu --tag cpu                   # CPU-only (num_gpu=0), verified via /api/ps
    python scripts/slm_benchmark.py --no-repair --tag norepair

Writes results/slm_benchmark_<tag>_<model>.json. Nothing is estimated: latency and tokens/s come from
Ollama's response metadata; CPU/RAM from psutil sampling of the Ollama processes during the run; the
CPU/GPU placement from Ollama's /api/ps (size_vram) while the model is loaded.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
import threading
import time
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinel.config import load_config, override  # noqa: E402
from sentinel.evidence import known_entities  # noqa: E402
from sentinel.pipeline import analyze_paths  # noqa: E402
from sentinel.slm import PROMPT_VERSION, explain, status, unload  # noqa: E402
from sentinel.verifier import verify_output  # noqa: E402


class Sampler(threading.Thread):
    """Samples CPU% and RSS of all ollama processes every 0.5 s."""

    def __init__(self):
        super().__init__(daemon=True)
        self.stop = threading.Event()
        self.cpu, self.rss, self.priv = [], [], []
        self.ncpu = psutil.cpu_count() or 1

    def procs(self):
        """Ollama processes (server + model runner), kept across samples so cpu_percent has a baseline."""
        for p in psutil.process_iter(["name"]):
            n = (p.info["name"] or "").lower()
            if ("ollama" in n or n.startswith("llama-server")) and p.pid not in self.cache:
                try:
                    p.cpu_percent(None)
                    self.cache[p.pid] = p
                except psutil.Error:
                    pass
        return list(self.cache.values())

    def run(self):
        self.cache = {}
        self.procs()
        while not self.stop.wait(0.5):
            tot_cpu, tot_rss, tot_priv = 0.0, 0, 0
            for p in self.procs():
                try:
                    tot_cpu += p.cpu_percent(None)
                    mi = p.memory_info()
                    tot_rss += mi.rss
                    tot_priv += getattr(mi, "private", 0)
                except psutil.Error:
                    self.cache.pop(p.pid, None)
            self.cpu.append(tot_cpu / self.ncpu)      # % of the whole machine
            self.rss.append(tot_rss / 2**20)
            self.priv.append(tot_priv / 2**20)

    def summary(self):
        busy = [c for c in self.cpu if c > 1] or [0]
        return {"ollama_cpu_pct_of_machine_mean_busy": round(sum(busy) / len(busy), 1),
                "ollama_cpu_pct_of_machine_peak": round(max(self.cpu or [0]), 1),
                "ollama_rss_peak_mb": round(max(self.rss or [0]), 1),
                "ollama_private_peak_mb": round(max(self.priv or [0]), 1), "samples": len(self.cpu)}


def placement(cfg) -> dict:
    st = status(cfg)
    loaded = [m for m in st.get("loaded", []) if m["name"] == cfg["slm"]["model"]]
    if not loaded:
        return {"model_loaded": False}
    m = loaded[0]
    mode = "CPU" if (m["vram_gb"] or 0) == 0 else ("GPU" if (m["gpu_share"] or 0) >= 0.99 else "CPU+GPU split")
    return {"model_loaded": True, "size_gb": m["size_gb"], "vram_gb": m["vram_gb"], "gpu_share": m["gpu_share"],
            "mode": mode}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets", default="test_seed101,test_seed202,test_seed303")
    ap.add_argument("--model", default=None)
    ap.add_argument("--cpu", action="store_true", help="force CPU-only inference (Ollama option num_gpu=0)")
    ap.add_argument("--no-repair", action="store_true")
    ap.add_argument("--limit", type=int, default=0, help="max incidents per dataset (0 = all)")
    ap.add_argument("--tag", default="test")
    ap.add_argument("--cache", action="store_true", help="allow cached explanations")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    cfg = load_config()
    if a.model:
        cfg = override(cfg, **{"slm.model": a.model})
    if a.cpu:
        cfg = override(cfg, **{"slm.num_gpu": 0, "slm.timeout_seconds": 600})
    repair = not a.no_repair
    # Unload every model first, so this run's CPU/GPU option decides where the model is loaded
    # (Ollama otherwise reuses a runner loaded earlier with different options).
    for m in status(cfg).get("loaded", []):
        unload(cfg, m["name"])
    rows, places = [], []
    sampler = Sampler()
    sampler.start()
    for name in a.datasets.split(","):
        d = ROOT / "data" / "samples" / name
        an = analyze_paths([d / "auth_logs.csv", d / "endpoint_logs.json"], cfg)
        ke = known_entities(an.events)
        incs = an.incidents[: a.limit] if a.limit else an.incidents
        for inc in incs:
            p = an.packs[inc["incident_id"]]
            t0 = time.perf_counter()
            r = explain(p, cfg, use_cache=a.cache, known=ke, repair=repair)
            wall = time.perf_counter() - t0
            places.append(placement(cfg))
            v = verify_output(r["output"], p, ke)
            rep = r.get("repair", {})
            rows.append({"dataset": name, "incident_id": inc["incident_id"], "level": inc["severity"]["level"],
                         "source": r["source"], "error": r.get("error"), "wall_s": round(wall, 2),
                         **{k: r.get("stats", {}).get(k) for k in ("tokens_per_s", "output_tokens", "prompt_tokens",
                                                                   "load_s", "prompt_eval_s")},
                         **v["stats"], "repair": {k: x for k, x in rep.items() if k != "stats"},
                         "unverified": [{"text": c["text"], "problems": c["problems"]}
                                        for c in v["summary"] + v["conclusions"] if c["status"] != "Verified"]})
            print(f"{name} {inc['incident_id']} {inc['severity']['level']:<8} src={r['source']} wall={wall:.1f}s "
                  f"tok/s={r.get('stats', {}).get('tokens_per_s')} verified={v['stats']['verified']}/"
                  f"{v['stats']['factual_claims']} repair={rep.get('initial_verified')}/{rep.get('initial_claims')}"
                  f"->{rep.get('final_verified')}/{rep.get('final_claims')} ({rep.get('kept', '-')}) "
                  f"mode={places[-1].get('mode')}", flush=True)
            if a.verbose:
                for c in v["summary"] + v["conclusions"]:
                    print(f"   [{c['status']}] {c['fact_ids']} {c['text']}  {c['problems'] or ''}")
    sampler.stop.set()
    sampler.join()
    slm_rows = [r for r in rows if r["source"] == "slm"]
    claims = sum(r["factual_claims"] for r in rows)
    ver = sum(r["verified"] for r in rows)
    reps = [r["repair"] for r in slm_rows if r["repair"]]
    att = [x for x in reps if x.get("attempted")]
    init_c, init_v = sum(x["initial_claims"] for x in reps), sum(x["initial_verified"] for x in reps)
    fin_c, fin_v = sum(x["final_claims"] for x in reps), sum(x["final_verified"] for x in reps)
    modes = sorted({p.get("mode") for p in places if p.get("mode")})
    summary = {"datasets": a.datasets.split(","), "model": cfg["slm"]["model"], "prompt_version": PROMPT_VERSION,
               "inference_mode": modes, "placement": places[-1] if places else {},
               "forced_cpu": a.cpu, "self_repair": repair, "incidents": len(rows),
               "slm_answers": len(slm_rows), "fallbacks": sum(1 for r in rows if r["source"] == "template"),
               "factual_claims": claims, "verified": ver,
               "verification_rate": round(ver / claims, 3) if claims else None,
               "repair": {"incidents_with_failures": len(att), "initial_claims": init_c, "initial_verified": init_v,
                          "initial_rate": round(init_v / init_c, 3) if init_c else None,
                          "final_claims": fin_c, "final_verified": fin_v,
                          "final_rate": round(fin_v / fin_c, 3) if fin_c else None,
                          "claims_still_failing": fin_c - fin_v,
                          "repaired_kept": sum(1 for x in att if x.get("kept") == "repaired"),
                          "mean_extra_latency_s": round(sum(x["latency_s"] for x in att) / len(att), 2) if att else 0.0},
               "mean_wall_s": round(sum(r["wall_s"] for r in slm_rows) / len(slm_rows), 2) if slm_rows else None,
               "mean_tokens_per_s": round(sum(r["tokens_per_s"] or 0 for r in slm_rows) / len(slm_rows), 1) if slm_rows else None,
               "mean_prompt_tokens": round(sum(r["prompt_tokens"] or 0 for r in slm_rows) / len(slm_rows)) if slm_rows else None,
               "mean_output_tokens": round(sum(r["output_tokens"] or 0 for r in slm_rows) / len(slm_rows)) if slm_rows else None,
               "resources": sampler.summary(),
               "hardware": {"cpu": platform.processor(), "logical_cpus": psutil.cpu_count(),
                            "ram_gb": round(psutil.virtual_memory().total / 2**30, 1)},
               "recorded_at": time.strftime("%Y-%m-%d %H:%M:%S"), "ollama": status(cfg)}
    print(json.dumps({k: v for k, v in summary.items() if k != "ollama"}, default=str))
    out = ROOT / "results" / f"slm_benchmark_{a.tag}_{cfg['slm']['model'].replace(':', '-')}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"summary": summary, "incidents": rows}, indent=1, default=str), encoding="utf-8")
    print("wrote", out)


if __name__ == "__main__":
    main()
