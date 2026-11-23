"""Large-scale deterministic-pipeline benchmark (no SLM): >= 100,000 events.

    python scripts/scale_benchmark.py            -> results/scale_benchmark.json

Generates a synthetic organisation of 420 accounts over 35 days (data/samples/scale_100k, git-ignored),
then times each stage separately and samples the process's peak RSS. SLM inference is NOT run per
event; it is benchmarked separately (slm_benchmark.py) because it is per incident, on demand.
"""
from __future__ import annotations

import json
import platform
import sys
import threading
import time
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "data"))

from generator import GenParams, generate  # noqa: E402
from sentinel.config import load_config  # noqa: E402
from sentinel.correlate import correlate  # noqa: E402
from sentinel.evidence import build_evidence_pack  # noqa: E402
from sentinel.ingest import ingest  # noqa: E402
from sentinel.ingest import guess_mapping, normalize, read_file  # noqa: E402
from sentinel.rules import run_rules  # noqa: E402
from sentinel.severity import score_all  # noqa: E402

PARAMS = GenParams(seed=9001, name="scale_100k", start="2026-08-03", days=35, n_regular=420, n_workstations=200,
                   description="Scale benchmark: 420 accounts, 35 days (>100k events).")


class Peak(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.p = psutil.Process()
        self.peak = self.p.memory_info().rss
        self.stop = threading.Event()

    def run(self):
        while not self.stop.wait(0.05):
            self.peak = max(self.peak, self.p.memory_info().rss)


def main():
    folder = ROOT / "data" / "samples" / PARAMS.name
    t0 = time.perf_counter()
    gt = generate(PARAMS)
    gen_s = time.perf_counter() - t0
    paths = [folder / "auth_logs.csv", folder / "endpoint_logs.json"]
    sizes = {p.name: p.stat().st_size for p in paths}
    cfg = load_config()
    mon = Peak()
    base_rss = mon.p.memory_info().rss
    mon.start()
    t = {}
    blobs = [(p.name, p.read_bytes()) for p in paths]
    # stage 1: parse (CSV/JSON -> flat frames) and stage 2: normalise (column mapping, timestamps, schema)
    s = time.perf_counter()
    loads = [read_file(n, b) for n, b in blobs]
    t["parse_s"] = time.perf_counter() - s
    s = time.perf_counter()
    for ld in loads:
        normalize(ld, guess_mapping(ld.frame))
    t["normalise_s"] = time.perf_counter() - s
    # full ingestion as the app runs it (parse + normalise + merge + dedupe + IDs)
    s = time.perf_counter()
    ds = ingest(blobs)
    t["ingest_total_s"] = time.perf_counter() - s
    s = time.perf_counter()
    alerts, coverage, base = run_rules(ds.events, cfg)
    t["detection_s"] = time.perf_counter() - s
    by_id = {a["alert_id"]: a for a in alerts}
    s = time.perf_counter()
    incidents = correlate(alerts, ds.events, cfg)
    t["correlation_s"] = time.perf_counter() - s
    s = time.perf_counter()
    score_all(incidents, by_id, cfg)
    t["severity_s"] = time.perf_counter() - s
    s = time.perf_counter()
    for inc in incidents:
        build_evidence_pack(inc, by_id, ds, cfg)
    t["evidence_s"] = time.perf_counter() - s
    t["analysis_total_s"] = t["detection_s"] + t["correlation_s"] + t["severity_s"] + t["evidence_s"]
    t["end_to_end_s"] = t["ingest_total_s"] + t["analysis_total_s"]
    mon.stop.set()
    mon.join()
    n = len(ds.events)
    out = {"recorded_at": time.strftime("%Y-%m-%d %H:%M:%S"), "dataset": PARAMS.name,
           "generator": {"accounts": gt["accounts"], "hosts": gt["hosts"], "days": PARAMS.days, "seconds": round(gen_s, 2)},
           "input_bytes": sizes, "events": n, "records_read": ds.summary["records_read"],
           "timings_s": {k: round(v, 3) for k, v in t.items()},
           "throughput_events_per_s": {"ingest": round(n / t["ingest_total_s"]), "analysis": round(n / t["analysis_total_s"]),
                                        "end_to_end": round(n / t["end_to_end_s"])},
           "peak_rss_mb": round(mon.peak / 2**20, 1), "rss_before_mb": round(base_rss / 2**20, 1),
           "alerts": len(alerts), "alerts_by_rule": {k: v["alerts"] for k, v in coverage.items() if v.get("alerts")},
           "incidents": len(incidents),
           "incident_levels": {lv: sum(1 for i in incidents if i["severity"]["level"] == lv)
                               for lv in ("Critical", "High", "Medium", "Low")},
           "hardware": {"cpu": platform.processor(), "logical_cpus": psutil.cpu_count(),
                        "ram_gb": round(psutil.virtual_memory().total / 2**30, 1), "python": platform.python_version()},
           "method": "single run, wall-clock perf_counter per stage, peak RSS sampled every 50 ms; SLM not involved"}
    print(json.dumps(out, indent=1))
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "scale_benchmark.json").write_text(json.dumps(out, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
