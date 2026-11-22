"""End-to-end deterministic analysis: ingest -> rules -> correlation -> severity -> evidence packs."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import pandas as pd

from .config import load_config
from .correlate import correlate
from .evidence import build_evidence_pack
from .ingest import Dataset, ingest, ingest_paths
from .rules import run_rules
from .severity import score_all

LEVEL_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


@dataclass
class Analysis:
    dataset: Dataset
    alerts: list
    alerts_by_id: dict
    incidents: list            # sorted by severity (highest first)
    coverage: dict
    baselines: pd.DataFrame
    packs: dict                # incident_id -> evidence pack
    timings: dict = field(default_factory=dict)

    @property
    def events(self):
        return self.dataset.events

    def incident(self, iid):
        return next(i for i in self.incidents if i["incident_id"] == iid)


def analyze_dataset(ds: Dataset, cfg: dict | None = None) -> Analysis:
    cfg = cfg or load_config()
    t = {}
    t0 = time.perf_counter()
    alerts, coverage, base = run_rules(ds.events, cfg)
    t["detection_s"] = time.perf_counter() - t0
    t1 = time.perf_counter()
    by_id = {a["alert_id"]: a for a in alerts}
    incidents = correlate(alerts, ds.events, cfg)
    t["correlation_s"] = time.perf_counter() - t1
    t2 = time.perf_counter()
    score_all(incidents, by_id, cfg)
    incidents.sort(key=lambda i: (-i["severity"]["score"], i["start"]))
    t["severity_s"] = time.perf_counter() - t2
    t3 = time.perf_counter()
    packs = {i["incident_id"]: build_evidence_pack(i, by_id, ds, cfg) for i in incidents}
    t["evidence_s"] = time.perf_counter() - t3
    t["analysis_total_s"] = time.perf_counter() - t0
    return Analysis(ds, alerts, by_id, incidents, coverage, base, packs, t)


def analyze_paths(paths, cfg=None, mappings=None) -> Analysis:
    t0 = time.perf_counter()
    ds = ingest_paths(paths, mappings)
    ing = time.perf_counter() - t0
    a = analyze_dataset(ds, cfg)
    a.timings["ingest_s"] = ing
    return a


def analyze_files(files, cfg=None, mappings=None) -> Analysis:
    t0 = time.perf_counter()
    ds = ingest(files, mappings)
    ing = time.perf_counter() - t0
    a = analyze_dataset(ds, cfg)
    a.timings["ingest_s"] = ing
    return a
