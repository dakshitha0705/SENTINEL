"""External evaluation on public attack recordings (data/external_catalog.json).

    python -I scripts/get_external_data.py   # once, online
    python scripts/external_eval.py          # offline

Each recording is analysed on its own through the normal pipeline (EVTX files go through the offline
converter). The datasets carry per-recording ATT&CK labels, not event-level ground truth, so this
reports SCENARIO DETECTION only: did one of the expected rules fire on the recording? Precision/recall
are deliberately not computed. Results are kept separate from the synthetic metrics.
"""
from __future__ import annotations

import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from get_external_data import CATALOG, local_dir  # noqa: E402
from sentinel.config import load_config  # noqa: E402
from sentinel.ingest import ingest_paths  # noqa: E402
from sentinel.pipeline import analyze_dataset  # noqa: E402

SUPPORTED = {"login_success", "login_failure", "privilege_logon", "group_add", "group_enum", "process_start",
             "log_cleared", "device_connected"}


def files_for(rec) -> list[Path]:
    d = local_dir(rec)
    name = Path(rec["path"]).name
    if name.endswith(".zip"):
        return sorted(p for p in d.iterdir() if p.suffix == ".json")
    return [d / name]


def explain_miss(rec, ds, alerts) -> str:
    acts = ds.events["action"].value_counts().to_dict()
    codes = Counter(ds.events["event_code"]).most_common(6)
    usable = {a: n for a, n in acts.items() if a in SUPPORTED}
    if not usable:
        return (f"no event types SENTINEL analyses (top codes: {', '.join(f'{c}x{n}' for c, n in codes)}); "
                "the behaviour is only visible in telemetry outside the supported schema")
    return (f"supported events present ({', '.join(f'{a}={n}' for a, n in usable.items())}) but no expected rule "
            "matched: the technique is outside the rule patterns")


def main():
    cfg = load_config()
    rows = []
    for rec in CATALOG["recordings"]:
        paths = files_for(rec)
        if not all(p.exists() for p in paths) or not paths:
            rows.append({**rec, "status": "not downloaded"})
            continue
        t0 = time.perf_counter()
        ds = ingest_paths(paths)
        a = analyze_dataset(ds, cfg)
        secs = time.perf_counter() - t0
        fired = Counter(x["rule"] for x in a.alerts if x["rule"] != "CTX")
        exp = rec["expected_rules"]
        detected = any(fired.get(r) for r in exp) if exp else None
        row = {**rec, "files": [p.name for p in paths], "events": int(len(ds.events)),
               "rejected": int(ds.summary["rejected"]), "duplicates": int(ds.summary["duplicates"]),
               "unevaluable": int(ds.summary["unevaluable"]),
               "by_action": ds.summary["by_action"],
               "evtx": [f.get("evtx") for f in ds.files if f.get("evtx")],
               "rules_fired": dict(fired), "incidents": [
                   {"id": i["incident_id"], "level": i["severity"]["level"], "score": i["severity"]["score"],
                    "title": i["title"]} for i in a.incidents],
               "seconds": round(secs, 3)}
        if exp:
            row["status"] = "detected" if detected else "missed"
            if not detected:
                row["why_missed"] = explain_miss(rec, ds, a.alerts)
        else:
            row["status"] = "control (no rule expected)"
        rows.append(row)
        print(f"{rec['id']} {row['status']:<28} events={row['events']:<6} fired={dict(fired)} | {rec['behaviour']}")
    scored = [r for r in rows if r["status"] in ("detected", "missed")]
    summary = {"recordings": len(rows), "with_expected_rule": len(scored),
               "detected": sum(r["status"] == "detected" for r in scored),
               "missed": sum(r["status"] == "missed" for r in scored),
               "controls": sum(r["status"].startswith("control") for r in rows),
               "techniques_detected": sorted({r["technique"] for r in scored if r["status"] == "detected"}),
               "techniques_missed": sorted({r["technique"] for r in scored if r["status"] == "missed"})}
    print("SUMMARY:", json.dumps(summary))
    out = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "method": "scenario detection on technique-labelled recordings; no event-level ground truth, so no "
                     "precision/recall", "sources": CATALOG["sources"], "summary": summary, "recordings": rows}
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "external_eval.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    print("wrote results/external_eval.json")


if __name__ == "__main__":
    main()
