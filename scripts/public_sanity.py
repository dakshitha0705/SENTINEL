"""Qualitative sanity run on public OTRF Security-Datasets samples (no ground-truth labels exist).

    python -I scripts/get_public_data.py     # once, while online
    python scripts/public_sanity.py          # offline; writes results/public_sanity.json
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinel.ingest import ingest_paths  # noqa: E402
from sentinel.pipeline import analyze_dataset  # noqa: E402


def main():
    out = []
    files = sorted((ROOT / "data" / "public" / "otrf").glob("*/*.json"))
    if not files:
        print("No public data found. Run: python -I scripts/get_public_data.py")
        return 1
    for f in files:
        ds = ingest_paths([f])
        a = analyze_dataset(ds)
        actions = ds.events.groupby(["event_code"]).size().sort_values(ascending=False).head(10).to_dict()
        rec = {"file": f.name, "source": "OTRF Security-Datasets (MIT), atomic/windows/credential_access/host",
               "summary": ds.summary, "top_event_codes": actions,
               "alerts": dict(Counter(x["rule"] for x in a.alerts)),
               "incidents": [{"id": i["incident_id"], "level": i["severity"]["level"], "score": i["severity"]["score"],
                              "title": i["title"], "rules": i["rules"]} for i in a.incidents],
               "alert_reasons": [f"{x['rule']}: {x['reason']}" for x in a.alerts if x["rule"] != "CTX"],
               "timings_s": {k: round(v, 3) for k, v in a.timings.items()}}
        out.append(rec)
        print(f"{f.name}: {ds.summary['accepted']} events, {len(a.incidents)} incidents, alerts {rec['alerts']}")
        for i in rec["incidents"]:
            print(f"   {i['id']} {i['level']} {i['score']} {i['title']}")
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "public_sanity.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
