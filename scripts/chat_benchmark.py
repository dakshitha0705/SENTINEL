"""Measure the incident chat: empty replies and per-sentence verification on the demo dataset.

    python scripts/chat_benchmark.py      -> results/chat_benchmark.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinel.config import load_config  # noqa: E402
from sentinel.evidence import known_entities  # noqa: E402
from sentinel.ingest import guess_mapping, ingest, read_file  # noqa: E402
from sentinel.pipeline import analyze_dataset  # noqa: E402
from sentinel.slm import answer  # noqa: E402

QUESTIONS = ["What happened after the successful login?", "Why was this incident classified with this severity?",
             "Which devices were involved?", "What evidence contradicts the hypothesis?",
             "What is the attacker's home country?", "Which events support this conclusion?",
             "What should be investigated?"]


def main():
    cfg = load_config()
    d = ROOT / "data" / "samples" / "demo_unseen"
    files = [(p.name, p.read_bytes()) for p in (d / "siem_auth_export.csv", d / "edr_process_events.jsonl")]
    mp = {n: guess_mapping(read_file(n, b).frame) for n, b in files}
    mp["siem_auth_export.csv"].update({"actor": "Initiated By", "target_user": "Member Added"})
    a = analyze_dataset(ingest(files, mp), cfg)
    ke = known_entities(a.events)
    rows = []
    for inc in a.incidents:
        p = a.packs[inc["incident_id"]]
        for q in QUESTIONS:
            r = answer(p, q, cfg, ke)
            v = r["verification"]
            out = r["output"]
            rows.append({"incident": inc["incident_id"], "question": q, "source": r["source"], "error": r["error"],
                         "wall_s": (r.get("stats") or {}).get("wall_s"), "sentences": v["stats"]["factual_claims"],
                         "verified": v["stats"]["verified"], "cannot_answer": out.get("cannot_answer", ""),
                         "answer": [c["text"] for c in v["summary"]]})
            print(f"{inc['incident_id']} | {q[:40]:<40} | {r['source']:<13} | verified {v['stats']['verified']}/"
                  f"{v['stats']['factual_claims']} | {(out.get('cannot_answer') or '')[:50]}")
    silent = sum(1 for r in rows if not r["sentences"] and not r["cannot_answer"])
    s = sum(r["sentences"] for r in rows)
    v = sum(r["verified"] for r in rows)
    summary = {"questions": len(rows), "silent_replies": silent,
               "answered_by_slm": sum(r["source"] == "slm" for r in rows),
               "answered_by_deterministic_fallback": sum(r["source"] == "deterministic" and r["sentences"] > 0 for r in rows),
               "explicit_cannot_answer": sum(not r["sentences"] and bool(r["cannot_answer"]) for r in rows),
               "sentences": s, "verified": v, "verification_rate": round(v / s, 3) if s else None,
               "mean_wall_s": round(sum(r["wall_s"] or 0 for r in rows) / len(rows), 2)}
    print(summary)
    (ROOT / "results" / "chat_benchmark.json").write_text(json.dumps({"summary": summary, "rows": rows}, indent=1),
                                                          encoding="utf-8")


if __name__ == "__main__":
    main()
