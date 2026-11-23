"""Incident exports: JSON (full, machine-readable) and CSV (one row per incident / per evidence event)."""
from __future__ import annotations

import io
import json
from datetime import datetime, timezone

import pandas as pd

from . import __version__
from .correlate import storyline


def _iso(x):
    return pd.Timestamp(x).isoformat()


def incident_record(analysis, inc: dict, verification: dict | None = None, workflow: dict | None = None) -> dict:
    pack = analysis.packs[inc["incident_id"]]
    rec = {
        "incident_id": inc["incident_id"], "title": inc["title"],
        "severity": {k: inc["severity"][k] for k in ("level", "score", "raw_score", "breakdown", "confidence")},
        "start": _iso(inc["start"]), "end": _iso(inc["end"]),
        "users": inc["users"], "hosts": inc["hosts"], "source_ips": inc["ips"], "rules": inc["rules"],
        "mitre": inc["mitre"], "stages": inc["stages"],
        "storyline": [{"alert_id": s["alert_id"], "time": _iso(s["time"]), "rule": s["rule"], "name": s["name"],
                       "reason": s["reason"], "membership": s["membership"], "context": s["context"],
                       "event_ids": s["event_ids"], "link": s["link"]} for s in storyline(inc, analysis.alerts_by_id)],
        "evidence_event_ids": inc["event_ids"],
        "facts": [{k: f[k] for k in ("id", "kind", "text", "event_ids")} for f in pack["facts"]],
        "contradicting_fact_ids": pack["contradicting_fact_ids"], "limitations": pack["limitations"],
        "playbooks": pack["playbooks"], "evidence_pack_hash": pack["hash"],
    }
    if verification:
        rec["slm_verification"] = {
            "stats": verification["stats"],
            "verified_statements": [{"text": c["text"], "fact_ids": c["fact_ids"]}
                                    for c in verification["summary"] + verification["conclusions"] if c["status"] == "Verified"],
            "unverified_statements": [{"text": c["text"], "problems": c["problems"]}
                                      for c in verification["summary"] + verification["conclusions"] if c["status"] != "Verified"],
            "hypotheses": [{k: h[k] for k in ("text", "status", "supporting_fact_ids", "contradicting_fact_ids", "how_to_confirm")}
                           for h in verification["hypotheses"]]}
    if workflow:
        rec["workflow"] = workflow
    return rec


def incidents_json(analysis, incidents, verifications: dict | None = None, workflows: dict | None = None) -> bytes:
    doc = {"generator": f"SENTINEL {__version__}", "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "dataset_files": [{k: f[k] for k in ("name", "sha256", "format", "rows", "accepted")} for f in analysis.dataset.files],
           "incidents": [incident_record(analysis, i, (verifications or {}).get(i["incident_id"]),
                                         (workflows or {}).get(i["incident_id"])) for i in incidents]}
    return json.dumps(doc, indent=1, ensure_ascii=False, default=str).encode("utf-8")


def incidents_csv(analysis, incidents, workflows: dict | None = None) -> bytes:
    rows = []
    for i in incidents:
        wf = (workflows or {}).get(i["incident_id"], {})
        rows.append({"incident_id": i["incident_id"], "severity": i["severity"]["level"], "score": i["severity"]["score"],
                     "confidence": i["severity"]["confidence"]["level"], "title": i["title"],
                     "start_utc": _iso(i["start"]), "end_utc": _iso(i["end"]), "users": ";".join(i["users"]),
                     "hosts": ";".join(i["hosts"]), "source_ips": ";".join(i["ips"]), "rules": ";".join(i["rules"]),
                     "mitre": ";".join(i["mitre"]), "events": len(i["event_ids"]),
                     "evidence_event_ids": ";".join(i["event_ids"]),
                     "status": wf.get("status", ""), "disposition": wf.get("disposition", ""),
                     "evidence_pack_hash": analysis.packs[i["incident_id"]]["hash"]})
    buf = io.StringIO()
    pd.DataFrame(rows).to_csv(buf, index=False)
    return buf.getvalue().encode("utf-8")


def evidence_csv(analysis, inc) -> bytes:
    cols = ["event_id", "timestamp", "source_file", "source_row", "record_id", "event_code", "action", "user", "actor",
            "target_user", "host", "src_ip", "group", "process", "parent_process", "command_line"]
    df = analysis.events.set_index("event_id", drop=False).loc[inc["event_ids"], cols].copy()
    df["timestamp"] = df["timestamp"].astype(str)
    return df.to_csv(index=False).encode("utf-8")
