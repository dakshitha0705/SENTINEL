"""End-to-end offline verification run.

Disconnect Wi-Fi / Ethernet first, then:   python scripts/offline_check.py
Runs the complete workflow (CSV + JSON + EVTX ingestion, detection, correlation, severity, live local SLM
with verification and self-repair, analyst chat with deterministic fallback, handoff note, HTML report,
JSON/CSV exports, accuracy evaluation) while sampling the network connections of
SENTINEL and Ollama. Writes results/offline_run.json (latest) and results/offline_runs/<stamp>.json.

The record states whether the internet was reachable during the run, so an online rehearsal can
never be mistaken for an offline test.
"""
from __future__ import annotations

import json
import platform
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "data"))

from sentinel.config import load_config  # noqa: E402
from sentinel.evidence import known_entities  # noqa: E402
from sentinel.ingest import guess_mapping, ingest, read_file  # noqa: E402
from sentinel.metrics import evaluate, load_ground_truth  # noqa: E402
from sentinel.perf import Monitor, internet_reachable, system_info  # noqa: E402
from sentinel.pipeline import analyze_dataset, analyze_paths  # noqa: E402
from sentinel.report import render_report  # noqa: E402
from sentinel import exports  # noqa: E402
from sentinel.handoff import handoff_claims, handoff_note  # noqa: E402
from sentinel.slm import answer, explain, status  # noqa: E402
from sentinel.verifier import verify_output  # noqa: E402


def main():
    cfg = load_config()
    online = internet_reachable()
    print(f"Internet reachable at start: {online}  ->  this is {'an ONLINE rehearsal' if online else 'an OFFLINE test'}")
    steps, t_all = {}, time.perf_counter()
    with Monitor(interval=0.2) as mon:
        t = time.perf_counter()
        st = status(cfg)
        steps["ollama_status"] = {"reachable": st["reachable"], "model_installed": st["model_installed"],
                                  "version": st.get("version"), "models": st["models"]}
        demo = ROOT / "data" / "samples" / "demo_unseen"
        files = [(p.name, p.read_bytes()) for p in (demo / "siem_auth_export.csv", demo / "edr_process_events.jsonl")]
        mp = {n: guess_mapping(read_file(n, b).frame) for n, b in files}
        mp["siem_auth_export.csv"].update({"actor": "Initiated By", "target_user": "Member Added"})
        ds = ingest(files, mp)
        steps["ingest"] = {"seconds": round(time.perf_counter() - t, 3), **{k: ds.summary[k] for k in
                           ("records_read", "accepted", "rejected", "duplicates")}, "formats": [f["format"] for f in ds.files]}
        t = time.perf_counter()
        a = analyze_dataset(ds, cfg)
        steps["analysis"] = {"seconds": round(time.perf_counter() - t, 3), "alerts": len(a.alerts),
                             "incidents": [(i["incident_id"], i["severity"]["level"], i["severity"]["score"], i["title"])
                                           for i in a.incidents], "timings": {k: round(v, 3) for k, v in a.timings.items()}}
        ke = known_entities(a.events)
        slm_runs = []
        for inc in a.incidents[:3]:
            p = a.packs[inc["incident_id"]]
            r = explain(p, cfg, use_cache=False, known=ke)
            v = verify_output(r["output"], p, ke)
            rep = r.get("repair") or {}
            slm_runs.append({"incident": inc["incident_id"], "source": r["source"], "error": r.get("error"),
                             **{k: r.get("stats", {}).get(k) for k in ("wall_s", "tokens_per_s", "output_tokens", "load_s")},
                             "verified": v["stats"]["verified"], "claims": v["stats"]["factual_claims"],
                             "repair": {k: rep.get(k) for k in ("attempted", "initial_verified", "initial_claims",
                                                                "final_verified", "final_claims", "latency_s")}})
            if inc is a.incidents[0]:
                html = render_report(a, inc["incident_id"], r, v)
                out = ROOT / "reports" / f"offline_{inc['incident_id']}.html"
                out.parent.mkdir(exist_ok=True)
                out.write_text(html, encoding="utf-8")
                steps["report"] = {"file": str(out.relative_to(ROOT)), "bytes": len(html.encode()),
                                   "external_refs": html.count("http://") + html.count("https://")}
        steps["slm"] = slm_runs
        # analyst chat (SLM answer or deterministic fallback; never silent)
        t = time.perf_counter()
        p0 = a.packs[a.incidents[0]["incident_id"]]
        chat = []
        for q in ("Why is the severity high?", "Which devices were involved?", "What is the attacker's home country?"):
            r = answer(p0, q, cfg, ke)
            chat.append({"question": q, "source": r["source"], "verified": r["verification"]["stats"]["verified"],
                         "sentences": r["verification"]["stats"]["factual_claims"],
                         "cannot_answer": bool((r["output"].get("cannot_answer") or "").strip())})
        steps["chat"] = {"seconds": round(time.perf_counter() - t, 2), "answers": chat,
                         "silent": sum(1 for c in chat if not c["sentences"] and not c["cannot_answer"])}
        inc0 = a.incidents[0]
        note = handoff_note(p0, inc0, "In progress", None, [])
        hv = verify_output({"summary": handoff_claims(note)}, p0, ke)["stats"]
        steps["handoff"] = {"verified": hv["verified"], "claims": hv["factual_claims"]}
        js, cs = exports.incidents_json(a, a.incidents), exports.incidents_csv(a, a.incidents)
        steps["exports"] = {"json_incidents": len(json.loads(js)["incidents"]), "csv_bytes": len(cs)}
        # EVTX conversion + detection on a public attack recording (if downloaded)
        evtx = ROOT / "data" / "public" / "evtx_attack_samples" / "kerberos_pwd_spray_4771.evtx"
        if evtx.exists():
            t = time.perf_counter()
            ax = analyze_paths([evtx], cfg)
            steps["evtx"] = {"file": evtx.name, "seconds": round(time.perf_counter() - t, 3),
                             "records": ax.dataset.files[0].get("evtx", {}).get("records"),
                             "rules_fired": sorted({x["rule"] for x in ax.alerts if x["rule"] != "CTX"}),
                             "incidents": len(ax.incidents)}
        t = time.perf_counter()
        ev = []
        for name in ("test_seed101", "test_seed202", "test_seed303"):
            d = ROOT / "data" / "samples" / name
            m = evaluate(analyze_paths([d / "auth_logs.csv", d / "endpoint_logs.json"], cfg), load_ground_truth(d))
            ev.append({k: m[k] for k in ("dataset", "incident_precision", "incident_recall", "f1", "false_positive_rate")})
        steps["evaluation"] = {"seconds": round(time.perf_counter() - t, 3), "results": ev}
    rec = {"recorded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z").strip() or datetime.now().isoformat(),
           "internet_reachable": online, "internet_reachable_after": internet_reachable(),
           "test_type": "online rehearsal" if online else "offline test",
           "total_seconds": round(time.perf_counter() - t_all, 2), "host": platform.node() and "local machine",
           "system": system_info(), "steps": steps, "monitor": mon.result()}
    res = ROOT / "results"
    (res / "offline_runs").mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for p in (res / "offline_run.json", res / "offline_runs" / f"{stamp}.json"):
        p.write_text(json.dumps(rec, indent=1, default=str), encoding="utf-8")
    m = rec["monitor"]
    print(f"Done in {rec['total_seconds']} s. Peak RAM: SENTINEL {m['peak_sentinel_rss_mb']} MB, Ollama {m['peak_ollama_rss_mb']} MB.")
    print(f"Connections observed: {len(m['loopback_connections'])} loopback, {len(m['external_connections'])} EXTERNAL")
    for c in m["external_connections"]:
        print("   EXTERNAL:", c)
    for s in slm_runs:
        print(f"   SLM {s['incident']}: {s['source']} {s['wall_s']} s, {s['tokens_per_s']} tok/s, verified {s['verified']}/{s['claims']}")
    print(f"   chat: {steps['chat']['silent']} silent replies; handoff verified {steps['handoff']['verified']}/"
          f"{steps['handoff']['claims']}; EVTX: {steps.get('evtx', {}).get('rules_fired')}")
    print("wrote results/offline_run.json")


if __name__ == "__main__":
    main()
