"""Integration tests for the live demo: NEXUS portal -> event stream -> SENTINEL live engine.

NEXUS is served on a real local port (scenarios send genuine HTTP requests); every test uses its own
temporary demo root, so nothing touches demo_data/ or any evaluation dataset.
"""
import json
import socket
import threading
import time
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from helpers import CFG

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = {"event_uid", "EventRecordID", "TimeCreated", "emitted_at", "EventID", "event_type", "source_app", "origin",
            "simulated", "source_address_simulated", "scenario_id", "session_id", "Computer", "TargetUserName",
            "IpAddress", "outcome", "payload"}


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def demo(tmp_path):
    from demo_target.app import create_app
    from sentinel.live import LiveEngine
    port = _free_port()
    app = create_app(root=tmp_path, base_url=f"http://127.0.0.1:{port}")
    srv = make_server("127.0.0.1", port, app, threaded=True)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    nx = app.extensions["nexus"]
    nx["runner"].speed = 0.05
    client = app.test_client()
    client.post("/api/demo/start")
    eng = LiveEngine(CFG, root=tmp_path)
    eng.poll()
    yield {"app": app, "client": client, "nx": nx, "eng": eng, "root": tmp_path}
    nx["runner"].stop()
    srv.shutdown()


def run(d, sid):
    r = d["nx"]["runner"]
    ok, msg = r.start(sid)
    assert ok, msg
    while r.busy():
        d["eng"].poll()
        time.sleep(0.05)
    assert r.status["state"] == "completed", r.status
    d["eng"].poll()
    return d["eng"].analysis


def scenario_incidents(a, sid, eng):
    uids = {u for u, rec in eng.records.items() if rec.get("scenario_id") == sid}
    rid = a.events.set_index("event_id")["record_id"].astype(str)
    out = []
    for inc in a.incidents:
        recs = {eng.by_rid[rid[e]]["event_uid"] for e in inc["event_ids"] if rid[e] in eng.by_rid}
        if recs & uids:
            out.append(inc)
    return out


# --------------------------------------------------------------------------- NEXUS application

def test_nexus_auth_hashing_lockout_and_header_spoofing(demo):
    c, ids = demo["client"], demo["nx"]["ids"]
    assert all(u["hash"] != ids.passwords[n] and u["hash"].startswith(("scrypt:", "pbkdf2:")) for n, u in ids.users.items())
    assert c.post("/login", data={"username": "arjun.rao", "password": "nope"}).status_code == 401
    r = c.post("/login", data={"username": "arjun.rao", "password": ids.passwords["arjun.rao"]})
    assert r.status_code == 302 and c.get("/dashboard").status_code == 200
    assert c.get("/admin").status_code == 403                       # employee is not an admin
    c.get("/logout")
    # a client WITHOUT the controller token cannot choose its source address
    c.post("/login", data={"username": "leela.menon", "password": "x"}, headers={"X-NEXUS-Sim-Source": "203.0.113.9"})
    last = demo["nx"]["stream"].read_all()[-1]
    assert last["IpAddress"] == "127.0.0.1" and last["source_address_simulated"] is False
    for _ in range(15):                                              # lockout after 15 failures, no bypass
        c.post("/login", data={"username": "divya.pillai", "password": "bad"})
    assert c.post("/login", data={"username": "divya.pillai", "password": ids.passwords["divya.pillai"]}).status_code == 401
    assert any(e["EventID"] == "4740" for e in demo["nx"]["stream"].read_all())


def test_event_schema_ordering_and_provenance(demo):
    run(demo, "G")
    evs = demo["nx"]["stream"].read_all()
    assert all(REQUIRED <= set(e) for e in evs)
    assert len({e["event_uid"] for e in evs}) == len(evs)
    assert [e["EventRecordID"] for e in evs] == list(range(1, len(evs) + 1))
    assert all(a["emitted_at"] <= b["emitted_at"] for a, b in zip(evs, evs[1:]))
    g = [e for e in evs if e["scenario_id"] == "G"]
    assert {e["origin"] for e in g} == {"nexus-app", "simulated-endpoint"}
    assert all(e["simulated"] for e in g if e["origin"] == "simulated-endpoint")
    assert all(not e["simulated"] for e in g if e["origin"] == "nexus-app")
    assert all(e["source_address_simulated"] for e in g if e["origin"] == "nexus-app")
    assert all(e["origin"] == "baseline-backfill" and e["simulated"] for e in evs if e["scenario_id"] is None and e["EventID"] == "4624")


# --------------------------------------------------------------------------- live pipeline

def test_incremental_ingestion_duplicates_partial_lines_and_restart(demo):
    from sentinel.live import LiveEngine
    eng, stream = demo["eng"], demo["nx"]["stream"]
    base = len(eng.records)
    assert base == stream.seq > 0
    assert eng.poll() == 0                                           # nothing new
    run(demo, "B")
    assert len(eng.records) == stream.seq
    # a duplicate line (same event_uid) and a partial line are not ingested
    with open(stream.path, "ab") as fh:
        fh.write(open(stream.path, "rb").read().splitlines()[-1] + b"\n")
        fh.write(b'{"event_uid": "NX-partial"')
    n = len(eng.records)
    eng.poll()
    assert len(eng.records) == n and eng.duplicates == 1
    with open(stream.path, "ab") as fh:                              # complete the partial line -> now malformed JSON? no:
        fh.write(b', "EventRecordID": 999999, "TimeCreated": "2026-11-23T10:00:00Z", "EventID": "4624", "emitted_at": 1}\n')
    eng.poll()
    assert "NX-partial" in eng.records
    # restart recovery: a new engine resumes from the persisted cursor without re-counting
    cur = json.loads((eng.sdir() / "sentinel_cursor.json").read_text())
    eng2 = LiveEngine(CFG, root=demo["root"])
    assert eng2.poll() == 0 and len(eng2.records) == len(eng.records) and eng2.offset == cur["offset"]
    assert eng2.analysis is not None and len(eng2.analysis.incidents) == len(eng.analysis.incidents)


def test_normal_and_benign_scenarios_create_no_incident(demo):
    a = run(demo, "A")
    assert scenario_incidents(a, "A", demo["eng"]) == []
    a = run(demo, "H")
    assert scenario_incidents(a, "H", demo["eng"]) == []            # approved change in a ticket window, new laptop, typos
    r6 = [x for x in a.alerts if x["rule"] == "R6"]
    assert r6 == []


def test_attack_scenarios_detected(demo):
    eng = demo["eng"]
    a = run(demo, "B")
    inc = scenario_incidents(a, "B", eng)
    assert inc and "R1" in inc[0]["rules"]
    a = run(demo, "C")
    inc = scenario_incidents(a, "C", eng)
    assert inc and "R2" in inc[0]["rules"]
    a = run(demo, "D")
    inc = scenario_incidents(a, "D", eng)
    assert inc and {"R1", "R3"} <= set(inc[0]["rules"])
    a = run(demo, "E")
    r6 = [x for x in a.alerts if x["rule"] == "R6"]
    assert len(r6) == 1 and r6[0]["details"]["actor"] == "omar.khan"   # the approved change is NOT flagged
    a = run(demo, "F")
    inc = scenario_incidents(a, "F", eng)
    assert inc and {"R7", "R8"} <= set(inc[0]["rules"])


def test_full_storyline_uses_generated_event_ids_and_escalates(demo):
    eng = demo["eng"]
    a = run(demo, "G")
    inc = scenario_incidents(a, "G", eng)
    assert len(inc) == 1
    i = inc[0]
    assert {"R1", "R3", "R6", "R7", "R8"} <= set(i["rules"]) and i["severity"]["level"] == "Critical"
    rid = a.events.set_index("event_id")["record_id"].astype(str)
    uids = [eng.by_rid[rid[e]]["event_uid"] for e in i["event_ids"]]
    assert all(u.startswith("NX-" + eng.session_id) for u in uids)
    kinds = [n["kind"] for n in eng.notifications if n["incident_id"] == i["incident_id"]]
    assert "new" in kinds and "escalated" in kinds                   # severity grew as evidence accumulated
    t = eng._track_of(i)
    assert t["latency_s"] is not None and t["latency_s"] < 30 and len(t["history"]) >= 2
    status = json.loads((eng.sdir() / "sentinel_status.json").read_text())
    assert status["events_ingested"] == len(eng.records) and status["incidents"]


def test_live_incident_report_verification_and_globe(demo):
    from sentinel import geospatial
    from sentinel.evidence import known_entities
    from sentinel.report import render_report
    from sentinel.slm import template_explanation
    from sentinel.verifier import verify_output
    a = run(demo, "G")
    i = a.incidents[0]
    p = a.packs[i["incident_id"]]
    ver = verify_output(template_explanation(p), p, known_entities(a.events))
    assert ver["stats"]["verification_rate"] == 1.0
    html = render_report(a, i["incident_id"], {"source": "template"}, ver)
    assert i["incident_id"] in html and "http://" not in html.replace("http://198.51.100.9", "")
    g = geospatial.markers(a)
    assert g["mode"] == "intel"
    labels = {m["label"] for m in g["markers"]}
    assert any("simulated source" in l for l in labels)
    assert not any(m for m in g["markers"] if "127.0.0.1" in m.get("ips", []))   # loopback never located


def test_reset_isolation(demo):
    root, stream = demo["root"], demo["nx"]["stream"]
    old = stream.session_id
    run(demo, "B")
    samples = ROOT / "data" / "samples" / "test_seed101" / "auth_logs.csv"
    before = samples.stat().st_mtime
    demo["client"].post("/api/demo/reset")
    assert stream.session_id != old and (root / "sessions" / old / "events.jsonl").exists()
    eng = demo["eng"]
    eng.poll()
    assert eng.session_id == stream.session_id and not scenario_incidents(eng.analysis, "B", eng)
    assert samples.stat().st_mtime == before
    assert root.resolve() != (ROOT / "data").resolve()


def test_runner_control_pause_resume_stop_and_conflicts(demo):
    r, c = demo["nx"]["runner"], demo["client"]
    r.speed = 1.0                                         # real pacing so control actions land mid-run
    assert c.post("/api/demo/run/G").status_code == 200
    assert c.post("/api/demo/run/B").status_code == 409   # one scenario at a time
    time.sleep(1.0)
    c.post("/api/demo/pause")
    time.sleep(0.6)
    step = r.status["step"]
    time.sleep(1.2)
    assert r.status["state"] == "paused" and r.status["step"] == step
    c.post("/api/demo/resume")
    time.sleep(1.0)
    assert r.status["step"] > step
    c.post("/api/demo/stop")
    r.wait(10)
    assert r.status["state"] == "stopped" and r.status["step"] < r.status["steps"]
    st = c.get("/api/demo/status").get_json()
    assert st["runner"]["state"] == "stopped" and st["events_emitted"] == demo["nx"]["stream"].seq
    assert c.post("/api/demo/run/Z").status_code == 409


def test_nexus_restart_continues_the_session_stream(demo):
    from demo_target.app import create_app
    stream = demo["nx"]["stream"]
    sid, seq = stream.session_id, stream.seq
    app2 = create_app(root=demo["root"])                 # simulates a NEXUS process restart
    s2 = app2.extensions["nexus"]["stream"]
    assert s2.session_id == sid and s2.seq == seq
    app2.test_client().post("/login", data={"username": "arjun.rao", "password": "bad"})
    evs = s2.read_all()
    assert evs[-1]["EventRecordID"] == seq + 1 and len({e["event_uid"] for e in evs}) == len(evs)
    demo["eng"].poll()
    assert evs[-1]["event_uid"] in demo["eng"].records
