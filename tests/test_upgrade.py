"""Tests for the upgrade: new rules, delayed success, EVTX, comparison/ablation, typed claims, self-repair,
chat fallback, handoff, exports, geospatial integrity, graph, search and local settings."""
import json
from datetime import timedelta
from pathlib import Path

import pytest

from helpers import CFG, LogBuilder
from sentinel.config import override

ROOT = Path(__file__).resolve().parent.parent
EVTX = ROOT / "data" / "public" / "evtx_attack_samples"


def rules_of(a):
    return [x["rule"] for x in a.alerts]


# --------------------------------------------------------------------------- detection

def test_r12_sustained_brute_force_detected_but_not_r1():
    b = LogBuilder().history("asha", "WS1", "10.0.1.5")
    for k in range(9):                                   # 9 failures over 45 min: below R1 (8 in 10), R12 = 8 in 60
        b.fail(b.at(6, 2, 5 * k), "asha", "WS1", "203.0.113.9")
    a = b.analyze()
    assert "R12" in rules_of(a) and "R1" not in rules_of(a)


def test_r12_ignores_source_that_already_logged_on_as_the_account():
    b = LogBuilder().history("asha", "WS1", "10.0.1.5")
    for k in range(25):                                  # stale saved password on own workstation
        b.fail(b.at(6, 8) + timedelta(minutes=20 * k), "asha", "FS01", "10.0.1.5")
    assert "R12" not in rules_of(b.analyze())


def test_r13_small_spray_detected():
    b = LogBuilder()
    for u in ("u1", "u2", "u3"):
        b.history(u, "WS-" + u, "10.0.2." + u[-1])
    for k, u in enumerate(("u1", "u2", "u3", "u1")):
        b.fail(b.at(6, 3, k), u, "DC01", "198.51.100.7")
    a = b.analyze()
    assert "R13" in rules_of(a) and "R2" not in rules_of(a)
    assert any("R13" in i["rules"] for i in a.incidents)


def test_r13_not_fired_for_shared_pc_typos():
    b = LogBuilder()
    for u in ("u1", "u2", "u3"):
        b.history(u, "WS-" + u, "10.0.2." + u[-1])
        b.fail(b.at(6, 11, int(u[-1]) * 4), u, "WS-MEET", "10.0.5.50")
        b.logon(b.at(6, 11, int(u[-1]) * 4, 40), u, "WS-MEET", "10.0.5.50")
    assert "R13" not in rules_of(b.analyze())


def test_r3_delayed_success_links_with_reduced_weight():
    b = LogBuilder().history("ravi", "WS2", "10.0.1.6")
    for k in range(12):
        b.fail(b.at(6, 2, 0, 10 * k), "ravi", "WS2", "203.0.113.50")
    b.logon(b.at(6, 2, 45), "ravi", "WS2", "203.0.113.50")       # ~43 min after the burst
    a = b.analyze()
    r3 = [x for x in a.alerts if x["rule"] == "R3"]
    assert r3 and r3[0]["details"]["late"] and 0.4 <= r3[0]["details"]["decay"] < 1
    inc = next(i for i in a.incidents if "R3" in i["rules"])
    assert "R1" in inc["rules"]                                    # causal link despite > 30 min gap
    line = next(l for l in inc["severity"]["breakdown"] if l["factor"].startswith("R3"))
    assert 0 < line["points"] < CFG["severity"]["rule_weights"]["high"]


def test_r3_success_after_60_minutes_not_linked():
    b = LogBuilder().history("ravi", "WS2", "10.0.1.6")
    for k in range(12):
        b.fail(b.at(6, 2, 0, 10 * k), "ravi", "WS2", "203.0.113.50")
    b.logon(b.at(6, 3, 30), "ravi", "WS2", "203.0.113.50")
    assert "R3" not in rules_of(b.analyze())


def test_r14_group_discovery_is_context_and_maps_t1069():
    b = LogBuilder()
    b.process(b.at(3, 10), "mallory", "DC01", "net.exe", "cmd.exe", 'net group "Domain Admins" /domain')
    b.process(b.at(3, 11), "admin01", "DC01", "net.exe", "cmd.exe", "net localgroup administrators")
    a = b.analyze()
    r14 = [x for x in a.alerts if x["rule"] == "R14"]
    assert len(r14) == 2 and all(x["context"] for x in r14)
    assert {x["mitre"][0] for x in r14} == {"T1069.002", "T1069.001"}
    assert next(x for x in r14 if "admin01" in x["users"])["confidence"] == "low"
    assert not a.incidents                                         # discovery alone never creates an incident


# --------------------------------------------------------------------------- EVTX / external formats

def test_evtx_rejects_non_evtx_with_diagnostic():
    from sentinel.evtx_converter import EvtxError, convert_evtx
    with pytest.raises(EvtxError, match="not an EVTX file"):
        convert_evtx(b"hello world, not a log", "x.evtx")
    from sentinel.ingest import ingest
    ds = ingest([("broken.evtx", b"garbage")])
    assert ds.summary["accepted"] == 0 and ds.files[0]["format"].startswith("evtx")


@pytest.mark.skipif(not (EVTX / "kerberos_pwd_spray_4771.evtx").exists(), reason="public EVTX samples not downloaded")
def test_evtx_kerberos_spray_detected():
    from sentinel.pipeline import analyze_paths
    a = analyze_paths([EVTX / "kerberos_pwd_spray_4771.evtx"])
    assert a.dataset.files[0]["format"] == "evtx" and a.dataset.files[0]["evtx"]["records"] > 0
    assert set(a.events["record_id"]) and (a.events["event_code"] == "4771").any()
    assert "R2" in rules_of(a)


def test_kerberos_and_system_log_codes_normalised():
    from sentinel.ingest import ingest
    rows = ("EventID,TimeCreated,Computer,TargetUserName,IpAddress,Status,Channel,Provider\n"
            "4771,2026-11-02 01:00:00,DC1,bob,10.1.1.1,0x18,Security,Microsoft-Windows-Security-Auditing\n"
            "4768,2026-11-02 01:00:01,DC1,eve,10.1.1.1,0x6,Security,Microsoft-Windows-Security-Auditing\n"
            "4768,2026-11-02 01:00:02,DC1,al,10.1.1.1,0x0,Security,Microsoft-Windows-Security-Auditing\n"
            "104,2026-11-02 01:00:03,DC1,,,,System,Microsoft-Windows-Eventlog\n")
    ev = ingest([("k.csv", rows.encode())]).events.set_index("event_code")
    acts = list(ingest([("k.csv", rows.encode())]).events["action"])
    assert acts == ["login_failure", "login_failure", "other", "log_cleared"]


# --------------------------------------------------------------------------- comparison / ablation / metrics

@pytest.fixture(scope="module")
def dev():
    from sentinel.metrics import load_ground_truth
    from sentinel.pipeline import analyze_paths
    d = ROOT / "data" / "samples" / "dev_seed7"
    return analyze_paths([d / "auth_logs.csv", d / "endpoint_logs.json"], CFG), load_ground_truth(d)


def test_compression_and_naive_comparison(dev):
    from sentinel.comparison import compression, evaluate_items
    from sentinel.naive import run_naive
    a, gt = dev
    c = compression(a)
    assert c["alerts"] > c["incidents"] > 0 and c["compression_pct"] == round((1 - c["incidents"] / c["alerts"]) * 100, 1)
    naive = run_naive(a.events, CFG)
    rn, rs = evaluate_items(naive, a.events, gt), evaluate_items(a.incidents, a.events, gt)
    assert rn["strict"]["items"] > rs["strict"]["items"]            # more items for the analyst
    assert rs["strict"]["precision"] >= rn["strict"]["precision"]
    assert rn["lenient"]["recall"] >= rn["strict"]["recall"]


def test_per_scenario_jaccard_reports_misses(dev):
    from sentinel.comparison import per_scenario_jaccard
    from sentinel.metrics import evaluate
    a, gt = dev
    m = evaluate(a, gt)
    gt2 = {**gt, "incidents": gt["incidents"] + [{"scenario_id": "S9", "name": "phantom", "record_ids": [1],
                                                 "expected_severity": "Low"}]}
    m2 = evaluate(a, gt2)
    pj = per_scenario_jaccard([m2])
    assert pj["S9"]["missed"] == 1 and pj["S9"]["mean_jaccard"] is None
    assert all(0 < v["mean_jaccard"] <= 1 for k, v in pj.items() if k != "S9")


def test_ablation_configs_change_behaviour(dev):
    from sentinel.comparison import ablation_cfg
    from sentinel.pipeline import analyze_dataset
    a, _ = dev
    nb = analyze_dataset(a.dataset, ablation_cfg(CFG, "no_baselines"))
    assert not any(x["rule"] in ("R4", "R5", "R9") for x in nb.alerts)
    nc = analyze_dataset(a.dataset, ablation_cfg(CFG, "no_context"))
    assert len(nc.incidents) > len(a.incidents) and all(not x["context"] for x in nc.alerts if x["rule"] != "CTX")
    na = analyze_dataset(a.dataset, ablation_cfg(CFG, "no_allowlists"))
    assert len(na.incidents) >= len(a.incidents)


# --------------------------------------------------------------------------- evidence contract

@pytest.fixture(scope="module")
def pack(dev):
    from sentinel.evidence import known_entities
    a, _ = dev
    inc = next(i for i in a.incidents if "R1" in i["rules"])
    return a.packs[inc["incident_id"]], known_entities(a.events), inc


def test_typed_claim_fields_are_verified(pack):
    from sentinel.verifier import verify_claim
    p, ke, inc = pack
    f = next(x for x in p["facts"] if x["kind"] == "detection" and " R1 " in f" {x['text']} ")
    n = len(f["event_ids"])
    ok = verify_claim({"text": f["text"], "fact_ids": [f["id"]], "count": n, "user": f["users"][0]}, p, ke)
    assert ok["status"] == "Verified", ok["problems"]
    bad = verify_claim({"text": f["text"], "fact_ids": [f["id"]], "count": n + 7, "host": "NOT-A-HOST",
                        "event_ids": ["EVT-999999"], "start_time": "23:59"}, p, ke)
    probs = " ".join(bad["problems"])
    assert bad["status"] == "Unverified"
    for s in ("typed count", "typed host", "typed event", "typed start_time"):
        assert s in probs


def test_self_repair_round_fixes_or_rejects(pack, monkeypatch):
    from sentinel import slm
    p, ke, inc = pack
    f = next(x for x in p["facts"] if x["kind"] == "detection")
    good = {"summary": [{"text": f["text"], "fact_ids": [f["id"]], "claim_type": "detection"}],
            "supported_conclusions": [], "hypotheses": [], "recommended_actions": [], "open_questions": []}
    bad = json.loads(json.dumps(good))
    bad["summary"][0]["text"] = "There were 987 failed logons."
    calls = []

    def fake_chat(cfg, messages, fmt, on_token=None, seed=42, temperature=None):
        calls.append(messages)
        return json.dumps(bad if len(calls) == 1 else good), {"wall_s": 0.1}
    monkeypatch.setattr(slm, "_chat", fake_chat)
    cfg = override(CFG, **{"slm.cache_dir": ".cache/test_slm"})
    r = slm.explain(p, cfg, use_cache=False, known=ke, repair=True)
    assert len(calls) == 2 and "987" in calls[1][-1]["content"]          # specific verifier feedback sent back
    assert r["repair"]["initial_verified"] == 0 and r["repair"]["final_verified"] == r["repair"]["final_claims"] > 0
    calls.clear()
    monkeypatch.setattr(slm, "_chat", lambda *a_, **k: (calls.append(1), (json.dumps(bad), {}))[1])
    r2 = slm.explain(p, cfg, use_cache=False, known=ke, repair=True)
    assert r2["repair"]["still_failing"] == 1                             # never overrides the verifier


def test_chat_falls_back_deterministically(pack, monkeypatch):
    from sentinel import slm
    p, ke, inc = pack
    monkeypatch.setattr(slm, "ask", lambda *a_, **k: {"ok": True, "output": {"answer": [], "cannot_answer": ""}, "stats": {}})
    for q in ("Why is the severity high?", "Which devices were involved?", "What happened next?",
              "Which events support this conclusion?", "What should be investigated?"):
        r = slm.answer(p, q, CFG, ke)
        assert r["source"] == "deterministic"
        assert r["verification"]["summary"] and all(c["status"] == "Verified" for c in r["verification"]["summary"]), q
    r = slm.answer(p, "What is the attacker's favourite colour?", CFG, ke)
    assert not r["verification"]["summary"] and r["output"]["cannot_answer"]   # explicit, never silent


def test_handoff_note_factual_lines_verify(pack):
    from sentinel.handoff import handoff_claims, handoff_note, handoff_text
    from sentinel.verifier import verify_output
    p, ke, inc = pack
    note = handoff_note(p, inc, "In progress", "Needs investigation", [{"note": "called user"}])
    v = verify_output({"summary": handoff_claims(note)}, p, ke)
    assert v["stats"]["verified"] == v["stats"]["factual_claims"] > 0
    txt = handoff_text(note)
    assert inc["incident_id"] in txt and "called user" in txt and "Next actions" in txt


def test_exports_json_and_csv(dev):
    import io
    import pandas as pd
    from sentinel import exports
    a, _ = dev
    doc = json.loads(exports.incidents_json(a, a.incidents))
    assert len(doc["incidents"]) == len(a.incidents)
    assert doc["incidents"][0]["evidence_event_ids"] and doc["incidents"][0]["evidence_pack_hash"]
    df = pd.read_csv(io.BytesIO(exports.incidents_csv(a, a.incidents)))
    assert list(df["incident_id"]) == [i["incident_id"] for i in a.incidents]
    ev = pd.read_csv(io.BytesIO(exports.evidence_csv(a, a.incidents[0])))
    assert len(ev) == len(a.incidents[0]["event_ids"])


# --------------------------------------------------------------------------- globe / graph / search

def test_globe_explore_mode_without_location_fields(dev):
    from sentinel import geospatial
    a, _ = dev
    g = geospatial.markers(a)
    assert g["mode"] == "explore" and g["markers"] == [] and g["arcs"] == []


def test_globe_markers_only_from_logged_coordinates():
    from sentinel import geospatial
    from sentinel.pipeline import analyze_dataset
    from sentinel.ingest import ingest
    csv = ("TimeCreated,EventID,EventRecordID,Computer,TargetUserName,IpAddress,Src Latitude,Src Longitude,Src Location\n"
           "2026-11-02 01:00:00,4624,1,WS1,bob,203.0.113.4,1.35,103.82,Singapore\n"
           "2026-11-02 01:00:05,4624,2,WS1,bob,10.0.0.4,,,\n"
           "2026-11-02 01:00:09,4624,3,WS1,bob,10.0.0.5,999,5,bad\n")
    a = analyze_dataset(ingest([("g.csv", csv.encode())]), CFG)
    g = geospatial.markers(a)
    assert g["mode"] == "intel" and len(g["markers"]) == 1 and g["located_events"] == 1   # invalid lat dropped
    m = g["markers"][0]
    assert (m["lat"], m["lng"]) == (1.35, 103.82) and m["label"] == "Singapore"
    recs = geospatial.marker_records(a, g, m["id"])
    assert list(recs["src_ip"]) == ["203.0.113.4"]
    assert "event_ids" not in geospatial.for_component(g)["markers"][0]


def test_graph_edges_come_from_correlation(dev):
    from sentinel import graph
    a, _ = dev
    inc = max(a.incidents, key=lambda i: len(i["alert_ids"]))
    data = graph.build(a, [inc])
    links = [e for e in data["edges"] if e["kind"] == "link"]
    assert {(e["from"], e["to"]) for e in links} == {(l["from"], l["to"]) for l in inc["links"]}
    for e in data["edges"]:
        if e["kind"] == "involves":
            al = a.alerts_by_id[e["from"]]
            assert e["to"].split(":", 1)[1] in al["users"] + al["hosts"] + al["ips"]
    d = graph.node_details(a, inc["incident_id"])
    assert d["type"] == "incident" and d["incident"]["incident_id"] == inc["incident_id"]


def test_global_search(dev):
    from sentinel.search import search
    a, _ = dev
    u = a.incidents[0]["users"][0]
    r = search(a, u)
    assert any(i["incident_id"] == a.incidents[0]["incident_id"] for i in r["incidents"]) and r["total_events"] > 0
    assert search(a, "")["incidents"] == []


def test_local_settings_override_and_validation(tmp_path, monkeypatch):
    from sentinel import config
    monkeypatch.setattr(config, "LOCAL_SETTINGS", tmp_path / "settings.yaml")
    config.save_local_settings({"slm": {"model": "qwen2.5:1.5b"}})
    assert config.load_config(local=True)["slm"]["model"] == "qwen2.5:1.5b"
    assert config.load_config()["slm"]["model"] == "qwen2.5:3b"          # scripts/tests unaffected
    with pytest.raises(config.ConfigError):
        config.save_local_settings({"correlation": {"max_gap_minutes": -5}})


def test_workspace_status_notes_dispositions_and_suppressions(dev, tmp_path):
    from sentinel import workspace as ws
    a, _ = dev
    con = ws.connect(tmp_path / "analyst.db")
    inc = a.incidents[0]
    key = ws.incident_key(a, inc)
    assert ws.current_status(con, key) == "New"
    ws.set_status(con, key, inc["incident_id"], "In progress")
    ws.add_note(con, key, inc["incident_id"], "called the user")
    ws.set_disposition(con, key, inc["incident_id"], "Confirmed", "owner did not log on")
    assert ws.current_status(con, key) == "In progress" and ws.current_disposition(con, key) == "Confirmed"
    assert [n["note"] for n in ws.notes(con, key)] == ["called the user"]
    assert {h["action"] for h in ws.history(con, key)} >= {"status", "note", "disposition"}
    with pytest.raises(ValueError):
        ws.set_status(con, key, inc["incident_id"], "Deleted")
    rule, user = inc["rules"][0], inc["users"][0]
    alert_rule = next(a.alerts_by_id[x]["rule"] for x in inc["alert_ids"] if user in a.alerts_by_id[x]["users"])
    sid = ws.propose_suppression(con, alert_rule, {"user": user}, "test")
    assert ws.matching_suppressions(con, inc, a.alerts_by_id) == []          # proposals have no effect
    ws.decide_suppression(con, sid, "approved")
    assert ws.matching_suppressions(con, inc, a.alerts_by_id) == [f"SUP-{sid}"]   # tagged, never hidden
    ws.decide_suppression(con, sid, "revoked")
    assert ws.matching_suppressions(con, inc, a.alerts_by_id) == []
