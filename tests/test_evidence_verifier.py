from datetime import timedelta

from helpers import LogBuilder

from sentinel.evidence import known_entities
from sentinel.slm import template_explanation
from sentinel.verifier import verify_claim, verify_output


def analysed():
    b = LogBuilder().history("jdoe", "WS1", "10.0.0.5")
    t = b.at(4, 3)
    for i in range(12):
        b.fail(t + timedelta(seconds=10 * i), "jdoe", "WS1", "203.0.113.5")
    b.logon(t + timedelta(minutes=4), "jdoe", "WS1", "203.0.113.5")
    a = b.analyze()
    inc = a.incidents[0]
    return a, a.packs[inc["incident_id"]], known_entities(a.events)


def fid_for(pack, rule):
    return next(f["id"] for f in pack["facts"] if f"{rule} " in f["text"] and f["kind"] in ("detection", "context"))


def test_evidence_pack_structure():
    a, p, _ = analysed()
    ids = [f["id"] for f in p["facts"]]
    assert ids == [f"F{i}" for i in range(1, len(ids) + 1)]
    r1 = next(f for f in p["facts"] if "R1 " in f["text"])
    assert len(r1["event_ids"]) == 12 and 12.0 in r1["numbers"] and "203.0.113.5" in r1["ips"]
    assert p["severity"]["fact_id"] in ids and p["playbooks"]
    assert all(x in ids for x in p["contradicting_fact_ids"] + p["supporting_fact_ids"])


def test_correct_claim_verified():
    _, p, ke = analysed()
    f = fid_for(p, "R1")
    v = verify_claim({"text": "jdoe had 12 failed logons from 203.0.113.5.", "fact_ids": [f]}, p, ke)
    assert v["status"] == "Verified", v["problems"]


def test_invalid_citation_rejected():
    _, p, ke = analysed()
    v = verify_claim({"text": "jdoe had 12 failed logons.", "fact_ids": ["F999"]}, p, ke)
    assert v["status"] == "Unverified" and any("unknown fact" in x for x in v["problems"])
    v = verify_claim({"text": "jdoe had 12 failed logons.", "fact_ids": []}, p, ke)
    assert v["status"] == "Unverified"


def test_incorrect_number_rejected():
    _, p, ke = analysed()
    f = fid_for(p, "R1")
    v = verify_claim({"text": "jdoe had 15 failed logons from 203.0.113.5.", "fact_ids": [f]}, p, ke)
    assert v["status"] == "Unverified" and any("number 15" in x for x in v["problems"])
    v = verify_claim({"text": "jdoe had twelve failed logons.", "fact_ids": [f]}, p, ke)
    assert v["status"] == "Verified"


def test_wrong_time_and_entity_rejected():
    _, p, ke = analysed()
    f = fid_for(p, "R1")
    assert verify_claim({"text": "Failures for jdoe began at 05:40.", "fact_ids": [f]}, p, ke)["status"] == "Unverified"
    v = verify_claim({"text": "Failures came from 198.51.100.77.", "fact_ids": [f]}, p, ke)
    assert v["status"] == "Unverified" and any("198.51.100.77" in x for x in v["problems"])


def test_valid_citation_on_unrelated_statement_rejected():
    _, p, ke = analysed()
    f = fid_for(p, "R1")
    v = verify_claim({"text": "Ransomware encrypted the finance database backups overnight.", "fact_ids": [f]}, p, ke)
    assert v["status"] == "Unverified"


def test_overclaiming_intent_rejected():
    _, p, ke = analysed()
    f = fid_for(p, "R3")
    v = verify_claim({"text": "This confirms the attack: jdoe was definitely compromised.", "fact_ids": [f]}, p, ke)
    assert v["status"] == "Unverified"


def test_unsupported_slm_output_handled():
    _, p, ke = analysed()
    out = {"summary": [{"text": "jdoe had 12 failed logons. Then 40 files were exfiltrated.", "fact_ids": [fid_for(p, "R1")]}],
           "supported_conclusions": ["no citation here"],
           "hypotheses": [{"text": "Password guessed", "supporting_fact_ids": ["F77"]}],
           "recommended_actions": [{"playbook_id": "PB-99", "adaptation": "x"}, {"playbook_id": p["playbooks"][0]["id"], "adaptation": "Reset jdoe"}],
           "open_questions": ["Was it jdoe?"]}
    v = verify_output(out, p, ke)
    assert [c["status"] for c in v["summary"]] == ["Verified", "Unverified"]   # verified per sentence
    assert v["conclusions"][0]["status"] == "Unverified"
    assert v["hypotheses"][0]["status"] == "Ungrounded hypothesis"
    assert v["stats"]["actions_rejected"] == 1 and v["stats"]["actions_accepted"] == 1
    assert v["stats"]["verification_rate"] == 1 / 3


def test_template_explanation_fully_verifies():
    a, _, ke = analysed()
    for inc in a.incidents:
        p = a.packs[inc["incident_id"]]
        v = verify_output(template_explanation(p), p, ke)
        assert v["stats"]["verification_rate"] == 1.0, [c["problems"] for c in v["summary"] + v["conclusions"]]
