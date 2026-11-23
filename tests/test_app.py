"""Headless UI tests: every page renders on real analysis results, and key interactions work."""
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parent.parent
PAGES = ["Command Center", "Live Demo", "Log Intelligence", "Investigation Studio", "Threat Hunting", "Reports & Evaluation"]
STUDIO_VIEWS = ["Story", "Evidence", "Severity", "Attack graph", "AI investigation", "Next steps", "Notes", "Export"]


@pytest.fixture(scope="module")
def app():
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=180)
    at.run()          # first visit loads the bundled demo dataset and runs the deterministic analysis
    assert not at.exception, [e.value for e in at.exception]
    return at


@pytest.mark.parametrize("page", PAGES)
def test_page_renders(app, page):
    app.session_state["nav"] = page
    app.run()
    assert not app.exception, [e.value for e in app.exception]


def test_first_visit_loads_demo_dataset(app):
    from sentinel.live import LiveReader
    if LiveReader.worker_alive():          # with the live demo running, a first visit monitors the live stream
        assert app.session_state["dataset"].startswith("LIVE")
        return
    assert app.session_state["dataset"] == "demo_unseen"
    a = app.session_state["analysis"]
    assert a is not None and len(a.incidents) == 5
    # mapping profile applied (Initiated By -> actor) so the approved change-window group add is not flagged
    assert app.session_state["mappings"]["siem_auth_export.csv"]["actor"] == "Initiated By"


def test_dataset_switch_changes_analysis(app):
    app.session_state["nav"] = "Command Center"
    app.run()
    sb = next(s for s in app.selectbox if s.key == "dataset_pick")
    sb.set_value("test_seed101").run()
    assert not app.exception
    assert app.session_state["dataset"] == "test_seed101"
    assert app.session_state["analysis"].dataset.files[0]["name"] == "auth_logs.csv"


def test_time_range_filters_incidents(app):
    from sentinel.ui import state
    app.session_state["time_range"] = "Last 24 h"
    app.run()
    a = app.session_state["analysis"]
    hi = a.events["timestamp"].max()
    import pandas as pd
    lo = hi - pd.Timedelta(hours=24)
    expected = [i for i in a.incidents if i["end"] >= lo and i["start"] <= hi]
    assert len(expected) <= len(a.incidents)
    app.session_state["time_range"] = "All data"
    app.run()


def test_global_search_finds_incident(app):
    app.session_state["nav"] = "Command Center"
    a = app.session_state["analysis"]
    user = a.incidents[0]["users"][0]
    app.text_input(key="search_q").set_value(user).run()
    assert not app.exception
    assert any(b.label == "Open" for b in app.button)
    app.text_input(key="search_q").set_value("").run()


def test_incident_navigation_preserves_selection(app):
    a = app.session_state["analysis"]
    iid = a.incidents[-1]["incident_id"]
    app.session_state["selected"] = iid
    for page in ("Investigation Studio", "Reports & Evaluation", "Command Center"):
        app.session_state["nav"] = page
        app.run()
        assert not app.exception
        assert app.session_state["selected"] == iid


@pytest.mark.parametrize("view", STUDIO_VIEWS)
def test_investigation_studio_views_render(app, view):
    app.session_state["nav"] = "Investigation Studio"
    app.session_state["studio_view"] = view
    app.run()
    assert not app.exception, (view, [e.value for e in app.exception])


@pytest.mark.parametrize("view", ["Report", "Evaluation", "Offline evidence"])
def test_reports_evaluation_views_render(app, view):
    app.session_state["nav"] = "Reports & Evaluation"
    app.session_state["re_view"] = view
    app.run()
    assert not app.exception, (view, [e.value for e in app.exception])


def test_old_page_names_map_to_new_destinations(app):
    """Deep links and buttons that still use the former nine page names land on the right destination and view."""
    from sentinel.ui.state import ALIASES, PAGES as P
    assert len(P) == 6 and "System & Settings" not in P
    for old, (new, view) in ALIASES.items():
        assert new in P


def test_threat_hunting_cards_run_real_queries(app):
    from sentinel.hunting import CATEGORIES, category
    a = app.session_state["analysis"]
    app.session_state["nav"] = "Threat Hunting"
    app.session_state["hunt_sel"] = "Credential Attacks"
    app.run()
    assert not app.exception
    hits = category(a, "Credential Attacks")
    assert len(hits) > 0 and set(hits["action"]) & {"login_failure", "login_success"}
    # every card's count equals its backend query
    for name in CATEGORIES:
        assert any(f"{len(category(a, name)):,} matching events" in b.label for b in app.button)


def test_command_center_counters_match_backend(app):
    app.session_state["nav"] = "Command Center"
    app.session_state["time_range"] = "All data"
    app.run()
    a = app.session_state["analysis"]
    html = " ".join(m.value for m in app.markdown)
    users = {u for i in a.incidents for u in i["users"]}
    hosts = {h for i in a.incidents for h in i["hosts"]}
    for v, l in ((f"{len(a.events):,}", "Total events"), (len(a.incidents), "Incidents"), (len(users), "Affected users"),
                 (len(hosts), "Affected devices")):
        assert f'<div class="v">{v}</div><div class="l">{l}</div>' in html


def test_live_mode_pages_render(tmp_path, monkeypatch):
    """Every page renders while monitoring a (temporary) NEXUS demo stream."""
    import sentinel.live as live
    from demo_target.auth import IdentityStore
    from demo_target.events import EventStream
    from demo_target.simulator import backfill_history
    monkeypatch.setattr(live, "DEMO_ROOT", tmp_path)
    stream = EventStream(tmp_path)
    backfill_history(stream, IdentityStore(tmp_path / "creds.json"))
    for k in range(10):
        stream.emit("4625", "auth.login_failure", user="arjun.rao", ip="198.51.100.23", outcome="failure",
                    status="0xC000006A", ip_simulated=True, scenario_id="B")
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=180)
    at.query_params["live"] = "1"
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    assert at.session_state["dataset"].startswith("LIVE")
    a = at.session_state["analysis"]
    assert a is not None and any("R1" in i["rules"] for i in a.incidents)
    for page in PAGES:
        at.session_state["nav"] = page
        at.run()
        assert not at.exception, (page, [e.value for e in at.exception])
    # refreshing / navigating keeps the live stream selected (the URL is the source of truth)
    at.session_state["nav"] = "Investigation Studio"
    at.run()
    assert at.session_state["dataset"].startswith("LIVE")
    # the live engine's real notification reaches the session (shown once, kept in the bell history)
    hist = at.session_state["notif_history"]
    assert hist and hist[0]["kind"] == "new" and "R1" in hist[0]["rules"] and hist[0]["summary"]
    n_before = len(hist)
    at.run()
    assert len(at.session_state["notif_history"]) == n_before        # no duplicate for the same update
    # an explicit switch to a saved dataset leaves live mode
    sb = next(s for s in at.selectbox if s.key == "dataset_pick")
    sb.set_value("demo_unseen").run()
    assert at.session_state["dataset"] == "demo_unseen" and "live" not in at.query_params
