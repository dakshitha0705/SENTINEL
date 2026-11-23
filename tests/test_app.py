"""Headless UI tests: every page renders on real analysis results, and key interactions work."""
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parent.parent
PAGES = ["Command Center", "Log Intelligence", "Incident Investigation", "Attack Graph", "AI Investigation Lab",
         "Threat Intelligence", "Evaluation & Benchmarks", "Report Studio", "System & Settings"]


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
    for page in ("Incident Investigation", "AI Investigation Lab", "Report Studio"):
        app.session_state["nav"] = page
        app.run()
        assert not app.exception
        assert app.session_state["selected"] == iid
