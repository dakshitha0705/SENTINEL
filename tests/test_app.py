"""Headless UI smoke test: every page renders without exceptions on real analysis results."""
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parent.parent
PAGES = ["Incident queue", "Log upload & mapping", "Incident investigation", "Accuracy & evaluation",
         "Offline system monitor", "Analyst workspace"]


@pytest.fixture(scope="module")
def app_with_analysis():
    from sentinel.config import load_config, override
    from sentinel.evidence import known_entities
    from sentinel.pipeline import analyze_paths

    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    at.run()
    d = ROOT / "data" / "samples" / "dev_seed7"
    a = analyze_paths([d / "auth_logs.csv", d / "endpoint_logs.json"], load_config())
    at.session_state["analysis"] = a
    at.session_state["known_entities"] = known_entities(a.events)
    at.session_state["files"] = {"auth_logs.csv": (d / "auth_logs.csv").read_bytes(),
                                 "endpoint_logs.json": (d / "endpoint_logs.json").read_bytes()}
    at.session_state["sample_name"] = "dev_seed7"
    return at


@pytest.mark.parametrize("page", PAGES)
def test_page_renders(app_with_analysis, page):
    at = app_with_analysis
    at.session_state["nav"] = page
    at.run()
    assert not at.exception, [e.value for e in at.exception]
