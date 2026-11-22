"""SLM timeout/fallback, report generation and offline guarantees."""
import json
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from helpers import CFG, LogBuilder

from sentinel.config import override
from sentinel.evidence import known_entities
from sentinel.report import render_report
from sentinel.slm import explain, status
from sentinel.verifier import verify_output

ROOT = Path(__file__).resolve().parent.parent


def analysed():
    b = LogBuilder()
    b.process(b.at(2, 3), "admin02", "FIN-SRV01", "mimikatz.exe", "cmd.exe", "mimikatz sekurlsa::logonpasswords")
    b.log_clear(b.at(2, 3, 5), "admin02", "FIN-SRV01")
    return b.analyze()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_slm_unreachable_falls_back_to_template(tmp_path):
    cfg = override(CFG, **{"slm.host": f"http://127.0.0.1:{free_port()}", "slm.cache_dir": str(tmp_path),
                           "slm.timeout_seconds": 2})
    a = analysed()
    p = a.packs[a.incidents[0]["incident_id"]]
    r = explain(p, cfg, use_cache=False)
    assert r["source"] == "template" and r["error"]
    assert verify_output(r["output"], p, known_entities(a.events))["stats"]["verification_rate"] == 1.0
    assert status(cfg)["reachable"] is False


class SlowHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        time.sleep(3)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


class GarbageHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"message": {"content": "not json at all"}, "eval_count": 3}).encode())

    def log_message(self, *a):
        pass


@pytest.mark.parametrize("handler,expect", [(SlowHandler, "timed out"), (GarbageHandler, "invalid output")])
def test_slm_timeout_and_invalid_output_fall_back(tmp_path, handler, expect):
    port = free_port()
    srv = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = override(CFG, **{"slm.host": f"http://127.0.0.1:{port}", "slm.cache_dir": str(tmp_path),
                               "slm.timeout_seconds": 1})
        a = analysed()
        r = explain(a.packs[a.incidents[0]["incident_id"]], cfg, use_cache=False)
        assert r["source"] == "template" and expect in r["error"].lower().replace("timeout", "timed out")
    finally:
        srv.shutdown()


def test_report_is_self_contained_and_complete():
    a = analysed()
    iid = a.incidents[0]["incident_id"]
    p = a.packs[iid]
    from sentinel.slm import template_explanation
    res = {"source": "template", "output": template_explanation(p), "stats": {}}
    html = render_report(a, iid, res, verify_output(res["output"], p, known_entities(a.events)))
    for needle in [iid, "Severity breakdown", "Original log evidence", "MITRE", "T1070.001", "Recommended response actions",
                   "Evidence verification", "Analysis limitations", "SHA-256", "Contradicting evidence"]:
        assert needle in html, needle
    assert not re.search(r"<(script|link)[^>]+(src|href)=[\"']https?://", html, re.I)
    assert "@import" not in html and "fonts.googleapis" not in html


def test_no_external_urls_in_runtime_code():
    """Static offline check: runtime code contacts only the configured local Ollama host."""
    allowed = ("127.0.0.1", "localhost", "attack.mitre.org", "198.51.100.", "203.0.113.", "192.0.2.")
    for f in list((ROOT / "sentinel").glob("*.py")) + [ROOT / "app.py"]:
        for url in re.findall(r"https?://[^\s\"')]+", f.read_text(encoding="utf-8")):
            assert any(x in url for x in allowed), f"{f.name}: {url}"


def test_streamlit_telemetry_disabled():
    cfg = (ROOT / ".streamlit" / "config.toml").read_text()
    assert re.search(r"gatherUsageStats\s*=\s*false", cfg)


def test_pipeline_makes_no_network_connections():
    from sentinel.perf import Monitor
    from sentinel.pipeline import analyze_paths
    d = ROOT / "data" / "samples" / "dev_seed7"
    with Monitor(interval=0.05) as mon:
        a = analyze_paths([d / "auth_logs.csv", d / "endpoint_logs.json"])
        p = a.packs[a.incidents[0]["incident_id"]]
        from sentinel.slm import template_explanation
        res = {"source": "template", "output": template_explanation(p), "stats": {}}
        render_report(a, a.incidents[0]["incident_id"], res, verify_output(res["output"], p, known_entities(a.events)))
    assert not [c for c in mon.result()["external_connections"] if c["process"].startswith("sentinel")]
