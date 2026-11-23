"""End-to-end live-demo check against the RUNNING services (start them with scripts\\start_demo.ps1).

    python scripts/live_demo_check.py [--shots] [--scenario G]

1. opens SENTINEL in live mode in the local Edge (every non-local request blocked and counted);
2. starts a fresh NEXUS demo session and runs the chosen scenario through the controller API;
3. waits until SENTINEL's live engine reports the incident and measures event->detection latency
   (from sentinel_status.json written by the engine);
4. checks the incident appears in the dashboard and opens its investigation;
5. writes results/live_demo_check.json (+ screenshots in docs/screenshots/v3 with --shots).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
SHOTS = ROOT / "docs" / "screenshots" / "v3"
NEXUS, SENT = "http://127.0.0.1:8502", "http://127.0.0.1:8501"


def api(path, post=False):
    req = urllib.request.Request(NEXUS + path, data=b"" if post else None, method="POST" if post else "GET")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def wait_idle(page, timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if not page.locator("[data-testid='stStatusWidget']").count():
            time.sleep(1.0)
            if not page.locator("[data-testid='stStatusWidget']").count():
                return
        time.sleep(0.3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shots", action="store_true")
    ap.add_argument("--scenario", default="G")
    a = ap.parse_args()
    SHOTS.mkdir(parents=True, exist_ok=True)
    blocked, out = [], {"recorded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "scenario": a.scenario}

    def route(r):
        host = urlparse(r.request.url).hostname or ""
        if host in ("127.0.0.1", "localhost") or r.request.url.startswith(("data:", "blob:")):
            r.continue_()
        else:
            blocked.append(r.request.url[:200])
            r.abort()

    with sync_playwright() as p:
        b = p.chromium.launch(channel="msedge", headless=True, args=["--use-angle=swiftshader", "--enable-unsafe-swiftshader"])
        ctx = b.new_context(viewport={"width": 1680, "height": 1050})
        ctx.route("**/*", route)
        sen = ctx.new_page()
        start = api("/api/demo/start", post=True)
        out["session"] = start["session"]
        out["baseline_events"] = start["backfilled"]
        sen.goto(f"{SENT}/?live=1&page=0")
        wait_idle(sen, 120)
        time.sleep(3)
        nx = ctx.new_page()
        nx.goto(f"{NEXUS}/demo")
        time.sleep(1.5)
        if a.shots:
            nx.screenshot(path=str(SHOTS / "n01_controller_idle.png"))
            nx.goto(f"{NEXUS}/login")
            nx.screenshot(path=str(SHOTS / "n02_nexus_login.png"))
            nx.goto(f"{NEXUS}/demo")
        t_run = time.time()
        api(f"/api/demo/run/{a.scenario}", post=True)
        incident_seen_at, mid_shot = None, False
        for _ in range(240):
            st = api("/api/demo/status")
            se = st.get("sentinel") or {}
            if se.get("session_id") == out["session"] and se.get("incidents") and incident_seen_at is None:
                incident_seen_at = time.time() - t_run
            if a.shots and not mid_shot and st["runner"]["step"] >= st["runner"]["steps"] // 2 and st["runner"]["steps"]:
                nx.screenshot(path=str(SHOTS / "n03_controller_running.png"))
                sen.screenshot(path=str(SHOTS / "s01_command_center_live_mid.png"))
                mid_shot = True
            if st["runner"]["state"] in ("completed", "stopped", "error"):
                break
            time.sleep(0.5)
        time.sleep(3.5)                                    # one more engine poll + UI refresh
        st = api("/api/demo/status")
        se = st.get("sentinel") or {}
        out["runner"] = {k: st["runner"][k] for k in ("state", "steps", "emitted", "error")}
        out["events_emitted"] = st["events_emitted"]
        out["events_ingested"] = se.get("events_ingested")
        out["incidents"] = se.get("incidents")
        out["first_incident_after_s"] = round(incident_seen_at, 1) if incident_seen_at else None
        out["engine_latency_s"] = [i.get("latency_s") for i in se.get("incidents", [])]
        if a.shots:
            nx.screenshot(path=str(SHOTS / "n04_controller_done.png"))
            sen.screenshot(path=str(SHOTS / "s02_command_center_live_incident.png"))
        body = sen.locator("body").inner_text()
        out["ui_shows_incident_mode"] = "INCIDENT INVESTIGATION" in body
        top = (se.get("incidents") or [{}])[0].get("incident_id")
        out["ui_lists_incident"] = bool(top) and top in body
        # open the investigation for the top incident
        sen.locator("[data-testid='stSidebar'] [role='radiogroup'] label").nth(2).click()
        wait_idle(sen)
        time.sleep(1)
        out["investigation_opened"] = "Attack storyline" in sen.locator("body").inner_text()
        if a.shots:
            sen.screenshot(path=str(SHOTS / "s03_investigation_live.png"), full_page=False)
        b.close()
    out["external_requests_blocked"] = len(blocked)
    out["blocked_urls"] = blocked
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "live_demo_check.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in out.items() if k != "blocked_urls"}, indent=1))


if __name__ == "__main__":
    main()
