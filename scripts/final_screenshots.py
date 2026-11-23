"""Final screenshots of the redesigned UI, taken from a real live session (start the services first with
scripts\\start_demo.ps1). Writes docs/screenshots/v4/*.png and results/final_screenshots.json.

    python scripts/final_screenshots.py

Flow: new NEXUS session -> a genuine browser sign-in on the NEXUS portal -> scenario G started from SENTINEL's
Live Demo page -> notification -> Command Center / globe -> Investigation Studio (story, evidence, attack graph,
local Qwen) -> Threat Hunting -> Evaluation -> Report. The controller's credentials panel stays closed, and the
password typed into NEXUS is masked, so no password appears in any screenshot. Non-local requests are blocked.
"""
from __future__ import annotations

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
OUT = ROOT / "docs" / "screenshots" / "v4"
NX, SN = "http://127.0.0.1:8502", "http://127.0.0.1:8501"
W, H = 1680, 1000


def api(path, post=False):
    req = urllib.request.Request(NX + path, data=b"" if post else None, method="POST" if post else "GET")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def idle(pg, t=90):
    t0 = time.time()
    while time.time() - t0 < t:
        if not pg.locator("[data-testid='stStatusWidget']").count():
            time.sleep(1.0)
            if not pg.locator("[data-testid='stStatusWidget']").count():
                return
        time.sleep(0.3)


def nav(pg, k):
    pg.locator("[data-testid='stSidebar'] [role='radiogroup'] label").nth(k).click()
    idle(pg)
    time.sleep(2)


def globe_ready(pg, timeout=40):
    """Wait until the WebGL globe has initialised (and painted a few frames)."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        for f in pg.frames:
            try:
                if f.evaluate("!!window.__sentinelGlobe"):
                    time.sleep(4)
                    return True
            except Exception:  # noqa: BLE001
                pass
        time.sleep(0.5)
    return False


def seg(pg, label):
    pg.locator("[data-testid='stButtonGroup'] button").filter(has_text=label).first.click()
    idle(pg)
    time.sleep(1.5)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    only_graph = "--graph-only" in sys.argv
    blocked, log = [], {"recorded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "shots": []}

    def route(r):
        host = urlparse(r.request.url).hostname or ""
        if host in ("127.0.0.1", "localhost") or r.request.url.startswith(("data:", "blob:")):
            r.continue_()
        else:
            blocked.append(r.request.url[:200])
            r.abort()

    def shot(pg, name, **kw):
        pg.screenshot(path=str(OUT / f"{name}.png"), **kw)
        log["shots"].append(name)
        print("  saved", name)

    creds = json.loads((ROOT / "demo_data" / "nexus_credentials.json").read_text(encoding="utf-8"))
    pw = creds.get("passwords", creds).get("arjun.rao") if isinstance(creds, dict) else None

    with sync_playwright() as p:
        b = p.chromium.launch(channel="msedge", headless=True, args=["--use-angle=swiftshader", "--enable-unsafe-swiftshader"])
        ctx = b.new_context(viewport={"width": W, "height": H})
        ctx.route("**/*", route)
        if only_graph:
            b.close()
            return graph_shot(p, route, shot, log, blocked)
        log["session"] = api("/api/demo/start", post=True)["session"]
        sen = ctx.new_page()
        sen.goto(f"{SN}/?live=1&page=1")          # Live Demo
        idle(sen, 120)
        time.sleep(3)
        sen.get_by_text("Presentation mode").first.click()
        time.sleep(3)
        # NEXUS sign-in page and controller (credentials panel closed)
        nx = ctx.new_page()
        nx.goto(f"{NX}/login")
        time.sleep(1.2)
        shot(nx, "04_nexus_login")
        if pw:                                     # a genuine sign-in (password field stays masked)
            nx.fill("#username", "arjun.rao")
            nx.fill("#password", pw)
            nx.click("#submit")
            time.sleep(1.5)
            nx.goto(f"{NX}/logout")
            time.sleep(0.8)
        nx.goto(f"{NX}/demo")
        time.sleep(2)
        assert not nx.locator("details#accounts[open]").count()
        shot(nx, "05_nexus_controller")
        # start the full attack from SENTINEL's Live Demo page
        sen.bring_to_front()
        time.sleep(3)
        sen.get_by_role("button", name="Start the full attack").click()
        for _ in range(60):
            st = api("/api/demo/status")["runner"]
            if st["steps"] and st["step"] >= st["steps"] * 0.6:
                break
            time.sleep(0.4)
        time.sleep(2.5)
        shot(sen, "03_live_demo")
        for _ in range(120):
            if api("/api/demo/status")["runner"]["state"] in ("completed", "stopped", "error"):
                break
            time.sleep(0.5)
        # Command Center: notification toast + bell
        nav(sen, 0)
        globe_ready(sen)
        shot(sen, "01_command_center")
        sen.locator("[data-testid='stPopover'] button").first.click()
        time.sleep(1.5)
        shot(sen, "06_notifications")
        sen.keyboard.press("Escape")
        time.sleep(1)
        # globe close-up after a drag and a zoom
        fr = None
        for f in sen.frames:
            try:
                if f.evaluate("!!window.__sentinelGlobe"):
                    fr = f
                    break
            except Exception:  # noqa: BLE001
                pass
        if fr:
            fr.evaluate("window.__sentinelGlobe.stopSpin()")
            el = fr.frame_element()
            bb = el.bounding_box()
            sen.mouse.move(bb["x"] + bb["width"] / 2, bb["y"] + bb["height"] / 2)
            sen.mouse.wheel(0, -500)
            time.sleep(2)
            el.screenshot(path=str(OUT / "02_globe.png"))
            log["shots"].append("02_globe")
            fr.evaluate("window.__sentinelGlobe.reset()")
        # Investigation Studio
        sen.locator("div[class*='st-key-cc_investigate'] button").first.click()
        sen.wait_for_selector("text=Playback", timeout=30000)
        idle(sen)
        time.sleep(1.5)
        shot(sen, "08_attack_storyline")
        seg(sen, "Evidence")
        shot(sen, "07_investigation_studio")
        seg(sen, "AI investigation")
        t0 = time.time()
        sen.get_by_role("button", name="Explain with local Qwen").click()
        sen.wait_for_selector("text=against the original logs", timeout=240000)
        idle(sen, 120)
        log["qwen_s"] = round(time.time() - t0, 1)
        shot(sen, "10_ai_investigation")
        # Threat Hunting, Evaluation, Report
        nav(sen, 4)
        sen.locator("[data-testid='stButtonGroup'] button, div[class*='st-key-hunt'] button").filter(has_text="Suspicious Execution").first.click()
        idle(sen)
        time.sleep(1)
        shot(sen, "11_threat_hunting")
        nav(sen, 5)
        time.sleep(3)
        shot(sen, "13_report")
        seg(sen, "Evaluation")
        time.sleep(2)
        shot(sen, "12_evaluation")
        b.close()
        graph_shot(p, route, shot, log, blocked)
    finish(log, blocked)


def finish(log, blocked):
    log["external_requests_blocked"] = len(blocked)
    (ROOT / "results" / "final_screenshots.json").write_text(json.dumps(log, indent=1), encoding="utf-8")
    print(json.dumps(log, indent=1))


def graph_shot(p, route, shot, log, blocked):
    # attack graph: vis-network's canvas renders best without the software-WebGL flags
    b2 = p.chromium.launch(channel="msedge", headless=True)
    ctx2 = b2.new_context(viewport={"width": W, "height": 1180})   # taller, so the graph is painted in view
    # (no request interception here: with it, headless Edge does not paint the vis-network canvas)
    g = ctx2.new_page()
    g.goto(f"{SN}/?live=1&page=3")
    idle(g, 120)
    time.sleep(3)
    seg(g, "Attack graph")
    time.sleep(18)                            # vis-network stabilises its layout before the first paint
    shot(g, "09_attack_graph")
    b2.close()



if __name__ == "__main__":
    main()
