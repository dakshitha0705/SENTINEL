"""Capture real screenshots of the running app with Playwright driving the locally installed Edge.

    streamlit run app.py          (in another terminal)
    python scripts/screenshots.py [--sample demo_unseen]

Dev-only tool (no browser download: channel="msedge"). Screenshots go to docs/screenshots/.
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "screenshots"
SHOTS = [("01_queue", 0, None), ("02_upload", 1, None), ("03_storyline", 2, "Attack storyline"),
         ("04_evidence_hypothesis", 2, "Evidence vs. hypothesis"), ("05_severity", 2, "Severity breakdown"),
         ("06_report", 2, "Report export"), ("07_accuracy", 3, None), ("08_monitor", 4, None), ("09_workspace", 5, None)]


def wait_idle(page, timeout=90):
    t0 = time.time()
    page.wait_for_selector("[data-testid='stSidebar']", timeout=timeout * 1000)
    while time.time() - t0 < timeout:
        running = page.locator("[data-testid='stStatusWidget']").count()
        if not running:
            time.sleep(1.5)
            if not page.locator("[data-testid='stStatusWidget']").count():
                return
        time.sleep(0.5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", default="demo_unseen")
    ap.add_argument("--base", default="http://127.0.0.1:8501")
    ap.add_argument("--incident", type=int, default=1, help="rank of the incident to open (0 = highest)")
    ap.add_argument("--only", nargs="*", help="capture only these shot names")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch(channel="msedge", headless=True)
        pg = b.new_page(viewport={"width": 1600, "height": 1000}, device_scale_factor=1)
        pg.goto(f"{a.base}/?sample={a.sample}&corrected=1&page=0&incident={a.incident}")
        wait_idle(pg, 240)   # first load runs the analysis + SLM on top incidents
        for name, page_idx, tab in [x for x in SHOTS if not a.only or x[0] in a.only]:
            pg.locator("[data-testid='stSidebar'] [role='radiogroup'] label").nth(page_idx).click()
            wait_idle(pg)
            if tab:
                pg.get_by_role("tab", name=tab).click()
                wait_idle(pg)
                if tab == "Evidence vs. hypothesis" and pg.get_by_role("button", name="Explain with local SLM").count():
                    pg.get_by_role("button", name="Explain with local SLM").click()
                    wait_idle(pg, 180)
            if name == "09_workspace":
                pg.get_by_role("textbox", name="Question").fill("What happened after the successful login?")
                pg.get_by_role("textbox", name="Question").press("Enter")
                wait_idle(pg)
                pg.get_by_role("button", name="Ask").click()
                pg.wait_for_selector("text=Q: What happened", timeout=180000)
                wait_idle(pg, 60)
            pg.screenshot(path=str(OUT / f"{name}.png"), full_page=False)
            print("saved", name)
        b.close()


if __name__ == "__main__":
    main()
