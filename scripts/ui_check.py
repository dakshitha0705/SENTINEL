"""Browser-level UI check: real interactions in the running dashboard, with every non-local request blocked.

    streamlit run app.py                     (another terminal)
    python scripts/ui_check.py [--shots]     -> results/offline_ui_check.json (+ docs/screenshots/v2/*.png)

Drives the locally installed Edge through Playwright (no browser download). Every request whose host is not
127.0.0.1/localhost is ABORTED and recorded, so the run proves the UI needs no external resources (fonts,
scripts, map tiles, textures). It then checks the globe (drag rotates, wheel zooms, reset restores, marker
click resolves to records in the page) and the attack graph (wheel zoom, node click opens the inspector),
and opens all nine pages looking for Streamlit exceptions.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
SHOTS = ROOT / "docs" / "screenshots" / "v2"
PAGES = ["Command Center", "Live Demo", "Log Intelligence", "Investigation Studio", "Threat Hunting", "Reports & Evaluation"]


def wait_idle(page, timeout=90):
    t0 = time.time()
    page.wait_for_selector("[data-testid='stSidebar']", timeout=timeout * 1000)
    while time.time() - t0 < timeout:
        if not page.locator("[data-testid='stStatusWidget']").count():
            time.sleep(1.2)
            if not page.locator("[data-testid='stStatusWidget']").count():
                return
        time.sleep(0.4)


def viz_frame(page, kind, timeout=30):
    """The component iframe that exposes the hook for `kind` ('globe' or 'graph')."""
    hook = "__sentinelGlobe" if kind == "globe" else "__sentinelGraph"
    t0 = time.time()
    while time.time() - t0 < timeout:
        for fr in page.frames:
            try:
                if fr.evaluate(f"!!window.{hook}"):
                    return fr
            except Exception:  # noqa: BLE001
                pass
        time.sleep(0.5)
    return None


def goto_page(page, name):
    page.locator("[data-testid='stSidebar'] [role='radiogroup'] label").nth(PAGES.index(name)).click()
    wait_idle(page)


def seg(page, label):
    """Click a segmented-control option (view switchers in Investigation Studio / Reports & Evaluation)."""
    page.locator("[data-testid='stButtonGroup'] button").filter(has_text=label).first.click()
    time.sleep(0.5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8501")
    ap.add_argument("--shots", action="store_true", help="also save screenshots to docs/screenshots/v2")
    ap.add_argument("--explain", action="store_true", help="also run a live local-Qwen explanation and one chat question")
    a = ap.parse_args()
    blocked, local = [], 0
    checks, pages = {}, {}
    if a.shots:
        SHOTS.mkdir(parents=True, exist_ok=True)

    def route(r):
        nonlocal local
        host = urlparse(r.request.url).hostname or ""
        if host in ("127.0.0.1", "localhost") or r.request.url.startswith(("data:", "blob:")):
            local += 1
            r.continue_()
        else:
            blocked.append(r.request.url[:200])
            r.abort()

    with sync_playwright() as p:
        b = p.chromium.launch(channel="msedge", headless=True, args=["--use-angle=swiftshader", "--enable-unsafe-swiftshader"])
        ctx = b.new_context(viewport={"width": 1680, "height": 1050})
        ctx.route("**/*", route)
        pg = ctx.new_page()
        errors = []
        pg.on("pageerror", lambda e: errors.append(str(e)[:200]))
        pg.goto(f"{a.base}/?sample=demo_unseen&page=0")
        wait_idle(pg, 180)
        # ---------------- globe
        fr = viz_frame(pg, "globe", 60)
        checks["globe_rendered"] = fr is not None
        if fr:
            time.sleep(2.5)
            fr.evaluate("window.__sentinelGlobe.stopSpin()")
            g = fr.evaluate("({m: window.__sentinelGlobe.markers, a: window.__sentinelGlobe.arcs, pov: window.__sentinelGlobe.pov()})")
            checks["globe_markers"], checks["globe_arcs"] = g["m"], g["a"]
            frame_el = fr.frame_element()
            bb = frame_el.bounding_box()
            cx, cy = bb["x"] + bb["width"] / 2, bb["y"] + bb["height"] / 2
            p0 = fr.evaluate("window.__sentinelGlobe.pov()")
            pg.mouse.move(cx, cy)
            pg.mouse.down()
            pg.mouse.move(cx + 220, cy + 40, steps=12)
            pg.mouse.up()
            time.sleep(1.5)
            p1 = fr.evaluate("window.__sentinelGlobe.pov()")
            checks["globe_drag_rotates"] = abs(p1["lng"] - p0["lng"]) + abs(p1["lat"] - p0["lat"]) > 5
            pg.mouse.move(cx, cy)
            pg.mouse.wheel(0, -900)
            time.sleep(1.5)
            p2 = fr.evaluate("window.__sentinelGlobe.pov()")
            checks["globe_wheel_zooms_in"] = p2["altitude"] < p1["altitude"] - 0.05
            pg.mouse.wheel(0, 1400)
            time.sleep(1.5)
            p3 = fr.evaluate("window.__sentinelGlobe.pov()")
            checks["globe_wheel_zooms_out"] = p3["altitude"] > p2["altitude"] + 0.05
            fr.evaluate("window.__sentinelGlobe.reset()")
            time.sleep(1.6)
            p4 = fr.evaluate("window.__sentinelGlobe.pov()")
            # reset returns to the default Asia-Pacific view (18N, 92E, altitude 1.75)
            checks["globe_reset_restores_view"] = abs(p4["lat"] - 18) < 1 and abs(p4["lng"] - 92) < 1 \
                and abs(p4["altitude"] - 1.75) < 0.05
            checks["globe_reset_pov"] = {k: round(v, 2) for k, v in p4.items()}
            if a.shots:
                pg.screenshot(path=str(SHOTS / "01_command_center.png"))
            # click a marker that is on the visible hemisphere
            ms = fr.evaluate("window.__sentinelGlobe.list")
            target = None
            for m in sorted(ms, key=lambda m: abs(m["lng"] - p4["lng"])):
                sc = fr.evaluate(f"window.__sentinelGlobe.screen({m['lat']}, {m['lng']})")
                if sc and 30 < sc["x"] < bb["width"] - 30 and 60 < sc["y"] < bb["height"] - 60:
                    target = (m, sc)
                    break
            if target:
                m, sc = target
                pg.mouse.click(bb["x"] + sc["x"], bb["y"] + sc["y"])
                wait_idle(pg, 30)
                time.sleep(1)
                txt = pg.locator("div[class*='st-key-card_geo']").inner_text() if pg.locator("div[class*='st-key-card_geo']").count() else ""
                checks["globe_marker_click_opens_records"] = "located event" in txt
                checks["globe_marker_clicked"] = m["label"]
                if a.shots:
                    pg.screenshot(path=str(SHOTS / "02_globe_marker_selected.png"))
        # ---------------- pages
        for name in PAGES:
            goto_page(pg, name)
            exc = pg.locator("[data-testid='stException']").count()
            pages[name] = "ok" if not exc else "EXCEPTION"
            if name == "Reports & Evaluation":
                time.sleep(4)          # let the report preview iframe render
            if a.shots:
                pg.screenshot(path=str(SHOTS / f"p{PAGES.index(name) + 1:02d}_{name.split()[0].lower()}.png"))
            if name == "Investigation Studio":
                for view in ("Evidence", "Severity", "Next steps", "Notes", "Export"):
                    seg(pg, view)
                    wait_idle(pg)
                    pages[f"{name} / {view}"] = "ok" if not pg.locator("[data-testid='stException']").count() else "EXCEPTION"
                seg(pg, "Attack graph")
                wait_idle(pg)
                gf = viz_frame(pg, "graph", 40)
                checks["graph_rendered"] = gf is not None
                if gf:
                    time.sleep(3)
                    s0 = gf.evaluate("window.__sentinelGraph.scale()")
                    gb = gf.frame_element().bounding_box()
                    pg.mouse.move(gb["x"] + gb["width"] / 2, gb["y"] + gb["height"] / 2)
                    pg.mouse.wheel(0, -500)
                    time.sleep(1)
                    checks["graph_wheel_zooms"] = gf.evaluate("window.__sentinelGraph.scale()") != s0
                    ids = gf.evaluate("window.__sentinelGraph.ids()")
                    nid = next((i for i in ids if i.startswith("INC-")), ids[0])
                    pos = gf.evaluate(f"window.__sentinelGraph.nodePos('{nid}')")
                    pg.mouse.click(gb["x"] + pos["x"], gb["y"] + pos["y"])
                    wait_idle(pg, 30)
                    checks["graph_node_click_opens_inspector"] = pg.get_by_role("button", name="Open investigation").count() > 0
                seg(pg, "AI investigation")
                wait_idle(pg)
                pages[f"{name} / AI investigation"] = "ok" if not pg.locator("[data-testid='stException']").count() else "EXCEPTION"
                if a.explain:
                    pg.get_by_role("button", name="Explain with local Qwen").click()
                    pg.wait_for_selector("text=against the original logs", timeout=240000)
                    wait_idle(pg, 120)
                    checks["ai_explanation_rendered"] = pg.get_by_text("What we know").count() > 0
                    if a.shots:
                        pg.screenshot(path=str(SHOTS / "p04b_ai_investigation.png"))
                    seg(pg, "Ask SENTINEL")
                    wait_idle(pg)
                    pg.get_by_placeholder("Ask about this incident").fill("Why is this incident critical?")
                    pg.get_by_role("button", name="Ask", exact=True).click()
                    pg.wait_for_selector("text=You:", timeout=180000)
                    wait_idle(pg, 60)
                    checks["chat_answer_rendered"] = pg.get_by_text("SENTINEL ·").count() > 0
                    if a.shots:
                        pg.screenshot(path=str(SHOTS / "p04c_ai_chat.png"))
            if name == "Threat Hunting":
                pg.get_by_role("button", name="Suspicious Execution").first.click()
                wait_idle(pg)
                checks["hunt_card_runs_query"] = "matching events" in pg.locator("body").inner_text()
            if name == "Reports & Evaluation":
                checks["report_rendered"] = "Download HTML report" in pg.locator("body").inner_text()
                seg(pg, "Evaluation")
                wait_idle(pg)
                pages[f"{name} / Evaluation"] = "ok" if not pg.locator("[data-testid='stException']").count() else "EXCEPTION"
                seg(pg, "Offline evidence")
                wait_idle(pg)
                pages[f"{name} / Offline evidence"] = "ok" if not pg.locator("[data-testid='stException']").count() else "EXCEPTION"
        b.close()
    from sentinel.perf import internet_reachable
    summary = {"recorded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
               "internet_reachable_after": internet_reachable(), "external_requests_blocked": len(blocked),
               "local_requests": local, "pages": pages, "checks": checks, "javascript_errors": errors[:10]}
    out = {"summary": summary, "blocked_urls": blocked}
    (ROOT / "results").mkdir(exist_ok=True)
    summary["test_type"] = "online rehearsal" if summary["internet_reachable_after"] else "offline test"
    (ROOT / "results" / "ui_check.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    if not summary["internet_reachable_after"]:          # keep the offline record only for a disconnected run
        (ROOT / "results" / "offline_ui_check.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
