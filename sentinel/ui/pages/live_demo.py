"""Live Demo: the NEXUS target, the scenario controller and the live detection view in one workspace, plus an
optional guided Presentation Mode. Everything shown comes from the running NEXUS controller API and the live
detection engine; scenario steps are the existing bounded NEXUS scenarios (nothing is simulated here)."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import pandas as pd
import streamlit as st

from ...live import RULE_PHRASE
from .. import SEV_COLOR, esc
from .. import state
from ..state import NEXUS_URL, S

CARDS = [  # id, title, what happens, what SENTINEL may report
    ("G", "Complete attack storyline", "Brute force, a successful login, sensitive pages, a self-add to Administrators, then "
     "synthetic encoded PowerShell and log clearing.", "One critical incident that escalates as evidence arrives"),
    ("A", "Normal activity", "Employees and the administrator sign in, browse and sign out from their usual devices.",
     "No incident: normal work is not flagged"),
    ("B", "Brute force", "3 failed sign-ins against one account from one simulated outside address (demo detection profile).", "Brute-force detection (Low: attempts only)"),
    ("C", "Password spraying", "One address tries a password against 6 different accounts.", "Password-spray detection"),
    ("D", "Suspicious login after failures", "10 failures, then a successful sign-in from the same address, then sensitive pages.",
     "Login-after-failures, severity rises"),
    ("E", "Privilege change", "An approved change inside a change ticket, then an unauthorised self-add to Administrators.",
     "Only the unauthorised change"),
    ("F", "Suspicious process + log clearing", "Synthetic endpoint events: encoded PowerShell, then the Security log cleared. "
     "Nothing is executed.", "Suspicious process and log clearing"),
    ("H", "Benign look-alike", "Approved maintenance with a ticket, a new laptop on the office network, two typos.",
     "No incident: look-alikes stay quiet"),
]
STEPS = ["Open NEXUS", "Demonstrate a normal login", "Start a controlled attack", "Watch SENTINEL detect it",
         "Open the incident", "Inspect the storyline and evidence", "Ask local Qwen for an explanation",
         "Generate the verified report"]


def api(path: str, post: bool = False, timeout: float = 4.0):
    """Call the local NEXUS controller API. Returns (json, http_status) or (None, None) if NEXUS is not running."""
    req = urllib.request.Request(NEXUS_URL + path, data=b"" if post else None, method="POST" if post else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()), e.code
        except ValueError:
            return None, e.code
    except (urllib.error.URLError, OSError, ValueError):
        return None, None


def render():
    if not state.is_live():
        st.markdown('<div class="sn-hero calm"><div class="eyebrow">Live demo</div><div class="h">Switch to the live NEXUS stream</div>'
                    '<div class="p">The live demo watches NEXUS, a fictional company portal running on this laptop. Its sign-ins '
                    'and changes are streamed to SENTINEL as they happen.</div></div>', unsafe_allow_html=True)
        if st.button("Switch to live monitoring", type="primary", icon=":material/sensors:"):
            state.select_live()
            st.rerun()
        return
    pm = st.toggle("Presentation mode", key="ld_pm", help="A guided five-minute walkthrough. Each step is ticked only when "
                   "the application state shows it has actually happened.")
    _workspace(pm)


@st.fragment(run_every=2)
def _workspace(pm):
    st_, code = api("/api/demo/status")
    snap = state.refresh_live()
    state.notify_tick(snap)
    if pm:
        _presentation(st_, snap)
    a, b = st.columns([1, 2.1], gap="large")
    with a:
        _target(st_)
    with b:
        _controller(st_)
    _detection(st_, snap)


# --------------------------------------------------------------------------- A. NEXUS target
def _target(st_):
    up = st_ is not None
    sess = (st_ or {}).get("session")
    html = (f'<div class="sn-card"><h4>A · NEXUS target</h4>'
            f'<div class="sn-row"><span>Portal</span><span style="color:{"var(--ok)" if up else "var(--bad)"}">'
            f'{"running on 127.0.0.1:8502" if up else "not running"}</span></div>'
            f'<div class="sn-row"><span>Demo session</span><span class="n">{esc(sess or "-")}</span></div>'
            f'<div class="sn-row"><span>Events written by NEXUS</span><span class="n">{(st_ or {}).get("events_emitted", 0):,}</span></div>'
            '<div class="sn-muted" style="margin-top:8px">NEXUS is a fictional corporate portal. Its sign-ins are real HTTP '
            'logins handled by its own code. Attacker addresses are simulated documentation addresses; endpoint process and '
            'log-clearing events are synthetic and labelled. Nothing leaves this laptop.</div></div>')
    st.markdown(html, unsafe_allow_html=True)
    if not up:
        st.warning("NEXUS is not reachable. Run `powershell -ExecutionPolicy Bypass -File scripts\\start_demo.ps1`, then this "
                   "page updates by itself. Fallback: choose a saved dataset (e.g. demo_unseen) in the selector above.")
        return
    c = st.columns(2)
    c[0].link_button("Open NEXUS login", f"{NEXUS_URL}/login", icon=":material/login:", use_container_width=True)
    c[1].link_button("Demo accounts", f"{NEXUS_URL}/demo#accounts", icon=":material/key:", use_container_width=True,
                     help="The local scenario controller lists the fictional accounts and their locally generated passwords.")


# --------------------------------------------------------------------------- B. scenario controller
def _controller(st_):
    r = (st_ or {}).get("runner") or {}
    stt = r.get("state", "idle")
    busy = stt in ("running", "paused")
    up = st_ is not None
    st.markdown(f'<div class="sn-eyebrow">B · Scenario controller</div>', unsafe_allow_html=True)
    rows = [CARDS[:4], CARDS[4:]]
    for row in rows:
        cols = st.columns(4, gap="small")
        for col, (sid, title, what, expect) in zip(cols, row):
            with col:
                cur = r.get("scenario") == sid and busy
                st.markdown(f'<div class="sn-scn{" primary" if sid == "G" else ""}"><span class="id">{sid}</span>'
                            f'<div class="t">{esc(title)}</div><div class="d">{esc(what)}</div>'
                            f'<div class="e">SENTINEL: {esc(expect)}</div></div>', unsafe_allow_html=True)
                if st.button("Running…" if cur else ("Start" if sid != "G" else "Start the full attack"), key=f"ld_run_{sid}",
                             type="primary" if sid == "G" else "secondary", use_container_width=True, disabled=busy or not up):
                    res, code = api(f"/api/demo/run/{sid}", post=True)
                    if code != 200:
                        st.toast((res or {}).get("message", "NEXUS refused the request"))
                    st.rerun(scope="fragment")
    c = st.columns(4)
    if c[0].button("Pause", icon=":material/pause:", disabled=stt != "running", use_container_width=True, key="ld_pause"):
        api("/api/demo/pause", post=True)
        st.rerun(scope="fragment")
    if c[1].button("Resume", icon=":material/play_arrow:", disabled=stt != "paused", use_container_width=True, key="ld_resume"):
        api("/api/demo/resume", post=True)
        st.rerun(scope="fragment")
    if c[2].button("Stop", icon=":material/stop:", disabled=not busy, use_container_width=True, key="ld_stop"):
        api("/api/demo/stop", post=True)
        st.rerun(scope="fragment")
    if c[3].button("New demo session", icon=":material/restart_alt:", disabled=not up, use_container_width=True, key="ld_reset",
                   help="Starts an empty session with 7 days of labelled synthetic baseline sign-ins. Only demo_data is affected; "
                        "the old session stays on disk."):
        res, _ = api("/api/demo/start", post=True, timeout=30)
        st.toast(f"New demo session {res['session']} with {res['backfilled']} baseline events" if res else "NEXUS did not respond")
        S.pop("pm_flags", None)
        st.rerun(scope="app")


# --------------------------------------------------------------------------- C. live detection
def _detection(st_, snap):
    r = (st_ or {}).get("runner") or {}
    se = (st_ or {}).get("sentinel") or {}
    emitted = (st_ or {}).get("events_emitted", 0)
    ingested = snap["events"]
    a = snap["analysis"]
    st.markdown('<div class="sn-eyebrow" style="margin-top:6px">C · Live detection</div>', unsafe_allow_html=True)
    k = st.columns([1, 1, 1, 1])
    vals = [(f"{emitted:,}", "events generated by NEXUS"), (f"{ingested:,}", "events ingested by SENTINEL"),
            (str(len(a.incidents) if a else 0), "incidents"),
            (f"{r.get('step', 0)}/{r.get('steps', 0)}" if r.get("steps") else "-", f"scenario steps · {r.get('state', 'idle')}")]
    for col, (v, l) in zip(k, vals):
        col.markdown(f'<div class="sn-stat" style="margin-bottom:14px"><div class="v">{esc(v)}</div><div class="l">{esc(l)}</div></div>', unsafe_allow_html=True)
    if r.get("steps"):
        st.progress(min(1.0, r.get("step", 0) / max(1, r["steps"])),
                    text=f"{r.get('name') or ''} · {r.get('state')}" + (f" · {r['elapsed_s']} s" if r.get("elapsed_s") else ""))
    left, right = st.columns([1.1, 1], gap="large")
    with left:
        incs = a.incidents if a else []
        if not incs:
            st.markdown('<div class="sn-card"><h4>Incidents</h4><div class="sn-muted">No incident in this session yet. Normal '
                        'activity produces events, not incidents.</div></div>', unsafe_allow_html=True)
        tracked = snap.get("track_by_incident") or {}
        for inc in incs[:4]:
            t = tracked.get(inc["incident_id"]) or state.live_engine()._track_of(inc)
            sev = inc["severity"]
            hist = t.get("history") or []
            path = " → ".join(dict.fromkeys(h["level"] for h in hist)) if hist else sev["level"]
            rules = [RULE_PHRASE.get(x, x) for x in inc["rules"] if x != "CTX"]
            lat = f" · detected {t['latency_s']:.1f} s after the triggering event" if t.get("latency_s") is not None else ""
            st.markdown(f'<div class="sn-notif" style="--c:{SEV_COLOR[sev["level"]]}"><div class="k">{esc(sev["level"])} · '
                        f'{sev["score"]}/100 · severity path {esc(path)}</div><div class="h">{esc(inc["title"])}</div>'
                        f'<div class="b">{esc("; ".join(rules[:5]))}</div><div class="m">{len(inc["event_ids"])} events{esc(lat)}</div></div>',
                        unsafe_allow_html=True)
            if st.button("Investigate", key=f"ld_inv_{inc['incident_id']}", type="primary"):
                state.goto("Investigation Studio", inc["incident_id"], view="Story")
                st.rerun(scope="app")
    with right:
        log = r.get("log") or []
        body = "".join(f'<div class="sn-act" style="grid-template-columns:1fr"><div class="d">{esc(x)}</div></div>' for x in log[-8:][::-1]) \
            or '<div class="sn-muted">Scenario steps appear here as they run.</div>'
        st.markdown(f'<div class="sn-card"><h4>Scenario steps (from the NEXUS controller)</h4>{body}</div>', unsafe_allow_html=True)
        if se:
            st.caption(f"Detection engine last checked the stream at {se.get('last_poll') or '-'} · "
                       f"{se.get('duplicates_skipped', 0)} duplicates skipped · analysis {se.get('analysis_s') or '-'} s")


# --------------------------------------------------------------------------- presentation mode
def _normal_login_seen(a) -> bool:
    if a is None:
        return False
    ok = a.events[a.events["action"] == "login_success"]
    for raw in ok["raw"].tail(400):
        try:
            r = json.loads(raw)
        except ValueError:
            continue
        # the normalised raw column keeps values as text ("False"), so compare as text
        if r.get("origin") == "nexus-app" and str(r.get("source_address_simulated")).strip().lower() in ("false", "0", ""):
            return True
    return False


def progress_flags(st_, snap) -> list[bool]:
    """Each step is done only when the application state shows it (not when a button was merely pressed)."""
    a = snap["analysis"]
    f = S.get("pm_flags", {})
    sess = snap.get("session_id")
    incs = a.incidents if a else []
    attack = bool(a is not None and a.events["raw"].str.contains(r'"scenario_id":\s*"[B-G]"', regex=True).any())
    iid = S.get("selected")
    return [st_ is not None,
            _normal_login_seen(a),
            attack,
            bool(incs),
            f.get("opened") == sess and bool(incs),
            f.get("story") == sess and bool(incs),
            any(i in S.get("explanations", {}) or S.get("chat", {}).get(i) for i in [x["incident_id"] for x in incs]),
            f.get("report") == sess and bool(incs)]


def mark(step: str):
    """Called by other pages when the presenter actually did something (opened the incident, viewed the evidence,
    produced the report)."""
    if not state.is_live():
        return
    f = S.setdefault("pm_flags", {})
    f[step] = state.live_engine().snapshot().get("session_id")


def _presentation(st_, snap):
    done = progress_flags(st_, snap)
    cur = next((k for k, d in enumerate(done) if not d), len(done))
    bar = "".join(f'<i class="{"done" if d else "now" if k == cur else ""}"></i>' for k, d in enumerate(done))
    items = "".join(f'<div class="sn-check {"done" if d else "now" if k == cur else "todo"}">{"✓" if d else k + 1}. {esc(s)}</div>'
                    for k, (s, d) in enumerate(zip(STEPS, done)))
    hint = {0: "Start the services: scripts\\start_demo.ps1. This page updates when NEXUS answers.",
            1: "Open NEXUS login, sign in as an employee (passwords are under Demo accounts), then sign out.",
            2: "Press “Start the full attack” (scenario G) below.",
            3: "Wait a few seconds: the incident appears below and a notification pops up.",
            4: "Press Investigate on the incident (or in the notification bell).",
            5: "In Investigation Studio, read the Story and open Evidence.",
            6: "In Investigation Studio → AI investigation, press “Explain with local Qwen” or ask a question.",
            7: "Open Reports & Evaluation → Report and download the HTML report."}.get(cur, "All steps complete.")
    c1, c2 = st.columns([1.2, 1], gap="large")
    with c1:
        st.markdown(f'<div class="sn-card"><h4>Presentation mode · step {min(cur + 1, len(STEPS))} of {len(STEPS)}</h4>'
                    f'<div class="sn-progress">{bar}</div><div class="sn-exec">Next: {esc(hint)}</div></div>', unsafe_allow_html=True)
        nxt = {1: ("Open NEXUS login", f"{NEXUS_URL}/login"), 4: None, 5: None, 6: None, 7: None}.get(cur)
        if nxt:
            st.link_button(nxt[0], nxt[1], type="primary")
        elif cur in (4, 5, 6) and snap["analysis"] is not None and snap["analysis"].incidents:
            iid = snap["analysis"].incidents[0]["incident_id"]
            view = {4: "Story", 5: "Evidence", 6: "AI investigation"}[cur]
            if st.button(f"Go: {STEPS[cur]}", type="primary", key="pm_go"):
                state.goto("Investigation Studio", iid, view=view)
                st.rerun(scope="app")
        elif cur == 7 and snap["analysis"] is not None and snap["analysis"].incidents:
            if st.button("Go: open the report", type="primary", key="pm_go_r"):
                state.goto("Reports & Evaluation", snap["analysis"].incidents[0]["incident_id"], view="Report")
                st.rerun(scope="app")
    with c2:
        st.markdown(f'<div class="sn-card">{items}</div>', unsafe_allow_html=True)
