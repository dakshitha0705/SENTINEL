"""SENTINEL - Offline Security Incident Triage Assistant (Tinyverse Hackathon, PS 02).

Run:  .venv\\Scripts\\streamlit run app.py
Everything runs locally; the only network traffic is to the local Ollama server on 127.0.0.1.
Pages live in sentinel/ui/pages/; backend logic in sentinel/*.py.
"""
from __future__ import annotations

import time

import streamlit as st

from sentinel import __version__
from sentinel.perf import connection_snapshot
from sentinel.search import search
from sentinel.slm import status as slm_status
from sentinel.ui import SEV_COLOR, esc, pill
from sentinel.ui import state
from sentinel.ui.pages import (command_center, hunting, live_demo, log_intelligence, reports_eval, studio,
                               system_settings)
from sentinel.ui.state import ICONS, PAGES, S
from sentinel.ui.theme import CSS

st.set_page_config(page_title="SENTINEL", page_icon=None, layout="wide", initial_sidebar_state="expanded")
st.markdown(CSS, unsafe_allow_html=True)
state.init()


@st.cache_data(ttl=15, show_spinner=False)
def _slm_status(host: str, model: str):
    return slm_status(S.cfg)


@st.cache_data(ttl=10, show_spinner=False)
def _external_now() -> int:
    return sum(1 for c in connection_snapshot() if c["scope"] == "EXTERNAL")


# --------------------------------------------------------------------------- URL shortcuts (demo / screenshots)
# ?live=1 selects the live NEXUS stream (and keeps it selected on refresh: the URL is the source of truth);
# ?sample=<dataset>&page=<n>&incident=<rank>&explain=1 loads a dataset, runs the analysis and opens a page.
_qp = st.query_params
if _qp.get("live") == "1":
    if not state.is_live():
        state.select_live()
    if not S.get("_qp_page_done") and _qp.get("page", "").isdigit():
        S.nav = PAGES[int(_qp["page"]) % len(PAGES)]
    S._qp_page_done = True
elif _qp.get("sample") and S.get("_qp_done") != _qp.get("sample"):
    if _qp["sample"] in state.list_datasets():
        with st.spinner("Loading dataset and running analysis..."):
            state.load_dataset(_qp["sample"], run=False)
            state.run_analysis(auto_explain=_qp.get("explain", "0") == "1")
    S._qp_done = _qp.get("sample")
    if _qp.get("page", "").isdigit():
        S.nav = PAGES[int(_qp["page"]) % len(PAGES)]
    if _qp.get("incident", "").isdigit() and S.analysis and S.analysis.incidents:
        S.selected = S.analysis.incidents[min(int(_qp["incident"]), len(S.analysis.incidents) - 1)]["incident_id"]
elif S.analysis is None and S.dataset is None:
    # First visit: open the bundled unseen-format demo dataset (deterministic analysis only, no SLM call).
    names = state.list_datasets()
    if names:
        state.load_dataset("demo_unseen" if "demo_unseen" in names else names[0])



def _toast(n):
    icon = ":material/crisis_alert:" if n["kind"] == "escalated" or n["level"] in ("Critical", "High") else ":material/notifications:"
    head = "New incident detected" if n["kind"] == "new" else "Incident escalated"
    st.toast(f"**{head}** · {n['level']} {n.get('score', '')}  \n{n.get('summary') or n['text']}  \n"
             "Open the bell (top right) to investigate.", icon=icon)


if state.is_live():
    _snap0 = state.refresh_live()
    for _n in S.pop("_pending_toasts", []) + state.sync_notifications(_snap0):
        _toast(_n)

# --------------------------------------------------------------------------- sidebar navigation
with st.sidebar:
    st.markdown('<div class="sn-brand">SENTINEL</div><div class="sn-brand-sub">Offline incident triage</div>',
                unsafe_allow_html=True)
    st.write("")
    if S.get("goto"):
        S.nav = S.pop("goto")
    if S.get("nav") not in PAGES:
        S.nav = PAGES[0]
    page = st.radio("Navigate", PAGES, key="nav", label_visibility="collapsed",
                    format_func=lambda p: f":material/{ICONS[p]}:  {p}")
    st.divider()
    a = S.analysis
    src = "Live NEXUS stream" if state.is_live() else (S.dataset or "-")
    if a is not None:
        st.markdown(f'<div class="sn-side-foot">Data source<br><b>{esc(src)}</b><br>'
                    f'{len(a.events):,} events &middot; {len(a.incidents)} incidents</div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="sn-side-foot">Data source<br><b>{esc(src)}</b><br>no events yet</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="sn-side-foot" style="margin-top:12px">v{__version__} &middot; Tinyverse PS 02<br>'
                'Runs fully offline on this laptop</div>', unsafe_allow_html=True)

# pending deep-link view switch (e.g. "Attack graph" inside Investigation Studio)
if S.get("_goto_view"):
    k, v = S.pop("_goto_view")
    S[k] = v


# --------------------------------------------------------------------------- system status (advanced panel)
@st.dialog("System status", width="large")
def _system_dialog():
    system_settings.render()


def _system_popover(stat, ext):
    qwen_ok = stat["reachable"] and stat["model_installed"]
    loaded = next((m for m in stat.get("loaded", []) if m["name"] == S.cfg["slm"]["model"]), None)
    place = "CPU only" if S.cfg["slm"].get("num_gpu") == 0 else (
        f"GPU ({loaded['gpu_share']:.0%} of the model in VRAM)" if loaded and loaded.get("gpu_share") else "GPU/CPU automatic (not loaded yet)")
    rows = [("Network", "0 external connections" if ext == 0 else f"{ext} external connection(s) open", ext == 0),
            ("Local model", f"{S.cfg['slm']['model']} {'ready' if qwen_ok else 'unavailable'}", qwen_ok),
            ("Model placement", place, True)]
    if state.is_live():
        ls = state.live_status()
        rows.append(("Live detection", f"{ls['engine']}" + (f" · last check {ls['last_poll']}" if ls["last_poll"] else ""),
                     ls["worker"] or ls["running"]))
    html = "".join(f'<div class="sn-row"><span>{esc(k)}</span><span style="color:{"var(--ok)" if ok else "var(--bad)"}">{esc(v)}</span></div>'
                   for k, v, ok in rows)
    st.markdown(html, unsafe_allow_html=True)
    st.caption("The network count is a live socket check of this app, the local model and NEXUS. The disconnected "
               "(Wi-Fi off) test is a separate, recorded run: see Reports & Evaluation → Offline evidence.")
    if st.button("Open advanced panel", icon=":material/tune:", use_container_width=True,
                 help="Offline monitor, model settings, detection configuration, audit, offline validation, credits"):
        _system_dialog()
    return qwen_ok


def _notif_popover():
    unread = state.unread_notifications()
    hist = S.get("notif_history", [])
    if not hist:
        st.caption("No notifications yet. In live mode, SENTINEL notifies you when a new incident is detected or an "
                   "incident's severity increases.")
        return
    if unread and st.button("Mark all as read", key="notif_all", use_container_width=True):
        S.notif_ack = S.get("notif_ack", set()) | {n["uid"] for n in hist}
        st.rerun()
    for n in hist[:8]:
        _notif_card(n, key=f"bell_{n['uid']}")


def _notif_card(n, key):
    c = SEV_COLOR.get(n.get("level"), "#E3A587")
    head = "New incident detected" if n["kind"] == "new" else "Incident escalated"
    who = ", ".join(n.get("users") or n.get("hosts") or [])
    meta = f"{n.get('level', '')} {n.get('score', '')}" + (f" · {who}" if who else "") + f" · {time.strftime('%H:%M:%S', time.localtime(n['t']))}"
    if n["kind"] == "escalated" and n.get("prev_level"):
        meta = f"{n['prev_level']} → " + meta
    unread = n["uid"] not in S.get("notif_ack", set())
    st.markdown(f'<div class="sn-notif" style="--c:{c}"><div class="k">{esc(head)}{" · unread" if unread else ""}</div>'
                f'<div class="b">{esc(n.get("summary") or n["text"])}</div><div class="m">{esc(meta)}</div></div>',
                unsafe_allow_html=True)
    b = st.columns(2)
    if b[0].button("Investigate", key=f"{key}_go", type="primary", use_container_width=True):
        S.notif_ack = S.get("notif_ack", set()) | {n["uid"]}
        state.goto("Investigation Studio", state.resolve_incident(n), view="Story")
        st.rerun()
    if unread and b[1].button("Dismiss", key=f"{key}_ok", use_container_width=True):
        S.notif_ack = S.get("notif_ack", set()) | {n["uid"]}
        st.rerun()


# --------------------------------------------------------------------------- top bar (every page)
stat = _slm_status(S.cfg["slm"]["host"], S.cfg["slm"]["model"])
ext = _external_now()
tb = st.columns([2.0, 2.7, 2.0, 1.75, 0.62, 0.62], vertical_alignment="center")
with tb[0]:
    sub = {"Command Center": "What is happening now", "Live Demo": "Watch a controlled attack being detected",
           "Log Intelligence": "Upload, review, analyse", "Investigation Studio": "Follow the evidence",
           "Threat Hunting": "Search for suspicious behaviour", "Reports & Evaluation": "Share findings, check accuracy"}[page]
    st.markdown(f'<div class="sn-title">{esc(page)}</div><div class="sn-title-sub">{esc(sub)}</div>', unsafe_allow_html=True)
with tb[1]:
    q = st.text_input("Search", key="search_q", placeholder="Search incidents, users, hosts, IPs, commands",
                      label_visibility="collapsed")
with tb[2]:
    names = state.list_datasets()
    if S.dataset in names and S.get("dataset_pick") != S.dataset:
        S.dataset_pick = S.dataset          # keep the selector in sync with programmatic switches

    def _switch():
        if S.dataset_pick != state.UPLOADED:
            state.load_dataset(S.dataset_pick)

    st.selectbox("Data source", names, key="dataset_pick", on_change=_switch, label_visibility="collapsed",
                 help="Where the data comes from. LIVE follows the NEXUS demo stream; the others are saved datasets. "
                      "Switching re-runs the deterministic analysis (the local model is not called).")
with tb[3]:
    if state.is_live():
        ls = state.live_status()
        ok = ls["worker"] or ls["running"]
        label = "LIVE · monitoring" if ok else "LIVE · detection stopped"
        st.markdown(f'<div class="sn-top"><span class="sn-chip {"live" if ok else "bad"}" title="{esc(ls["engine"])}">'
                    f'<i></i>{label}</span></div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="sn-top"><span class="sn-chip data"><i></i>Saved data</span>'
                    f'<span class="sn-chip {"ok" if ext == 0 else "bad"}" title="Live socket check"><i></i>Offline</span></div>',
                    unsafe_allow_html=True)
with tb[4]:
    n_unread = len(state.unread_notifications())
    with st.popover(str(n_unread) if n_unread else "", icon=":material/notifications:", use_container_width=True,
                    help="Notifications"):
        _notif_popover()
with tb[5]:
    with st.popover("", icon=":material/monitor_heart:", use_container_width=True, help="System status"):
        _system_popover(stat, ext)
if S.profile_note and page == "Log Intelligence":
    st.caption(S.profile_note)

# --------------------------------------------------------------------------- global search results
if q and q.strip():
    res = search(S.analysis, q)
    with st.container(key="card_search"):
        st.markdown(f"**Search** &middot; `{esc(q)}` &middot; {len(res['incidents'])} incident(s), {len(res['alerts'])} "
                    f"detection(s), {res['total_events']:,} event(s)", unsafe_allow_html=True)
        for inc in res["incidents"][:6]:
            c1, c2 = st.columns([6, 1], vertical_alignment="center")
            c1.markdown(pill(inc["severity"]["level"], f"{inc['severity']['level']} {inc['severity']['score']}")
                        + f" &nbsp;{esc(inc['title'])} <span class='sn-cite'>{esc(inc['incident_id'])}</span>", unsafe_allow_html=True)
            if c2.button("Open", key=f"sr_{inc['incident_id']}"):
                state.goto("Investigation Studio", inc["incident_id"], view="Story")
                st.rerun()
        if len(res["events"]):
            with st.expander(f"Matching events ({res['total_events']:,}; first {len(res['events'])} shown)"):
                show = res["events"].drop(columns=["raw"]).copy()
                show["timestamp"] = show["timestamp"].astype(str)
                st.dataframe(show, hide_index=True, use_container_width=True)
        if not (res["incidents"] or res["alerts"] or len(res["events"])):
            st.caption("No matches in the current data.")


# --------------------------------------------------------------------------- live watcher (every page)
@st.fragment(run_every=3)
def _live_watch():
    """Real `new`/`escalated` notifications from the live engine, shown once each, on whatever page is open."""
    snap = state.live_engine().snapshot()
    state.notify_tick(snap)          # a new/escalated incident refreshes the whole page once (bell, lists) + toast
    new = snap["events"] - S.get("_live_seen", snap["events"])
    if new > 0:
        c1, c2 = st.columns([5, 1], vertical_alignment="center")
        c1.markdown(f'<div class="sn-mode"><span class="sn-chip live"><i></i>LIVE</span><b>{new} new event(s)</b> '
                    f'arrived from NEXUS since this view was loaded &middot; '
                    f'{len(snap["analysis"].incidents) if snap["analysis"] else 0} incidents now</div>', unsafe_allow_html=True)
        if c2.button("Refresh view", key="live_refresh", use_container_width=True):
            st.rerun(scope="app")


if state.is_live() and page not in ("Command Center", "Live Demo"):   # those pages refresh themselves
    S._live_seen = state.live_engine().snapshot()["events"]     # this full run shows the engine's current state
    _live_watch()

# --------------------------------------------------------------------------- router
{"Command Center": command_center.render, "Live Demo": live_demo.render, "Log Intelligence": log_intelligence.render,
 "Investigation Studio": studio.render, "Threat Hunting": hunting.render,
 "Reports & Evaluation": reports_eval.render}[page]()
