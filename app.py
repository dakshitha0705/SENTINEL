"""SENTINEL - Offline Security Incident Triage Assistant (Tinyverse Hackathon, PS 02).

Run:  .venv\\Scripts\\streamlit run app.py
Everything runs locally; the only network traffic is to the local Ollama server on 127.0.0.1.
Pages live in sentinel/ui/pages/; backend logic in sentinel/*.py.
"""
from __future__ import annotations

import streamlit as st

from sentinel import __version__
from sentinel.perf import connection_snapshot
from sentinel.search import search
from sentinel.slm import status as slm_status
from sentinel.ui import esc, pill
from sentinel.ui import state
from sentinel.ui.pages import (ai_lab, attack_graph, command_center, evaluation, incidents, log_intelligence,
                               reports, system_settings, threat_intel)
from sentinel.ui.state import ICONS, PAGES, TIME_RANGES, S
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
# ?sample=<dataset>&page=<n>&incident=<rank>&explain=1  loads a dataset, runs the analysis and opens a page.
_qp = st.query_params
if _qp.get("live") == "1" and not S.get("_qp_live"):
    S._qp_live = True
    state.select_live()
    if _qp.get("page", "").isdigit():
        S.nav = PAGES[int(_qp["page"]) % len(PAGES)]
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

if state.is_live():
    state.refresh_live()

# --------------------------------------------------------------------------- sidebar navigation
with st.sidebar:
    st.markdown('<div class="sn-brand">SENTINEL</div><div class="sn-brand-sub">Offline incident triage</div>',
                unsafe_allow_html=True)
    st.write("")
    if S.get("goto"):
        S.nav = S.pop("goto")
    page = st.radio("Navigate", PAGES, key="nav", label_visibility="collapsed",
                    format_func=lambda p: f":material/{ICONS[p]}:  {p}")
    st.divider()
    a = S.analysis
    if a:
        st.markdown(f'<div class="sn-side-foot">Dataset<br><b>{esc(S.dataset or "-")}</b><br>'
                    f'{len(a.events):,} events &middot; {len(a.incidents)} incidents</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="sn-side-foot" style="margin-top:10px">v{__version__} &middot; Tinyverse PS 02<br>'
                'Runs fully offline</div>', unsafe_allow_html=True)

# --------------------------------------------------------------------------- top bar (every page)
stat = _slm_status(S.cfg["slm"]["host"], S.cfg["slm"]["model"])
ext = _external_now()
qwen_ok = stat["reachable"] and stat["model_installed"]
loaded = next((m for m in stat.get("loaded", []) if m["name"] == S.cfg["slm"]["model"]), None)
mode = "CPU" if S.cfg["slm"].get("num_gpu") == 0 else ("GPU" if loaded and (loaded.get("gpu_share") or 0) > 0.5 else "GPU/CPU auto")
tb = st.columns([2.2, 2.4, 2.1, 1.2, 3.1], vertical_alignment="center")
with tb[0]:
    st.markdown(f'<div class="sn-title{" page" if page != "Command Center" else ""}">{esc(page.upper()) if page != "Command Center" else "SENTINEL"}</div>'
                f'<div class="sn-title-sub">{"Command center" if page == "Command Center" else "SENTINEL"}</div>', unsafe_allow_html=True)
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

    st.selectbox("Dataset", names, key="dataset_pick", on_change=_switch, label_visibility="collapsed",
                 help="Active dataset. Switching re-runs the deterministic analysis (the local SLM is not called).")
with tb[3]:
    st.selectbox("Time range", list(TIME_RANGES), key="time_range", label_visibility="collapsed",
                 help="Filters incidents and globe markers to the last part of the dataset's own time span.")
with tb[4]:
    offline_cls = "ok" if ext == 0 else "bad"
    chips = [f'<span class="sn-chip {offline_cls}"><i></i>{"0 external connections" if ext == 0 else f"{ext} external connections"}</span>',
             f'<span class="sn-chip {"ok" if qwen_ok else "warn"}"><i></i>{esc(S.cfg["slm"]["model"])} '
             f'{"ready" if qwen_ok else "unavailable"}</span>',
             f'<span class="sn-chip"><i></i>{mode}</span>']
    if state.is_live():
        chips.insert(0, '<span class="sn-chip live"><i></i>LIVE MONITORING</span>')
    st.markdown('<div class="sn-top" style="justify-content:flex-end">' + "".join(chips) + "</div>", unsafe_allow_html=True)
if S.profile_note and page in ("Command Center", "Log Intelligence"):
    st.caption(S.profile_note)

# --------------------------------------------------------------------------- global search results
if q and q.strip():
    res = search(S.analysis, q)
    with st.container(key="card_search"):
        st.markdown(f"**Search** &middot; `{esc(q)}` &middot; {len(res['incidents'])} incident(s), {len(res['alerts'])} "
                    f"alert(s), {res['total_events']:,} event(s)", unsafe_allow_html=True)
        for inc in res["incidents"][:6]:
            c1, c2 = st.columns([6, 1], vertical_alignment="center")
            c1.markdown(pill(inc["severity"]["level"], f"{inc['incident_id']} · {inc['severity']['level']} {inc['severity']['score']}")
                        + f" &nbsp;{esc(inc['title'])}", unsafe_allow_html=True)
            if c2.button("Open", key=f"sr_{inc['incident_id']}"):
                state.goto("Incident Investigation", inc["incident_id"])
                st.rerun()
        if len(res["events"]):
            with st.expander(f"Matching events ({res['total_events']:,}; first {len(res['events'])} shown)"):
                show = res["events"].drop(columns=["raw"]).copy()
                show["timestamp"] = show["timestamp"].astype(str)
                st.dataframe(show, hide_index=True, use_container_width=True)
        if not (res["incidents"] or res["alerts"] or len(res["events"])):
            st.caption("No matches in the current analysis.")

# --------------------------------------------------------------------------- live banner on analysis pages


@st.fragment(run_every=3)
def _live_banner():
    snap = state.live_engine().snapshot()
    new = snap["events"] - S.get("_live_seen", snap["events"])
    if new > 0:
        c1, c2 = st.columns([5, 1], vertical_alignment="center")
        c1.markdown(f'<div class="sn-mode incident"><span class="sn-chip live"><i></i>LIVE</span><b>{new} new event(s)</b> '
                    f'arrived from NEXUS since this view was loaded &middot; '
                    f'{len(snap["analysis"].incidents) if snap["analysis"] else 0} incidents now</div>', unsafe_allow_html=True)
        if c2.button("Refresh view", key="live_refresh", use_container_width=True):
            st.rerun(scope="app")


if state.is_live() and page != "Command Center":
    S._live_seen = state.live_engine().snapshot()["events"]     # this full run shows the engine's current state
    _live_banner()

# --------------------------------------------------------------------------- router
{"Command Center": command_center.render, "Log Intelligence": log_intelligence.render,
 "Incident Investigation": incidents.render, "Attack Graph": attack_graph.render,
 "AI Investigation Lab": ai_lab.render, "Threat Intelligence": threat_intel.render,
 "Evaluation & Benchmarks": evaluation.render, "Report Studio": reports.render,
 "System & Settings": system_settings.render}[page]()
