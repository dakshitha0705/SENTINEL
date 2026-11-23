"""Command Center: KPIs, interactive 3D globe (or storyline view), severity, detections, urgent incidents,
live monitoring of the NEXUS demo stream, and the four primary actions."""
from __future__ import annotations

import time
from collections import Counter

import streamlit as st

from ... import geospatial
from ... import graph as gmod
from ...rules import RULES
from .. import SEV_COLOR, esc, pill
from .. import components, state
from ..state import S

ORIGIN_TAG = {"nexus-app": "APP", "simulated-endpoint": "SIM", "baseline-backfill": "HIST"}


def _kpi(label, value, sub, k):
    return (f'<div class="sn-kpi {k}"><div class="l">{esc(label)}</div><div class="v">{esc(value)}</div>'
            f'<div class="s">{esc(sub)}</div></div>')


def render():
    if state.is_live():
        _live()
    else:
        _body(None)


@st.fragment(run_every=2)
def _live():
    snap = state.refresh_live()
    seen = S.get("_notified", 0)
    for n in snap["notifications"]:
        if n["id"] > seen and (time.time() - n["t"]) < 60:
            st.toast(n["text"], icon=":material/crisis_alert:" if n["level"] in ("Critical", "High") else ":material/notifications:")
    S._notified = max([seen] + [n["id"] for n in snap["notifications"]])
    _body(snap)


def _mode_strip(a, incs, snap):
    if snap is None:
        return
    crit = [i for i in incs if i["severity"]["level"] in ("Critical", "High")]
    if crit:
        top = crit[0]
        cls, label = "incident", f"<b>INCIDENT INVESTIGATION</b> &middot; {esc(top['incident_id'])} {esc(top['severity']['level'])} " \
                                 f"{top['severity']['score']} &middot; {esc(' -> '.join(top['stages']))}"
    else:
        cls, label = "", "<b>LIVE MONITORING</b> &middot; no high-severity incident in the demo stream"
    lat = [t.get("latency_s") for t in snap["tracked"].values() if t.get("latency_s") is not None]
    st.markdown(f'<div class="sn-mode {cls}"><span class="sn-chip live"><i></i>LIVE · NEXUS DEMO</span>{label}'
                f'<span style="margin-left:auto">session {esc(snap["session_id"] or "-")} &middot; {snap["events"]:,} events '
                f'&middot; last poll {esc(snap["last_poll"] or "-")}'
                + (f' &middot; detection latency {min(lat):.1f}–{max(lat):.1f} s' if lat else "") + "</span></div>",
                unsafe_allow_html=True)
    if snap["error"]:
        st.error(f"Live engine error: {snap['error']}")


def _feed(snap):
    rows = []
    for e in state.live_engine().recent_events(14):
        if e.get("origin") == "baseline-backfill":
            continue
        cls = "f" if e.get("outcome") == "failure" else "s"
        who = e.get("TargetUserName") or e.get("SubjectUserName") or ""
        if e.get("EventID") == "4732":
            who = f'{e.get("SubjectUserName")} +{e.get("MemberName")} -> {e.get("TargetUserName")}'
        ip = e.get("IpAddress", "-")
        rows.append(f'<div><span class="x">{esc(e["TimeCreated"][11:19])}</span><span class="{cls}">{esc(e["EventID"])}</span>'
                    f'<span>{esc(e["event_type"])} · {esc(who)} · {esc(ip)} <span class="tag">[{ORIGIN_TAG.get(e.get("origin"), "?")}]</span>'
                    + (' <span class="tag">sim-src</span>' if e.get("source_address_simulated") else "") + "</span></div>")
    body = "".join(rows) or '<div class="sn-muted">Waiting for NEXUS events. Start a scenario in the NEXUS controller.</div>'
    st.markdown(f'<div class="sn-card"><h4>Live event stream &middot; NEXUS</h4><div class="sn-feed">{body}</div>'
                '<div class="sn-muted" style="margin-top:6px">APP = produced by NEXUS application code · SIM = synthetic endpoint '
                f'telemetry · sim-src = simulated client address &middot; <a href="{state.NEXUS_URL}/demo" target="_blank">open controller</a></div></div>',
                unsafe_allow_html=True)


def _body(snap):
    a = S.analysis
    if a is None:
        if snap is not None:
            st.markdown('<div class="sn-mode"><span class="sn-chip live"><i></i>LIVE · NEXUS DEMO</span>'
                        '<b>Waiting for events</b> &middot; start the NEXUS demo (scripts\\start_demo.ps1) and press "Start demo"</div>',
                        unsafe_allow_html=True)
            _feed(snap)
        else:
            st.info("No dataset loaded. Choose one in the dataset selector above or upload logs in Log Intelligence.")
        return
    incs = state.visible_incidents(a)
    win = state.time_window(a)
    ev = a.events if not win else a.events[(a.events["timestamp"] >= win[0]) & (a.events["timestamp"] <= win[1])]
    users = {u for i in incs for u in i["users"]}
    hosts = {h for i in incs for h in i["hosts"]}
    lv = Counter(i["severity"]["level"] for i in incs)
    _mode_strip(a, incs, snap)

    left, center, right = st.columns([1.0, 2.8, 1.35], gap="medium")
    with left:
        st.markdown(_kpi("Total events", f"{len(ev):,}", f"{ev['host'].nunique()} hosts in logs", "")
                    + _kpi("Active incidents", len(incs), f"{lv.get('Critical', 0)} critical · {lv.get('High', 0)} high", "k3" if lv.get("Critical") else "k2")
                    + _kpi("Affected identities", len(users), "accounts in incidents", "k2")
                    + _kpi("Affected hosts", len(hosts), "hosts in incidents", "k4"), unsafe_allow_html=True)
        span = f"{a.events['timestamp'].min():%d %b %H:%M} – {a.events['timestamp'].max():%d %b %H:%M} UTC" if len(a.events) else "-"
        st.markdown(f'<div class="sn-muted" style="padding:0 4px;font-family:var(--mono);font-size:.72rem">SPAN {esc(span)}<br>'
                    f'ANALYSIS {a.timings.get("analysis_total_s", 0):.2f} s · deterministic</div>', unsafe_allow_html=True)

    with center:
        c1, c2 = st.columns([3, 1.2])
        view = c1.radio("View", ["Geographic", "Attack storyline"], horizontal=True, key="cc_view", label_visibility="collapsed")
        quality = c2.radio("Quality", ["high", "low"], horizontal=True, key="cc_quality", label_visibility="collapsed",
                           help="Rendering quality for the 3D globe (low = no atmosphere/relief, for slower GPUs).")
        if view == "Geographic":
            geo = geospatial.markers(a, incidents=incs, time_range=win)
            ev_click = components.globe(geospatial.for_component(geo), height=560, selected=S.get("geo_sel"), key="cc_globe",
                                        quality=quality)
            if ev_click and ev_click.get("t") != S.get("_geo_t"):
                S._geo_t = ev_click.get("t")
                if ev_click["type"] == "marker":
                    S.geo_sel, S.geo_region = ev_click["id"], None
                elif ev_click["type"] == "region":
                    S.geo_sel, S.geo_region = None, ev_click
                elif ev_click["type"] == "arc":
                    state.goto("Incident Investigation", ev_click["incident"])
                    st.rerun(scope="app")
                elif ev_click["type"] == "clear":
                    S.geo_sel, S.geo_region = None, None
            if geo["mode"] == "explore":
                st.caption("Exploration mode: these logs carry no location fields, so nothing is placed on the globe. SENTINEL never "
                           "guesses a location from an IP address.")
            else:
                st.caption(f"Geographic mode: {geo['located_events']:,} of {geo['total_events']:,} events carry coordinates "
                           f"({geo['provenance']}). Arcs = logged events of one incident whose source and device sites differ.")
            _selection_panel(a, geo)
        else:
            ranked = incs[:4]
            if not ranked:
                st.info("No incidents to show as a storyline.")
            else:
                data = gmod.build(a, ranked, include=("user", "host", "ip"), include_context=False)
                clicked = components.graph(data, height=560, key="cc_graph")
                st.caption("Attack storyline mode: relationships from the correlation engine (incidents, detections, accounts, "
                           "hosts, source IPs). Positions are a force layout, NOT geography.")
                if clicked and clicked.get("t") != S.get("_cc_g") and str(clicked.get("id", "")).startswith("INC-"):
                    S._cc_g = clicked["t"]
                    state.goto("Incident Investigation", clicked["id"])
                    st.rerun(scope="app")

    with right:
        total = max(1, len(incs))
        rows = "".join(
            f'<div class="sn-row"><span>{pill(lvl)}</span><span class="n">{lv.get(lvl, 0)}</span></div>'
            f'<div class="sn-bar"><i style="width:{100 * lv.get(lvl, 0) / total:.0f}%;background:{SEV_COLOR[lvl]}"></i></div>'
            for lvl in ("Critical", "High", "Medium", "Low"))
        st.markdown(f'<div class="sn-card"><h4>Incident severity</h4>{rows}</div>', unsafe_allow_html=True)
        det = Counter(r for i in incs for r in i["rules"] if r != "CTX")
        top = det.most_common(5)
        mx = max([n for _, n in top] or [1])
        det_rows = "".join(
            f'<div class="sn-row"><span>{esc(r)} · {esc(RULES[r][0])}</span><span class="n">{n}</span></div>'
            f'<div class="sn-bar"><i style="width:{100 * n / mx:.0f}%;background:#86a091"></i></div>' for r, n in top) \
            or '<div class="sn-muted">No detections.</div>'
        st.markdown(f'<div class="sn-card"><h4>Top active detections</h4>{det_rows}</div>', unsafe_allow_html=True)
        urgent = [i for i in incs if i["severity"]["level"] in ("Critical", "High")]
        crit = sum(1 for i in urgent if i["severity"]["level"] == "Critical")
        headline = (f"{crit} critical incident{'s' if crit != 1 else ''} require{'s' if crit == 1 else ''} investigation."
                    if crit else f"{len(urgent)} high-severity incident(s) to review." if urgent
                    else "No critical or high-severity incidents.")
        body = ""
        for i in urgent[:3]:
            scope = a.packs[i["incident_id"]]["facts"][0]
            focus = i["title"].split("(")[-1].rstrip(")")
            lat = ""
            if snap is not None:
                t = state.live_engine()._track_of(i)
                if t.get("latency_s") is not None:
                    lat = f" &middot; detected {t['latency_s']:.1f} s after the triggering event"
            body += (f'<div class="sn-urgent"><div class="h"><span>{esc(i["incident_id"])}</span>'
                     f'{pill(i["severity"]["level"], str(i["severity"]["score"]))}</div>'
                     f'<div class="b">{esc(" -> ".join(i["stages"]))}</div>'
                     f'<div class="sn-muted">{esc(focus)} &middot; {len(i["event_ids"])} events{lat} '
                     f'<span class="sn-cite">[{esc(scope["id"])}]</span></div></div>')
        st.markdown(f'<div class="sn-card"><h4>Urgent incidents</h4><div class="sn-exec">{esc(headline)}</div>{body}</div>',
                    unsafe_allow_html=True)
        if urgent:
            cc = st.columns([3, 2])
            pick = cc[0].selectbox("Open urgent incident", [i["incident_id"] for i in urgent[:6]], key="cc_urgent",
                                   label_visibility="collapsed")
            if cc[1].button("Investigate", key="cc_urgent_go", use_container_width=True):
                state.goto("Incident Investigation", pick)
                st.rerun(scope="app")
        if snap is not None:
            _feed(snap)

    c = st.columns(4, gap="medium")
    top_iid = incs[0]["incident_id"] if incs else None
    with c[0]:
        with st.container(key="action1"):
            if st.button("**Run Analysis**\n\nRe-run detection and explain the top incidents with local Qwen",
                         icon=":material/play_arrow:", use_container_width=True):
                if state.is_live():
                    state.live_engine().poll()
                    st.rerun(scope="app")
                bar = st.progress(0.0)
                state.run_analysis(auto_explain=True, progress=lambda p, t: bar.progress(p, text=t))
                st.rerun(scope="app")
    with c[1]:
        with st.container(key="action2"):
            if st.button("**Explore Incidents**\n\nQueue, storyline and original evidence", icon=":material/policy:",
                         use_container_width=True):
                state.goto("Incident Investigation", top_iid)
                st.rerun(scope="app")
    with c[2]:
        with st.container(key="action3"):
            if st.button("**Generate Report**\n\nHTML, PDF, JSON and CSV exports", icon=":material/description:",
                         use_container_width=True, disabled=not top_iid):
                state.goto("Report Studio", top_iid)
                st.rerun(scope="app")
    with c[3]:
        with st.container(key="action4"):
            if st.button("**Ask SENTINEL**\n\nEvidence-grounded answers from local Qwen", icon=":material/forum:",
                         use_container_width=True, disabled=not top_iid):
                state.goto("AI Investigation Lab", top_iid)
                st.rerun(scope="app")


def _selection_panel(a, geo):
    sel_ids, title = [], ""
    if S.get("geo_sel"):
        sel_ids = [S.geo_sel]
        m = next((x for x in geo["markers"] if x["id"] == S.geo_sel), None)
        title = m["label"] if m else ""
    elif S.get("geo_region"):
        sel_ids = S.geo_region.get("marker_ids", [])
        title = S.geo_region.get("name", "")
    if not (S.get("geo_sel") or S.get("geo_region")):
        return
    with st.container(key="card_geo"):
        recs = geospatial.marker_records(a, geo, sel_ids)
        markers = [x for x in geo["markers"] if x["id"] in sel_ids]
        incs_here = sorted({i for m in markers for i in m["incidents"]})
        st.markdown(f"**{esc(title)}** · {len(recs):,} located event(s) · incidents: {esc(', '.join(incs_here) or 'none')}",
                    unsafe_allow_html=True)
        if recs.empty:
            st.caption("No events with coordinates in this selection.")
        else:
            show = recs.copy()
            show["timestamp"] = show["timestamp"].astype(str)
            st.dataframe(show, hide_index=True, use_container_width=True, height=200)
        bcols = st.columns(min(4, max(1, len(incs_here))))
        for k, iid in enumerate(incs_here[:4]):
            if bcols[k].button(f"Investigate {iid}", key=f"geo_inv_{iid}"):
                state.goto("Incident Investigation", iid)
                st.rerun(scope="app")
