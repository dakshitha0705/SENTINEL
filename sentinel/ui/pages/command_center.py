"""Command Center: KPIs, interactive globe, severity / detections / urgent summary, primary actions."""
from __future__ import annotations

from collections import Counter

import streamlit as st

from ... import geospatial
from ...rules import RULES
from .. import SEV_COLOR, esc, pill
from .. import components, state
from ..state import S


def _kpi(label, value, sub, k):
    return (f'<div class="sn-kpi {k}"><div class="l">{esc(label)}</div><div class="v">{esc(value)}</div>'
            f'<div class="s">{esc(sub)}</div></div>')


def render():
    a = S.analysis
    if a is None:
        st.info("No dataset loaded. Choose one in the dataset selector above or upload logs in Log Intelligence.")
        return
    incs = state.visible_incidents(a)
    win = state.time_window(a)
    ev = a.events if not win else a.events[(a.events["timestamp"] >= win[0]) & (a.events["timestamp"] <= win[1])]
    users = {u for i in incs for u in i["users"]}
    hosts = {h for i in incs for h in i["hosts"]}
    lv = Counter(i["severity"]["level"] for i in incs)

    left, center, right = st.columns([1.05, 2.75, 1.35], gap="medium")
    with left:
        st.markdown(_kpi("Total events", f"{len(ev):,}", f"{ev['host'].nunique()} hosts in logs", "")
                    + _kpi("Incidents", len(incs), f"{lv.get('Critical', 0)} critical · {lv.get('High', 0)} high", "k2")
                    + _kpi("Affected users", len(users), "accounts in incidents", "k3")
                    + _kpi("Affected hosts", len(hosts), "hosts in incidents", "k4"), unsafe_allow_html=True)
        span = f"{a.events['timestamp'].min():%d %b %H:%M} - {a.events['timestamp'].max():%d %b %H:%M} UTC" if len(a.events) else "-"
        st.markdown(f'<div class="sn-muted" style="padding:0 4px">Log span: {esc(span)}<br>'
                    f'Analysis: {a.timings.get("analysis_total_s", 0):.2f} s deterministic</div>', unsafe_allow_html=True)

    geo = geospatial.markers(a, incidents=incs, time_range=win)
    with center:
        ev_click = components.globe(geospatial.for_component(geo), height=600, selected=S.get("geo_sel"), key="cc_globe")
        if ev_click and ev_click.get("t") != S.get("_geo_t"):
            S._geo_t = ev_click.get("t")
            if ev_click["type"] == "marker":
                S.geo_sel, S.geo_region = ev_click["id"], None
            elif ev_click["type"] == "region":
                S.geo_sel, S.geo_region = None, ev_click
            elif ev_click["type"] == "arc":
                state.goto("Incident Investigation", ev_click["incident"])
                st.rerun()
            elif ev_click["type"] == "clear":
                S.geo_sel, S.geo_region = None, None
        if geo["mode"] == "explore":
            st.caption("Exploration mode: these logs carry no location fields, so no event is placed on the globe. "
                       "SENTINEL never guesses locations from IP addresses. Datasets with source/device coordinate "
                       "columns (e.g. a SIEM geo-enriched export) switch the globe to geographic intelligence mode.")
        else:
            st.caption(f"Geographic intelligence: {geo['located_events']:,} of {geo['total_events']:,} events carry coordinates "
                       f"({geo['provenance']}). Arcs = logged events of a correlated incident whose source and device "
                       "locations differ. Drag to rotate, scroll to zoom, click a marker or a country.")
        sel_ids = []
        title = ""
        if S.get("geo_sel"):
            sel_ids = [S.geo_sel]
            m = next((x for x in geo["markers"] if x["id"] == S.geo_sel), None)
            title = m["label"] if m else ""
        elif S.get("geo_region"):
            sel_ids = S.geo_region.get("marker_ids", [])
            title = S.geo_region.get("name", "")
        if S.get("geo_sel") or S.get("geo_region"):
            with st.container(key="card_geo"):
                recs = geospatial.marker_records(a, geo, sel_ids)
                markers = [x for x in geo["markers"] if x["id"] in sel_ids]
                incs_here = sorted({i for m in markers for i in m["incidents"]})
                st.markdown(f"**{esc(title)}** &middot; {len(recs):,} located event(s) &middot; "
                            f"incidents: {esc(', '.join(incs_here) or 'none')}", unsafe_allow_html=True)
                if recs.empty:
                    st.caption("No events with coordinates in this selection." if S.get("geo_region") else "")
                else:
                    show = recs.copy()
                    show["timestamp"] = show["timestamp"].astype(str)
                    st.dataframe(show, hide_index=True, use_container_width=True, height=220)
                bcols = st.columns(min(4, max(1, len(incs_here))) or 1)
                for k, iid in enumerate(incs_here[:4]):
                    if bcols[k].button(f"Investigate {iid}", key=f"geo_inv_{iid}"):
                        state.goto("Incident Investigation", iid)
                        st.rerun()

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
            f'<div class="sn-row"><span>{esc(r)} &middot; {esc(RULES[r][0])}</span><span class="n">{n}</span></div>'
            f'<div class="sn-bar"><i style="width:{100 * n / mx:.0f}%;background:#819B8D"></i></div>' for r, n in top) \
            or '<div class="sn-muted">No detections.</div>'
        st.markdown(f'<div class="sn-card"><h4>Top active detections</h4>{det_rows}'
                    '<div class="sn-muted" style="margin-top:6px">incidents in which each rule took part</div></div>',
                    unsafe_allow_html=True)
        urgent = [i for i in incs if i["severity"]["level"] in ("Critical", "High")]
        crit = sum(1 for i in urgent if i["severity"]["level"] == "Critical")
        headline = (f"{crit} critical incident{'s' if crit != 1 else ''} require{'s' if crit == 1 else ''} investigation."
                    if crit else f"{len(urgent)} high-severity incident(s) to review." if urgent
                    else "No critical or high-severity incidents in this range.")
        body = ""
        for i in urgent[:3]:
            scope = a.packs[i["incident_id"]]["facts"][0]
            focus = i["title"].split("(")[-1].rstrip(")")
            body += (f'<div class="sn-urgent"><div class="h"><span>{esc(i["incident_id"])}</span>'
                     f'{pill(i["severity"]["level"], str(i["severity"]["score"]))}</div>'
                     f'<div class="b">{esc(" -> ".join(i["stages"]))}</div>'
                     f'<div class="sn-muted">{esc(focus)} &middot; {len(i["event_ids"])} events '
                     f'<span class="sn-cite">[{esc(scope["id"])}]</span></div></div>')
        st.markdown(f'<div class="sn-card"><h4>Urgent incidents</h4><div class="sn-exec">{esc(headline)}</div>{body}</div>',
                    unsafe_allow_html=True)
        if urgent:
            pick = st.selectbox("Open urgent incident", [i["incident_id"] for i in urgent[:6]], key="cc_urgent",
                                label_visibility="collapsed")
            if st.button("Investigate", key="cc_urgent_go", use_container_width=True):
                state.goto("Incident Investigation", pick)
                st.rerun()

    st.write("")
    c = st.columns(4, gap="medium")
    top_iid = incs[0]["incident_id"] if incs else None
    with c[0]:
        with st.container(key="action1"):
            if st.button("**Run Analysis**\n\nRe-run detection and explain the top incidents with local Qwen",
                         icon=":material/play_arrow:", use_container_width=True):
                bar = st.progress(0.0)
                state.run_analysis(auto_explain=True, progress=lambda p, t: bar.progress(p, text=t))
                st.rerun()
    with c[1]:
        with st.container(key="action2"):
            if st.button("**Explore Incidents**\n\nRanked queue, storyline and evidence", icon=":material/policy:",
                         use_container_width=True):
                state.goto("Incident Investigation", top_iid)
                st.rerun()
    with c[2]:
        with st.container(key="action3"):
            if st.button("**Generate Report**\n\nHTML, PDF, JSON and CSV exports", icon=":material/description:",
                         use_container_width=True, disabled=not top_iid):
                state.goto("Report Studio", top_iid)
                st.rerun()
    with c[3]:
        with st.container(key="action4"):
            if st.button("**Ask SENTINEL**\n\nEvidence-grounded answers from local Qwen", icon=":material/forum:",
                         use_container_width=True, disabled=not top_iid):
                state.goto("AI Investigation Lab", top_iid)
                st.rerun()
