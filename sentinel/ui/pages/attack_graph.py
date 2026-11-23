"""Attack Graph: interactive relationship graph built only from correlation output."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from ... import graph as gmod
from .. import esc, pill, section, ts
from .. import components, state
from ..state import S


def render():
    a = S.analysis
    if a is None or not a.incidents:
        st.info("No incidents to graph. Load a dataset with detections first.")
        return
    incs = state.visible_incidents(a)
    st.markdown(section("Attack relationship graph",
                        "Incidents, detections and the accounts, hosts and source IPs they involve. Gold arrows are the "
                        "Storyline Engine's links between detections (dashed = weak); grey lines connect a detection to its "
                        "own entities. Scroll to zoom, drag to pan, click a node to inspect its evidence."),
                unsafe_allow_html=True)
    f = st.columns([2.6, 1.6, 2.2, 1.4])
    ids = [i["incident_id"] for i in incs]
    default = [S.selected] if S.selected in ids else ids[:3]
    chosen = f[0].multiselect("Incidents", ids, default=default, key="ag_incs",
                              format_func=lambda x: f"{x} · {a.incident(x)['severity']['level']}")
    lv = f[1].multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"],
                          key="ag_sev")
    types = f[2].multiselect("Entity types", ["user", "host", "ip"], default=["user", "host", "ip"], key="ag_types")
    ctx = f[3].toggle("Context alerts", value=True, key="ag_ctx")
    sel = [i for i in incs if i["incident_id"] in chosen and i["severity"]["level"] in lv]
    if not sel:
        st.info("Select at least one incident that matches the severity filter.")
        return
    data = gmod.build(a, sel, include=tuple(types), include_context=ctx)
    st.caption(f"{len(data['nodes'])} nodes · {len(data['edges'])} edges · every edge comes from the correlation engine")
    g, side = st.columns([3, 1.25], gap="medium")
    with g:
        clicked = components.graph(data, height=640, focus=S.get("ag_node"), key="ag_graph")
        if clicked and clicked.get("t") != S.get("_ag_t"):
            S._ag_t = clicked["t"]
            S.ag_node = clicked["id"]
    with side:
        nid = S.get("ag_node")
        if not nid or nid not in {n["id"] for n in data["nodes"]}:
            st.markdown('<div class="sn-card"><h4>Node inspector</h4><div class="sn-muted">Click a node to see the records '
                        'behind it.</div></div>', unsafe_allow_html=True)
            return
        d = gmod.node_details(a, nid)
        if d["type"] == "incident":
            inc = d["incident"]
            st.markdown(f'<div class="sn-card"><h4>Incident</h4>{pill(inc["severity"]["level"], inc["incident_id"])}'
                        f'<div style="margin-top:6px">{esc(inc["title"])}</div><div class="sn-muted">{ts(inc["start"])} &middot; '
                        f'{len(inc["event_ids"])} events &middot; {len(inc["alert_ids"])} alerts</div></div>', unsafe_allow_html=True)
            if st.button("Open investigation", type="primary", use_container_width=True):
                state.goto("Incident Investigation", inc["incident_id"])
                st.rerun()
        elif d["type"] == "alert":
            al = d["alert"]
            st.markdown(f'<div class="sn-card"><h4>Detection {esc(al["alert_id"])}</h4><b>{esc(al["rule"])} {esc(al["name"])}</b>'
                        f'<div class="sn-muted" style="margin-top:4px">{esc(al["reason"])}</div>'
                        f'<div class="sn-muted">in {esc(", ".join(d["incidents"]))} &middot; confidence {esc(al["confidence"])}'
                        f'{" &middot; context only" if al["context"] else ""}</div></div>', unsafe_allow_html=True)
            rows = a.events.set_index("event_id").loc[al["event_ids"], ["timestamp", "action", "user", "host", "src_ip",
                                                                         "command_line"]].reset_index()
            rows["timestamp"] = rows["timestamp"].astype(str)
            st.dataframe(rows, hide_index=True, use_container_width=True, height=260)
        else:
            evs = d["events"]
            st.markdown(f'<div class="sn-card"><h4>{esc(d["type"])}</h4><b>{esc(d["value"])}</b>'
                        f'<div class="sn-muted">{len(evs):,} events in the dataset &middot; incidents: '
                        f'{esc(", ".join(d["incidents"]) or "none")}</div></div>', unsafe_allow_html=True)
            show = evs[["event_id", "timestamp", "action", "user", "host", "src_ip"]].head(200).copy()
            show["timestamp"] = show["timestamp"].astype(str)
            st.dataframe(show, hide_index=True, use_container_width=True, height=300)
        if st.button("Clear selection", use_container_width=True):
            S.ag_node = None
            st.rerun()
    with st.expander("Edge list (as produced by the correlation engine)"):
        st.dataframe(pd.DataFrame(data["edges"]), hide_index=True, use_container_width=True)
