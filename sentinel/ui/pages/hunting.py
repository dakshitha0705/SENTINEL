"""Threat Hunting Lab: five hunt cards that run real queries over the normalised events (and the detection rules'
alert events), with readable results, pivots and actions. Advanced hunting (custom regex, prepared hunts, MITRE
ATT&CK explorer, detection rules) is kept below."""
from __future__ import annotations

import json

import streamlit as st

from ...hunting import CATEGORIES, category, summarise
from .. import esc
from .. import state
from ..state import S
from . import threat_intel


@st.cache_data(show_spinner=False, max_entries=8)
def _counts(_a, key):
    return {n: len(category(_a, n)) for n in CATEGORIES}


def _set_search(v):
    S.search_q = v


def render():
    a = S.analysis
    if a is None:
        st.info("No data yet. Choose a data source above or upload logs in Log Intelligence.")
        return
    counts = _counts(a, (S.get("dataset"), len(a.events), len(a.alerts), id(a)))
    st.caption("Pick a hunt. Each card searches every event in the current data, including activity that did not "
               "become an incident.")
    sel = S.setdefault("hunt_sel", "Credential Attacks")
    cols = st.columns(len(CATEGORIES), gap="small")
    for col, (name, c) in zip(cols, CATEGORIES.items()):
        with col:
            with st.container(key=("huntsel_" if sel == name else "hunt_") + name.replace(" ", "_")):
                if st.button(f"**{name}**\n\n{c['desc']}\n\n{counts[name]:,} matching events", key=f"hb_{name}",
                             icon=f":material/{c['icon']}:", use_container_width=True):
                    S.hunt_sel = name
                    st.rerun()
    if sel in CATEGORIES:
        _results(a, sel)
    st.write("")
    with st.expander("Advanced hunting: custom regular expressions, prepared hunts, MITRE ATT&CK explorer, detection rules"):
        threat_intel.render()


def _results(a, name):
    hits = category(a, name)
    sm = summarise(a, hits)
    ids = sorted({u for u in hits["user"] if u}) if len(hits) else []
    hosts = sorted({h for h in hits["host"] if h}) if len(hits) else []
    st.markdown(f'<div class="sn-card"><h4>{esc(name)}</h4><div class="sn-stats">'
                + "".join(f'<div class="sn-stat"><div class="v">{v}</div><div class="l">{esc(l)}</div></div>'
                          for v, l in ((f"{sm['events']:,}", "matching events"), (len(sm["incidents"]), "related incidents"),
                                       (len(ids), "identities involved"), (len(hosts), "devices involved")))
                + "</div></div>", unsafe_allow_html=True)
    if not len(hits):
        st.caption("Nothing matched in this data.")
        return
    left, right = st.columns([2.2, 1], gap="large")
    with left:
        show = hits[["timestamp", "action", "user", "host", "src_ip", "process", "command_line", "group", "event_id"]].copy()
        show.insert(1, "incident", show["event_id"].map(sm["incident_of"]).fillna(""))
        show["timestamp"] = show["timestamp"].astype(str)
        st.dataframe(show.rename(columns={"src_ip": "source address", "event_id": "event"}), hide_index=True,
                     use_container_width=True, height=330)
        c = st.columns([1.3, 1])
        c[0].download_button("Export matches (CSV)", show.to_csv(index=False).encode("utf-8"),
                             file_name=f"sentinel_hunt_{name.replace(' ', '_').lower()}.csv", mime="text/csv")
        with st.expander("Inspect an original event"):
            pick = st.selectbox("Event", hits["event_id"].tolist()[-300:], key="hunt_ev", label_visibility="collapsed")
            r = hits.set_index("event_id").loc[pick]
            st.caption(f"{r['source_file']} row {r['source_row']} · original event ID {r['record_id'] or '-'}")
            st.code(json.dumps(json.loads(r["raw"]), indent=2), language="json")
    with right:
        if sm["incidents"]:
            st.markdown("**Related incidents**")
            for iid in sm["incidents"][:5]:
                inc = a.incident(iid)
                if st.button(f"{inc['severity']['level']} · {inc['title'][:60]}", key=f"hunt_inc_{iid}", use_container_width=True):
                    state.goto("Investigation Studio", iid, view="Story")
                    st.rerun()
        else:
            st.caption("None of these events is part of an incident.")
        st.markdown("**Search related activity**")
        for col, lab in (("user", "Accounts"), ("host", "Devices"), ("src_ip", "Source addresses")):
            vc = sm["pivots"][col].head(4)
            if len(vc):
                st.caption(lab)
                pc = st.columns(2)
                for k, (v, n) in enumerate(vc.items()):
                    pc[k % 2].button(f"{v} ({n})", key=f"pv_{col}_{v}", on_click=_set_search, args=(v,),
                                     use_container_width=True, help="Search everything about this value (top bar)")
