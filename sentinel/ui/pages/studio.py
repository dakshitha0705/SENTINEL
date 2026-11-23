"""Investigation Studio: case queue + one incident workspace (story, evidence, severity, attack graph, AI
investigation, MITRE & next steps, notes, export). Combines the former Incident Investigation, Attack Graph and
AI Investigation Lab pages; all content comes from the correlation engine, the evidence pack and the workspace DB."""
from __future__ import annotations

import json

import altair as alt
import pandas as pd
import streamlit as st

from ... import exports
from ... import workspace as ws
from ...correlate import storyline
from ...live import RULE_PHRASE
from ...playbooks import load_playbooks, mitre_info
from .. import SEV_COLOR, duration, esc, pill, tag, ts
from .. import state
from ..state import S
from . import ai_lab, attack_graph
from .command_center import headline
from .live_demo import mark

VIEWS = ["Story", "Evidence", "Severity", "Attack graph", "AI investigation", "Next steps", "Notes", "Export"]
ICON = {"Story": "timeline", "Evidence": "fact_check", "Severity": "speed", "Attack graph": "hub",
        "AI investigation": "psychology", "Next steps": "checklist", "Notes": "edit_note", "Export": "download"}


def workflow(con, a, inc):
    key = ws.incident_key(a, inc)
    return {"status": ws.current_status(con, key), "disposition": ws.current_disposition(con, key) or "Not set",
            "notes": ws.notes(con, key)}


def render():
    a = S.analysis
    if a is None:
        st.info("No data yet. Choose a data source above, upload logs in Log Intelligence, or start the Live Demo.")
        return
    incs_all = state.visible_incidents(a)
    if not incs_all:
        st.markdown('<div class="sn-hero calm"><div class="eyebrow">No incidents</div><div class="h">Nothing to investigate yet</div>'
                    f'<div class="p">{len(a.events):,} events were checked and no related suspicious activity was found. '
                    'Try Threat Hunting to search the events directly.</div></div>', unsafe_allow_html=True)
        return
    con = ws.connect()
    queue, main = st.columns([1, 3.1], gap="large")
    with queue:
        iid = _queue(con, a, incs_all)
    if iid is None:
        return
    with main:
        _workspace(con, a, iid)


def _queue(con, a, incs_all):
    st.markdown('<div class="sn-eyebrow">Case queue</div>', unsafe_allow_html=True)
    lv = st.pills("Severity", ["Critical", "High", "Medium", "Low"], selection_mode="multi",
                  default=["Critical", "High", "Medium", "Low"], key="iq_sev", label_visibility="collapsed")
    txt = st.text_input("Filter", key="iq_text", placeholder="Filter by account, device, IP…", label_visibility="collapsed")
    keep = []
    for i in incs_all:
        hay = " ".join([i["incident_id"], i["title"], *i["users"], *i["hosts"], *i["ips"], *i["mitre"]]).lower()
        if i["severity"]["level"] in (lv or []) and (not txt or txt.lower() in hay):
            keep.append(i)
    if not keep:
        st.caption("No incident matches the filter.")
        return None
    iid = state.selected_incident(a, keep)
    S.selected = iid
    with st.container(height=640, border=False):
        for i in keep[:40]:
            sev = i["severity"]
            wf_status = ws.current_status(con, ws.incident_key(a, i))
            who = ", ".join(list(i["users"])[:1] or list(i["hosts"])[:1])
            label = (f"**{headline(i)[0].split(' — ')[0][:70]}**\n\n"
                     f"{sev['level']} {sev['score']} · {wf_status} · {pd.Timestamp(i['start']):%d %b %H:%M} · {who}")
            with st.container(key=("casesel_" if i["incident_id"] == iid else "case_") + i["incident_id"].replace("-", "_")):
                if st.button(label, key=f"q_{i['incident_id']}", use_container_width=True):
                    S.selected = i["incident_id"]
                    st.rerun()
    return iid


def _workspace(con, a, iid):
    inc = a.incident(iid)
    pack = a.packs[iid]
    sev = inc["severity"]
    wf = workflow(con, a, inc)
    h, p = headline(inc)
    mark("opened")
    st.markdown(f'<div class="sn-eyebrow">{esc(iid)} · {esc(wf["status"])}</div>'
                f'<h2 style="margin:2px 0 4px">{esc(h)}</h2><div class="sn-muted" style="font-size:.95rem">{esc(p)}</div>',
                unsafe_allow_html=True)
    st.markdown(f'<span class="sn-sev" style="--c:{SEV_COLOR[sev["level"]]}">{esc(sev["level"])} · {sev["score"]}/100</span> &nbsp;'
                f'<span class="sn-muted">Confidence it is malicious: <b>{esc(sev["confidence"]["level"])}</b> · '
                f'{ts(inc["start"])} UTC · {duration(inc["start"], inc["end"])} · {len(inc["event_ids"])} events · '
                f'accounts {esc(", ".join(list(inc["users"])[:3]) or "-")} · devices {esc(", ".join(list(inc["hosts"])[:3]) or "-")}</span>',
                unsafe_allow_html=True)
    if S.get("studio_view") not in VIEWS:
        S.studio_view = "Story"
    view = st.segmented_control("View", VIEWS, key="studio_view", label_visibility="collapsed",
                                format_func=lambda v: f":material/{ICON[v]}: {v}") or "Story"
    ev = a.events.set_index("event_id")
    if view == "Story":
        mark("story")
        _story(a, inc, ev)
    elif view == "Evidence":
        mark("story")
        _evidence(a, inc, pack, ev)
    elif view == "Severity":
        _severity(sev)
    elif view == "Attack graph":
        attack_graph.render(embedded=True)
    elif view == "AI investigation":
        ai_lab.render_for(iid)
    elif view == "Next steps":
        _next_steps(inc, pack)
    elif view == "Notes":
        _notes(con, a, inc, wf, iid)
    else:
        _export(a, inc, wf, iid)


def _story(a, inc, ev):
    steps = storyline(inc, a.alerts_by_id)
    st.caption("The incident in time order. Each stage says what happened, how SENTINEL recognised it and why it belongs to "
               "this incident. Open a stage to see the original records.")
    n = len(steps)
    upto = n
    if n > 1:
        upto = st.slider("Playback", 1, n, n, key=f"play_{inc['incident_id']}",
                         help="Reveal the recorded stages one by one (only stored events; nothing is generated).")
    for k, s in enumerate(steps[:upto]):
        what = RULE_PHRASE.get(s["rule"], s["name"])
        title = f"{ts(s['time'])[11:]} · {what[0].upper() + what[1:]}" + (" (context)" if s["context"] else "")
        with st.expander(title, expanded=(k == upto - 1)):
            cls = "sn-step" + (" weak" if s["membership"] == "weak" else "") + (" ctx" if s["context"] else "") + \
                  (" seed" if s["membership"] == "seed" else "")
            if s["link"]:
                link = (f'<b>Why it is linked:</b> {esc(s["link"]["strength"])} link via {esc(", ".join(s["link"]["keys"]))} — '
                        f'{esc(s["link"]["reason"])}')
            else:
                link = "<b>Why it is linked:</b> this is where the incident starts."
            st.markdown(f'<div class="{cls}"><div class="why"><b>What happened:</b> {esc(s["reason"])}</div>'
                        f'<div class="why"><b>How SENTINEL recognised it:</b> detection rule “{esc(s["name"])}”</div>'
                        f'<div class="link">{link}</div></div>', unsafe_allow_html=True)
            cols = [c for c in ["timestamp", "action", "user", "host", "src_ip", "process", "group", "record_id"] if c in ev.columns]
            rows = ev.loc[[e for e in s["event_ids"] if e in ev.index], cols].reset_index()
            rows["timestamp"] = rows["timestamp"].astype(str)
            st.dataframe(rows.rename(columns={"record_id": "original event ID", "src_ip": "source address"}),
                         hide_index=True, use_container_width=True, height=min(250, 38 + 35 * len(rows)))
            with st.popover("Technical details"):
                st.markdown(f"Rule `{s['rule']}` · alert `{s['alert_id']}` · membership `{s['membership']}`")
                st.code(", ".join(s["event_ids"]), language=None)


def _evidence(a, inc, pack, ev):
    facts = pack["facts"]
    c1, c2 = st.columns([1.2, 1], gap="medium")
    with c1:
        st.markdown("**Facts SENTINEL established** (the local model sees only these)")
        fid = st.radio("Fact", [f["id"] for f in facts], key="ev_fact", label_visibility="collapsed",
                       format_func=lambda x: f"{x} · {next(f for f in facts if f['id'] == x)['text'][:120]}")
        fe = next(f for f in facts if f["id"] == fid)["event_ids"]
    with c2:
        st.markdown(f"**Records behind {fid}** ({len(fe)})")
        if fe:
            rows = ev.loc[[e for e in fe if e in ev.index], ["timestamp", "action", "user", "host", "src_ip", "source_file",
                                                             "source_row", "record_id"]].reset_index()
            rows["timestamp"] = rows["timestamp"].astype(str)
            st.dataframe(rows, hide_index=True, use_container_width=True, height=220)
            pick = st.selectbox("Original record", [e for e in fe if e in ev.index], key="ev_raw")
            r = ev.loc[pick]
            st.caption(f"{r['source_file']} row {r['source_row']} · original event ID {r['record_id'] or '-'} (unmodified)")
            st.code(json.dumps(json.loads(r["raw"]), indent=2), language="json")
        else:
            st.caption("This fact summarises the incident; it has no single record.")
    fx = {f["id"]: f for f in facts}
    if pack["contradicting_fact_ids"]:
        st.markdown("**Evidence that points the other way**")
        for c in pack["contradicting_fact_ids"]:
            st.markdown(f'<div class="sn-claim"><span class="sn-cite">{c}</span> {esc(fx[c]["text"])}</div>', unsafe_allow_html=True)
    st.caption("Limitations: " + " ".join(pack["limitations"]))


def _severity(sev):
    bd = pd.DataFrame(sev["breakdown"])
    st.markdown(f"**{sev['level']} ({sev['score']}/100).** The score is a sum of named factors, not a black box:")
    if len(bd):
        ch = alt.Chart(bd).mark_bar(cornerRadius=5).encode(
            x=alt.X("points:Q", title="points"), y=alt.Y("factor:N", sort=None, title=None),
            color=alt.condition(alt.datum.points >= 0, alt.value("#E3A587"), alt.value("#A9C3D1")),
            tooltip=["factor", "points", "detail"]).properties(height=max(120, 32 * len(bd)))
        st.altair_chart(ch.configure_view(strokeWidth=0).configure_axis(gridColor="#1d4048", labelColor="#c9d3d1",
                                                                         titleColor="#9db1b2", domainColor="#1d4048"),
                        use_container_width=True)
        with st.expander("Factor table"):
            st.dataframe(bd, hide_index=True, use_container_width=True)
    st.caption(f"Confidence it is malicious: {sev['confidence']['level']} — {sev['confidence']['reason']}. Severity bands: "
               "Critical 80-100, High 60-79, Medium 35-59, Low 0-34. Each rule counts once; weak links add 0.")


def _next_steps(inc, pack):
    c1, c2 = st.columns(2, gap="large")
    with c1:
        st.markdown("**Recommended playbooks** (analyst-approved actions; nothing runs automatically)")
        pb = load_playbooks()
        for p in pack["playbooks"]:
            with st.expander(p["title"]):
                for stp in pb[p["id"]]["steps"]:
                    st.markdown(f"- {stp}")
    with c2:
        st.markdown("**MITRE ATT&CK techniques** (offline reference)")
        for t in inc["mitre"]:
            m = mitre_info(t)
            st.markdown(f"{tag(m['id'], 'gold')} **{esc(m['name'])}** · {esc(', '.join(m['tactics']))}<br>"
                        f"<span class='sn-muted'>{esc(m['summary'])}</span>", unsafe_allow_html=True)


def _notes(con, a, inc, wf, iid):
    key = ws.incident_key(a, inc)
    c1, c2 = st.columns(2, gap="large")
    with c1:
        new_status = st.radio("Investigation status", ws.STATUSES, index=ws.STATUSES.index(wf["status"]),
                              horizontal=True, key=f"st_{iid}")
        if new_status != wf["status"] and st.button("Update status", type="primary"):
            ws.set_status(con, key, iid, new_status)
            st.rerun()
        d = st.radio("Disposition", ws.DISPOSITIONS, horizontal=True, key=f"disp_{iid}")
        dnote = st.text_input("Reason", key=f"dnote_{iid}")
        if st.button("Record disposition"):
            ws.set_disposition(con, key, iid, d, dnote)
            st.rerun()
        note = st.text_area("Add analyst note", key=f"note_{iid}")
        if st.button("Save note", disabled=not note.strip()):
            ws.add_note(con, key, iid, note)
            st.rerun()
    with c2:
        st.markdown(f"**Notes** · disposition: {esc(wf['disposition'])}")
        for n in wf["notes"][::-1]:
            st.markdown(f'<div class="sn-claim"><span class="sn-cite">{esc(n["ts"])}</span> {esc(n["note"])}</div>',
                        unsafe_allow_html=True)
        if not wf["notes"]:
            st.caption("No notes yet.")
        with st.expander("Audit history"):
            hist = ws.history(con, key)
            st.dataframe(pd.DataFrame(hist) if hist else pd.DataFrame([{"history": "none"}]), hide_index=True,
                         use_container_width=True, height=220)
    st.caption("Stored locally in workspace/analyst.db (append-only history). Notes survive re-analysis of the same files.")


def _export(a, inc, wf, iid):
    ver = S.explanations.get(iid, (None, None))[1]
    wfd = {iid: {"status": wf["status"], "disposition": wf["disposition"], "notes": [n["note"] for n in wf["notes"]]}}
    c = st.columns(4)
    c[0].download_button("Incident JSON", exports.incidents_json(a, [inc], {iid: ver} if ver else None, wfd),
                         file_name=f"SENTINEL_{iid}.json", mime="application/json", type="primary")
    c[1].download_button("Incident CSV", exports.incidents_csv(a, [inc], wfd), file_name=f"SENTINEL_{iid}.csv", mime="text/csv")
    c[2].download_button("Evidence events CSV", exports.evidence_csv(a, inc), file_name=f"SENTINEL_{iid}_evidence.csv",
                         mime="text/csv")
    if c[3].button("Full report (HTML/PDF)", icon=":material/description:"):
        state.goto("Reports & Evaluation", iid, view="Report")
        st.rerun()
