"""Incident Investigation: filterable queue + dedicated investigation workspace for one incident."""
from __future__ import annotations

import json

import altair as alt
import pandas as pd
import streamlit as st

from ... import exports
from ... import workspace as ws
from ...correlate import storyline
from ...playbooks import load_playbooks, mitre_info
from .. import duration, esc, kpi, pill, section, tag, ts
from .. import state
from ..state import S


def workflow(con, a, inc):
    key = ws.incident_key(a, inc)
    return {"status": ws.current_status(con, key), "disposition": ws.current_disposition(con, key) or "Not set",
            "notes": ws.notes(con, key)}


def render():
    a = S.analysis
    if a is None:
        st.info("No analysis yet: load a dataset in Log Intelligence.")
        return
    con = ws.connect()
    incs_all = state.visible_incidents(a)
    st.markdown(section("Incident queue", "Ranked by severity score. Filters apply to this queue only."),
                unsafe_allow_html=True)
    f = st.columns([1.8, 1.6, 2.4, 1.3])
    lv = f[0].multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"],
                          key="iq_sev")
    stt = f[1].multiselect("Status", ws.STATUSES, default=ws.STATUSES, key="iq_status")
    txt = f[2].text_input("Filter (ID, title, user, host, IP, technique)", key="iq_text")
    sort = f[3].selectbox("Sort", ["Severity score", "Start time", "Events"], key="iq_sort")
    rows, keep = [], []
    for i in incs_all:
        wf = workflow(con, a, i)
        hay = " ".join([i["incident_id"], i["title"], *i["users"], *i["hosts"], *i["ips"], *i["mitre"]]).lower()
        if i["severity"]["level"] not in lv or wf["status"] not in stt or (txt and txt.lower() not in hay):
            continue
        keep.append(i)
        rows.append({"ID": i["incident_id"], "Severity": i["severity"]["level"], "Score": i["severity"]["score"],
                     "Confidence": i["severity"]["confidence"]["level"], "Title": i["title"],
                     "Start (UTC)": ts(i["start"]), "Duration": duration(i["start"], i["end"]), "Events": len(i["event_ids"]),
                     "MITRE": ", ".join(i["mitre"][:4]), "Status": wf["status"], "Disposition": wf["disposition"]})
    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values({"Severity score": "Score", "Start time": "Start (UTC)", "Events": "Events"}[sort],
                            ascending=sort == "Start time", kind="stable")
        st.dataframe(df, hide_index=True, use_container_width=True, height=min(320, 38 + 35 * len(df)),
                     column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d")})
    else:
        st.info("No incident matches the filters." if incs_all else "No incidents in this dataset / time range.")
        return
    ids = df["ID"].tolist()
    iid = state.selected_incident(a, [i for i in keep if i["incident_id"] in ids])
    iid = st.selectbox("Investigate", ids, index=ids.index(iid) if iid in ids else 0, key="iq_pick",
                       format_func=lambda x: f"{x} · {a.incident(x)['severity']['level']} {a.incident(x)['severity']['score']} · {a.incident(x)['title']}")
    S.selected = iid
    inc = a.incident(iid)
    pack = a.packs[iid]
    sev = inc["severity"]
    key = ws.incident_key(a, inc)
    wf = workflow(con, a, inc)

    st.markdown(f"### {esc(inc['title'])}", unsafe_allow_html=True)
    st.markdown(pill(sev["level"], f"{sev['level']} {sev['score']}") + "&nbsp; " + "".join(tag(t, "gold") for t in inc["mitre"][:6])
                + f'&nbsp; <span class="sn-muted">Confidence malicious: <b>{sev["confidence"]["level"]}</b> '
                  f'({esc(sev["confidence"]["reason"])}) &middot; status <b>{esc(wf["status"])}</b> &middot; disposition '
                  f'<b>{esc(wf["disposition"])}</b></span>', unsafe_allow_html=True)
    k = st.columns(5)
    for c, (lab, v) in zip(k, [("Start (UTC)", ts(inc["start"])), ("Duration", duration(inc["start"], inc["end"])),
                               ("Accounts", ", ".join(inc["users"][:3]) + (" …" if len(inc["users"]) > 3 else "")),
                               ("Hosts", ", ".join(inc["hosts"][:3])), ("Source IPs", ", ".join(inc["ips"][:3]) or "-")]):
        c.markdown(kpi(lab, v, small=True), unsafe_allow_html=True)
    nav = st.columns([1, 1, 1, 4])
    if nav[0].button("Ask SENTINEL about it", icon=":material/forum:"):
        state.goto("AI Investigation Lab", iid)
        st.rerun()
    if nav[1].button("Show in attack graph", icon=":material/hub:"):
        state.goto("Attack Graph", iid)
        st.rerun()
    if nav[2].button("Report", icon=":material/description:"):
        state.goto("Report Studio", iid)
        st.rerun()

    t1, t2, t3, t4, t5, t6 = st.tabs(["Attack storyline", "Evidence", "Severity breakdown", "MITRE & recommendations",
                                      "Notes & disposition", "Export"])
    ev = a.events.set_index("event_id")
    with t1:
        st.caption("Alerts in time order with the reason each one joined the incident. Gold = seed, solid = strong link "
                   "(2+ shared keys or a derived logon-after-failures link), dashed = weak link (shared account only: "
                   "shown, never scored). A shared host or IP alone never links alerts.")
        for s in storyline(inc, a.alerts_by_id):
            cls = "sn-step" + (" weak" if s["membership"] == "weak" else "") + (" ctx" if s["context"] else "") + \
                  (" seed" if s["membership"] == "seed" else "")
            if s["link"]:
                keys = ", ".join(s["link"]["keys"])
                link = (f'<div class="link"><b>{esc(s["link"]["strength"])} link</b> via {esc(keys)} &middot; '
                        f'{esc(s["link"]["reason"])}</div>')
            else:
                link = '<div class="link"><b>incident seed</b></div>'
            eids = s["event_ids"]
            eid_txt = ", ".join(eids) if len(eids) <= 4 else f"{eids[0]} … {eids[-1]} ({len(eids)} events)"
            st.markdown(f'<div class="{cls}"><span class="t">{ts(s["time"])}</span> &nbsp;{tag(s["rule"], "gold")} '
                        f'<span class="r">{esc(s["name"])}</span>{" " + tag("context") if s["context"] else ""}'
                        f'<div class="why">{esc(s["reason"])}</div><div class="link">{esc(s["alert_id"])} &middot; {esc(eid_txt)}</div>{link}</div>',
                        unsafe_allow_html=True)
    with t2:
        facts = pack["facts"]
        st.markdown("**Evidence pack** (deterministic facts; the local model sees only these, never raw logs)")
        st.dataframe(pd.DataFrame([{"id": f["id"], "kind": f["kind"], "fact": f["text"], "events": len(f["event_ids"])}
                                   for f in facts]), hide_index=True, use_container_width=True, height=260)
        cc = st.columns(2)
        with cc[0]:
            fid = st.selectbox("Inspect the events behind a fact", [f["id"] for f in facts if f["event_ids"]], key="ev_fact")
            fe = next(f for f in facts if f["id"] == fid)["event_ids"] if fid else []
            rows = ev.loc[fe, ["timestamp", "source_file", "source_row", "event_code", "action", "user", "host", "src_ip",
                               "process", "command_line", "group", "target_user"]].reset_index()
            rows["timestamp"] = rows["timestamp"].astype(str)
            st.dataframe(rows, hide_index=True, use_container_width=True, height=240)
        with cc[1]:
            pick = st.selectbox("Original record", inc["event_ids"], key="ev_raw")
            r = ev.loc[pick]
            st.caption(f"{r['source_file']} row {r['source_row']} · record {r['record_id'] or '-'} (unmodified)")
            st.code(json.dumps(json.loads(r["raw"]), indent=2), language="json")
        st.markdown("**Contradicting evidence** (computed by code)")
        fx = {f["id"]: f for f in facts}
        for c in pack["contradicting_fact_ids"]:
            st.markdown(f'<div class="sn-claim"><span class="sn-cite">{c}</span> {esc(fx[c]["text"])}</div>', unsafe_allow_html=True)
        if not pack["contradicting_fact_ids"]:
            st.caption("None found in the supplied logs.")
        st.caption("Limitations: " + " ".join(pack["limitations"]))
    with t3:
        bd = pd.DataFrame(sev["breakdown"])
        st.markdown(f"**{sev['level']} ({sev['score']}/100)** = " + ", ".join(f"{l['factor']} {l['points']:+d}" for l in sev["breakdown"]))
        if len(bd):
            ch = alt.Chart(bd).mark_bar(cornerRadius=4).encode(
                x=alt.X("points:Q", title="points"), y=alt.Y("factor:N", sort=None, title=None),
                color=alt.condition(alt.datum.points >= 0, alt.value("#C8AA7C"), alt.value("#9DB7A7")),
                tooltip=["factor", "points", "detail"]).properties(height=max(120, 30 * len(bd)))
            st.altair_chart(ch.configure_view(strokeWidth=0).configure_axis(gridColor="#22312E", labelColor="#A9B6AE",
                                                                             titleColor="#A9B6AE", domainColor="#22312E"),
                            use_container_width=True)
            st.dataframe(bd, hide_index=True, use_container_width=True)
        st.caption("Severity = potential impact (Critical 80-100, High 60-79, Medium 35-59, Low 0-34). Each rule counts once; "
                   "weak-link and low-confidence-baseline alerts add 0; a delayed logon-after-failures adds a reduced weight.")
    with t4:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**MITRE ATT&CK** (offline reference)")
            for t in inc["mitre"]:
                m = mitre_info(t)
                st.markdown(f"{tag(m['id'], 'gold')} **{esc(m['name'])}** &middot; {esc(', '.join(m['tactics']))}<br>"
                            f"<span class='sn-muted'>{esc(m['summary'])}</span>", unsafe_allow_html=True)
        with c2:
            st.markdown("**Recommended playbooks** (analyst-approved actions; nothing runs automatically)")
            pb = load_playbooks()
            for p in pack["playbooks"]:
                with st.expander(f"{p['id']} · {p['title']}"):
                    for stp in pb[p["id"]]["steps"]:
                        st.markdown(f"- {stp}")
    with t5:
        c1, c2 = st.columns(2)
        with c1:
            new_status = st.radio("Investigation status", ws.STATUSES, index=ws.STATUSES.index(wf["status"]),
                                  horizontal=True, key=f"st_{iid}")
            if new_status != wf["status"] and st.button("Update status", type="primary"):
                ws.set_status(con, key, iid, new_status)
                st.rerun()
            d = st.radio("Disposition", ws.DISPOSITIONS, horizontal=True, key=f"disp_{iid}")
            dnote = st.text_input("Disposition reason", key=f"dnote_{iid}")
            if st.button("Record disposition"):
                ws.set_disposition(con, key, iid, d, dnote)
                st.rerun()
            note = st.text_area("Add analyst note", key=f"note_{iid}")
            if st.button("Save note", disabled=not note.strip()):
                ws.add_note(con, key, iid, note)
                st.rerun()
        with c2:
            st.markdown("**Notes**")
            for n in wf["notes"][::-1]:
                st.markdown(f'<div class="sn-claim"><span class="sn-cite">{esc(n["ts"])}</span> {esc(n["note"])}</div>',
                            unsafe_allow_html=True)
            if not wf["notes"]:
                st.caption("No notes yet.")
            st.markdown("**Audit history for this incident**")
            hist = ws.history(con, key)
            st.dataframe(pd.DataFrame(hist) if hist else pd.DataFrame([{"history": "none"}]), hide_index=True,
                         use_container_width=True, height=220)
        st.caption("Stored locally in workspace/analyst.db (append-only history). Incident keys are derived from the input "
                   "file hashes, so notes survive re-analysis of the same files.")
    with t6:
        ver = S.explanations.get(iid, (None, None))[1]
        wfd = {iid: {"status": wf["status"], "disposition": wf["disposition"], "notes": [n["note"] for n in wf["notes"]]}}
        c = st.columns(3)
        c[0].download_button("Incident JSON", exports.incidents_json(a, [inc], {iid: ver} if ver else None, wfd),
                             file_name=f"SENTINEL_{iid}.json", mime="application/json", type="primary")
        c[1].download_button("Incident CSV", exports.incidents_csv(a, [inc], wfd), file_name=f"SENTINEL_{iid}.csv",
                             mime="text/csv")
        c[2].download_button("Evidence events CSV", exports.evidence_csv(a, inc), file_name=f"SENTINEL_{iid}_evidence.csv",
                             mime="text/csv")
        st.caption("HTML/PDF reports and multi-incident exports are in Report Studio.")
