"""SENTINEL - Offline Security Incident Triage Assistant (Tinyverse Hackathon, PS 02).

Run:  .venv\\Scripts\\streamlit run app.py
Everything runs locally; the only network traffic is to the local Ollama server on 127.0.0.1.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from sentinel import __version__
from sentinel import workspace as ws
from sentinel.config import ROOT, load_config
from sentinel.correlate import storyline
from sentinel.evidence import known_entities
from sentinel.ingest import MAPPABLE_FIELDS, guess_mapping, ingest, normalize, read_file
from sentinel.perf import Monitor, connection_snapshot, internet_reachable, system_info
from sentinel.pipeline import analyze_dataset
from sentinel.playbooks import load_playbooks, mitre_info
from sentinel.report import render_report
from sentinel.rules import RULES
from sentinel.slm import ask, explain, status as slm_status, template_explanation
from sentinel.ui import CSS, RULE_SHORT, SEV_COLOR, duration, esc, kpi, pill, tag, ts
from sentinel.verifier import verify_output

st.set_page_config(page_title="SENTINEL", page_icon=None, layout="wide", initial_sidebar_state="expanded")
st.markdown(CSS, unsafe_allow_html=True)

SAMPLES = ROOT / "data" / "samples"
RESULTS = ROOT / "results"
REPORTS = ROOT / "reports"
CFG = load_config()
S = st.session_state
S.setdefault("files", {})            # name -> bytes
S.setdefault("mappings", {})
S.setdefault("analysis", None)
S.setdefault("explanations", {})     # incident_id -> (result, verification)
S.setdefault("chat", {})             # incident_id -> [(q, answer_dict)]
S.setdefault("last_slm_stats", None)
S.setdefault("sample_name", None)

PAGES = ["Incident queue", "Log upload & mapping", "Incident investigation", "Accuracy & evaluation",
         "Offline system monitor", "Analyst workspace"]


# --------------------------------------------------------------------------- helpers

def analysis():
    return S.analysis


def explanation_for(iid, use_slm=True, on_token=None, force=False):
    a = analysis()
    if iid in S.explanations and not force:
        return S.explanations[iid]
    pack = a.packs[iid]
    if use_slm:
        res = explain(pack, CFG, use_cache=not force, on_token=on_token)
    else:
        res = {"source": "template", "output": template_explanation(pack), "stats": {}, "error": "template selected by analyst"}
    ver = verify_output(res["output"], pack, S.known_entities)
    S.explanations[iid] = (res, ver)
    if res.get("stats"):
        S.last_slm_stats = {**res["stats"], "incident": iid, "source": res["source"], "model": res.get("model")}
    return S.explanations[iid]


def sev_badge_row(inc):
    s = inc["severity"]
    return (pill(s["level"], f"{s['level']}  {s['score']}") + "&nbsp; "
            + "".join(tag(t) for t in inc["mitre"][:6]))


def require_analysis():
    if analysis() is None:
        st.info("No analysis yet. Open **Log upload & mapping**, load a sample dataset or upload logs, and run the analysis.")
        st.stop()


def run_analysis(auto_explain: bool):
    files = [(n, b) for n, b in S.files.items()]
    prog = st.progress(0.0, text="Normalising logs")
    t0 = time.perf_counter()
    ds = ingest(files, S.mappings)
    t_ing = time.perf_counter() - t0
    prog.progress(0.4, text="Detecting, correlating and scoring")
    a = analyze_dataset(ds, CFG)
    a.timings["ingest_s"] = t_ing
    S.analysis = a
    S.known_entities = known_entities(ds.events)
    S.explanations = {}
    S.chat = {}
    prog.progress(0.7, text="Evidence packs built")
    if auto_explain and a.incidents:
        stat = slm_status(CFG)
        if stat["reachable"] and stat["model_installed"]:
            top = a.incidents[: CFG["slm"]["auto_explain_top_n"]]
            for k, inc in enumerate(top):
                prog.progress(0.7 + 0.3 * k / len(top), text=f"Local SLM explaining {inc['incident_id']}")
                explanation_for(inc["incident_id"])
        else:
            st.warning("Local SLM not reachable; explanations will use the deterministic template.")
    prog.progress(1.0, text=f"Done in {time.perf_counter() - t0:.1f} s")


# --------------------------------------------------------------------------- sidebar

with st.sidebar:
    st.markdown('<div class="sn-brand">SENTINEL</div><div class="sn-sub">Offline incident triage &middot; PS 02</div>',
                unsafe_allow_html=True)
    st.write("")
    if S.get("goto"):
        S.nav = S.pop("goto")
    page = st.radio("Navigate", PAGES, label_visibility="collapsed", key="nav")
    st.divider()
    a = analysis()
    if a:
        st.caption(f"Dataset: {', '.join(f['name'] for f in a.dataset.files)}")
        st.caption(f"{len(a.events):,} events Â· {len(a.incidents)} incidents")
    stat = slm_status(CFG)
    ok = stat["reachable"] and stat["model_installed"]
    st.caption(("Local SLM: " + CFG["slm"]["model"] + (" Â· ready" if ok else " Â· unavailable (template mode)")))
    st.caption(f"v{__version__} Â· runs fully offline")


# --------------------------------------------------------------------------- page: upload

def page_upload():
    st.header("Log upload & column mapping")
    st.caption("Accepts authentication and endpoint logs as CSV, JSON arrays or JSON-lines (nested JSON is flattened). "
               "Original files are never modified; every record keeps its file and row reference.")
    c1, c2 = st.columns([3, 2])
    with c1:
        up = st.file_uploader("Upload log files", type=["csv", "json", "jsonl", "ndjson"], accept_multiple_files=True)
        if up:
            for f in up:
                S.files[f.name] = f.getvalue()
            S.sample_name = None
    with c2:
        samples = sorted(p.name for p in SAMPLES.iterdir() if p.is_dir()) if SAMPLES.exists() else []
        default = samples.index("demo_unseen") if "demo_unseen" in samples else 0
        choice = st.selectbox("Or load a bundled sample dataset", samples, index=default if samples else None)
        fmt = st.radio("Sample format", ["auth CSV + endpoint JSON-lines", "JSON only", "CSV only"], horizontal=True)
        if st.button("Load sample", use_container_width=True, disabled=not samples):
            names = {"auth CSV + endpoint JSON-lines": ["auth_logs.csv", "endpoint_logs.json"],
                     "JSON only": ["auth_logs.json", "endpoint_logs.json"],
                     "CSV only": ["auth_logs.csv", "endpoint_logs.csv"]}[fmt]
            folder = SAMPLES / choice
            avail = [n for n in names if (folder / n).exists()] or [p.name for p in folder.iterdir()
                                                                    if p.suffix in (".csv", ".json", ".jsonl") and p.stem not in ("labels", "ground_truth")]
            S.files = {n: (folder / n).read_bytes() for n in avail}
            S.mappings = {}
            S.sample_name = choice
            st.rerun()
    if not S.files:
        st.stop()
    st.subheader("Files and field mapping")
    st.caption("SENTINEL guesses each schema field from column names and value patterns. Correct any guess before running.")
    loads = {}
    for name, data in S.files.items():
        load = read_file(name, data)
        loads[name] = load
        guess = S.mappings.get(name) or guess_mapping(load.frame)
        cols = ["(none)"] + [c for c in load.frame.columns if c != "__row"]
        with st.expander(f"{name} Â· {load.fmt.upper()} Â· {len(load.frame):,} records Â· SHA-256 {load.sha256[:16]}â€¦",
                         expanded=len(S.files) <= 2):
            grid = st.columns(5)
            new = {}
            for i, fld in enumerate(MAPPABLE_FIELDS):
                cur = guess.get(fld)
                new[fld] = grid[i % 5].selectbox(fld, cols, index=cols.index(cur) if cur in cols else 0,
                                                 key=f"map_{name}_{fld}")
                new[fld] = None if new[fld] == "(none)" else new[fld]
            S.mappings[name] = new
            norm, rej = normalize(load, new)
            show = norm.drop(columns=["raw"]).head(8).copy()
            show["timestamp"] = show["timestamp"].astype(str)
            st.dataframe(show, hide_index=True, use_container_width=True)
            if rej:
                st.caption(f"{len(rej)} record(s) would be rejected in this file (see validation after running).")
            if (norm["action"] == "group_add").any() and not (new.get("actor") and new.get("target_user")):
                st.warning("Group-membership events found but the **actor** and/or **target_user** column is not mapped. "
                           "R6 cannot check who made the change or who was added; approved changes may be flagged. "
                           "Map them above if the file contains them.")
            if not new.get("timestamp"):
                st.error("No timestamp column mapped: every record in this file would be rejected.")
    cc = st.columns([1, 1, 3])
    auto = cc[1].checkbox("Explain top incidents with local SLM", value=True)
    if cc[0].button("Run analysis", type="primary", use_container_width=True):
        run_analysis(auto)
    if cc[2].button("Clear files"):
        S.files, S.mappings, S.analysis = {}, {}, None
        st.rerun()
    a = analysis()
    if a:
        st.subheader("Validation summary")
        sm = a.dataset.summary
        k = st.columns(6)
        for col, (lab, v) in zip(k, [("Records read", sm["records_read"]), ("Accepted", sm["accepted"]),
                                     ("Rejected", sm["rejected"]), ("Duplicates", sm["duplicates"]),
                                     ("Unevaluable", sm["unevaluable"]), ("Incidents", len(a.incidents))]):
            col.markdown(kpi(lab, f"{v:,}"), unsafe_allow_html=True)
        st.write("")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Per file**")
            st.dataframe(pd.DataFrame(a.dataset.files), hide_index=True, use_container_width=True)
            st.markdown("**Rule coverage on this data**")
            cov = pd.DataFrame([{"rule": r, "name": RULES[r][0], "evaluated": v["evaluated"], "alerts": v["alerts"],
                                 "requirement": v["requirement"]} for r, v in a.coverage.items()])
            st.dataframe(cov, hide_index=True, use_container_width=True)
        with c2:
            if len(a.dataset.rejected):
                st.markdown("**Rejected records (not analysed, kept for review)**")
                st.dataframe(a.dataset.rejected, hide_index=True, use_container_width=True)
            if len(a.dataset.duplicates):
                st.markdown("**Duplicate records (analysed once)**")
                st.dataframe(a.dataset.duplicates[["source_file", "source_row", "event_code", "duplicate_of"]],
                             hide_index=True, use_container_width=True)
            st.markdown("**Timing (measured)**")
            st.json({k: f"{v:.3f} s" for k, v in a.timings.items()})


# --------------------------------------------------------------------------- page: queue

def page_queue():
    st.header("Incident queue")
    require_analysis()
    a = analysis()
    incs = a.incidents
    lv = pd.Series([i["severity"]["level"] for i in incs]).value_counts()
    users = {u for i in incs for u in i["users"]}
    hosts = {h for i in incs for h in i["hosts"]}
    cols = st.columns(6)
    for c, (lab, v) in zip(cols, [("Events processed", f"{len(a.events):,}"), ("Incidents", len(incs)),
                                  ("Critical", int(lv.get("Critical", 0))), ("High", int(lv.get("High", 0))),
                                  ("Affected accounts", len(users)), ("Affected hosts", len(hosts))]):
        c.markdown(kpi(lab, v), unsafe_allow_html=True)
    st.write("")
    con = ws.connect()
    rows = []
    for i in incs:
        key = ws.incident_key(a, i)
        sup = ws.matching_suppressions(con, i, a.alerts_by_id)
        rows.append({"ID": i["incident_id"], "Severity": i["severity"]["level"], "Score": i["severity"]["score"],
                     "Confidence": i["severity"]["confidence"]["level"], "Title": i["title"],
                     "Accounts": ", ".join(i["users"][:4]) + (" â€¦" if len(i["users"]) > 4 else ""),
                     "Hosts": ", ".join(i["hosts"][:3]), "Start (UTC)": ts(i["start"]),
                     "Duration": duration(i["start"], i["end"]), "Events": len(i["event_ids"]),
                     "MITRE": ", ".join(i["mitre"][:4]),
                     "Disposition": ws.current_disposition(con, key) or "New",
                     "Suppression tag": ", ".join(sup)})
    df = pd.DataFrame(rows)
    st.subheader("Ranked incidents")
    if df.empty:
        st.success("No incidents: no primary detection fired and no anomalous logon was found.")
    else:
        st.dataframe(df, hide_index=True, use_container_width=True,
                     column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d")})
        pick = st.selectbox("Open incident", df["ID"], format_func=lambda x: f"{x} Â· {df.set_index('ID').at[x, 'Title']}")
        if st.button("Investigate selected incident", type="primary"):
            S.selected = pick
            S.goto = "Incident investigation"
            st.rerun()
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Severity distribution")
        sd = pd.DataFrame({"level": ["Critical", "High", "Medium", "Low"],
                           "count": [int(lv.get(x, 0)) for x in ["Critical", "High", "Medium", "Low"]]})
        ch = alt.Chart(sd).mark_bar(cornerRadiusEnd=2).encode(
            x=alt.X("count:Q", title="incidents", axis=alt.Axis(tickMinStep=1)),
            y=alt.Y("level:N", sort=["Critical", "High", "Medium", "Low"], title=None),
            color=alt.Color("level:N", scale=alt.Scale(domain=list(SEV_COLOR), range=list(SEV_COLOR.values())), legend=None))
        st.altair_chart(ch.properties(height=170), use_container_width=True)
    with c2:
        st.subheader("Detection summary")
        det = pd.DataFrame([{"rule": r, "detection": RULES[r][0], "alerts": v["alerts"],
                             "status": "evaluated" if v["evaluated"] else "not evaluated (missing data)"}
                            for r, v in a.coverage.items()])
        st.dataframe(det, hide_index=True, use_container_width=True, height=320)
    st.subheader("Activity over time")
    ev = a.events.copy()
    ev["hour"] = ev["timestamp"].dt.floor("h").dt.tz_localize(None)
    vol = ev.groupby(["hour", "log_type"]).size().reset_index(name="events")
    marks = pd.DataFrame([{"hour": pd.Timestamp(i["start"]).tz_localize(None), "incident": i["incident_id"],
                           "level": i["severity"]["level"]} for i in incs])
    base = alt.Chart(vol).mark_area(opacity=0.55, interpolate="step-after").encode(
        x=alt.X("hour:T", title=None), y=alt.Y("events:Q", stack=True, title="events / hour"),
        color=alt.Color("log_type:N", scale=alt.Scale(range=["#5B8DB8", "#4E6E58", "#7A7F87"]), title="log"))
    layers = [base]
    if len(marks):
        layers.append(alt.Chart(marks).mark_rule(strokeWidth=2).encode(
            x="hour:T", color=alt.Color("level:N", scale=alt.Scale(domain=list(SEV_COLOR), range=list(SEV_COLOR.values())),
                                        title="incident"), tooltip=["incident", "level", "hour"]))
    st.altair_chart(alt.layer(*layers).resolve_scale(color="independent").properties(height=220), use_container_width=True)


# --------------------------------------------------------------------------- page: investigation

def page_investigate():
    st.header("Incident investigation")
    require_analysis()
    a = analysis()
    if not a.incidents:
        st.success("No incidents in this dataset.")
        return
    ids = [i["incident_id"] for i in a.incidents]
    sel = S.get("selected") if S.get("selected") in ids else ids[0]
    iid = st.selectbox("Incident", ids, index=ids.index(sel),
                       format_func=lambda x: f"{x} Â· {a.incident(x)['severity']['level']} {a.incident(x)['severity']['score']} Â· {a.incident(x)['title']}")
    S.selected = iid
    inc = a.incident(iid)
    pack = a.packs[iid]
    sev = inc["severity"]
    st.markdown(f"### {esc(inc['title'])}", unsafe_allow_html=True)
    st.markdown(sev_badge_row(inc) + f'&nbsp;&nbsp;<span class="sn-muted">Confidence malicious: <b>{sev["confidence"]["level"]}</b> '
                f'({esc(sev["confidence"]["reason"])})</span>', unsafe_allow_html=True)
    k = st.columns(5)
    for c, (lab, v) in zip(k, [("Start (UTC)", ts(inc["start"])), ("Duration", duration(inc["start"], inc["end"])),
                               ("Accounts", ", ".join(inc["users"][:3]) + (" â€¦" if len(inc["users"]) > 3 else "")),
                               ("Hosts", ", ".join(inc["hosts"][:3])), ("Source IPs", ", ".join(inc["ips"][:3]) or "-")]):
        c.markdown(kpi(lab, v), unsafe_allow_html=True)
    st.write("")
    t1, t2, t3, t4, t5, t6 = st.tabs(["Attack storyline", "Evidence vs. hypothesis", "Severity breakdown",
                                      "Raw log evidence", "MITRE & playbooks", "Report export"])
    ev = a.events.set_index("event_id")

    with t1:
        st.caption("Alerts in time order. Solid bar = seed or strong link (2+ shared keys). Dashed = weak link "
                   "(shared account only): shown, never scored.")
        for s in storyline(inc, a.alerts_by_id):
            cls = "sn-step" + (" weak" if s["membership"] == "weak" else "") + (" ctx" if s["context"] else "")
            link = (f'<div class="link"><b>{s["link"]["strength"]} link</b> Â· {esc(s["link"]["reason"])}</div>'
                    if s["link"] else '<div class="link">incident seed</div>')
            eids = s["event_ids"]
            eid_txt = ", ".join(eids) if len(eids) <= 4 else f"{eids[0]} â€¦ {eids[-1]} ({len(eids)} events)"
            st.markdown(f'<div class="{cls}"><span class="t">{ts(s["time"])}</span> &nbsp;{tag(s["rule"])} '
                        f'<span class="r">{esc(s["name"])}</span>{" " + tag("context") if s["context"] else ""}'
                        f'<div class="why">{esc(s["reason"])}</div><div class="link">{esc(s["alert_id"])} Â· {esc(eid_txt)}</div>{link}</div>',
                        unsafe_allow_html=True)
            with st.expander(f"Evidence rows for {s['alert_id']} ({len(eids)})"):
                rows = ev.loc[eids, ["timestamp", "source_file", "source_row", "event_code", "action", "user", "host",
                                     "src_ip", "process", "command_line", "group", "target_user"]].reset_index()
                rows["timestamp"] = rows["timestamp"].astype(str)
                st.dataframe(rows, hide_index=True, use_container_width=True)

    with t2:
        cached = S.explanations.get(iid)
        c1, c2, c3 = st.columns([1.3, 1.3, 3])
        gen = c1.button("Explain with local SLM" if not cached else "Regenerate with SLM", type="primary")
        tmpl = c2.button("Use deterministic template")
        if gen:
            box = st.empty()
            buf = []

            def on_tok(t):
                buf.append(t)
                if len(buf) % 8 == 0:
                    box.code("".join(buf)[-1500:], language="json")
            with st.spinner("Local SLM is reading the evidence packâ€¦"):
                explanation_for(iid, use_slm=True, on_token=on_tok, force=bool(cached))
            box.empty()
        if tmpl:
            explanation_for(iid, use_slm=False, force=True)
        if iid not in S.explanations:
            st.info("No explanation yet. The SLM only sees the numbered facts below, never raw logs.")
        else:
            res, ver = S.explanations[iid]
            stt = ver["stats"]
            src = {"slm": "Local SLM (live)", "cache": "Local SLM (cached)", "template": "Deterministic template"}[res["source"]]
            meta = f"{src} Â· {res.get('model') or ''}"
            if res.get("stats", {}).get("tokens_per_s"):
                meta += f" Â· {res['stats']['wall_s']} s Â· {res['stats']['tokens_per_s']} tok/s"
            rate = f"{stt['verification_rate']:.0%}" if stt["verification_rate"] is not None else "n/a"
            st.markdown(f'<span class="sn-muted">{esc(meta)}</span> &nbsp; {tag(f"verified {stt["verified"]}/{stt["factual_claims"]} = {rate}")}',
                        unsafe_allow_html=True)
            if res.get("error") and res["source"] == "template":
                st.caption(f"Fallback reason: {res['error']}")
            colA, colB = st.columns(2)
            with colA:
                html = '<div class="sn-box"><h4>Verified evidence (from code)</h4>'
                for f in pack["facts"]:
                    if f["kind"] in ("detection", "context") and "[weak link" not in f["text"]:
                        html += f'<div class="sn-claim"><span class="sn-ok">VERIFIED</span> <span class="sn-cite">{f["id"]}</span> {esc(f["text"])}</div>'
                st.markdown(html + "</div>", unsafe_allow_html=True)
                html = '<div class="sn-box"><h4>Summary &amp; supported conclusions</h4>'
                for c in ver["summary"] + ver["conclusions"]:
                    lab = '<span class="sn-ok">VERIFIED</span>' if c["status"] == "Verified" else '<span class="sn-bad">UNVERIFIED</span>'
                    prob = f'<div class="sn-muted">{esc("; ".join(c["problems"]))}</div>' if c["problems"] else ""
                    html += f'<div class="sn-claim">{lab} {esc(c["text"])} <span class="sn-cite">[{esc(", ".join(c["fact_ids"]))}]</span>{prob}</div>'
                st.markdown(html + "</div>", unsafe_allow_html=True)
            with colB:
                html = '<div class="sn-box"><h4>Hypotheses requiring investigation</h4>'
                for h in ver["hypotheses"]:
                    lab = '<span class="sn-hyp">HYPOTHESIS</span>' if h["status"] == "Grounded hypothesis" else '<span class="sn-bad">UNGROUNDED</span>'
                    html += (f'<div class="sn-claim">{lab} {esc(h["text"])} <span class="sn-cite">supports [{esc(", ".join(h["supporting_fact_ids"]))}]'
                             f'{" Â· contradicts [" + esc(", ".join(h["contradicting_fact_ids"])) + "]" if h["contradicting_fact_ids"] else ""}</span>'
                             f'<div class="sn-muted">How to confirm: {esc(h["how_to_confirm"])}</div></div>')
                st.markdown(html + "</div>", unsafe_allow_html=True)
                facts = {f["id"]: f for f in pack["facts"]}
                html = '<div class="sn-box"><h4>Contradicting evidence (computed by code)</h4>'
                for fid in pack["contradicting_fact_ids"]:
                    html += f'<div class="sn-claim"><span class="sn-cite">{fid}</span> {esc(facts[fid]["text"])}</div>'
                if not pack["contradicting_fact_ids"]:
                    html += '<div class="sn-muted">None found in the logs.</div>'
                st.markdown(html + "</div>", unsafe_allow_html=True)
                pb = load_playbooks()
                html = '<div class="sn-box"><h4>Recommended next steps</h4>'
                for x in ver["actions"]:
                    html += f'<div class="sn-claim"><b>{x["playbook_id"]}</b> {esc(pb[x["playbook_id"]]["title"])}<div class="sn-muted">{esc(x["adaptation"])}</div></div>'
                for x in ver["rejected_actions"]:
                    html += f'<div class="sn-claim"><span class="sn-bad">REJECTED</span> {esc(x["playbook_id"])}: {esc(x["reason"])}</div>'
                for q in ver["questions"]:
                    html += f'<div class="sn-claim"><span class="sn-muted">Open question:</span> {esc(q)}</div>'
                st.markdown(html + "</div>", unsafe_allow_html=True)
        with st.expander(f"Evidence pack sent to the SLM ({len(pack['facts'])} facts)"):
            st.dataframe(pd.DataFrame([{"id": f["id"], "kind": f["kind"], "fact": f["text"]} for f in pack["facts"]]),
                         hide_index=True, use_container_width=True)
            st.caption("Limitations: " + " ".join(pack["limitations"]))

    with t3:
        bd = pd.DataFrame(sev["breakdown"])
        st.markdown(f"**{sev['level']} ({sev['score']}/100)** = " + ", ".join(f"{l['factor']} {l['points']:+d}" for l in sev["breakdown"]))
        if len(bd):
            ch = alt.Chart(bd).mark_bar().encode(
                x=alt.X("points:Q", title="points"), y=alt.Y("factor:N", sort=None, title=None),
                color=alt.condition(alt.datum.points >= 0, alt.value("#5B8DB8"), alt.value("#5FAF7F")),
                tooltip=["factor", "points", "detail"])
            st.altair_chart(ch.properties(height=max(120, 28 * len(bd))), use_container_width=True)
            st.dataframe(bd, hide_index=True, use_container_width=True)
        st.caption("Severity = potential impact (Critical 80-100, High 60-79, Medium 35-59, Low 0-34). Each rule counts once; "
                   "weak-link and low-confidence-baseline alerts add 0. Confidence that the activity is malicious is reported separately.")

    with t4:
        rows = ev.loc[inc["event_ids"]].reset_index()
        rows["timestamp"] = rows["timestamp"].astype(str)
        st.dataframe(rows.drop(columns=["raw"]), hide_index=True, use_container_width=True)
        pick = st.selectbox("Inspect original record", inc["event_ids"])
        r = ev.loc[pick]
        st.caption(f"{r['source_file']} row {r['source_row']} Â· original record, unmodified:")
        st.code(json.dumps(json.loads(r["raw"]), indent=2), language="json")

    with t5:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**MITRE ATT&CK (offline reference)**")
            for t in inc["mitre"]:
                m = mitre_info(t)
                st.markdown(f"{tag(m['id'])} **{esc(m['name'])}** Â· {esc(', '.join(m['tactics']))}<br>"
                            f"<span class='sn-muted'>{esc(m['summary'])}</span>", unsafe_allow_html=True)
        with c2:
            st.markdown("**Candidate playbooks for this incident** (analyst-approved actions only)")
            pb = load_playbooks()
            for p in pack["playbooks"]:
                with st.expander(f"{p['id']} Â· {p['title']}"):
                    for stp in pb[p["id"]]["steps"]:
                        st.markdown(f"- {stp}")

    with t6:
        res, ver = S.explanations.get(iid) or explanation_for(iid, use_slm=False)
        html = render_report(a, iid, res, ver)
        REPORTS.mkdir(exist_ok=True)
        fname = f"SENTINEL_{iid}_{datetime.now():%Y%m%d_%H%M%S}.html"
        st.download_button("Download HTML report", html.encode("utf-8"), file_name=fname, mime="text/html", type="primary")
        if st.button("Save report to reports/ folder"):
            (REPORTS / fname).write_text(html, encoding="utf-8")
            st.success(f"Saved {REPORTS / fname}")
        st.caption(f"Report uses: {res['source']} explanation Â· self-contained HTML, no external assets.")
        components.html(html, height=700, scrolling=True)


# --------------------------------------------------------------------------- page: accuracy

def page_accuracy():
    st.header("Accuracy & evaluation")
    st.caption("Measured on labelled synthetic data. Thresholds were tuned on the development seed only; test seeds were "
               "evaluated once after the detector was frozen. Stress seeds use out-of-envelope attack parameters and were never tuned on.")
    mp = RESULTS / "metrics.json"
    if st.button("Re-run evaluation now (deterministic, ~15 s)"):
        import subprocess, sys
        with st.spinner("Generating datasets and evaluatingâ€¦"):
            out = subprocess.run([sys.executable, str(ROOT / "scripts" / "evaluate.py")], capture_output=True, text=True, cwd=ROOT)
        st.code(out.stdout[-3000:] or out.stderr[-3000:])
    if not mp.exists():
        st.warning("No evaluation results yet. Run `python scripts/evaluate.py`.")
        return
    m = json.loads(mp.read_text(encoding="utf-8"))
    st.caption(f"Results file generated {m['generated_at']} Â· matching rule: {m['matching_rule']}")
    for label, agg in [("Held-out test seeds", m["test_aggregate"]), ("Stress seeds (out-of-envelope)", m.get("stress_aggregate"))]:
        if not agg:
            continue
        st.subheader(label)
        c = st.columns(7)
        for col, (lab, v) in zip(c, [("Incident precision", agg["incident_precision"]), ("Incident recall", agg["incident_recall"]),
                                     ("F1", agg["f1"]), ("False-positive rate", agg["false_positive_rate"]),
                                     ("Correlation (Jaccard)", agg["correlation_jaccard_mean"]),
                                     ("Severity agreement", agg["severity_agreement"]),
                                     ("Attacks / benign", f"{agg['gt_incidents']} / {agg['benign_lookalikes']}")]):
            col.markdown(kpi(lab, v), unsafe_allow_html=True)
        st.write("")
    sets = m["test"] + m.get("stress", [])
    st.subheader("Per dataset")
    st.dataframe(pd.DataFrame([{"dataset": x["dataset"], "events": x["events"], "attacks": x["gt_incidents"],
                                "benign look-alikes": x["gt_benign"], "detected": x["detected_incidents"],
                                "precision": x["incident_precision"], "recall": x["incident_recall"], "F1": x["f1"],
                                "FPR": x["false_positive_rate"], "Jaccard": x["correlation_jaccard_mean"],
                                "severity agreement": x["severity_agreement"]} for x in [m["dev"]] + sets]),
                 hide_index=True, use_container_width=True)
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Event-level confusion matrix (test seeds)")
        cm = [[0, 0], [0, 0]]
        for x in m["test"]:
            for i in range(2):
                for j in range(2):
                    cm[i][j] += x["event_confusion"]["matrix"][i][j]
        cmd = pd.DataFrame([{"actual": a_, "predicted": p_, "events": cm[i][j]}
                            for i, a_ in enumerate(["benign", "malicious"]) for j, p_ in enumerate(["not in incident", "in incident"])])
        ch = alt.Chart(cmd).mark_rect().encode(x="predicted:N", y="actual:N",
                                               color=alt.Color("events:Q", scale=alt.Scale(scheme="blues"), legend=None))
        txt = alt.Chart(cmd).mark_text(fontSize=15, color="#E3E9EF").encode(x="predicted:N", y="actual:N", text="events:Q")
        st.altair_chart((ch + txt).properties(height=200), use_container_width=True)
        st.caption("Malicious events not in an incident are mostly attack steps that no rule targets (e.g. `net group` reconnaissance).")
        st.subheader("Severity: expected vs detected")
        pairs = pd.DataFrame(m["test_aggregate"]["severity_pairs"] + (m.get("stress_aggregate") or {}).get("severity_pairs", []),
                             columns=["expected", "detected"])
        st.dataframe(pd.crosstab(pairs["expected"], pairs["detected"]), use_container_width=True)
    with c2:
        st.subheader("Per-rule alert precision (test seeds)")
        pr = []
        for rule in m["test"][0]["per_rule"]:
            fl = sum(x["per_rule"][rule]["flagged_events"] for x in m["test"])
            tp = sum(x["per_rule"][rule]["malicious_events"] for x in m["test"])
            al = sum(x["per_rule"][rule]["alerts"] for x in m["test"])
            pr.append({"rule": rule, "name": RULES[rule][0], "alerts": al, "flagged events": fl,
                       "event precision": round(tp / fl, 3) if fl else None,
                       "note": "context only; never creates an incident alone" if rule in ("R4", "R5") else ""})
        st.dataframe(pd.DataFrame(pr), hide_index=True, use_container_width=True)
    st.subheader("Missed incidents and false positives")
    miss = [{"dataset": x["dataset"], **y} for x in sets for y in x["missed_incidents"]]
    fps = [{"dataset": x["dataset"], "incident": y["incident_id"], "level": y["level"], "title": y["title"],
            "overlaps benign": ", ".join(y["benign_overlap"])} for x in sets for y in x["false_positive_incidents"]]
    c1, c2 = st.columns(2)
    c1.markdown("**Missed ground-truth incidents**")
    c1.dataframe(pd.DataFrame(miss) if miss else pd.DataFrame([{"result": "none"}]), hide_index=True, use_container_width=True)
    c2.markdown("**Detected incidents with no ground-truth match**")
    c2.dataframe(pd.DataFrame(fps) if fps else pd.DataFrame([{"result": "none"}]), hide_index=True, use_container_width=True)
    a = analysis()
    if a and S.sample_name and (SAMPLES / S.sample_name / "ground_truth.json").exists():
        st.subheader(f"Live check: current analysis vs. ground truth ({S.sample_name})")
        from sentinel.metrics import evaluate, load_ground_truth
        r = evaluate(a, load_ground_truth(SAMPLES / S.sample_name))
        st.json({k: r[k] for k in ("incident_precision", "incident_recall", "f1", "false_positive_rate",
                                   "correlation_jaccard_mean", "severity_agreement", "missed_incidents", "flagged_benign")})
    sb = sorted(RESULTS.glob("slm_benchmark_*.json"))
    if sb:
        st.subheader("Evidence verification rate (SLM output)")
        st.dataframe(pd.DataFrame([json.loads(p.read_text(encoding="utf-8"))["summary"] for p in sb]).drop(columns=["ollama"]),
                     hide_index=True, use_container_width=True)


# --------------------------------------------------------------------------- page: monitor

def page_monitor():
    st.header("Offline system monitor")
    st.caption("Current measurements are live; the offline test record below is historical and shown with its timestamp.")
    stat = slm_status(CFG)
    sysi = system_info()
    c = st.columns(5)
    model = next((m for m in stat["models"] if m["name"] == CFG["slm"]["model"]), None)
    loaded = next((m for m in stat["loaded"] if m["name"] == CFG["slm"]["model"]), None)
    for col, (lab, v) in zip(c, [("Model", CFG["slm"]["model"]),
                                 ("Model status", "loaded" if loaded else ("installed" if stat["model_installed"] else "unavailable")),
                                 ("Model size", f"{model['size_gb']} GB {model['quant']}" if model else "-"),
                                 ("GPU offload", f"{loaded['gpu_share']:.0%} in VRAM" if loaded and loaded["gpu_share"] is not None else "not loaded"),
                                 ("Runtime", f"Ollama {stat.get('version', '-')} @ 127.0.0.1")]):
        col.markdown(kpi(lab, v), unsafe_allow_html=True)
    st.write("")
    c = st.columns(5)
    g = sysi.get("gpu") or {}
    for col, (lab, v) in zip(c, [("CPU load", f"{sysi['cpu_percent']}% of {sysi['logical_cpus']} threads"),
                                 ("System RAM used", f"{sysi['ram_used_percent']}% of {sysi['ram_total_gb']} GB"),
                                 ("SENTINEL process RAM", f"{sysi['process_rss_mb']} MB"),
                                 ("GPU", f"{g.get('utilization_percent', '-')}% Â· {g.get('memory_used_mb', '-')}/{g.get('memory_total_mb', '-')} MB" if g else "not detected"),
                                 ("GPU name", g.get("name", "-"))]):
        col.markdown(kpi(lab, v), unsafe_allow_html=True)
    st.write("")
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Latest measured latency")
        a = analysis()
        if a:
            st.json({k: f"{v:.3f} s" for k, v in a.timings.items()})
        else:
            st.caption("Run an analysis to measure processing latency.")
        if S.last_slm_stats:
            st.json(S.last_slm_stats)
        else:
            st.caption("No SLM call in this session yet.")
        if st.button("Measure SLM now (one incident, no cache)", disabled=not (a and a.incidents and stat["reachable"])):
            with Monitor() as mon:
                res = explain(a.packs[a.incidents[0]["incident_id"]], CFG, use_cache=False)
            S.last_slm_stats = {**res.get("stats", {}), "source": res["source"], "peak_ollama_rss_mb": mon.result()["peak_ollama_rss_mb"]}
            st.rerun()
    with c2:
        st.subheader("Network")
        st.markdown("Remote connections of SENTINEL and Ollama processes right now:")
        snap = connection_snapshot()
        if snap:
            st.dataframe(pd.DataFrame(snap), hide_index=True, use_container_width=True)
        else:
            st.caption("No open remote connections.")
        ext = [x for x in snap if x["scope"] == "EXTERNAL"]
        st.markdown(f"External connections now: **{len(ext)}** (loopback to the local model server is expected).")
        if st.button("Test internet reachability (opens one TCP probe to 1.1.1.1:53)"):
            st.session_state.net = internet_reachable()
        if "net" in S:
            st.markdown("Internet reachable: **" + ("YES - machine is online" if S.net else "NO - machine is offline") + "**")
    st.subheader("Last verified offline test (historical record)")
    op = RESULTS / "offline_run.json"
    if op.exists():
        rec = json.loads(op.read_text(encoding="utf-8"))
        st.markdown(f"Recorded **{rec.get('recorded_at')}** Â· internet reachable during run: **{rec.get('internet_reachable')}** Â· "
                    f"external connections observed: **{len(rec.get('monitor', {}).get('external_connections', []))}**")
        st.json(rec)
    else:
        st.caption("No offline test recorded yet. Run `scripts\\offline_check.ps1` with Wi-Fi disconnected.")


# --------------------------------------------------------------------------- page: workspace

def page_workspace():
    st.header("Analyst workspace")
    require_analysis()
    a = analysis()
    con = ws.connect()
    if not a.incidents:
        st.success("No incidents.")
        return
    ids = [i["incident_id"] for i in a.incidents]
    iid = st.selectbox("Incident", ids, index=ids.index(S.get("selected")) if S.get("selected") in ids else 0,
                       format_func=lambda x: f"{x} Â· {a.incident(x)['title']}")
    inc = a.incident(iid)
    key = ws.incident_key(a, inc)
    t1, t2, t3 = st.tabs(["Ask the incident", "Disposition & notes", "Suppression proposals & audit"])
    with t1:
        st.caption("Answers use only this incident's evidence pack and pass through the same verifier. Unsupported sentences are labelled.")
        hist = S.chat.setdefault(iid, [])
        for q, ans in hist:
            st.markdown(f"**Q:** {esc(q)}")
            for c in ans["verified"]["summary"]:
                lab = '<span class="sn-ok">VERIFIED</span>' if c["status"] == "Verified" else '<span class="sn-bad">UNVERIFIED</span>'
                st.markdown(f'{lab} {esc(c["text"])} <span class="sn-cite">[{esc(", ".join(c["fact_ids"]))}]</span>'
                            + (f'<div class="sn-muted">{esc("; ".join(c["problems"]))}</div>' if c["problems"] else ""),
                            unsafe_allow_html=True)
            if ans.get("cannot_answer"):
                st.markdown(f'<span class="sn-muted">Not answerable from the evidence: {esc(ans["cannot_answer"])}</span>', unsafe_allow_html=True)
            if ans.get("error"):
                st.caption(f"SLM error: {ans['error']}")
        presets = ["Why was this incident classified with this severity?", "Which events support the compromise hypothesis?",
                   "What happened after the successful login?", "Which devices were involved?",
                   "What evidence contradicts the hypothesis?", "What should the analyst investigate next?"]
        q = st.selectbox("Suggested questions", ["(type your own below)"] + presets)
        free = st.text_input("Question")
        if st.button("Ask", type="primary"):
            question = free.strip() or (q if q != "(type your own below)" else "")
            if question:
                with st.spinner("Local SLM answering from the evidence packâ€¦"):
                    r = ask(a.packs[iid], question, CFG, [(x, json.dumps(y["raw_output"])) for x, y in hist])
                ver = verify_output({"summary": r["output"].get("answer", [])}, a.packs[iid], S.known_entities)
                hist.append((question, {"verified": ver, "cannot_answer": r["output"].get("cannot_answer"),
                                        "error": r.get("error"), "raw_output": r["output"]}))
                ws.audit(con, key, "chat question", question)
                st.rerun()
    with t2:
        cur = ws.current_disposition(con, key) or "New (no disposition)"
        st.markdown(f"Current disposition: **{cur}**")
        d = st.radio("Set disposition", ws.DISPOSITIONS, horizontal=True)
        note = st.text_area("Investigation note")
        if st.button("Record disposition", type="primary"):
            ws.set_disposition(con, key, iid, d, note)
            st.success("Recorded. The incident stays in the queue with its disposition and history.")
            st.rerun()
        st.markdown("**History for this incident**")
        st.dataframe(pd.DataFrame(ws.history(con, key)), hide_index=True, use_container_width=True)
    with t3:
        st.caption("Suppressions are narrow (one rule + exact account/host/IP), must be approved, only TAG matching incidents "
                   "(never hide them), and can be revoked.")
        c1, c2 = st.columns(2)
        with c1:
            rule = st.selectbox("Rule", sorted({a.alerts_by_id[x]["rule"] for x in inc["alert_ids"]}))
            fld = st.selectbox("Match field", ["user", "host", "ip"])
            opts = {"user": inc["users"], "host": inc["hosts"], "ip": inc["ips"]}[fld]
            val = st.selectbox("Exact value", opts) if opts else None
            reason = st.text_input("Justification")
            if st.button("Propose suppression", disabled=not (val and reason)):
                ws.propose_suppression(con, rule, {fld: val}, reason)
                st.rerun()
        with c2:
            for s in ws.suppressions(con):
                st.markdown(f"**SUP-{s['id']}** Â· {s['rule']} Â· `{s['match']}` Â· *{s['status']}* Â· {esc(s['reason'])}")
                b = st.columns(3)
                if s["status"] == "proposed":
                    if b[0].button("Approve", key=f"ap{s['id']}"):
                        ws.decide_suppression(con, s["id"], "approved"); st.rerun()
                    if b[1].button("Reject", key=f"rj{s['id']}"):
                        ws.decide_suppression(con, s["id"], "rejected"); st.rerun()
                elif s["status"] == "approved":
                    if b[0].button("Revoke", key=f"rv{s['id']}"):
                        ws.decide_suppression(con, s["id"], "revoked"); st.rerun()
        st.markdown("**Audit trail**")
        st.dataframe(pd.DataFrame(ws.history(con)), hide_index=True, use_container_width=True)


# --------------------------------------------------------------------------- router
{"Incident queue": page_queue, "Log upload & mapping": page_upload, "Incident investigation": page_investigate,
 "Accuracy & evaluation": page_accuracy, "Offline system monitor": page_monitor,
 "Analyst workspace": page_workspace}[page]()
