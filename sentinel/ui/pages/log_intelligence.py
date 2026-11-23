"""Log Intelligence: upload, EVTX conversion, column mapping, validation, event explorer, exports."""
from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from ...evtx_converter import EvtxError, available as evtx_available, convert_evtx
from ...ingest import MAPPABLE_FIELDS, guess_mapping, normalize, read_file, sha256_bytes
from ...rules import RULES
from .. import esc, kpi, section
from .. import state
from ..state import S

FIELD_HELP = {"src_lat": "optional: source latitude (only if the log provides it)",
              "src_lon": "optional: source longitude", "src_geo": "optional: source location label",
              "dst_lat": "optional: device latitude", "dst_lon": "optional: device longitude",
              "dst_geo": "optional: device location label"}


def _load(name: str, data: bytes):
    """read_file, with EVTX converted first (cached per file hash)."""
    if name.lower().endswith(".evtx"):
        key = ("evtx", sha256_bytes(data))
        cache = S.setdefault("_evtx_cache", {})
        if key not in cache:
            cache[key] = convert_evtx(data, name)
        res = cache[key]
        load = read_file(name, res.to_jsonl())
        load.sha256, load.fmt = sha256_bytes(data), "evtx"
        return load, res
    return read_file(name, data), None


def _problems(mp, norm) -> list[str]:
    out = []
    if not mp.get("timestamp"):
        out.append("No timestamp column mapped: every record in this file would be rejected.")
    if (norm["action"] == "group_add").any() and not (mp.get("actor") and mp.get("target_user")):
        out.append("Group-membership events found but the actor and/or target_user column is not mapped. "
                   "R6 cannot check who made the change or who was added; approved changes may be flagged.")
    if len(norm) and (norm["action"] == "other").all():
        out.append("No record maps to a supported action (logons, group changes, process starts, log clears). "
                   "Map event_code or action, or this file cannot be analysed.")
    return out


def _live_source():
    snap = state.live_engine().snapshot()
    a = snap["analysis"]
    origins = {}
    for e in state.live_engine().recent_events(10_000):
        origins[e.get("origin")] = origins.get(e.get("origin"), 0) + 1
    st.markdown(
        f'<div class="sn-card"><h4>Live source &middot; NEXUS event stream</h4>'
        f'<b style="color:var(--ivory)">demo_data/sessions/{esc(snap["session_id"] or "-")}/events.jsonl</b>'
        f'<div class="sn-muted">{snap["events"]:,} events ingested incrementally (durable byte-offset cursor, de-duplicated by '
        f'event_uid; {snap["duplicates"]} duplicate(s) skipped) &middot; last poll {esc(snap["last_poll"] or "-")} &middot; '
        f'analysis {snap["analysis_s"] or 0} s &middot; mapping fixed by the NEXUS schema</div>'
        f'<div class="sn-muted">Recent origins: ' + esc(", ".join(f"{k} {v}" for k, v in origins.items())) +
        ' (nexus-app = produced by NEXUS application code; simulated-endpoint / baseline-backfill = synthetic, labelled)</div></div>',
        unsafe_allow_html=True)
    return a


def render():
    step = 1 if not S.files and not state.is_live() else (3 if S.analysis is not None else 2)
    st.markdown('<div class="sn-progress">' + "".join(f'<i class="{"done" if k < step else "now" if k == step else ""}"></i>'
                                                      for k in (1, 2, 3)) + '</div>'
                '<div style="display:flex;justify-content:space-between" class="sn-muted"><span>1 · Upload</span>'
                '<span>2 · Review</span><span>3 · Analyze</span></div>', unsafe_allow_html=True)
    if state.is_live():
        _live_source()
        _analysis_panels(S.analysis)
        return
    c1, c2 = st.columns([3, 2], gap="medium")
    with c1:
        up = st.file_uploader("Drop CSV, JSON, JSON-lines or Windows EVTX files here", type=["csv", "json", "jsonl", "ndjson", "evtx"],
                              accept_multiple_files=True, key="uploader")
        if up and st.button("Use uploaded files", type="primary"):
            S.files = {f.name: f.getvalue() for f in up}
            S.mappings, S.dataset, S.profile_note = {}, state.UPLOADED, ""
            S.analysis = None
            st.rerun()
        if not evtx_available():
            st.caption("EVTX support is not installed (pip install evtx); export EVTX to CSV/JSON instead.")
    with c2:
        st.markdown('<div class="sn-card"><h4>How it works</h4><div class="sn-muted">SENTINEL recognises the columns of '
                    'unfamiliar logs automatically. If it is unsure about a field, it asks you to confirm the mapping. Original '
                    'files are never modified; every record keeps its file, row and original event ID.</div></div>',
                    unsafe_allow_html=True)
    if not S.files:
        st.info("No files loaded.")
        return

    st.markdown(f'<div class="sn-eyebrow">Files · {esc(S.dataset or "")}</div>', unsafe_allow_html=True)
    changed = False
    for name, data in S.files.items():
        try:
            load, evtx_res = _load(name, data)
        except EvtxError as exc:
            st.error(f"{name}: {exc}")
            continue
        guess = S.mappings.get(name) or guess_mapping(load.frame)
        cols = ["(none)"] + [c for c in load.frame.columns if c != "__row"]
        cur_map = S.mappings.get(name) or guess
        norm0, rej0 = normalize(load, cur_map)
        problems = _problems(cur_map, norm0)
        acts = norm0["action"].value_counts().to_dict()
        mapped = sum(1 for f in MAPPABLE_FIELDS if cur_map.get(f))
        chip = ('<span class="sn-chip ok"><i></i>Ready</span>' if not problems
                else f'<span class="sn-chip warn"><i></i>Check mapping ({len(problems)})</span>')
        st.markdown(
            f'<div class="sn-act" style="grid-template-columns:1fr auto auto auto"><div class="d"><b>{esc(name)}</b></div>'
            f'<div class="t">{esc(load.fmt.upper())}</div><div class="t">{len(load.frame):,} records</div><div>{chip}</div></div>',
            unsafe_allow_html=True)
        with st.popover("Details"):
            st.markdown(f"{mapped}/{len(MAPPABLE_FIELDS)} fields mapped · {len(rej0)} record(s) would be rejected")
            st.markdown("Recognised activity: " + esc(", ".join(f"{k} {v:,}" for k, v in acts.items())))
            st.caption(f"SHA-256 {load.sha256}")
        if evtx_res is not None:
            d = evtx_res.diagnostics
            c1, c2 = st.columns([4, 1.3], vertical_alignment="center")
            c1.markdown(f"**EVTX converted offline** · {d['records']:,} records · {d['unreadable_records']} unreadable · "
                        f"channels: {esc(', '.join(d['channels']) or '-')} · top event IDs: "
                        f"{esc(', '.join(f'{k}x{v}' for k, v in list(d['event_codes'].items())[:8]))}", unsafe_allow_html=True)
            c2.download_button("Converted JSON-lines", evtx_res.to_jsonl(), file_name=name + ".jsonl",
                               mime="application/x-ndjson", key=f"dl_evtx_{name}", use_container_width=True)
        for p_ in problems:
            st.warning(p_)
        with st.expander(f"Advanced field mapping · {name}", expanded=bool(problems)):
            grid = st.columns(6)
            new = {}
            for i, fld in enumerate(MAPPABLE_FIELDS):
                cur = cur_map.get(fld)
                v = grid[i % 6].selectbox(fld, cols, index=cols.index(cur) if cur in cols else 0,
                                          key=f"map_{name}_{fld}", help=FIELD_HELP.get(fld))
                new[fld] = None if v == "(none)" else v
            if "_provider" in guess:
                new["_provider"] = guess["_provider"]
            if {k: v for k, v in new.items()} != {k: guess.get(k) for k in new}:
                changed = True
            S.mappings[name] = new
            norm, rej = normalize(load, new)
            show = norm.drop(columns=["raw"]).head(8).copy()
            show["timestamp"] = show["timestamp"].astype(str)
            st.dataframe(show, hide_index=True, use_container_width=True)
    b = st.columns([1.2, 1.6, 1.4, 3])
    auto = b[1].checkbox("Also explain the top incidents with local Qwen", value=False)
    if b[0].button("Run Analysis", type="primary", use_container_width=True, icon=":material/play_arrow:"):
        bar = st.progress(0.0)
        state.run_analysis(auto_explain=auto, progress=lambda p, t: bar.progress(p, text=t))
        st.rerun()
    if b[2].button("Save mapping profile", help="Store these mappings next to a bundled dataset so it reopens mapped",
                   disabled=S.dataset in (None, state.UPLOADED) or S.dataset.startswith("external")):
        prof = {}
        for fname, mp in S.mappings.items():
            g = guess_mapping(_load(fname, S.files[fname])[0].frame)
            diff = {k: v for k, v in mp.items() if k != "_provider" and v != g.get(k)}
            if diff:
                prof[fname] = diff
        path = state.SAMPLES / S.dataset / "mapping_profile.json"
        path.write_text(json.dumps({"note": "Analyst-saved mapping profile.", "files": prof}, indent=1), encoding="utf-8")
        st.success(f"Saved {len(prof)} file mapping correction(s) to {path.name}.")
    if changed and S.analysis is not None:
        st.caption("Mappings differ from the last analysis: run the analysis again to apply them.")

    _analysis_panels(S.analysis)


ACTION_TEXT = {"login_failure": "Failed sign-in", "login_success": "Signed in", "logout": "Signed out",
               "group_add": "Added to a group", "group_enum": "Listed group members", "process_start": "Process started",
               "log_cleared": "Audit log cleared", "privilege_logon": "Privileged sign-in"}


def _analysis_panels(a):
    if a is None:
        return
    sm = a.dataset.summary
    st.markdown('<div class="sn-stats">' + "".join(
        f'<div class="sn-stat"><div class="v">{v}</div><div class="l">{esc(l)}</div></div>'
        for v, l in ((f'{sm["accepted"]:,}', "events analysed"), (f'{sm["rejected"]:,}', "records rejected"),
                     (f'{sm["duplicates"]:,}', "duplicates skipped"), (len(a.incidents), "incidents"))) + "</div>",
        unsafe_allow_html=True)
    ev = a.events
    in_inc = {e: i["incident_id"] for i in a.incidents for e in i["event_ids"]}
    f = st.columns([2.6, 1.4, 1.4, 1.2], vertical_alignment="center")
    text = f[0].text_input("Search events", key="li_text", placeholder="Search events (account, device, address, command…)",
                           label_visibility="collapsed")
    usr = f[1].multiselect("Account", sorted(x for x in ev["user"].unique() if x), key="li_user", placeholder="Account",
                           label_visibility="collapsed")
    hst = f[2].multiselect("Device", sorted(x for x in ev["host"].unique() if x), key="li_host", placeholder="Device",
                           label_visibility="collapsed")
    only = f[3].toggle("Only in incidents", key="li_only")
    m = pd.Series(True, index=ev.index)
    if text:
        mm = pd.Series(False, index=ev.index)
        for c in ("user", "actor", "target_user", "host", "src_ip", "process", "command_line", "group", "event_code", "event_id"):
            mm |= ev[c].astype(str).str.contains(text, case=False, regex=False, na=False)
        m &= mm
    for col, vals in (("user", usr), ("host", hst)):
        if vals:
            m &= ev[col].isin(vals)
    if only:
        m &= ev["event_id"].isin(set(in_inc))
    hits = ev[m].sort_values("timestamp", kind="stable")
    page_size = 400
    pages = max(1, (len(hits) - 1) // page_size + 1)
    pg = min(int(S.get("li_page", pages) or pages), pages)
    view = hits.iloc[(pg - 1) * page_size: pg * page_size]
    table = pd.DataFrame({
        "Time": view["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S"),
        "Activity": [ACTION_TEXT.get(x, x or f"Event {c}") for x, c in zip(view["action"], view["event_code"])],
        "User": view["user"], "Device": view["host"], "Source": view["src_ip"],
        "Result": view["outcome"] if "outcome" in view.columns else "",
        "Linked incident": view["event_id"].map(in_inc).fillna(""),
    })
    left, right = st.columns([2.2, 1], gap="large")
    with left:
        sel = st.dataframe(table, hide_index=True, use_container_width=True, height=400, on_select="rerun",
                           selection_mode="single-row", key=f"li_table_{pg}")
        if pages > 1:
            S.setdefault("li_page", pages)
            if S.li_page > pages:
                S.li_page = pages
            st.number_input(f"Page (of {pages}; {len(hits):,} matching events, oldest first)", 1, pages, key="li_page")
        else:
            st.caption(f"{len(hits):,} matching events. Select a row to see its details.")
    with right:
        rows = list(getattr(getattr(sel, "selection", None), "rows", []) or [])
        if not rows:
            st.markdown('<div class="sn-card"><h4>Event details</h4><div class="sn-muted">Select a row in the table to see a '
                        'readable summary, the original record and where it came from.</div></div>', unsafe_allow_html=True)
        else:
            r = view.iloc[rows[0]]
            act = ACTION_TEXT.get(r["action"], r["action"] or f"Event {r['event_code']}")
            who = r["user"] or r["actor"] or "an unknown account"
            summary = f"{act} by {who}" + (f" on {r['host']}" if r["host"] else "") + (f" from {r['src_ip']}" if r["src_ip"] else "")
            if r["process"]:
                summary += f" · process {r['process']}"
            inc = in_inc.get(r["event_id"])
            st.markdown(f'<div class="sn-card"><h4>Event details</h4><div class="sn-exec">{esc(summary)}</div>'
                        f'<div class="sn-row"><span>Time (UTC)</span><span class="n">{r["timestamp"]}</span></div>'
                        f'<div class="sn-row"><span>Linked incident</span><span class="n">{esc(inc or "none")}</span></div>'
                        f'<div class="sn-row"><span>Source file</span><span class="n">{esc(r["source_file"])} row {r["source_row"]}</span></div>'
                        f'<div class="sn-row"><span>Original event ID</span><span class="n">{esc(r["record_id"] or "-")}</span></div></div>',
                        unsafe_allow_html=True)
            if inc and st.button("Investigate this incident", type="primary", key="li_inv"):
                state.goto("Investigation Studio", inc, view="Story")
                st.rerun()
            with st.expander("Original record"):
                st.code(json.dumps(json.loads(r["raw"]), indent=2), language="json")
            with st.expander("Technical identifiers"):
                st.json({k: str(r[k]) for k in ("event_id", "event_code", "action", "actor", "target_user", "group",
                                                "command_line") if k in r.index})

    with st.expander("Technical details: sources, rule coverage, rejected records, exports"):
        t2, t3, t4 = st.tabs(["Sources & rule coverage", "Rejected & duplicates", "Export"])
        with t2:
            st.dataframe(pd.DataFrame([{k: v for k, v in f.items() if k != "evtx"} for f in a.dataset.files]),
                         hide_index=True, use_container_width=True)
            cov = pd.DataFrame([{"rule": r, "name": RULES[r][0], "evaluated": v["evaluated"], "alerts": v["alerts"],
                                 "requirement": v["requirement"]} for r, v in a.coverage.items()])
            st.markdown("**Rule coverage on this data** (a rule is *not evaluated* when the fields it needs are missing)")
            st.dataframe(cov, hide_index=True, use_container_width=True)
            st.markdown("**Measured processing time**")
            st.json({k: f"{v:.3f} s" for k, v in a.timings.items()})
        with t3:
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Rejected records** (not analysed, kept for review)")
                st.dataframe(a.dataset.rejected if len(a.dataset.rejected) else pd.DataFrame([{"result": "none"}]),
                             hide_index=True, use_container_width=True)
            with c2:
                st.markdown("**Duplicate records** (analysed once)")
                if len(a.dataset.duplicates):
                    st.dataframe(a.dataset.duplicates[["source_file", "source_row", "event_code", "record_id", "duplicate_of"]],
                                 hide_index=True, use_container_width=True)
                else:
                    st.dataframe(pd.DataFrame([{"result": "none"}]), hide_index=True, use_container_width=True)
        with t4:
            norm = a.events.copy()
            norm["timestamp"] = norm["timestamp"].astype(str)
            c = st.columns(3)
            c[0].download_button("Normalised events (CSV)", norm.to_csv(index=False).encode("utf-8"),
                                 file_name="sentinel_normalised_events.csv", mime="text/csv", type="primary")
            c[1].download_button("Normalised events (JSON-lines)",
                                 norm.to_json(orient="records", lines=True, force_ascii=False).encode("utf-8"),
                                 file_name="sentinel_normalised_events.jsonl", mime="application/x-ndjson")
            c[2].download_button("Column mappings (JSON)", json.dumps(S.mappings, indent=1).encode("utf-8"),
                                 file_name="sentinel_mappings.json", mime="application/json")
            st.caption("Exports contain the normalised schema plus each record's original content in the raw column.")
