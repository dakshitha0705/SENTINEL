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


def render():
    st.markdown(section("Log sources", "CSV, JSON arrays, JSON-lines and Windows EVTX. Original files are never modified; "
                        "every record keeps its file, row and original record ID."), unsafe_allow_html=True)
    c1, c2 = st.columns([3, 2], gap="medium")
    with c1:
        up = st.file_uploader("Upload log files", type=["csv", "json", "jsonl", "ndjson", "evtx"],
                              accept_multiple_files=True, key="uploader")
        if up and st.button("Use uploaded files", type="primary"):
            S.files = {f.name: f.getvalue() for f in up}
            S.mappings, S.dataset, S.profile_note = {}, state.UPLOADED, ""
            S.analysis = None
            st.rerun()
        if not evtx_available():
            st.caption("EVTX support is not installed (pip install evtx); export EVTX to CSV/JSON instead.")
    with c2:
        st.markdown(f'<div class="sn-card"><h4>Active source</h4><div>{esc(S.dataset or "none")}</div>'
                    f'<div class="sn-muted">{len(S.files)} file(s) &middot; switch datasets with the selector above</div></div>',
                    unsafe_allow_html=True)
    if not S.files:
        st.info("No files loaded.")
        return

    st.markdown(section("Files, conversion and field mapping",
                        "SENTINEL guesses each schema field from column names and value patterns. Correct any guess, "
                        "then run the analysis."), unsafe_allow_html=True)
    changed = False
    for name, data in S.files.items():
        try:
            load, evtx_res = _load(name, data)
        except EvtxError as exc:
            st.error(f"{name}: {exc}")
            continue
        guess = S.mappings.get(name) or guess_mapping(load.frame)
        cols = ["(none)"] + [c for c in load.frame.columns if c != "__row"]
        label = f"{name} · {load.fmt.upper()} · {len(load.frame):,} records · SHA-256 {load.sha256[:16]}…"
        with st.expander(label, expanded=len(S.files) <= 2):
            if evtx_res is not None:
                d = evtx_res.diagnostics
                st.markdown(f"**EVTX converted offline** &middot; {d['records']:,} records &middot; "
                            f"{d['unreadable_records']} unreadable &middot; channels: {esc(', '.join(d['channels']) or '-')} "
                            f"&middot; top event IDs: {esc(', '.join(f'{k}x{v}' for k, v in list(d['event_codes'].items())[:8]))}",
                            unsafe_allow_html=True)
                st.download_button("Download converted JSON-lines", evtx_res.to_jsonl(), file_name=name + ".jsonl",
                                   mime="application/x-ndjson", key=f"dl_evtx_{name}")
            st.caption(f"SHA-256 {load.sha256}")
            grid = st.columns(6)
            new = {}
            for i, fld in enumerate(MAPPABLE_FIELDS):
                cur = guess.get(fld)
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
            acts = norm["action"].value_counts().to_dict()
            st.caption("Recognised actions: " + ", ".join(f"{k} {v:,}" for k, v in acts.items()))
            problems = []
            if not new.get("timestamp"):
                problems.append("No timestamp column mapped: every record in this file would be rejected.")
            if (norm["action"] == "group_add").any() and not (new.get("actor") and new.get("target_user")):
                problems.append("Group-membership events found but the actor and/or target_user column is not mapped. "
                                "R6 cannot check who made the change or who was added; approved changes may be flagged.")
            if acts.get("other", 0) == len(norm) and len(norm):
                problems.append("No record maps to a supported action (logons, group changes, process starts, log clears). "
                                "Map event_code or action, or this file cannot be analysed.")
            for p in problems:
                st.warning(p)
            if rej:
                st.caption(f"{len(rej)} record(s) would be rejected (listed after the run).")
    b = st.columns([1.2, 1.6, 1.4, 3])
    auto = b[1].checkbox("Explain top incidents with local Qwen", value=False)
    if b[0].button("Run analysis", type="primary", use_container_width=True):
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

    a = S.analysis
    if a is None:
        return
    st.markdown(section("Validation summary"), unsafe_allow_html=True)
    sm = a.dataset.summary
    k = st.columns(6)
    for col, (lab, v) in zip(k, [("Records read", sm["records_read"]), ("Accepted", sm["accepted"]),
                                 ("Rejected", sm["rejected"]), ("Duplicates", sm["duplicates"]),
                                 ("Unevaluable", sm["unevaluable"]), ("Incidents", len(a.incidents))]):
        col.markdown(kpi(lab, f"{v:,}"), unsafe_allow_html=True)
    t1, t2, t3, t4 = st.tabs(["Event explorer", "Source metadata & rule coverage", "Rejected & duplicates", "Export"])
    with t1:
        ev = a.events
        f = st.columns([2.4, 1.3, 1.3, 1.3, 1.3])
        text = f[0].text_input("Filter text (any field)", key="li_text")
        act = f[1].multiselect("Action", sorted(ev["action"].unique()), key="li_act")
        usr = f[2].multiselect("User", sorted(x for x in ev["user"].unique() if x), key="li_user")
        hst = f[3].multiselect("Host", sorted(x for x in ev["host"].unique() if x), key="li_host")
        src = f[4].multiselect("Source file", sorted(ev["source_file"].unique()), key="li_src")
        m = pd.Series(True, index=ev.index)
        if text:
            mm = pd.Series(False, index=ev.index)
            for c in ("user", "actor", "target_user", "host", "src_ip", "process", "command_line", "group", "event_code",
                      "event_id"):
                mm |= ev[c].astype(str).str.contains(text, case=False, regex=False, na=False)
            m &= mm
        for col, vals in (("action", act), ("user", usr), ("host", hst), ("source_file", src)):
            if vals:
                m &= ev[col].isin(vals)
        hits = ev[m]
        sort_col = st.selectbox("Sort by", ["timestamp", "user", "host", "action", "event_code"], key="li_sort")
        hits = hits.sort_values(sort_col, kind="stable")
        page_size = 500
        pages = max(1, (len(hits) - 1) // page_size + 1)
        pg = st.number_input(f"Page (of {pages}; {len(hits):,} matching events)", 1, pages, 1, key="li_page")
        show = hits.iloc[(pg - 1) * page_size: pg * page_size].drop(columns=["raw"]).copy()
        show["timestamp"] = show["timestamp"].astype(str)
        st.dataframe(show, hide_index=True, use_container_width=True, height=380)
        pick = st.selectbox("Inspect original record", show["event_id"].tolist() or ["-"], key="li_pick")
        if pick in set(ev["event_id"]):
            r = ev.set_index("event_id").loc[pick]
            st.caption(f"{r['source_file']} row {r['source_row']} · record ID {r['record_id'] or '-'} · original, unmodified:")
            st.code(json.dumps(json.loads(r["raw"]), indent=2), language="json")
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
