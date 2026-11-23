"""Report Studio: preview and export incident reports (HTML / PDF) and incident data (JSON / CSV)."""
from __future__ import annotations

import io
import zipfile
from datetime import datetime

import streamlit as st
import streamlit.components.v1 as stc

from ... import exports
from ... import workspace as ws
from ...handoff import handoff_note, handoff_text
from ...report import html_to_pdf, pdf_available, render_report
from .. import esc, section
from .. import state
from ..state import REPORTS, S


def _workflow(con, a, inc):
    key = ws.incident_key(a, inc)
    notes = ws.notes(con, key)
    return {"status": ws.current_status(con, key), "disposition": ws.current_disposition(con, key) or "Not set",
            "notes": notes}


def render():
    a = S.analysis
    if a is None or not a.incidents:
        st.info("No incidents to report. Load a dataset first.")
        return
    con = ws.connect()
    ids = [i["incident_id"] for i in a.incidents]
    c = st.columns([2.2, 1.6, 1.4])
    cur = state.selected_incident(a)
    iid = c[0].selectbox("Report incident", ids, index=ids.index(cur), key="rs_pick",
                         format_func=lambda x: f"{x} · {a.incident(x)['severity']['level']} · {a.incident(x)['title']}")
    S.selected = iid
    have = iid in S.explanations
    src = c[1].radio("Explanation", ["Existing / template", "Generate with local Qwen"], key="rs_src",
                     help="Existing = the explanation already produced in this session, else the deterministic template.")
    inc_handoff = c[2].toggle("Include handoff note", value=True, key="rs_handoff")
    if src == "Generate with local Qwen" and st.button("Generate explanation now", type="primary"):
        with st.spinner("Local Qwen explaining..."):
            state.explanation_for(iid, use_slm=True, force=True)
        st.rerun()
    res, ver = S.explanations[iid][:2] if have else state.explanation_for(iid, use_slm=False)
    inc = a.incident(iid)
    pack = a.packs[iid]
    wf = _workflow(con, a, inc)
    ho = handoff_text(handoff_note(pack, inc, wf["status"], wf["disposition"], wf["notes"], ver["stats"])) if inc_handoff else None
    html = render_report(a, iid, res, ver, handoff=ho)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"SENTINEL_{iid}_{stamp}.html"
    from .live_demo import mark
    from .command_center import headline
    ver_ok = ver["stats"]["verified"] == ver["stats"]["factual_claims"]
    st.markdown(f'<div class="sn-card"><h4>Executive summary</h4><div class="sn-exec">{esc(headline(inc)[0])}</div>'
                f'<div class="sn-muted">{esc(headline(inc)[1])} Severity {esc(inc["severity"]["level"])} {inc["severity"]["score"]}/100. '
                f'Verification: <b style="color:{"var(--ok)" if ver_ok else "var(--hyp)"}">{ver["stats"]["verified"]} of '
                f'{ver["stats"]["factual_claims"]} statements verified</b> against the original logs; only verified statements '
                'are presented as findings.</div></div>', unsafe_allow_html=True)
    b = st.columns(4)
    if b[0].download_button("Download HTML report", html.encode("utf-8"), file_name=fname, mime="text/html", type="primary"):
        mark("report")
    if b[1].button("Export PDF (local Edge)", disabled=not pdf_available()):
        REPORTS.mkdir(exist_ok=True)
        hp = REPORTS / fname
        hp.write_text(html, encoding="utf-8")
        with st.spinner("Printing PDF with the local browser engine (offline)..."):
            ok = html_to_pdf(hp, hp.with_suffix(".pdf"))
        if ok:
            mark("report")
            S.rs_pdf = (hp.with_suffix(".pdf").name, hp.with_suffix(".pdf").read_bytes())
            ws.audit(con, ws.incident_key(a, inc), "report", f"PDF exported {hp.with_suffix('.pdf').name}")
        else:
            st.error("PDF export failed; the HTML report is still available.")
    if S.get("rs_pdf"):
        b[1].download_button("Download PDF", S.rs_pdf[1], file_name=S.rs_pdf[0], mime="application/pdf")
    if b[2].button("Save HTML to reports/"):
        REPORTS.mkdir(exist_ok=True)
        (REPORTS / fname).write_text(html, encoding="utf-8")
        mark("report")
        ws.audit(con, ws.incident_key(a, inc), "report", f"HTML saved {fname}")
        st.success(f"Saved {REPORTS / fname}")
    st.caption(f"Explanation used: {res['source']} · verified {ver['stats']['verified']}/{ver['stats']['factual_claims']} "
               f"factual statements · evidence pack hash {pack['hash']}")
    stc.html(html, height=720, scrolling=True)

    with st.expander("Export several incidents (JSON, CSV, ZIP of reports)"):
        _bulk(con, a, ids, stamp)


def _bulk(con, a, ids, stamp):
    if True:
        sel = st.multiselect("Incidents", ids, default=ids, key="rs_multi")
        chosen = [a.incident(x) for x in sel]
        wfs = {i["incident_id"]: {**_workflow(con, a, i), "notes": [n["note"] for n in _workflow(con, a, i)["notes"]]}
               for i in chosen}
        vers = {k: v[1] for k, v in S.explanations.items() if k in sel}
        e = st.columns(3)
        e[0].download_button("Incidents JSON", exports.incidents_json(a, chosen, vers, wfs), file_name=f"SENTINEL_incidents_{stamp}.json",
                             mime="application/json", disabled=not chosen)
        e[1].download_button("Incidents CSV", exports.incidents_csv(a, chosen, wfs), file_name=f"SENTINEL_incidents_{stamp}.csv",
                             mime="text/csv", disabled=not chosen)
        if chosen:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for i in chosen:
                    r, v = (S.explanations.get(i["incident_id"]) or state.explanation_for(i["incident_id"], use_slm=False))[:2]
                    z.writestr(f"SENTINEL_{i['incident_id']}.html", render_report(a, i["incident_id"], r, v))
                z.writestr("incidents.json", exports.incidents_json(a, chosen, vers, wfs))
                z.writestr("incidents.csv", exports.incidents_csv(a, chosen, wfs))
            e[2].download_button("All reports (ZIP)", buf.getvalue(), file_name=f"SENTINEL_reports_{stamp}.zip",
                                 mime="application/zip")
