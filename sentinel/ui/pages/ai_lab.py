"""AI Investigation Lab: local Qwen explanation under the Evidence Contract, self-repair, chat, handoff."""
from __future__ import annotations

import json

import streamlit as st

from ... import workspace as ws
from ...handoff import handoff_claims, handoff_note, handoff_text
from ...playbooks import load_playbooks
from ...slm import answer
from ...verifier import verify_output
from .. import esc, pill, section, tag
from .. import state
from ..state import S

PRESETS = ["Why is the severity high?", "Which devices were involved?", "What happened next?",
           "Which events support this conclusion?", "What evidence contradicts the hypothesis?",
           "What should be investigated?"]


def _claim_html(c):
    lab = '<span class="sn-ok">VERIFIED</span>' if c["status"] == "Verified" else '<span class="sn-bad">UNVERIFIED</span>'
    typed = {k: c.get(k) for k in ("claim_type",) if c.get(k)}
    prob = f'<div class="sn-muted">{esc("; ".join(c["problems"]))}</div>' if c["problems"] else ""
    return (f'<div class="sn-claim">{lab} {esc(c["text"])} <span class="sn-cite">[{esc(", ".join(c["fact_ids"]))}]'
            f'{" · " + esc(typed["claim_type"]) if typed else ""}</span>{prob}</div>')


def render():
    a = S.analysis
    if a is None or not a.incidents:
        st.info("No incidents to investigate. Load a dataset first.")
        return
    incs = state.visible_incidents(a) or a.incidents
    ids = [i["incident_id"] for i in incs]
    cur = state.selected_incident(a, incs)
    iid = st.selectbox("Incident", ids, index=ids.index(cur), key="ai_pick",
                       format_func=lambda x: f"{x} · {a.incident(x)['severity']['level']} {a.incident(x)['severity']['score']} · {a.incident(x)['title']}")
    S.selected = iid
    inc, pack = a.incident(iid), a.packs[iid]
    st.markdown(pill(inc["severity"]["level"], f"{inc['severity']['level']} {inc['severity']['score']}")
                + f" &nbsp;{esc(inc['title'])} &nbsp;<span class='sn-muted'>{len(pack['facts'])} facts in the evidence pack</span>",
                unsafe_allow_html=True)
    t1, t2, t3 = st.tabs(["Explanation & Evidence Contract", "Ask SENTINEL", "Analyst handoff note"])

    with t1:
        st.caption("Deterministic code establishes the facts; local Qwen interprets them; the verifier checks every factual "
                   "sentence and its typed fields (counts, times, users, hosts, IPs, event IDs) against the cited facts. "
                   "With self-repair on, failing claims are sent back once with the specific verifier errors.")
        cached = S.explanations.get(iid)
        c = st.columns([1.5, 1.5, 1.4, 3])
        gen = c[0].button("Explain with local Qwen" if not cached else "Regenerate", type="primary")
        tmpl = c[1].button("Deterministic template")
        repair_on = c[2].toggle("Self-repair", value=S.cfg["slm"].get("self_repair", True), key="ai_repair")
        if gen:
            S.cfg["slm"]["self_repair"] = repair_on
            box = st.empty()
            buf = []

            def on_tok(t):
                buf.append(t)
                if len(buf) % 8 == 0:
                    box.code("".join(buf)[-1400:], language="json")
            with st.spinner("Local Qwen is reading the evidence pack (and repairing failed claims if needed)..."):
                state.explanation_for(iid, use_slm=True, on_token=on_tok, force=bool(cached))
            box.empty()
        if tmpl:
            state.explanation_for(iid, use_slm=False, force=True)
        if iid not in S.explanations:
            st.info("No explanation yet for this incident.")
        else:
            res, ver = S.explanations[iid][:2]
            stt = ver["stats"]
            src = {"slm": "Local Qwen (live)", "cache": "Local Qwen (cached)", "template": "Deterministic template"}[res["source"]]
            meta = f"{src} · {res.get('model') or ''}"
            if res.get("stats", {}).get("tokens_per_s"):
                meta += f" · {res['stats']['wall_s']} s · {res['stats']['tokens_per_s']} tok/s"
            rate = f"{stt['verification_rate']:.0%}" if stt["verification_rate"] is not None else "n/a"
            st.markdown(f'<span class="sn-muted">{esc(meta)}</span> &nbsp; {tag(f"verified {stt["verified"]}/{stt["factual_claims"]} = {rate}", "gold")}',
                        unsafe_allow_html=True)
            if res.get("error") and res["source"] == "template":
                st.caption(f"Fallback reason: {res['error']}")
            rep = res.get("repair")
            if rep:
                if rep.get("attempted"):
                    st.markdown(f'<div class="sn-card"><h4>Self-repair outcome</h4>Initial: <b>{rep["initial_verified"]}/{rep["initial_claims"]}</b> '
                                f'verified &rarr; after one repair round: <b>{rep["final_verified"]}/{rep["final_claims"]}</b> '
                                f'&middot; still failing (rejected): <b>{rep["still_failing"]}</b> &middot; extra latency '
                                f'{rep["latency_s"]} s &middot; kept: {esc(rep.get("kept", "-"))}</div>', unsafe_allow_html=True)
                    with st.expander("Verifier feedback sent to the model"):
                        for line in rep.get("feedback", []):
                            st.markdown(f"- {line}")
                    if res.get("initial_output"):
                        with st.expander("Initial (pre-repair) output"):
                            st.json(res["initial_output"])
                else:
                    st.caption("Self-repair: not needed (every factual claim passed on the first attempt)." if rep["initial_claims"]
                               else "Self-repair: no factual claims to check.")
            cA, cB = st.columns(2, gap="medium")
            with cA:
                html = '<div class="sn-card"><h4>Verified facts (from code)</h4>'
                for f in pack["facts"]:
                    if f["kind"] in ("detection", "context") and "[weak link" not in f["text"]:
                        html += f'<div class="sn-claim"><span class="sn-ok">FACT</span> <span class="sn-cite">{f["id"]}</span> {esc(f["text"])}</div>'
                st.markdown(html + "</div>", unsafe_allow_html=True)
                html = '<div class="sn-card"><h4>Model summary &amp; conclusions (checked)</h4>'
                html += "".join(_claim_html(c) for c in ver["summary"] + ver["conclusions"]) or '<div class="sn-muted">none</div>'
                st.markdown(html + "</div>", unsafe_allow_html=True)
            with cB:
                html = '<div class="sn-card"><h4>Hypotheses (not facts)</h4>'
                for h in ver["hypotheses"]:
                    lab = '<span class="sn-hyp">HYPOTHESIS</span>' if h["status"] == "Grounded hypothesis" else '<span class="sn-bad">UNGROUNDED</span>'
                    html += (f'<div class="sn-claim">{lab} {esc(h["text"])} <span class="sn-cite">supports [{esc(", ".join(h["supporting_fact_ids"]))}]'
                             f'{" · contradicts [" + esc(", ".join(h["contradicting_fact_ids"])) + "]" if h["contradicting_fact_ids"] else ""}</span>'
                             f'<div class="sn-muted">How to confirm: {esc(h["how_to_confirm"])}</div></div>')
                st.markdown(html + "</div>", unsafe_allow_html=True)
                facts = {f["id"]: f for f in pack["facts"]}
                html = '<div class="sn-card"><h4>Contradicting evidence (code)</h4>'
                html += "".join(f'<div class="sn-claim"><span class="sn-cite">{fid}</span> {esc(facts[fid]["text"])}</div>'
                                for fid in pack["contradicting_fact_ids"]) or '<div class="sn-muted">None found in the logs.</div>'
                st.markdown(html + "</div>", unsafe_allow_html=True)
                pb = load_playbooks()
                html = '<div class="sn-card"><h4>Recommended investigation</h4>'
                for x in ver["actions"]:
                    html += f'<div class="sn-claim"><b>{x["playbook_id"]}</b> {esc(pb[x["playbook_id"]]["title"])}<div class="sn-muted">{esc(x["adaptation"])}</div></div>'
                for x in ver["rejected_actions"]:
                    html += f'<div class="sn-claim"><span class="sn-bad">REJECTED</span> {esc(x["playbook_id"])}: {esc(x["reason"])}</div>'
                for q in ver["questions"]:
                    html += f'<div class="sn-claim"><span class="sn-muted">Open question:</span> {esc(q)}</div>'
                st.markdown(html + "</div>", unsafe_allow_html=True)

    with t2:
        st.caption("Answers use only this incident's evidence pack and pass the same verifier. If local Qwen returns nothing "
                   "verifiable, SENTINEL answers deterministically from the facts (labelled) - never with silence.")
        hist = S.chat.setdefault(iid, [])
        for q, ans in hist:
            st.markdown(f"**You:** {esc(q)}")
            src = {"slm": "local Qwen", "deterministic": "deterministic fallback"}[ans["source"]]
            html = f'<div class="sn-card"><h4>SENTINEL &middot; {esc(src)}</h4>'
            html += "".join(_claim_html(c) for c in ans["verification"]["summary"])
            if ans["output"].get("cannot_answer"):
                html += f'<div class="sn-claim"><span class="sn-muted">Cannot answer from the evidence: {esc(ans["output"]["cannot_answer"])}</span></div>'
            if ans.get("note"):
                html += f'<div class="sn-claim"><span class="sn-muted">{esc(ans["note"])}</span></div>'
            if ans["source"] == "deterministic" and ans.get("error"):
                html += f'<div class="sn-muted">Why the fallback was used: {esc(ans["error"])}</div>'
            st.markdown(html + "</div>", unsafe_allow_html=True)
        cq = st.columns([2, 3, 1])
        preset = cq[0].selectbox("Suggested", ["(type your own)"] + PRESETS, key="ai_preset", label_visibility="collapsed")
        free = cq[1].text_input("Question", key="ai_q", label_visibility="collapsed", placeholder="Ask about this incident")
        if cq[2].button("Ask", type="primary", use_container_width=True):
            question = free.strip() or (preset if preset != "(type your own)" else "")
            if question:
                with st.spinner("Answering from the evidence pack..."):
                    r = answer(pack, question, S.cfg, S.known_entities,
                               [(x, json.dumps(y["output"])) for x, y in hist])
                hist.append((question, r))
                ws.audit(ws.connect(), ws.incident_key(a, inc), "chat question", question)
                st.rerun()

    with t3:
        con = ws.connect()
        key = ws.incident_key(a, inc)
        ver = S.explanations.get(iid, (None, None))[1]
        note = handoff_note(pack, inc, ws.current_status(con, key), ws.current_disposition(con, key), ws.notes(con, key),
                            ver["stats"] if ver else None)
        nv = verify_output({"summary": handoff_claims(note)}, pack, S.known_entities)
        ok = nv["stats"]["verified"]
        st.markdown(f'{tag(f"factual lines verified {ok}/{nv["stats"]["factual_claims"]}", "gold")} '
                    '<span class="sn-muted">Workflow lines (status, notes) come from the analyst workspace.</span>',
                    unsafe_allow_html=True)
        txt = handoff_text(note)
        st.code(txt, language=None)
        c = st.columns(3)
        c[0].download_button("Download handoff (TXT)", txt.encode("utf-8"), file_name=f"SENTINEL_{iid}_handoff.txt",
                             mime="text/plain", type="primary")
        c[1].download_button("Download handoff (JSON)", json.dumps({**note, "verification": nv["stats"]}, indent=1, default=str).encode("utf-8"),
                             file_name=f"SENTINEL_{iid}_handoff.json", mime="application/json")
        if c[2].button("Record handoff in audit trail"):
            ws.audit(con, key, "handoff", f"handoff note generated ({ok}/{nv['stats']['factual_claims']} verified)")
            st.success("Recorded.")
