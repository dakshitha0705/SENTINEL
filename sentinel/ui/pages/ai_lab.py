"""AI investigation (inside Investigation Studio): local Qwen explanation under the Evidence Contract, organised as
What We Know / What Might Have Happened / What Needs Checking / Recommended Next Steps, plus grounded chat and the
analyst handoff note. Facts come from code; every model sentence is verified against the cited facts."""
from __future__ import annotations

import json

import streamlit as st

from ... import workspace as ws
from ...handoff import handoff_claims, handoff_note, handoff_text
from ...playbooks import load_playbooks
from ...slm import answer
from ...verifier import verify_output
from .. import esc, tag
from .. import state
from ..state import S

PRESETS = ["What happened?", "Why is this incident critical?", "Which accounts are affected?",
           "What evidence supports this conclusion?", "What should we check next?",
           "Can you summarize this for the next analyst?"]
SOURCE = {"slm": "Local Qwen (live)", "cache": "Local Qwen (cached)", "template": "Deterministic template (not the model)"}


def _claim_html(c, show_status=True):
    lab = ('<span class="sn-ok">VERIFIED</span> ' if c["status"] == "Verified" else '<span class="sn-bad">UNVERIFIED</span> ') if show_status else ""
    prob = f'<div class="sn-muted">Why: {esc("; ".join(c["problems"]))}</div>' if c["problems"] and c["status"] != "Verified" else ""
    return (f'<div class="sn-claim">{lab}{esc(c["text"])} <span class="sn-cite">[{esc(", ".join(c["fact_ids"]))}]</span>{prob}</div>')


def render_for(iid: str):
    a = S.analysis
    inc, pack = a.incident(iid), a.packs[iid]
    v = st.segmented_control("AI view", ["Explanation", "Ask SENTINEL", "Handoff note"], default="Explanation",
                             key="ai_view", label_visibility="collapsed") or "Explanation"
    if v == "Explanation":
        _explanation(a, iid, inc, pack)
    elif v == "Ask SENTINEL":
        _chat(a, iid, inc, pack)
    else:
        _handoff(a, iid, inc, pack)


def _explanation(a, iid, inc, pack):
    cached = S.explanations.get(iid)
    c = st.columns([1.6, 1.5, 1.2, 2.6], vertical_alignment="center")
    gen = c[0].button("Explain with local Qwen" if not cached else "Regenerate with Qwen", type="primary", key="ai_gen")
    tmpl = c[1].button("Deterministic template", key="ai_tmpl", help="Built only from the facts; verified by construction. "
                       "Labelled as a template, never as model output.")
    repair_on = c[2].toggle("Self-repair", value=S.cfg["slm"].get("self_repair", True), key="ai_repair",
                            help="Claims that fail verification are sent back to the model once with the verifier's errors.")
    c[3].caption("Qwen sees only the numbered facts below, never raw logs. Each sentence is checked against the facts it cites.")
    if gen:
        S.cfg["slm"]["self_repair"] = repair_on
        box = st.empty()
        buf = []

        def on_tok(t):
            buf.append(t)
            if len(buf) % 8 == 0:
                box.code("".join(buf)[-900:], language="json")
        with st.spinner("Local Qwen is reading the evidence (and repairing failed claims if needed)..."):
            state.explanation_for(iid, use_slm=True, on_token=on_tok, force=bool(cached))
        box.empty()
    if tmpl:
        state.explanation_for(iid, use_slm=False, force=True)
    from .live_demo import mark  # noqa: F401  (presentation-mode progress is derived from S.explanations)
    facts = {f["id"]: f for f in pack["facts"]}
    exp = S.explanations.get(iid)
    res, ver = (exp[0], exp[1]) if exp else (None, None)

    if res:
        stt = ver["stats"]
        src = SOURCE[res["source"]]
        rate = f"{stt['verification_rate']:.0%}" if stt["verification_rate"] is not None else "n/a"
        st.markdown(f'<div class="sn-mode"><b>{esc(src)}</b> &middot; {stt["verified"]} of {stt["factual_claims"]} statements '
                    f'verified against the original logs ({rate})'
                    + (f' &middot; {res["stats"]["wall_s"]} s' if res.get("stats", {}).get("wall_s") else "") + "</div>",
                    unsafe_allow_html=True)
        if res["source"] == "template" and res.get("error"):
            st.caption(f"Why the template is shown: {res['error']}")

    k1, k2 = st.columns(2, gap="medium")
    with k1:
        # What We Know: code-derived facts (+ the model's verified statements)
        html = ('<div class="sn-know k1"><h4>What we know</h4><div class="sub">Facts computed from the logs by code, with the '
                'records behind them. Model statements appear here only if they passed verification.</div>')
        for f in pack["facts"]:
            if f["kind"] in ("detection", "context", "scope") and "[weak link" not in f["text"]:
                html += f'<div class="sn-claim"><span class="sn-cite">{f["id"]}</span> {esc(f["text"])}</div>'
        if ver:
            okc = [c for c in ver["summary"] + ver["conclusions"] if c["status"] == "Verified"]
            if okc:
                html += '<div class="sub" style="margin-top:8px">Model summary (verified)</div>' + "".join(_claim_html(c) for c in okc)
        st.markdown(html + "</div>", unsafe_allow_html=True)
        # What Needs Checking
        html = ('<div class="sn-know k3"><h4>What needs checking</h4><div class="sub">Unverified statements, contradicting '
                'evidence and open questions.</div>')
        items = ""
        if ver:
            items += "".join(_claim_html(c) for c in ver["summary"] + ver["conclusions"] if c["status"] != "Verified")
            items += "".join(f'<div class="sn-claim"><span class="sn-muted">Question:</span> {esc(q)}</div>' for q in ver["questions"])
        items += "".join(f'<div class="sn-claim"><span class="sn-hyp">CONTRADICTS</span> <span class="sn-cite">{fid}</span> '
                         f'{esc(facts[fid]["text"])}</div>' for fid in pack["contradicting_fact_ids"])
        items += "".join(f'<div class="sn-claim"><span class="sn-muted">Missing evidence:</span> {esc(x)}</div>' for x in pack["limitations"][:3])
        st.markdown(html + (items or '<div class="sn-muted">Nothing open.</div>') + "</div>", unsafe_allow_html=True)
    with k2:
        # What Might Have Happened: hypotheses, never presented as fact
        html = ('<div class="sn-know k2"><h4>What might have happened</h4><div class="sub">Hypotheses, not confirmed findings. '
                'Each lists the facts that support or contradict it.</div>')
        if ver and ver["hypotheses"]:
            for h in ver["hypotheses"]:
                lab = '<span class="sn-hyp">HYPOTHESIS</span>' if h["status"] == "Grounded hypothesis" else '<span class="sn-bad">UNGROUNDED</span>'
                html += (f'<div class="sn-claim">{lab} {esc(h["text"])} <span class="sn-cite">supports [{esc(", ".join(h["supporting_fact_ids"]))}]'
                         + (f' · contradicts [{esc(", ".join(h["contradicting_fact_ids"]))}]' if h["contradicting_fact_ids"] else "")
                         + f'</span><div class="sn-muted">How to confirm: {esc(h["how_to_confirm"])}</div></div>')
        else:
            html += '<div class="sn-muted">Press “Explain with local Qwen” to get hypotheses grounded in these facts.</div>'
        st.markdown(html + "</div>", unsafe_allow_html=True)
        # Recommended Next Steps
        pb = load_playbooks()
        html = ('<div class="sn-know k4"><h4>Recommended next steps</h4><div class="sub">From SENTINEL\'s offline playbooks for '
                'the rules that fired. Analyst-approved actions; nothing runs automatically.</div>')
        acts = ver["actions"] if ver else []
        if acts:
            for x in acts:
                html += f'<div class="sn-claim"><b>{esc(pb[x["playbook_id"]]["title"])}</b><div class="sn-muted">{esc(x["adaptation"])}</div></div>'
        else:
            for p in pack["playbooks"]:
                html += f'<div class="sn-claim"><b>{esc(p["title"])}</b><div class="sn-muted">{esc(pb[p["id"]]["steps"][0])}</div></div>'
        st.markdown(html + "</div>", unsafe_allow_html=True)

    if res:
        with st.expander("Verification details"):
            stt = ver["stats"]
            rep = res.get("repair") or {}
            rows = [("Source", SOURCE[res["source"]]), ("Model", res.get("model") or "-"),
                    ("Verified statements", f'{stt["verified"]} of {stt["factual_claims"]}'),
                    ("Failed statements", stt["factual_claims"] - stt["verified"])]
            if res.get("stats", {}).get("tokens_per_s"):
                rows.append(("Latency", f'{res["stats"]["wall_s"]} s · {res["stats"]["tokens_per_s"]} tokens/s'))
            if rep.get("attempted"):
                rows.append(("Self-repair", f'{rep["initial_verified"]}/{rep["initial_claims"]} → {rep["final_verified"]}/{rep["final_claims"]} '
                                            f'verified after one round · still failing {rep["still_failing"]} · +{rep["latency_s"]} s'))
            elif rep:
                rows.append(("Self-repair", "not needed: every statement passed first time" if rep.get("initial_claims") else "no statements to check"))
            st.markdown("".join(f'<div class="sn-row"><span>{esc(k)}</span><span class="n">{esc(v)}</span></div>' for k, v in rows),
                        unsafe_allow_html=True)
            for x in ver["rejected_actions"]:
                st.markdown(f'<div class="sn-claim"><span class="sn-bad">REJECTED ACTION</span> {esc(x["playbook_id"])}: {esc(x["reason"])}</div>',
                            unsafe_allow_html=True)
            if rep.get("feedback"):
                st.markdown("**Verifier feedback sent to the model**")
                for line in rep["feedback"]:
                    st.markdown(f"- {line}")
            st.markdown("**Typed claims (as returned and checked)**")
            st.json({"summary": ver["summary"], "conclusions": ver["conclusions"]}, expanded=False)
            if res.get("initial_output"):
                st.markdown("**Initial (pre-repair) output**")
                st.json(res["initial_output"], expanded=False)


def _chat(a, iid, inc, pack):
    hist = S.chat.setdefault(iid, [])
    facts = {f["id"]: f for f in pack["facts"]}
    st.caption("Answers use only this incident's evidence and pass the same verifier. If local Qwen returns nothing "
               "verifiable, SENTINEL answers from the facts and says so - it never stays silent.")
    chosen = st.pills("Suggestions", PRESETS, key=f"ai_pill_{len(hist)}", label_visibility="collapsed")
    cq = st.columns([5, 1])
    free = cq[0].text_input("Question", key="ai_q", label_visibility="collapsed", placeholder="Ask about this incident")
    ask = cq[1].button("Ask", type="primary", use_container_width=True, key="ai_ask")
    question = (free.strip() if ask else "") or (chosen or "")
    if question:
        with st.spinner("Answering from the evidence..."):
            r = answer(pack, question, S.cfg, S.known_entities, [(x, json.dumps(y["output"])) for x, y in hist])
        hist.append((question, r))
        ws.audit(ws.connect(), ws.incident_key(a, inc), "chat question", question)
        st.rerun()
    for q, ans in hist[::-1]:
        src = {"slm": "local Qwen", "deterministic": "deterministic answer from the facts (model output was not verifiable)"}[ans["source"]]
        cited = []
        for c in ans["verification"]["summary"]:
            cited += [x for x in c["fact_ids"] if x in facts and x not in cited]
        html = (f'<div class="sn-card"><div class="sn-muted">You: {esc(q)}</div><h4 style="margin-top:8px">SENTINEL · {esc(src)}</h4>'
                + "".join(_claim_html(c) for c in ans["verification"]["summary"]))
        if ans["output"].get("cannot_answer"):
            html += f'<div class="sn-claim"><span class="sn-muted">Cannot answer from the evidence: {esc(ans["output"]["cannot_answer"])}</span></div>'
        if ans.get("note"):
            html += f'<div class="sn-claim"><span class="sn-muted">{esc(ans["note"])}</span></div>'
        if cited:
            html += '<div class="sn-muted" style="margin-top:6px">Sources: ' + " · ".join(
                f'<span class="sn-cite">{fid}</span> {esc(facts[fid]["text"][:90])}…' for fid in cited[:4]) + "</div>"
        if ans["source"] == "deterministic" and ans.get("error"):
            html += f'<div class="sn-muted">Why the fallback was used: {esc(ans["error"])}</div>'
        st.markdown(html + "</div>", unsafe_allow_html=True)
    if not hist:
        st.markdown('<div class="sn-card"><div class="sn-muted">Pick a suggestion or type a question. Answers cite the numbered '
                    'facts they rely on.</div></div>', unsafe_allow_html=True)


def _handoff(a, iid, inc, pack):
    con = ws.connect()
    key = ws.incident_key(a, inc)
    ver = S.explanations.get(iid, (None, None))[1]
    note = handoff_note(pack, inc, ws.current_status(con, key), ws.current_disposition(con, key), ws.notes(con, key),
                        ver["stats"] if ver else None)
    nv = verify_output({"summary": handoff_claims(note)}, pack, S.known_entities)
    ok = nv["stats"]["verified"]
    st.markdown(f'{tag(f"factual lines verified {ok}/{nv["stats"]["factual_claims"]}", "gold")} '
                '<span class="sn-muted">A note for the next analyst. Workflow lines (status, notes) come from the analyst workspace.</span>',
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
