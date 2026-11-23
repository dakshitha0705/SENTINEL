"""Threat Intelligence: threat hunting, MITRE ATT&CK explorer, detection rules and investigation pivots."""
from __future__ import annotations

import re

import pandas as pd
import streamlit as st

from ...hunting import HUNTS, custom, prepared
from ...playbooks import load_mitre, mitre_info
from ...rules import CONTEXT_RULES, RULES
from .. import esc, section, tag
from .. import state
from ..state import S

RULE_EXPLAIN = {
    "R1": "Many failed logons for one account from one source in a short window (dense brute force).",
    "R2": "One source failing against many accounts with few attempts each (password spraying).",
    "R3": "A successful logon by a targeted account from the same source after R1/R2/R12/R13 failures. Up to 15 min: "
          "full weight; up to 60 min: linked with decreasing weight. Never treated as proof of compromise.",
    "R4": "Logon hour unusual for this account's own history (context only; needs a confident baseline).",
    "R5": "Device or source IP never used by this account before (context only; labelled by baseline confidence).",
    "R6": "Account added to a privileged group by a non-administrator or outside an approved change window.",
    "R7": "Process command line matches a suspicious pattern (encoded PowerShell, Mimikatz, LSASS dump, certutil download...).",
    "R8": "Audit log cleared; scored higher when preceded by other suspicious activity on the same host/user.",
    "R9": "Account logs on to several hosts it never used before within 30 min (context only).",
    "R10": "Recursive copy / archive command writing to a removable drive or network share.",
    "R11": "External storage device recognised (context only).",
    "R12": "Failures spread over longer windows (8 in 60 min, 20 in 24 h) from a source that never logged on as the account.",
    "R13": "One source failing against 3-4 accounts with >= 80% failures and mostly unknown to those accounts (small spray).",
    "R14": "Enumeration of privileged groups (net group \"Domain Admins\", net localgroup administrators, 4799). Context only.",
    "CTX": "4672 special privileges at logon - informational context, never evidence of escalation.",
}


def _thresholds(rule, cfg):
    d = cfg["detection"]
    return {"R1": d["brute_force"], "R2": d["password_spray"], "R3": d["failure_then_success"],
            "R4": d["baseline"], "R5": d["baseline"], "R9": d.get("lateral_movement"),
            "R12": d.get("sustained_brute_force"), "R13": d.get("small_spray")}.get(rule)


def render():
    a = S.analysis
    t1, t2, t3 = st.tabs(["Custom & prepared hunts", "MITRE ATT&CK explorer", "Detection rules"])
    with t1:
        if a is None:
            st.info("Load a dataset to hunt.")
        else:
            st.markdown(section("Hunt across normalised events", "Pick a prepared hunt or write your own regular expression. "
                                "Results are raw events, independent of the detection rules."), unsafe_allow_html=True)
            c = st.columns([2, 2, 1.4])
            hunt = c[0].selectbox("Prepared hunt", ["(custom)"] + list(HUNTS), key="ti_hunt")
            field = c[1].selectbox("Field (custom)", ["command_line", "user", "host", "src_ip", "process", "group",
                                                      "event_code", "action"], key="ti_field")
            pattern = c[2].text_input("Regex (custom)", key="ti_rx")
            ev = a.events
            hits = pd.DataFrame()
            label = ""
            try:
                if hunt != "(custom)":
                    label = hunt
                    hits = prepared(ev, hunt)
                elif pattern:
                    label = f"{field} ~ /{pattern}/"
                    hits = custom(ev, field, pattern)
            except re.error as exc:
                st.error(f"Invalid regular expression: {exc}")
            if label:
                in_inc = {e: i["incident_id"] for i in a.incidents for e in i["event_ids"]}
                st.markdown(f"**{esc(label)}** &middot; {len(hits):,} event(s) &middot; "
                            f"{sum(1 for e in hits['event_id'] if e in in_inc) if len(hits) else 0} already in incidents",
                            unsafe_allow_html=True)
                if len(hits):
                    show = hits.drop(columns=["raw"]).head(1000).copy()
                    show.insert(1, "incident", show["event_id"].map(in_inc).fillna(""))
                    show["timestamp"] = show["timestamp"].astype(str)
                    st.dataframe(show, hide_index=True, use_container_width=True, height=330)
                    st.download_button("Export hunt results (CSV)", show.to_csv(index=False).encode("utf-8"),
                                       file_name="sentinel_hunt.csv", mime="text/csv")
                    st.markdown("**Pivots**")
                    pc = st.columns(3)
                    for k, (col, lab) in enumerate((("user", "accounts"), ("host", "hosts"), ("src_ip", "source IPs"))):
                        vc = hits[col][hits[col] != ""].value_counts().head(8)
                        pc[k].markdown(f"Top {lab}")
                        pc[k].dataframe(vc.rename("events").reset_index(), hide_index=True, use_container_width=True)
                    incs = sorted({in_inc[e] for e in hits["event_id"] if e in in_inc})
                    if incs:
                        pick = st.selectbox("Open related incident", incs, key="ti_inc")
                        if st.button("Investigate", key="ti_go"):
                            state.goto("Investigation Studio", pick, view="Story")
                            st.rerun()
    with t2:
        mitre = load_mitre()
        observed = {}
        if a:
            for i in a.incidents:
                for t in i["mitre"]:
                    observed.setdefault(t, []).append(i["incident_id"])
        rules_for = {}
        for r, (_, techs, _) in RULES.items():
            for t in techs:
                rules_for.setdefault(t, []).append(r)
        for p in S.cfg["detection"]["suspicious_processes"]:
            for t in p["mitre"]:
                rules_for.setdefault(t, [])
                if "R7" not in rules_for[t]:
                    rules_for[t].append("R7")
        rows = []
        for tid in sorted(mitre):
            m = mitre_info(tid)
            rows.append({"technique": tid, "name": m["name"], "tactics": ", ".join(m["tactics"]),
                         "SENTINEL rules": ", ".join(sorted(set(rules_for.get(tid, [])))) or "-",
                         "incidents in this dataset": ", ".join(observed.get(tid, [])) or "-"})
        df = pd.DataFrame(rows)
        tac = sorted({t for r in rows for t in r["tactics"].split(", ") if t})
        ft = st.multiselect("Tactic", tac, key="ti_tac")
        if ft:
            df = df[df["tactics"].apply(lambda s: any(t in s for t in ft))]
        st.dataframe(df, hide_index=True, use_container_width=True)
        pick = st.selectbox("Technique details", df["technique"].tolist(), key="ti_tech")
        if pick:
            m = mitre_info(pick)
            st.markdown(f"{tag(m['id'], 'gold')} **{esc(m['name'])}** &middot; {esc(', '.join(m['tactics']))}<br>"
                        f"<span class='sn-muted'>{esc(m['summary'])}</span><br><span class='sn-muted'>Reference (offline text): "
                        f"{esc(m['url'])}</span>", unsafe_allow_html=True)
        st.caption("Offline ATT&CK subset bundled in data/mitre.json; URLs are shown as text only.")
    with t3:
        cfg = S.cfg
        cov = a.coverage if a else {}
        rows = []
        for r, (name, techs, weight) in RULES.items():
            rows.append({"rule": r, "name": name, "MITRE": ", ".join(techs), "weight": weight,
                         "role": "context only" if r in CONTEXT_RULES else "detection",
                         "alerts (current dataset)": str(cov.get(r, {}).get("alerts", "-")) if r != "CTX" else "-",
                         "evaluated": str(cov.get(r, {}).get("evaluated", "-")) if r != "CTX" else "-"})
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        pick = st.selectbox("Rule", list(RULES), key="ti_rule", format_func=lambda r: f"{r} · {RULES[r][0]}")
        st.markdown(f'<div class="sn-card"><h4>{esc(pick)} &middot; {esc(RULES[pick][0])}</h4>{esc(RULE_EXPLAIN.get(pick, ""))}'
                    + (f'<div class="sn-muted" style="margin-top:6px">Requirement: {esc(cov[pick]["requirement"])}</div>'
                       if pick in cov else "") + "</div>", unsafe_allow_html=True)
        th = _thresholds(pick, cfg)
        if th:
            st.markdown("Current thresholds (edit them in System status → Open advanced panel):")
            st.json(th)
        if pick == "R7":
            st.dataframe(pd.DataFrame(cfg["detection"]["suspicious_processes"]), hide_index=True, use_container_width=True)
