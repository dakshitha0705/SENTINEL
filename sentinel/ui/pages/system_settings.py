"""System & Settings: offline monitor, model settings, detection configuration, data, audit, validation, credits."""
from __future__ import annotations

import copy
import json
import shutil

import pandas as pd
import streamlit as st

from ... import __version__
from ... import workspace as ws
from ...config import ConfigError, LOCAL_SETTINGS, ROOT, clear_local_settings, load_config, save_local_settings, validate_config
from ...perf import connection_snapshot, internet_reachable, system_info
from ...slm import explain, status as slm_status, unload
from .. import esc, kpi, section
from .. import state
from ..state import RESULTS, S


def _diff(base, new, path=()):
    out = {}
    for k, v in new.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            d = _diff(base[k], v, path + (k,))
            if d:
                out[k] = d
        elif base.get(k) != v:
            out[k] = v
    return out


def render():
    tabs = st.tabs(["Offline monitor", "Model", "Detection configuration", "Data & audit", "Offline validation",
                    "Credits & about"])
    cfg = S.cfg
    with tabs[0]:
        stat = slm_status(cfg)
        sysi = system_info()
        g = sysi.get("gpu") or {}
        model = next((m for m in stat["models"] if m["name"] == cfg["slm"]["model"]), None)
        loaded = next((m for m in stat["loaded"] if m["name"] == cfg["slm"]["model"]), None)
        place = ("not loaded" if not loaded else "CPU (0% in VRAM)" if not loaded["vram_gb"] else f"{loaded['gpu_share']:.0%} in GPU VRAM")
        k = st.columns(5)
        for c, (lab, v) in zip(k, [("Model", cfg["slm"]["model"]),
                                   ("Status", "loaded" if loaded else ("installed" if stat["model_installed"] else "unavailable")),
                                   ("Size", f"{model['size_gb']} GB {model['quant']}" if model else "-"), ("Placement", place),
                                   ("Runtime", f"Ollama {stat.get('version', '-')} @ 127.0.0.1")]):
            c.markdown(kpi(lab, v), unsafe_allow_html=True)
        k = st.columns(5)
        for c, (lab, v) in zip(k, [("CPU load", f"{sysi['cpu_percent']}% / {sysi['logical_cpus']} threads"),
                                   ("System RAM", f"{sysi['ram_used_percent']}% of {sysi['ram_total_gb']} GB"),
                                   ("SENTINEL RAM", f"{sysi['process_rss_mb']} MB"),
                                   ("GPU", f"{g.get('utilization_percent', '-')}% · {g.get('memory_used_mb', '-')}/{g.get('memory_total_mb', '-')} MB" if g else "not detected"),
                                   ("GPU name", g.get("name", "-"))]):
            c.markdown(kpi(lab, v), unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Remote connections of SENTINEL and Ollama right now**")
            snap = connection_snapshot()
            st.dataframe(pd.DataFrame(snap) if snap else pd.DataFrame([{"connections": "none"}]), hide_index=True,
                         use_container_width=True)
            ext = [x for x in snap if x["scope"] == "EXTERNAL"]
            st.markdown(f"External connections: **{len(ext)}** (loopback to the local model server is expected).")
            if st.button("Test internet reachability (one TCP probe to 1.1.1.1:53)"):
                S.net = internet_reachable()
            if "net" in S:
                st.markdown("Internet reachable: **" + ("YES - machine is online" if S.net else "NO - machine is offline") + "**")
        with c2:
            st.markdown("**Latest measured latency**")
            a = S.analysis
            if a:
                st.json({k: f"{v:.3f} s" for k, v in a.timings.items()})
            st.json(S.last_slm_stats or {"slm": "no call in this session yet"})
            if st.button("Measure local Qwen now (one incident, no cache)", disabled=not (a and a.incidents and stat["reachable"])):
                res = explain(a.packs[a.incidents[0]["incident_id"]], cfg, use_cache=False, known=S.known_entities)
                S.last_slm_stats = {**res.get("stats", {}), "source": res["source"], "model": res.get("model"),
                                    "repair": {k: v for k, v in (res.get("repair") or {}).items() if k not in ("feedback", "stats")}}
                st.rerun()
    with tabs[1]:
        stat = slm_status(cfg)
        names = [m["name"] for m in stat["models"]] or [cfg["slm"]["model"]]
        st.markdown(section("Local model settings", "Applied to this session immediately. 'Save as default' writes "
                            "workspace/settings.yaml (config.yaml is never modified)."), unsafe_allow_html=True)
        c = st.columns(3)
        mdl = c[0].selectbox("Model (installed in Ollama)", names, index=names.index(cfg["slm"]["model"]) if cfg["slm"]["model"] in names else 0)
        mode = c[1].radio("Inference", ["Auto (GPU if available)", "CPU only"],
                          index=1 if cfg["slm"].get("num_gpu") == 0 else 0, horizontal=True,
                          help="CPU only sets Ollama's num_gpu=0 (for limited-compute machines).")
        rep = c[2].toggle("Self-repair (one bounded round)", value=cfg["slm"].get("self_repair", True))
        c = st.columns(3)
        tmo = c[0].number_input("Timeout (s)", 10, 1200, int(cfg["slm"]["timeout_seconds"]))
        temp = c[1].number_input("Temperature", 0.0, 1.0, float(cfg["slm"]["temperature"]), step=0.05)
        topn = c[2].number_input("Auto-explain top N incidents", 0, 10, int(cfg["slm"]["auto_explain_top_n"]))
        new = copy.deepcopy(cfg)
        new["slm"].update(model=mdl, self_repair=rep, timeout_seconds=int(tmo), temperature=float(temp),
                          auto_explain_top_n=int(topn))
        if mode == "CPU only":
            new["slm"]["num_gpu"] = 0
        else:
            new["slm"].pop("num_gpu", None)
        b = st.columns(3)
        if b[0].button("Apply to session", type="primary"):
            if new["slm"].get("num_gpu") != cfg["slm"].get("num_gpu") or new["slm"]["model"] != cfg["slm"]["model"]:
                for m in slm_status(cfg).get("loaded", []):
                    unload(cfg, m["name"])     # reload with the new placement on next use
            S.cfg = new
            S.explanations = {}
            st.success(f"Session now uses {mdl} ({mode.lower()}); self-repair {'on' if rep else 'off'}.")
        if b[1].button("Save as default", key="save_model"):
            base = load_config()
            save_local_settings({"slm": _diff(base["slm"], new["slm"])})
            st.success(f"Saved to {LOCAL_SETTINGS.relative_to(ROOT)}")
        st.caption("Measured on this laptop (Evaluation & Benchmarks -> Local SLM): qwen2.5:3b about 6-10 s per incident on the "
                   "RTX 4060 and about 40-50 s on CPU only; qwen2.5:1.5b is faster but verified far fewer claims.")
    with tabs[2]:
        st.markdown(section("Detection configuration", "Thresholds are validated before use. Apply re-runs the "
                            "deterministic analysis on the current dataset."), unsafe_allow_html=True)
        d = copy.deepcopy(cfg["detection"])
        c = st.columns(4)
        d["brute_force"]["min_failures"] = c[0].number_input("R1 failures", 2, 100, d["brute_force"]["min_failures"])
        d["brute_force"]["window_minutes"] = c[0].number_input("R1 window (min)", 1, 240, d["brute_force"]["window_minutes"])
        d["password_spray"]["min_distinct_users"] = c[1].number_input("R2 accounts", 2, 100, d["password_spray"]["min_distinct_users"])
        d["password_spray"]["window_minutes"] = c[1].number_input("R2 window (min)", 1, 240, d["password_spray"]["window_minutes"])
        d["failure_then_success"]["max_minutes_after_burst"] = c[2].number_input("R3 max gap (min)", 1, 240, d["failure_then_success"]["max_minutes_after_burst"])
        d["failure_then_success"]["full_weight_minutes"] = c[2].number_input("R3 full-weight gap (min)", 1, 240, d["failure_then_success"].get("full_weight_minutes", 15))
        w = d.get("sustained_brute_force", {}).get("windows", [])
        if w:
            w[0]["min_failures"] = c[3].number_input(f"R12 failures / {w[0]['window_minutes']} min", 2, 500, w[0]["min_failures"])
        if len(w) > 1:
            w[1]["min_failures"] = c[3].number_input(f"R12 failures / {w[1]['window_minutes']} min", 2, 5000, w[1]["min_failures"])
        c = st.columns(4)
        if "small_spray" in d:
            d["small_spray"]["min_distinct_users"] = c[0].number_input("R13 accounts", 2, 50, d["small_spray"]["min_distinct_users"])
            d["small_spray"]["min_failure_ratio"] = c[0].number_input("R13 failure ratio", 0.1, 1.0, float(d["small_spray"]["min_failure_ratio"]), step=0.05)
        d["baseline"]["min_logins"] = c[1].number_input("Baseline min logons", 1, 200, d["baseline"]["min_logins"])
        d["baseline"]["min_days"] = c[1].number_input("Baseline min days", 1, 60, d["baseline"]["min_days"])
        corr = copy.deepcopy(cfg["correlation"])
        corr["max_gap_minutes"] = c[2].number_input("Correlation gap (min)", 1, 600, corr["max_gap_minutes"])
        corr["max_span_hours"] = c[2].number_input("Incident span (h)", 1, 72, corr["max_span_hours"])
        lv = copy.deepcopy(cfg["severity"]["levels"])
        lv["critical"] = c[3].number_input("Critical >=", 1, 100, lv["critical"])
        lv["high"] = c[3].number_input("High >=", 1, 100, lv["high"])
        lv["medium"] = c[3].number_input("Medium >=", 1, 100, lv["medium"])
        admins = st.text_input("Authorised administrators (comma-separated)", ", ".join(cfg["allowlists"]["authorized_admins"]))
        crit = st.text_input("Critical assets", ", ".join(cfg["assets"]["critical"]))
        new = copy.deepcopy(cfg)
        new["detection"], new["correlation"] = d, corr
        new["severity"]["levels"] = lv
        new["allowlists"]["authorized_admins"] = [x.strip() for x in admins.split(",") if x.strip()]
        new["assets"]["critical"] = [x.strip() for x in crit.split(",") if x.strip()]
        try:
            validate_config(new)
            valid = True
        except ConfigError as exc:
            st.error(f"Invalid configuration: {exc}")
            valid = False
        b = st.columns(4)
        if b[0].button("Apply & re-run analysis", type="primary", disabled=not valid):
            S.cfg = new
            if S.files:
                state.run_analysis()
            st.success("Applied to this session and re-analysed.")
        if b[1].button("Save as default", disabled=not valid, key="save_det"):
            base = load_config()
            save_local_settings(_diff(base, {k: new[k] for k in ("detection", "correlation", "severity", "allowlists", "assets")}))
            st.success(f"Saved to {LOCAL_SETTINGS.relative_to(ROOT)} (reported metrics always use config.yaml).")
        if b[2].button("Reset to config.yaml"):
            clear_local_settings()
            S.cfg = load_config()
            if S.files:
                state.run_analysis()
            st.success("Defaults restored.")
        if LOCAL_SETTINGS.exists():
            st.caption("Saved overrides in workspace/settings.yaml:")
            st.code(LOCAL_SETTINGS.read_text(encoding="utf-8"), language="yaml")
    with tabs[3]:
        con = ws.connect()
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Session**")
            if st.button("Clear loaded files and analysis"):
                S.files, S.mappings, S.analysis, S.dataset = {}, {}, None, None
                S.explanations, S.chat = {}, {}
                st.rerun()
            cache = ROOT / S.cfg["slm"]["cache_dir"]
            n = len(list(cache.glob("*.json"))) if cache.exists() else 0
            st.markdown(f"**SLM explanation cache**: {n} file(s) in {esc(S.cfg['slm']['cache_dir'])}")
            ok = st.checkbox("I understand cached explanations will be deleted", key="cc_ok")
            if st.button("Delete SLM cache", disabled=not (ok and n)):
                shutil.rmtree(cache, ignore_errors=True)
                st.success("Cache cleared.")
        with c2:
            st.markdown("**Suppression proposals** (narrow, reviewed, tag-only, revocable)")
            a = S.analysis
            if a and a.incidents:
                inc = a.incident(state.selected_incident(a))
                rule = st.selectbox("Rule", sorted({a.alerts_by_id[x]["rule"] for x in inc["alert_ids"]}), key="sp_rule")
                fld = st.selectbox("Match field", ["user", "host", "ip"], key="sp_fld")
                opts = {"user": inc["users"], "host": inc["hosts"], "ip": inc["ips"]}[fld]
                val = st.selectbox("Exact value", opts, key="sp_val") if opts else None
                reason = st.text_input("Justification", key="sp_reason")
                if st.button("Propose suppression", disabled=not (val and reason)):
                    ws.propose_suppression(con, rule, {fld: val}, reason)
                    st.rerun()
            for s in ws.suppressions(con):
                st.markdown(f"**SUP-{s['id']}** · {s['rule']} · `{s['match']}` · *{s['status']}* · {esc(s['reason'])}")
                bb = st.columns(3)
                if s["status"] == "proposed":
                    if bb[0].button("Approve", key=f"ap{s['id']}"):
                        ws.decide_suppression(con, s["id"], "approved")
                        st.rerun()
                    if bb[1].button("Reject", key=f"rj{s['id']}"):
                        ws.decide_suppression(con, s["id"], "rejected")
                        st.rerun()
                elif s["status"] == "approved" and bb[0].button("Revoke", key=f"rv{s['id']}"):
                    ws.decide_suppression(con, s["id"], "revoked")
                    st.rerun()
        st.markdown("**Audit trail** (append-only, workspace/analyst.db)")
        st.dataframe(pd.DataFrame(ws.history(con)) if ws.history(con) else pd.DataFrame([{"audit": "empty"}]),
                     hide_index=True, use_container_width=True)
    with tabs[4]:
        runs = sorted((RESULTS / "offline_runs").glob("*.json")) if (RESULTS / "offline_runs").exists() else []
        rows = []
        for p in runs:
            r = json.loads(p.read_text(encoding="utf-8"))
            rows.append({"file": p.name, "recorded": r.get("recorded_at"), "type": r.get("test_type"),
                         "internet reachable": r.get("internet_reachable"),
                         "external connections": len(r.get("monitor", {}).get("external_connections", [])),
                         "loopback connections": len(r.get("monitor", {}).get("loopback_connections", [])),
                         "total s": r.get("total_seconds"),
                         "SLM runs": len(r.get("steps", {}).get("slm", [])),
                         "peak SENTINEL MB": r.get("monitor", {}).get("peak_sentinel_rss_mb")})
        st.markdown(section("Recorded offline runs", "Written by scripts/offline_check.py. 'offline test' only when the "
                            "internet was unreachable before and after the run."), unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(rows) if rows else pd.DataFrame([{"runs": "none"}]), hide_index=True, use_container_width=True)
        ui = RESULTS / "offline_ui_check.json"
        if ui.exists():
            st.markdown("**Offline UI check** (browser automation, external requests blocked and counted)")
            st.json(json.loads(ui.read_text(encoding="utf-8")).get("summary", {}))
    with tabs[5]:
        st.markdown(f"""
<div class="sn-card"><h4>SENTINEL v{__version__}</h4>
Offline Security Incident Triage Assistant &middot; Tinyverse Hackathon Phase 2, Problem Statement 02.<br>
Deterministic code establishes facts, the local model interprets them, the verifier checks every factual claim.
</div>
<div class="sn-card"><h4>Third-party components (bundled, offline)</h4>
<b>globe.gl</b> 2.46.2 and <b>three.js</b> (MIT) &middot; <b>vis-network</b> 9.1.9 (Apache-2.0 / MIT) &middot;
<b>Natural Earth</b> 1:110m country outlines (public domain) &middot; Streamlit, pandas, Altair/Vega-Lite, scikit-learn,
Jinja2, PyYAML, psutil, evtx (MIT/Apache-2.0) &middot; <b>Qwen2.5</b> 3B/1.5B/7B Instruct via Ollama (Qwen licence /
Apache-2.0) &middot; Material Symbols (Apache-2.0, shipped with Streamlit).</div>
<div class="sn-card"><h4>Datasets</h4>
Synthetic logs from SENTINEL's own generator (with ground truth). External evaluation recordings, not redistributed:
<b>EVTX-ATTACK-SAMPLES</b> by Samir Bousseaden (GPL-3.0) and <b>OTRF Security-Datasets</b> (MIT).
Offline MITRE ATT&amp;CK descriptions summarised from attack.mitre.org.</div>
<div class="sn-card"><h4>AI assistance</h4>Built with the help of Claude Code (Anthropic). See docs/credits.md.</div>
""", unsafe_allow_html=True)
