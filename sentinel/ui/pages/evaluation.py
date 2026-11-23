"""Evaluation & Benchmark Lab: every number is read from a results/*.json file written by a script."""
from __future__ import annotations

import json
import subprocess
import sys

import altair as alt
import pandas as pd
import streamlit as st

from ...config import ROOT
from ...metrics import evaluate, load_ground_truth
from .. import esc, kpi, section
from ..state import RESULTS, SAMPLES, S

AX = dict(gridColor="#22312E", labelColor="#A9B6AE", titleColor="#A9B6AE", domainColor="#2A3A37")


def _load(name):
    p = RESULTS / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def _run(script, label, secs):
    with st.spinner(f"Running {label} (about {secs} s, deterministic, no SLM)..."):
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / script)], capture_output=True, text=True, cwd=ROOT)
    st.code((out.stdout or "")[-2500:] + (out.stderr or "")[-1500:])


def _agg_row(label, agg):
    return {"set": label, "P": agg["incident_precision"], "R": agg["incident_recall"], "F1": agg["f1"],
            "FPR": agg["false_positive_rate"], "Jaccard": agg["correlation_jaccard_mean"],
            "severity agreement": agg["severity_agreement"],
            "attacks / look-alikes": f"{agg['gt_incidents']} / {agg['benign_lookalikes']}"}


def _chart(df, x, y, color=None, height=220):
    enc = dict(x=alt.X(f"{x}:Q", title=x), y=alt.Y(f"{y}:N", sort=None, title=None))
    mark = alt.Chart(df).mark_bar(cornerRadius=4) if color else alt.Chart(df).mark_bar(cornerRadius=4, color="#C8AA7C")
    ch = mark.encode(**enc,
        **({"color": alt.Color(f"{color}:N", scale=alt.Scale(range=["#C8AA7C", "#819B8D", "#B98780", "#A7BFAF", "#7F9495"]),
                               legend=alt.Legend(orient="bottom", labelColor="#A9B6AE", titleColor="#A9B6AE"))} if color else {}),
        tooltip=list(df.columns))
    return ch.properties(height=height).configure_view(strokeWidth=0).configure_axis(**AX)


def render():
    m = _load("metrics.json")
    st.markdown(section("Evaluation & benchmark lab", "Every value on this page is read from a results file produced by a "
                        "script in scripts/. Synthetic results use generator ground truth; external recordings only "
                        "support scenario-level detection."), unsafe_allow_html=True)
    tabs = st.tabs(["Accuracy", "Scenarios & errors", "Naive & ablation", "External recordings", "Local SLM",
                    "Scale & performance"])
    with tabs[0]:
        b = st.columns([1.3, 4])
        if b[0].button("Re-run evaluation", help="python scripts/evaluate.py"):
            _run("evaluate.py", "the synthetic evaluation", 40)
            m = _load("metrics.json")
        if not m:
            st.warning("No results yet: run python scripts/evaluate.py")
        else:
            st.caption(f"results/metrics.json · generated {m['generated_at']} · {m['matching_rule']}")
            rows = [_agg_row("Held-out test seeds 101/202/303", m["test_aggregate"]),
                    _agg_row("Fresh held-out seeds 5001-5010 (after the upgrade freeze)", m["fresh_aggregate"]),
                    _agg_row("Stress seeds 1001-1010 (diagnostic since the upgrade)", m["stress_aggregate"])]
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
            fa = m["fresh_aggregate"]
            k = st.columns(6)
            for c, (lab, v) in zip(k, [("Fresh precision", fa["incident_precision"]), ("Fresh recall", fa["incident_recall"]),
                                       ("Fresh F1", fa["f1"]), ("Fresh FPR", fa["false_positive_rate"]),
                                       ("Fresh Jaccard", fa["correlation_jaccard_mean"]),
                                       ("Severity agreement", fa["severity_agreement"])]):
                c.markdown(kpi(lab, v), unsafe_allow_html=True)
            before = _load("before_upgrade_detector.json")
            if before:
                st.markdown("**Before vs after the detection upgrade** (same datasets; *before* = detector at tag "
                            "checkpoint-pre-upgrade)")
                ba = []
                for grp, aft in (("test", m["test_aggregate"]), ("stress", m["stress_aggregate"]), ("fresh", m["fresh_aggregate"])):
                    bb = before[grp]["aggregate"]
                    for key, lab in (("incident_precision", "P"), ("incident_recall", "R"), ("f1", "F1"),
                                     ("false_positive_rate", "FPR"), ("correlation_jaccard_mean", "Jaccard"),
                                     ("severity_agreement", "severity agreement")):
                        ba.append({"set": grp, "metric": lab, "before": bb[key], "after": aft[key],
                                   "change": round((aft[key] or 0) - (bb[key] or 0), 3)})
                st.dataframe(pd.DataFrame(ba).pivot(index="metric", columns="set", values=["before", "after"]),
                             use_container_width=True)
            st.caption("Dataset roles: " + "; ".join(f"{k}: {v}" for k, v in m["dataset_roles"].items()))
            cm = [[0, 0], [0, 0]]
            for x in m["fresh"]:
                for i in range(2):
                    for j in range(2):
                        cm[i][j] += x["event_confusion"]["matrix"][i][j]
            cmd = pd.DataFrame([{"actual": a_, "predicted": p_, "events": cm[i][j]}
                                for i, a_ in enumerate(["benign", "malicious"])
                                for j, p_ in enumerate(["not in incident", "in incident"])])
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Event-level confusion matrix (fresh seeds)**")
                ch = alt.Chart(cmd).mark_rect(cornerRadius=6).encode(x=alt.X("predicted:N", title=None), y=alt.Y("actual:N", title=None),
                    color=alt.Color("events:Q", scale=alt.Scale(range=["#1C2B29", "#819B8D"], type="log"), legend=None))
                txt = alt.Chart(cmd).mark_text(fontSize=15, color="#E8DDC9").encode(x="predicted:N", y="actual:N", text="events:Q")
                st.altair_chart((ch + txt).properties(height=200).configure_view(strokeWidth=0).configure_axis(**AX),
                                use_container_width=True)
            with c2:
                st.markdown("**Severity: expected vs detected (fresh seeds)**")
                pairs = pd.DataFrame(fa["severity_pairs"], columns=["expected", "detected"])
                st.dataframe(pd.crosstab(pairs["expected"], pairs["detected"]), use_container_width=True)
            a = S.analysis
            if a and S.dataset and (SAMPLES / S.dataset / "ground_truth.json").exists():
                st.markdown(f"**Live check: current analysis vs ground truth ({esc(S.dataset)})**")
                r = evaluate(a, load_ground_truth(SAMPLES / S.dataset))
                st.json({k: r[k] for k in ("incident_precision", "incident_recall", "f1", "false_positive_rate",
                                           "correlation_jaccard_mean", "severity_agreement", "missed_incidents", "flagged_benign")})
    with tabs[1]:
        if m:
            st.markdown("**Per-scenario correlation quality (Jaccard of event sets, matched incidents only)**")
            grp = st.radio("Seeds", ["fresh", "test", "stress"], horizontal=True, key="ev_grp")
            pj = m["per_scenario_jaccard"][grp]
            rows = [{"scenario": sid, "name": v["name"], "matched": v["matched"], "missed": v["missed"],
                     "mean Jaccard": v["mean_jaccard"], "min Jaccard": v["min_jaccard"]} for sid, v in pj.items()]
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
            runs = [{"scenario": sid, **r} for sid, v in pj.items() for r in v["runs"]]
            with st.expander("Every run (None = scenario missed)"):
                st.dataframe(pd.DataFrame(runs), hide_index=True, use_container_width=True)
            sets = m[grp]
            miss = [{"dataset": x["dataset"], **y} for x in sets for y in x["missed_incidents"]]
            fps = [{"dataset": x["dataset"], "incident": y["incident_id"], "level": y["level"], "title": y["title"],
                    "overlaps benign": ", ".join(y["benign_overlap"])} for x in sets for y in x["false_positive_incidents"]]
            flagged = [{"dataset": x["dataset"], "benign look-alike": b} for x in sets for b in x["flagged_benign"]]
            c1, c2, c3 = st.columns(3)
            c1.markdown("**Missed attacks**")
            c1.dataframe(pd.DataFrame(miss) if miss else pd.DataFrame([{"result": "none"}]), hide_index=True, use_container_width=True)
            c2.markdown("**Detections matching no attack**")
            c2.dataframe(pd.DataFrame(fps) if fps else pd.DataFrame([{"result": "none"}]), hide_index=True, use_container_width=True)
            c3.markdown("**Benign look-alikes flagged**")
            c3.dataframe(pd.DataFrame(flagged) if flagged else pd.DataFrame([{"result": "none"}]), hide_index=True,
                         use_container_width=True)
            st.markdown("**Per-rule alert precision (fresh seeds, event level)**")
            pr = []
            for rule in m["fresh"][0]["per_rule"]:
                fl = sum(x["per_rule"][rule]["flagged_events"] for x in m["fresh"])
                tp = sum(x["per_rule"][rule]["malicious_events"] for x in m["fresh"])
                al = sum(x["per_rule"][rule]["alerts"] for x in m["fresh"])
                pr.append({"rule": rule, "alerts": al, "flagged events": fl, "malicious share": round(tp / fl, 3) if fl else None})
            st.dataframe(pd.DataFrame(pr), hide_index=True, use_container_width=True)
    with tabs[2]:
        if m:
            comp = m["comparison"]
            st.caption(f"Identical held-out data for every variant: {', '.join(comp['datasets'])}. Strict = SENTINEL's "
                       ">=50%-of-events match; lenient = any overlap (fair to a detector without correlation).")
            rows = []
            for k in ("full", "no_baselines", "no_context", "no_allowlists", "naive"):
                v = comp[k]
                rows.append({"variant": k, "what is disabled": v["description"], "items to review": v["items_to_review"],
                             "strict P": v["strict"]["precision"], "strict R": v["strict"]["recall"], "strict F1": v["strict"]["f1"],
                             "lenient P": v["lenient"]["precision"], "lenient R": v["lenient"]["recall"],
                             "lenient F1": v["lenient"]["f1"], "FPR": v["false_positive_rate"],
                             "Jaccard": v["correlation_jaccard_mean"], "raw alerts": v["alerts"]})
            df = pd.DataFrame(rows)
            st.dataframe(df, hide_index=True, use_container_width=True)
            c1, c2 = st.columns(2)
            long = df.melt(id_vars="variant", value_vars=["strict F1", "lenient F1"], var_name="metric", value_name="F1")
            c1.markdown("**F1 by variant**")
            c1.altair_chart(_chart(long, "F1", "variant", "metric"), use_container_width=True)
            c2.markdown("**Items an analyst must review**")
            c2.altair_chart(_chart(df[["variant", "items to review"]], "items to review", "variant"), use_container_width=True)
            cp = m["compression"]
            st.markdown(f"**Alert compression** (held-out seeds): {cp['alerts']:,} raw alerts &rarr; {cp['incidents']} incidents "
                        f"= **{cp['compression_pct']}%** fewer items. {esc(cp['note'])}.", unsafe_allow_html=True)
            st.dataframe(pd.DataFrame([{"dataset": d, **c} for d, c in zip(cp["datasets"], cp["per_dataset"])]),
                         hide_index=True, use_container_width=True)
    with tabs[3]:
        b = st.columns([1.3, 4])
        if b[0].button("Re-run external evaluation", help="python scripts/external_eval.py (needs the downloaded recordings)"):
            _run("external_eval.py", "the external evaluation", 20)
        x = _load("external_eval.json")
        if not x:
            st.warning("No external results: run python -I scripts/get_external_data.py (online, once) then scripts/external_eval.py")
        else:
            s = x["summary"]
            st.caption(f"results/external_eval.json · {x['generated_at']} · {x['method']}")
            k = st.columns(4)
            for c, (lab, v) in zip(k, [("Recordings", s["recordings"]), ("With an expected rule", s["with_expected_rule"]),
                                       ("Detected", s["detected"]), ("Missed", s["missed"])]):
                c.markdown(kpi(lab, v), unsafe_allow_html=True)
            st.dataframe(pd.DataFrame([{"id": r["id"], "source": x["sources"][r["source"]]["name"], "technique": r["technique"],
                                        "behaviour": r["behaviour"], "events": r.get("events"), "expected": ", ".join(r["expected_rules"]),
                                        "fired": ", ".join(f"{k}x{v}" for k, v in (r.get("rules_fired") or {}).items()),
                                        "result": r["status"], "why missed": r.get("why_missed", "")}
                                       for r in x["recordings"]]), hide_index=True, use_container_width=True)
            st.caption("Sources: " + "; ".join(f"{v['name']} ({v['license']}, {v['url']})" for v in x["sources"].values())
                       + ". Raw recordings are not redistributed in this repository.")
    with tabs[4]:
        files = sorted(RESULTS.glob("slm_benchmark_*.json"))
        rows = []
        for p in files:
            s = json.loads(p.read_text(encoding="utf-8"))["summary"]
            rep = s.get("repair") or {}
            rows.append({"file": p.name, "model": s.get("model"), "mode": ", ".join(s.get("inference_mode") or ["GPU (not recorded)"]),
                         "prompt": s.get("prompt_version", "v6"), "self-repair": s.get("self_repair", False),
                         "incidents": s["incidents"], "fallbacks": s["fallbacks"],
                         "verified / claims": f"{s['verified']}/{s['factual_claims']}", "rate": s["verification_rate"],
                         "initial rate": rep.get("initial_rate"), "after repair": rep.get("final_rate"),
                         "repair extra s": rep.get("mean_extra_latency_s"),
                         "mean latency s": s["mean_wall_s"], "tokens/s": s["mean_tokens_per_s"],
                         "Ollama CPU % (machine)": (s.get("resources") or {}).get("ollama_cpu_pct_of_machine_mean_busy"),
                         "recorded": s.get("recorded_at", "")})
        if rows:
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
            st.caption("CPU mode = Ollama option num_gpu=0, confirmed by /api/ps reporting 0 bytes in VRAM while the model "
                       "was loaded. GPU inference is not bit-deterministic, so verification rates vary run to run. "
                       "Files without a prompt version are earlier (v6) runs, kept for history.")
        ch = _load("chat_benchmark.json")
        if ch:
            st.markdown("**Incident chat**")
            st.json(ch["summary"])
    with tabs[5]:
        b = st.columns([1.3, 4])
        if b[0].button("Re-run scale benchmark", help="python scripts/scale_benchmark.py (~30 s)"):
            _run("scale_benchmark.py", "the 100k-event benchmark", 30)
        sc = _load("scale_benchmark.json")
        if sc:
            st.caption(f"results/scale_benchmark.json · {sc['recorded_at']} · {sc['method']} · {sc['hardware']['cpu']}, "
                       f"{sc['hardware']['logical_cpus']} threads, {sc['hardware']['ram_gb']} GB RAM, Python {sc['hardware']['python']}")
            k = st.columns(5)
            for c, (lab, v) in zip(k, [("Events", f"{sc['events']:,}"), ("End-to-end", f"{sc['timings_s']['end_to_end_s']} s"),
                                       ("Throughput", f"{sc['throughput_events_per_s']['end_to_end']:,}/s"),
                                       ("Peak RAM", f"{sc['peak_rss_mb']} MB"), ("Alerts -> incidents", f"{sc['alerts']} -> {sc['incidents']}")]):
                c.markdown(kpi(lab, v), unsafe_allow_html=True)
            stages = pd.DataFrame([{"stage": k.replace("_s", ""), "seconds": v} for k, v in sc["timings_s"].items()
                                   if k in ("parse_s", "normalise_s", "detection_s", "correlation_s", "severity_s", "evidence_s")])
            st.altair_chart(_chart(stages, "seconds", "stage"), use_container_width=True)
        off = _load("offline_run.json")
        if off:
            st.markdown(f"**Latest offline run** ({off['recorded_at']}, {off['test_type']}): "
                        f"{len(off['monitor']['external_connections'])} external connections, total {off['total_seconds']} s. "
                        "Full history in System & Settings.")
