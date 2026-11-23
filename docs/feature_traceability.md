# Feature traceability: frontend → backend → data → test

Every visible control in the dashboard is listed with the code that implements it, the data it uses and the test that exercises it. A feature counts as **Implemented and tested** only when its full data path ran in a test: a pytest test (`tests/`), the browser check `scripts/ui_check.py` (real clicks in Edge with every non-local request blocked; result in `results/offline_ui_check.json`), or a benchmark script.

Status values: **Implemented and tested** · **Implemented with limitations** · **Not implemented**.

## Command Center

| Feature | Frontend | Backend | Data source | Test | Status |
|---|---|---|---|---|---|
| Interactive 3D globe (drag rotate, wheel zoom, reset, auto-rotate toggle) | `ui/pages/command_center.py`, `ui/static/viz/index.html` (globe.gl + three.js, local) | `ui/components.py` (bidirectional Streamlit component) | Natural Earth 110m outlines (local file) | `ui_check.py`: drag changes the point of view, wheel zooms in and out, reset returns to 16°N 96°E alt 1.8 | Implemented and tested |
| Geographic intelligence mode (markers) | same | `geospatial.markers()` | `src_lat/src_lon` and `dst_lat/dst_lon` columns from the logs (column mapper) | `test_globe_markers_only_from_logged_coordinates` (invalid coordinates dropped, nothing invented) | Implemented and tested |
| Exploration mode when logs have no coordinates | same | `geospatial.markers()` → `mode="explore"` | – | `test_globe_explore_mode_without_location_fields` | Implemented and tested |
| Marker click → records panel → open incident | same | `geospatial.marker_records()` | normalised events | `ui_check.py` clicks a visible marker and finds the records panel | Implemented and tested |
| Country (region) click → records of markers inside it | same | point-in-polygon in the component, records via `marker_records()` | Natural Earth polygons + markers | Exercised manually; point-in-polygon logic not unit-tested | Implemented with limitations |
| Connections toggle (arcs) | same | arcs from `geospatial.markers()` | one arc = logged events of one incident whose source and device locations differ | `test_globe_markers…` + `ui_check.py` (3 arcs on the demo) | Implemented and tested |
| Offline geolocation database for IPs | – | – | – | – | **Not implemented** (deliberately: no IP is placed on the map unless the log itself carries coordinates) |
| KPI cards (events, incidents, users, hosts) | `command_center.py` | `state.visible_incidents()` | analysis | `test_page_renders[Command Center]` | Implemented and tested |
| Severity / top detections / urgent summary | same | analysis incidents and rules | analysis | `test_page_renders` | Implemented and tested |
| Executive summary ("N critical incidents require investigation") | same | computed from incidents; cites the scope fact ID | evidence packs | `test_page_renders` | Implemented and tested |
| Run Analysis action (with local Qwen for the top N) | same | `state.run_analysis(auto_explain=True)` | loaded files | `test_first_visit_loads_demo_dataset`; SLM path via `offline_check.py` | Implemented and tested |
| Explore Incidents / Generate Report / Ask SENTINEL actions | same | `state.goto()` with the selected incident | session state | `test_incident_navigation_preserves_selection` | Implemented and tested |

## Global top bar

| Feature | Frontend | Backend | Data source | Test | Status |
|---|---|---|---|---|---|
| Global search | `app.py` | `search.search()` | incidents, alerts, events | `test_global_search`, `test_global_search_finds_incident` | Implemented and tested |
| Dataset selector (synthetic, demo, external recordings) | `app.py` | `state.load_dataset()` (+ saved mapping profile) | `data/samples/*`, `data/public/*` | `test_dataset_switch_changes_analysis` | Implemented and tested |
| Time range | `app.py` | `state.time_window()` / `visible_incidents()` | analysis | `test_time_range_filters_incidents` | Implemented and tested |
| Offline / Qwen / CPU-GPU status chips | `app.py` | `perf.connection_snapshot()`, `slm.status()` | live process connections, Ollama `/api/ps` | `test_page_renders` | Implemented and tested |

## Log Intelligence

| Feature | Frontend | Backend | Data source | Test | Status |
|---|---|---|---|---|---|
| CSV / JSON / JSON-lines upload | `ui/pages/log_intelligence.py` | `ingest.ingest()` | uploaded bytes | `tests/test_ingest.py` (11 tests) | Implemented and tested |
| EVTX conversion (offline) with diagnostics and JSONL download | same | `evtx_converter.convert_evtx()` (`evtx` package) | `.evtx` files | `test_evtx_kerberos_spray_detected`, `test_evtx_rejects_non_evtx_with_diagnostic`, `external_eval.py` (13 EVTX files) | Implemented and tested |
| Column mapping (18 fields incl. optional geo) | same | `guess_mapping()` / `normalize()` | file columns | `test_ingest.py`, demo mapping profile test | Implemented and tested |
| Schema validation warnings (no timestamp, group events without actor/member, nothing analysable) | same | `normalize()` output | – | `test_page_renders[Log Intelligence]` | Implemented and tested |
| Save mapping profile | same | writes `data/samples/<ds>/mapping_profile.json` | mappings | Exercised manually; profile loading tested by `test_first_visit_loads_demo_dataset` | Implemented with limitations |
| Event explorer: text and field filters, sort, pagination, original record | same | pandas filtering | normalised events | `test_page_renders` | Implemented and tested |
| Duplicates, rejected records, SHA-256, rule coverage | same | `Dataset` | ingestion | `test_ingest.py` | Implemented and tested |
| Export normalised events (CSV, JSONL) and mappings | same | pandas | normalised events | `test_page_renders` (download built) | Implemented and tested |

## Incident Investigation

| Feature | Frontend | Backend | Data source | Test | Status |
|---|---|---|---|---|---|
| Queue with severity / status / text filters and sorting | `ui/pages/incidents.py` | `workspace.current_status()` | analysis + `workspace/analyst.db` | `test_page_renders` | Implemented and tested |
| Attack Storyline Engine with link reasons | same | `correlate.correlate()`, `storyline()` | alerts | `tests/test_correlate_severity.py`, `test_r3_delayed_success_links_with_reduced_weight` | Implemented and tested |
| Evidence pack, events behind each fact, original records, contradicting evidence | same | `evidence.build_evidence_pack()` | events | `tests/test_evidence_verifier.py` | Implemented and tested |
| Severity breakdown | same | `severity.score_incident()` | alerts | `tests/test_correlate_severity.py` | Implemented and tested |
| MITRE mapping + playbooks | same | `playbooks.py` | `data/mitre.json`, `data/playbooks.json` | `test_page_renders` | Implemented and tested |
| Status, disposition, notes, audit history (persisted) | same | `workspace.py` (SQLite) | `workspace/analyst.db` | `test_workspace_status_notes_dispositions_and_suppressions` | Implemented and tested |
| Incident JSON / CSV / evidence CSV export | same | `exports.py` | analysis | `test_exports_json_and_csv` | Implemented and tested |

## Attack Graph

| Feature | Frontend | Backend | Data source | Test | Status |
|---|---|---|---|---|---|
| Interactive graph (zoom, pan, hover, select) | `ui/pages/attack_graph.py`, vis-network (local) | `graph.build()` | correlation output only | `test_graph_edges_come_from_correlation`; `ui_check.py` wheel zoom | Implemented and tested |
| Filters (incidents, severity, entity types, context alerts) | same | `graph.build()` arguments | – | `test_page_renders` | Implemented and tested |
| Node click → evidence inspector → open incident | same | `graph.node_details()` | analysis | `ui_check.py` clicks an incident node and finds "Open investigation" | Implemented and tested |

## AI Investigation Lab

| Feature | Frontend | Backend | Data source | Test | Status |
|---|---|---|---|---|---|
| Local Qwen explanation (streamed) | `ui/pages/ai_lab.py` | `slm.explain()` | evidence pack | `slm_benchmark.py`, `offline_check.py` | Implemented and tested |
| Typed factual claims (count, times, user, host, IP, event IDs) | same | `OUTPUT_SCHEMA` v7, `verifier.verify_claim()` | evidence pack | `test_typed_claim_fields_are_verified` | Implemented and tested |
| Bounded self-repair (one round, verifier feedback, never overrides verifier) | same | `slm.explain(..., repair=True)` | verifier output | `test_self_repair_round_fixes_or_rejects`; measured in `slm_benchmark_test_qwen2.5-3b.json` | Implemented and tested |
| Verified facts / hypotheses / contradicting evidence / recommendations | same | `verifier.verify_output()` | evidence pack | `tests/test_evidence_verifier.py` | Implemented and tested |
| Chat with deterministic fallback (never silent) | same | `slm.answer()`, `handoff.deterministic_answer()` | evidence pack | `test_chat_falls_back_deterministically`; `chat_benchmark.py` (35 questions, 0 silent) | Implemented and tested |
| Analyst handoff note (TXT / JSON, audit entry) | same | `handoff.handoff_note()` | evidence pack + workspace | `test_handoff_note_factual_lines_verify` | Implemented and tested |

## Threat Intelligence

| Feature | Frontend | Backend | Data source | Test | Status |
|---|---|---|---|---|---|
| Threat hunting (7 prepared hunts, custom regex, pivots, CSV export) | `ui/pages/threat_intel.py` | pandas over normalised events | events | `test_page_renders` | Implemented and tested |
| MITRE ATT&CK explorer (rules per technique, incidents per technique) | same | `playbooks.load_mitre()` | `data/mitre.json` (offline subset) | `test_page_renders` | Implemented with limitations (subset of ATT&CK, not the full matrix) |
| Detection rule catalogue with explanations and thresholds | same | `rules.RULES`, config | `config.yaml` | `test_page_renders` | Implemented and tested |

## Evaluation & Benchmarks

| Feature | Frontend | Backend | Data source | Test | Status |
|---|---|---|---|---|---|
| Accuracy (test, fresh, stress), before/after upgrade | `ui/pages/evaluation.py` | `scripts/evaluate.py`, `metrics.py` | `results/metrics.json`, `results/before_upgrade_detector.json` | `test_page_renders`; re-run button runs the script | Implemented and tested |
| Confusion matrix, severity agreement, per-rule precision | same | `metrics.evaluate()` | same | same | Implemented and tested |
| Per-scenario Jaccard incl. misses | same | `comparison.per_scenario_jaccard()` | same | `test_per_scenario_jaccard_reports_misses` | Implemented and tested |
| Naive-detector comparison | same | `naive.run_naive()`, `comparison.evaluate_items()` | same | `test_compression_and_naive_comparison` | Implemented and tested |
| Ablation (no baselines / no context / no allowlists) | same | `comparison.ablation_cfg()` + `cfg["features"]` | same | `test_ablation_configs_change_behaviour` | Implemented and tested |
| Alert compression | same | `comparison.compression()` | same | `test_compression_and_naive_comparison` | Implemented and tested |
| External recordings (EVTX-ATTACK-SAMPLES, OTRF) | same | `scripts/external_eval.py` | `results/external_eval.json` | script run (15 recordings) | Implemented with limitations (scenario-level only; no event labels) |
| SLM GPU vs CPU, 1.5B / 3B / 7B, self-repair | same | `scripts/slm_benchmark.py` | `results/slm_benchmark_*.json` | script runs | Implemented and tested |
| 100k-event scale benchmark | same | `scripts/scale_benchmark.py` | `results/scale_benchmark.json` | script run (126,919 events) | Implemented and tested |

## Report Studio

| Feature | Frontend | Backend | Data source | Test | Status |
|---|---|---|---|---|---|
| Report preview + HTML download (self-contained) | `ui/pages/reports.py` | `report.render_report()` | analysis + explanation | `tests/test_slm_report_offline.py` (no external refs) | Implemented and tested |
| PDF export | same | `report.html_to_pdf()` (local Edge, headless) | HTML | earlier PDF tests; button available only when Edge is installed | Implemented with limitations (needs Edge/Chrome installed) |
| Handoff note inside the report | same | `handoff_text()` | as above | `test_handoff_note_factual_lines_verify` | Implemented and tested |
| Bulk JSON / CSV / ZIP of all reports | same | `exports.py` | analysis | `test_exports_json_and_csv` | Implemented and tested |

## System & Settings

| Feature | Frontend | Backend | Data source | Test | Status |
|---|---|---|---|---|---|
| Offline monitor (connections, reachability probe, CPU/GPU/RAM) | `ui/pages/system_settings.py` | `perf.py` | live system | `test_page_renders`; `offline_check.py` | Implemented and tested |
| Model selector, CPU-only mode, self-repair toggle, timeouts | same | session config; `slm.unload()` on placement change | Ollama | `slm_benchmark.py --cpu` (placement confirmed via `/api/ps`) | Implemented and tested |
| Detection configuration editor (validated, apply + re-run, save, reset) | same | `config.validate_config()`, `save_local_settings()` | `config.yaml` + `workspace/settings.yaml` | `test_local_settings_override_and_validation` | Implemented and tested |
| Suppression proposals (narrow, reviewed, tag-only, revocable) and audit trail | same | `workspace.py` | `workspace/analyst.db` | `test_workspace_status_notes_dispositions_and_suppressions` | Implemented and tested |
| Offline validation history, UI check summary | same | – | `results/offline_runs/*.json`, `results/offline_ui_check.json` | `test_page_renders` | Implemented and tested |
| Credits and application info | same | – | – | `test_page_renders` | Implemented and tested |

## Not implemented (stated, not hidden)

- Offline IP geolocation database (no location is inferred from an IP address).
- Sigma rule import (rules are configurable through `config.yaml` only).
- PowerShell script-block / module log analysis (4103/4104/800), Sysmon process-access (event 10) analysis.
- Multi-user authentication for the dashboard (single local analyst; audit entries use the name "analyst").
