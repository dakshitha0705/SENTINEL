# Feature traceability: frontend → backend → data → test

Every visible control in the dashboard is listed with the code that implements it, the data it uses and the test that exercises it. A feature counts as **Implemented and tested** only when its full data path ran in a test: a pytest test (`tests/`), the browser check `scripts/ui_check.py` (real clicks in Edge with every non-local request blocked; result in `results/offline_ui_check.json`), or a benchmark script.

Status values: **Implemented and tested** · **Implemented with limitations** · **Not implemented**.

## Redesigned UI (24 Nov): six destinations

The nine pages were reorganised into six destinations; no backend feature was removed. Where each former page lives now:

| Former page | Now |
|---|---|
| Command Center | **Command Center** (story card, globe, counters, activity, detection overview, quick actions) |
| Log Intelligence | **Log Intelligence** (Upload → Review → Analyze; mapping editor opens when unsure; technical details in an expander) |
| Incident Investigation, Attack Graph, AI Investigation Lab | **Investigation Studio** views: Story, Evidence, Severity, Attack graph, AI investigation, Next steps, Notes, Export |
| Threat Intelligence | **Threat Hunting** (hunt cards + advanced hunting: regex, prepared hunts, MITRE explorer, rules) |
| Evaluation & Benchmarks, Report Studio | **Reports & Evaluation** views: Report, Evaluation, Offline evidence |
| System & Settings | **System status** popover (top right) → advanced dialog with the same tabs |
| — | **Live Demo** (new) |

| Feature | Frontend | Backend | Data source | Test | Status |
|---|---|---|---|---|---|
| Six-destination navigation; old names as deep links | `app.py`, `ui/state.py` (`PAGES`, `ALIASES`, `goto`) | – | session state | `test_page_renders[*]`, `test_old_page_names_map_to_new_destinations`, `ui_check.py` (all destinations and views) | Implemented and tested |
| Live mode selected by `?live=1`, kept on refresh/navigation, left on explicit switch | `app.py`, `state.select_live()` / `load_dataset()` | `live.LiveReader` / `LiveEngine` | NEXUS stream | `test_live_mode_pages_render` (navigation keeps LIVE; switch removes `live` from the URL) | Implemented and tested |
| Honest live status chip (monitoring / detection stopped) | `app.py` | `state.live_status()` (worker heartbeat or in-process engine) | `demo_data/live_worker.json` | `test_live_mode_pages_render`; browser check | Implemented and tested |
| Notifications: toast once per update, bell history, Investigate, Dismiss | `app.py` (`_notif_popover`, `_toast`), `state.sync_notifications()` / `notify_tick()` / `resolve_incident()` | `live.LiveEngine._notify()` (real `new` / `escalated`, plain-language summary, tracking key) | live analysis | `test_live_mode_pages_render` (real R1 notification, no duplicate on rerun), `test_full_storyline_uses_generated_event_ids_and_escalates`; `live_demo_check.py` (bell count 3) | Implemented and tested |
| Command Center story card and counters | `ui/pages/command_center.py` (`headline`, `_hero`) | `live.plain_summary()`; analysis | analysis | `test_command_center_counters_match_backend` | Implemented and tested |
| Live Demo page: NEXUS target, scenario cards, pause/resume/stop/new session, generated vs ingested, severity path | `ui/pages/live_demo.py` | NEXUS controller API (`/api/demo/*`), `LiveEngine` tracking | NEXUS + live snapshot | `test_runner_control_pause_resume_stop_and_conflicts`; browser check; `final_screenshots.py` (scenario G started from this page) | Implemented and tested |
| Presentation Mode (steps tick only from real state) | `live_demo.py` (`progress_flags`, `mark`) | live analysis events, session flags set by the studio/report pages | live analysis | `final_screenshots.py` (genuine sign-in ticks step 2; steps 3–4 after the attack) | Implemented and tested in the browser |
| Investigation Studio case queue + story playback | `ui/pages/studio.py` | `correlate.storyline()` | alerts, events | `test_investigation_studio_views_render[*]` | Implemented and tested |
| AI investigation cards (What we know / might have happened / needs checking / next steps) + Verification details | `ui/pages/ai_lab.py` (`render_for`) | `slm.explain`, `verifier.verify_output` | evidence packs | `test_investigation_studio_views_render[AI investigation]`; `live_demo_check.py` (Qwen + verification shown) | Implemented and tested |
| Threat Hunting cards (real queries) | `ui/pages/hunting.py` | `sentinel/hunting.py` (`category`, `summarise`) | normalised events + rule alert events | `test_threat_hunting_cards_run_real_queries`; `ui_check.py` (`hunt_card_runs_query`) | Implemented and tested |
| Event explorer with selectable rows and detail panel | `log_intelligence.py` (`_analysis_panels`) | pandas | normalised events | `test_page_renders[Log Intelligence]` | Implemented and tested |
| Reports & Evaluation views incl. offline evidence | `ui/pages/reports_eval.py` | `report.py`, results files, `system_settings.offline_validation()` | `results/*.json` | `test_reports_evaluation_views_render[*]` | Implemented and tested |
| NEXUS sign-in redesign (show/hide password, accessible states) | `demo_target/templates/login.html`, `static/nexus.css` | `IdentityStore.authenticate()` (unchanged) | – | `test_nexus_login_page_and_credentials_panel` | Implemented and tested |
| Demo accounts & credentials panel (collapsed, copy buttons, local only) | `demo_target/templates/demo.html` | `IdentityStore.passwords` (local file, git-ignored) | `demo_data/nexus_credentials.json` | `test_nexus_login_page_and_credentials_panel` (passwords only inside the collapsed panel, never on the login page) | Implemented and tested |

## Command Center (details)

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
| Queue with severity / status / text filters and sorting | `ui/pages/studio.py` | `workspace.current_status()` | analysis + `workspace/analyst.db` | `test_page_renders` | Implemented and tested |
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


## Live attack demonstration (NEXUS → SENTINEL)

| Feature | Frontend | Backend | Data source | Test | Status |
|---|---|---|---|---|---|
| NEXUS portal: login, dashboard, account, resources (access-controlled), activity history, admin group management, logout | `demo_target/templates/*` | `demo_target/app.py`, `auth.py` (scrypt hashes, lockout at 15) | fictional identities, `demo_data/nexus_credentials.json` | `test_nexus_auth_hashing_lockout_and_header_spoofing` | Implemented and tested |
| Security events from NEXUS actions (4624/4625/4634/4740/4732/4663/4656) with provenance | – | `demo_target/events.py` (append-only JSONL, fsync) | `demo_data/sessions/<id>/events.jsonl` | `test_event_schema_ordering_and_provenance` | Implemented and tested |
| Scenario controller: start, reset, A–H, pause, resume, stop, live status | `/demo` page | `demo_target/simulator.py` (bounded steps, safe cancellation) | the event stream + `sentinel_status.json` | `test_runner_control_pause_resume_stop_and_conflicts`, `test_attack_scenarios_detected`, `test_normal_and_benign_scenarios_create_no_incident` | Implemented and tested |
| Synthetic endpoint events (encoded PowerShell, certutil, wevtutil, 1102), labelled `simulated-endpoint` | – | `simulator._endpoint`, `_log_clear` | event stream | `test_event_schema_ordering_and_provenance` | Implemented and tested (synthetic by design) |
| Incremental ingestion with a durable cursor, duplicate and partial-line handling, restart recovery | – | `sentinel/live.py` `LiveEngine` | cursor file per session | `test_incremental_ingestion_duplicates_partial_lines_and_restart`, `test_nexus_restart_continues_the_session_stream` | Implemented and tested |
| Live detection worker (separate process) + dashboard reader + in-process fallback | (live mode in the dashboard) | `sentinel/live.py` `run_worker`, `LiveReader` | `live_snapshot.pkl`, `live_worker.json` heartbeat | `scripts/live_demo_check.py` (real services), `test_live_mode_pages_render` (fallback) | Implemented and tested |
| New/escalated incident notifications from real data; detection latency per incident | dashboard toasts / mode strip | `LiveEngine._notify`, tracking | engine state | `test_full_storyline_uses_generated_event_ids_and_escalates` | Implemented and tested |
| Approved change tickets as absolute change windows | – | `rules.in_change_window`, `LiveEngine.live_cfg` | `change_windows.json` | `test_normal_and_benign_scenarios_create_no_incident` (approved change not flagged), `test_attack_scenarios_detected` (unauthorised one flagged) | Implemented and tested |
| Demo isolation and reset (session folders; evaluation data untouched) | controller *Reset* | `EventStream.new_session` | `demo_data/` | `test_reset_isolation` | Implemented and tested |
| One-command start / stop (no duplicates, only own processes stopped) | – | `scripts/start_demo.ps1`, `stop_demo.ps1` | `demo_data/pids.json` | manual stop/start cycles (23 Nov 18:2x), `live_demo_check.py` | Implemented with limitations (Windows PowerShell only; not unit-tested) |
| Live pipeline in the offline check | – | `scripts/offline_check.py` `live_step` | temporary demo root | offline check runs | Implemented and tested |

**Frontend ownership.** From 23 Nov 18:30 IST the dashboard frontend (`app.py`, `sentinel/ui/**`) is maintained by the participant. The frontend rows above describe the state at that hand-over; open UI items are listed in `docs/progress.md`.

## Not implemented (stated, not hidden)

- Offline IP geolocation database (no location is inferred from an IP address).
- Sigma rule import (rules are configurable through `config.yaml` only).
- PowerShell script-block / module log analysis (4103/4104/800), Sysmon process-access (event 10) analysis.
- Multi-user authentication for the dashboard (single local analyst; audit entries use the name "analyst").
