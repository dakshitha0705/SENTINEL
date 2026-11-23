# Requirements traceability: Tinyverse PS 02

**Problem statement:** PS 02, Offline Security Incident Triage Assistant (Cybersecurity | Small Language Models).
**Authority order:** official participant instructions > PS 02 > SENTINEL Stage 1 specification > implementation brief.

## Key requirements (PS 02 §2)

| PS 02 requirement | SENTINEL implementation | Automated tests | Demo / evidence |
|---|---|---|---|
| **Log processing:** auth and endpoint logs in CSV or JSON | `sentinel/ingest.py`: CSV, JSON array, JSON-lines, **EVTX (offline converter)**, nested flattening, column mapper with manual correction and saved profiles, UTC timestamps, rejects/duplicates/unevaluable summary, SHA-256 | `test_ingest.py` (11 tests: CSV, JSON, JSONL, timestamps, missing fields, invalid records, duplicates, mapper, Windows semantics, untrusted content) | Log Intelligence page; `demo_unseen` (SIEM CSV + EDR JSONL); 13 public EVTX recordings (`results/external_eval.json`); format robustness in `results/metrics.json` |
| **Suspicious activity detection:** at least 3 distinct patterns | 8 required rules R1–R8 plus R9–R14 (`sentinel/rules.py`): sustained brute force, small sprays, delayed success, T1069 discovery; per-user baselines; allowlists; change windows | `test_rules.py` (14) + `test_upgrade.py` (R12, R13, R3 decay, R14) | Command Center detections; Threat Intelligence → rules; fresh held-out F1 0.961 |
| **Event correlation** by user, device, timestamp | Attack Storyline Engine (`sentinel/correlate.py`): time windows, identity/host/IP keys, strong/weak links with a recorded reason for each | `test_correlate_severity.py` (ordering, strong/weak, separation on a shared host, time-window separation) | Incident Investigation → storyline; Attack Graph; per-scenario Jaccard |
| **Severity classification** | 0–100 score with a line-by-line breakdown → Critical/High/Medium/Low; separate confidence (`sentinel/severity.py`) | `test_correlate_severity.py` (breakdown sums, levels, no double counting, benign context) | Severity breakdown tab; report table |
| **SLM integration:** local SLM explains and analyses incidents | qwen2.5:3b (Q4_K_M) via Ollama on 127.0.0.1 (`sentinel/slm.py`): summaries, supported conclusions, hypotheses with supporting/contradicting facts, playbook selection and adaptation, open questions, incident chat | `test_slm_report_offline.py` (fallbacks), `test_upgrade.py` (typed claims, self-repair, chat fallback, handoff) | AI Investigation Lab; `results/slm_benchmark_*.json` (GPU and CPU-only) |
| **Evidence-based reporting:** threats, severity, supporting log entries, recommended actions | Self-contained HTML report (+ PDF via local Edge): verified summary, breakdown, storyline, original log rows (file:row + raw record), MITRE, playbooks, verification results, limitations, file hashes | `test_report_is_self_contained_and_complete` | Report Studio (HTML, PDF, JSON, CSV, ZIP, handoff note); `reports/offline_INC-0001.html` |
| **Offline functionality:** analysis, SLM inference and reporting without internet | Pre-pulled model; no CDNs or remote fonts; telemetry off; local MITRE and playbooks; connection monitor | `test_no_external_urls_in_runtime_code`, `test_pipeline_makes_no_network_connections`, `test_streamlit_telemetry_disabled` | `scripts/offline_check.py`, `scripts/ui_check.py` (external requests blocked and counted); System & Settings → Offline validation; `docs/offline_validation.md` |

## Evaluation focus (PS 02 §3)

| Evaluation point | How SENTINEL shows it | Where |
|---|---|---|
| Threat detection accuracy, few false positives | Precision/recall/F1/FPR on test seeds and on fresh seeds generated after the upgrade freeze; before/after; naive comparison and ablation; 10 look-alike types; external real recordings (scenario detection) | `docs/evaluation.md`, Evaluation & Benchmarks page |
| Event correlation and prioritisation | Storyline with link reasons; per-scenario Jaccard; alert compression 88.3%; ranked queue; executive summary | Evaluation §3–4; Command Center |
| SLM utilisation | Explains incidents, weighs supporting vs. contradicting evidence, adapts playbooks, answers questions; measured latency and tokens/s; 7B vs 3B comparison | Evaluation §4–5; Analyst workspace |
| Evidence reliability | Evidence Contract: typed claims, per-sentence verification, one bounded self-repair round (73% → 83% verified), Verified/Unverified labels, chat with 0 silent replies, template fallback | `sentinel/verifier.py`, `sentinel/slm.py`; `test_evidence_verifier.py`, `test_upgrade.py` |
| Offline performance | GPU vs CPU-only inference, 1.5B/3B/7B, 126,919-event scale test, peak RAM, connection log, disconnected runs | `results/*.json`; Evaluation & Benchmarks; System & Settings |
| Usability and practicality | Nine-page dashboard with an interactive offline globe and attack graph, global search, dataset/time filters, analyst workflow (status, notes, dispositions, handoff), exports | `docs/feature_traceability.md`; `docs/screenshots/v2/` |

## Stage 1 feature status

| Stage 1 item | Priority | Status |
|---|---|---|
| Normalised schema, CSV/JSON ingestion, column mapper | P0 | Done |
| Synthetic generator: normal, 4–5 attacks, look-alikes, dev/test seeds, ground truth | P0 | Done (5 attacks, 7 look-alikes, plus stress seeds and an unseen-format demo) |
| 8 rules with sliding windows and per-user baselines (low-confidence flag) | P0 | Done |
| Correlation with link reasons, strong/weak links, timeline | P0 | Done |
| Explainable severity score and levels | P0 | Done |
| Local SLM with Evidence Contract, JSON output and verifier | P0 | Done |
| Template fallback report | P0 | Done |
| Streamlit UI and HTML report | P0 | Done |
| Metrics script (precision, recall, F1, FPR on test seeds) | P0 | Done (`scripts/evaluate.py`) |
| Full run with network disconnected | P0 | See `docs/offline_validation.md` for the status of the disconnected run |
| Evidence vs. Hypothesis view, code-computed contradicting evidence | P1 | Done |
| MITRE ATT&CK tags (offline JSON) | P1 | Done (`data/mitre.json`) |
| Offline playbook library | P1 | Done (12 playbooks) |
| Performance panel | P1 | Done |
| Public dataset sanity run | P1 | Done (OTRF, `results/public_sanity.json`) |
| Accuracy page | P1 | Done |
| Polished styling | P1 | Done |
| Ask-the-incident chat | P2 | Done (verified answers) |
| Dispositions, audit trail, reversible suppressions | P2 | Done (SQLite) |
| SHA-256 input fingerprints in reports | P2 | Done |
| YAML rule files | P2 | Partial: all thresholds, groups, allowlists, windows and R7 process patterns are in validated YAML; not a full Sigma rule engine |
| Lateral movement and USB/bulk-copy rules | P2 | Done (R9 context, R10, R11 context; R10/R11 unit-tested only, not in synthetic data) |
| Upgrade (23 Nov): R12–R14, EVTX, external evaluation, comparison/ablation, typed claims + self-repair, chat fallback, handoff, CPU/scale benchmarks, globe + 9-page UI | Upgrade brief | Done; see `docs/feature_traceability.md` for per-feature status |
| PDF export | P2 | Done (local Edge print-to-PDF) |

## Conflicts and interpretations (recorded as required)

| # | Conflict / ambiguity | Decision | Reason |
|---|---|---|---|
| 1 | The implementation brief said to configure Ollama model storage on D:; the participant's later explicit decision was to keep the already-downloaded models on E: and not download duplicates | Models stay on E: (`OLLAMA_MODELS=E:\ollama\models`) | Explicit, more specific instruction; avoids a duplicate 6.6 GB download |
| 2 | The brief said to preserve the three reference documents in `docs/`; the participant decided not to publish organiser material | The files stay in `docs/` locally but are excluded by `.gitignore` | Organiser PDFs contain contact details and are not ours to publish |
| 3 | The brief preferred Python 3.11/3.12 "if required" | Python 3.13.5 used | All dependencies install and pass tests on 3.13 |
| 4 | Stage 1: "context-only rules never create an incident", but Stage 1 also lists "off-hours login from a new device" as an attack scenario | An R4 + R5 composite on the **same logon** with a **confident** baseline may start a Low-severity "anomalous logon" incident; a single context signal never does | Two independent anomalies on one event is a stronger signal than either alone; one stress-seed FP is reported |
| 5 | Stage 1: "baselines computed from data before the analysed window" | Per-event prior history with a 4 h learning lag | Works on a single uploaded file; prevents an attack from learning itself |
| 6 | Stage 1: weak links never raise severity; the brief: never merge on one shared attribute | Weak link allowed **only** on a shared account; host-only or IP-only matches never merge; weak alerts score 0 | Satisfies both |
| 7 | Stage 1 low-confidence baseline: "reduced weight" **and** a −10 penalty | Low-confidence R4/R5 score 0; −10 applies only when the incident rests solely on baselines | Avoids penalising unrelated high-signal evidence (found on the dev seed) |
| 8 | Stage 1 storage: "SQLite only if feedback/audit is built" | Feedback/audit was built, so SQLite is used | As specified |
| 9 | Stage 1 repository layout nests a `sentinel/` folder | Repo root = project root; `sentinel/` is the Python package | Avoids `SENTINEL/sentinel/sentinel` |
| 10 | Official PPT format not yet released | Built the suggested structure; to be adapted when the organisers publish requirements | The official format overrides the suggested one |
| 11 | Upgrade brief asked for the globe to show geographic sources, but the logs have no trustworthy locations and online geolocation is forbidden | Globe plots only coordinates present in the logs (demo export carries synthetic SIEM geo columns, labelled as such); otherwise exploration mode with an explicit notice | The brief itself forbids fabricated locations |
| 12 | Upgrade brief: "do not tune against the final held-out test set", but the stress seeds had motivated the new rules | Stress seeds were re-labelled *diagnostic*; ten fresh seeds were generated after the upgrade freeze and are the held-out set | Keeps one untouched held-out set |
| 13 | Upgrade brief referenced an approved dashboard screenshot | No screenshot was in the workspace; the written design specification (palette, layout, globe) was followed | As the brief instructs when the image is unavailable |
