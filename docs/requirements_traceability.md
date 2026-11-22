# Requirements traceability: Tinyverse PS 02

**Problem statement:** PS 02, Offline Security Incident Triage Assistant (Cybersecurity | Small Language Models).
**Authority order:** official participant instructions > PS 02 > SENTINEL Stage 1 specification > implementation brief.

## Key requirements (PS 02 §2)

| PS 02 requirement | SENTINEL implementation | Automated tests | Demo / evidence |
|---|---|---|---|
| **Log processing:** auth and endpoint logs in CSV or JSON | `sentinel/ingest.py`: CSV, JSON array, JSON-lines, nested flattening, column mapper with manual correction, UTC timestamps, rejects/duplicates/unevaluable summary, SHA-256 | `test_ingest.py` (11 tests: CSV, JSON, JSONL, timestamps, missing fields, invalid records, duplicates, mapper, Windows semantics, untrusted content) | Upload & mapping page; `demo_unseen` (SIEM CSV + EDR JSONL); format robustness in `results/metrics.json` |
| **Suspicious activity detection:** at least 3 distinct patterns | 8 required rules R1–R8 plus R9–R11 (`sentinel/rules.py`); per-user baselines; allowlists; change windows | `test_rules.py` (14 tests: every rule incl. R9–R11, thresholds, ordering, look-alikes, baselines, insufficient history) | Incident queue → detection summary; Accuracy page per-rule table |
| **Event correlation** by user, device, timestamp | Attack Storyline Engine (`sentinel/correlate.py`): time windows, identity/host/IP keys, strong/weak links with a recorded reason for each | `test_correlate_severity.py` (ordering, strong/weak, separation on a shared host, time-window separation) | Investigation → Attack storyline tab |
| **Severity classification** | 0–100 score with a line-by-line breakdown → Critical/High/Medium/Low; separate confidence (`sentinel/severity.py`) | `test_correlate_severity.py` (breakdown sums, levels, no double counting, benign context) | Severity breakdown tab; report table |
| **SLM integration:** local SLM explains and analyses incidents | qwen2.5:3b (Q4_K_M) via Ollama on 127.0.0.1 (`sentinel/slm.py`): summaries, supported conclusions, hypotheses with supporting/contradicting facts, playbook selection and adaptation, open questions, incident chat | `test_slm_report_offline.py` (timeout, invalid output, unavailable server → fallback) | Evidence vs. hypothesis tab; Analyst workspace chat; `results/slm_benchmark_*.json` |
| **Evidence-based reporting:** threats, severity, supporting log entries, recommended actions | Self-contained HTML report (+ PDF via local Edge): verified summary, breakdown, storyline, original log rows (file:row + raw record), MITRE, playbooks, verification results, limitations, file hashes | `test_report_is_self_contained_and_complete` | Report export tab; `reports/offline_INC-0001.html` |
| **Offline functionality:** analysis, SLM inference and reporting without internet | Pre-pulled model; no CDNs or remote fonts; telemetry off; local MITRE and playbooks; connection monitor | `test_no_external_urls_in_runtime_code`, `test_pipeline_makes_no_network_connections`, `test_streamlit_telemetry_disabled` | `scripts/offline_check.py` → `results/offline_run.json`; Offline system monitor page; `docs/offline_validation.md` |

## Evaluation focus (PS 02 §3)

| Evaluation point | How SENTINEL shows it | Where |
|---|---|---|
| Threat detection accuracy, few false positives | Incident precision/recall/F1/FPR on held-out test seeds plus out-of-envelope stress seeds; 7 benign look-alike types per dataset; context-only rules; baselines with explicit confidence | `docs/evaluation.md`, Accuracy page |
| Event correlation and prioritisation | Storyline with link reasons; Jaccard correlation quality; ranked queue; severity agreement | Evaluation §3; Incident queue |
| SLM utilisation | Explains incidents, weighs supporting vs. contradicting evidence, adapts playbooks, answers questions; measured latency and tokens/s; 7B vs 3B comparison | Evaluation §4–5; Analyst workspace |
| Evidence reliability | Evidence Contract: fact-ID citations, per-sentence verification, Verified/Unverified labels, measured verification rate, template fallback at 100% | `sentinel/verifier.py`; `test_evidence_verifier.py` (10 tests) |
| Offline performance | Measured processing time, SLM latency, tokens/s, peak RAM, VRAM share, connection log | `results/offline_run.json`; Monitor page |
| Usability and practicality | Streamlit SOC dashboard, column mapper with warnings, one-click report/PDF, MITRE tags, playbooks, dispositions/audit, URL-loadable demo | Screenshots in `docs/screenshots/` |

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
