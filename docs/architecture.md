# Architecture

SENTINEL is a single local Python application. **Code produces the facts; the SLM only interprets them.** Detection, correlation, severity, evidence verification and reporting all work without the model. If the model is off, slow or wrong, the deterministic template explanation takes over.

```
 CSV / JSON / JSON-lines / EVTX files  (originals never modified, SHA-256 of the original recorded)
        │   evtx_converter.py: offline EVTX → flat JSON records (System + EventData, record IDs kept)
        │
        ▼
 ingest.py ── column mapper (guess + analyst correction) ── normalised event schema
        │      rejects / duplicates / unevaluable records reported, never silently dropped
        ▼
 baselines.py ── per-user history strictly before each logon (4 h learning lag)
        │
        ▼
 rules.py ── R1–R8 (+ R9–R14, 4672 context) ── alerts with event IDs, reason, MITRE, confidence
        │
        ▼
 correlate.py ── Attack Storyline Engine: time-ordered linking, strong/weak links with reasons
        │
        ▼
 severity.py ── explainable 0–100 score, line-by-line breakdown, separate confidence
        │
        ▼
 evidence.py ── evidence pack: numbered facts F1..Fn + supporting / contradicting evidence
        │
        ├──► slm.py ── Ollama on 127.0.0.1 (qwen2.5:3b) ── typed, schema-constrained JSON citing fact IDs
        │        │        one bounded self-repair round with the verifier's specific errors
        │        │        (timeout / invalid output / unavailable → template explanation)
        │        │        chat: SLM answer → verifier → deterministic evidence answer (never silent)
        │        ▼
        └──► verifier.py ── per-sentence checks → Verified / Unverified, verification rate
                 │
                 ▼
 report.py (HTML/PDF) · exports.py (JSON/CSV) · handoff.py (shift notes) · workspace.py (SQLite audit)
 app.py + sentinel/ui/ (9 pages) · geospatial.py (globe, log coordinates only) · graph.py · search.py
```

## Modules

| Module | Responsibility |
|---|---|
| `sentinel/ingest.py` | Load CSV / JSON array / JSON-lines; flatten nested JSON; guess column mapping (names + value patterns); normalise users, hosts, IPs, processes and timestamps to UTC (day/month order inferred per column); Windows field semantics (4728/4732/4756 TargetUserName = group); per-row fallbacks for mixed Sysmon + Security exports; rejects with reasons; duplicates (same record ID, or identical original content); SHA-256 per file. |
| `sentinel/baselines.py` | For each successful logon, the user's prior hours, hosts and IPs. A logon only enters the baseline once it is older than the maximum incident span (4 h), so an attack cannot normalise itself. "Low confidence" below 10 logons / 3 days. |
| `sentinel/rules.py` | R1–R11 and 4672 context. Thresholds come from `config.yaml`. A rule needing fields the data lacks is reported as "not evaluated". |
| `sentinel/correlate.py` | Storyline engine (linking policy below). |
| `sentinel/severity.py` | Score breakdown and confidence. |
| `sentinel/evidence.py` | Evidence pack; contradicting evidence computed from logs and baselines; limitations. |
| `sentinel/slm.py` | Ollama client: prompt, JSON schema with length limits, streaming, timeout, retry with a different seed, cache keyed by evidence-pack hash, template fallback, incident chat. |
| `sentinel/verifier.py` | Evidence Contract checks (below). |
| `sentinel/report.py` | Jinja2 HTML report with inline CSS only; PDF through the locally installed Edge. |
| `sentinel/metrics.py` | Incident-level matching and metrics (see `evaluation.md`). |
| `sentinel/perf.py` | psutil peak-RAM sampler, connection log (loopback vs external), local `nvidia-smi` query. |
| `sentinel/workspace.py` | Dispositions, notes, audit trail, reviewable suppressions (SQLite, `workspace/analyst.db`). |
| `sentinel/evtx_converter.py` | Offline EVTX parsing (`evtx` package): System fields, EventData/UserData flattened, original record IDs, diagnostics for unreadable files. |
| `sentinel/naive.py`, `sentinel/comparison.py` | Naive baseline detector; strict/lenient matching; ablation switches (`cfg["features"]`); alert compression; per-scenario Jaccard. |
| `sentinel/handoff.py` | Deterministic chat answers by intent, and shift-handoff notes, built only from pack facts (so they pass the verifier). |
| `sentinel/exports.py` | Incident JSON (storyline, facts, verification, workflow) and CSV exports. |
| `sentinel/geospatial.py` | Globe markers/arcs from coordinate columns present in the logs; exploration mode otherwise. |
| `sentinel/graph.py`, `sentinel/search.py` | Attack-graph nodes/edges from correlation output; global search. |
| `app.py`, `sentinel/ui/` | Streamlit shell (top bar, navigation, search) and nine pages; `ui/static/viz` is a local bidirectional component (globe.gl + three.js, vis-network, Natural Earth outlines). |

## Normalised event schema

`event_id, source_file, source_row, record_id, timestamp (UTC), log_type (auth/endpoint), event_code, action, user, target_user, actor, host, src_ip, group, process, parent_process, command_line, outcome, src_lat, src_lon, src_geo, dst_lat, dst_lon, dst_geo, raw`

The six geo fields are optional and are filled only from columns the log itself provides (for example a SIEM's geo-enrichment).

`raw` is the original record, verbatim. `event_id` (EVT-nnnnnn) is assigned after time-sorting and is used in every citation. `source_file:source_row` points to the original line.

Action normalisation:
- **Windows event IDs:** 4624 login_success; 4625 and 4771 login_failure; 4768 login_failure when Status ≠ 0x0; 4634/4647 logout; 4672 privilege_logon; 4728/4732/4756 group_add; 4799 group_enum; 4688 process_start; 1102 (and 104 from the Eventlog provider) log_cleared; 6416 device_connected.
- **Other sources:** Sysmon 1 → process_start; free-text actions such as "Logon Failed" are mapped by keywords.

## Detection rules

| Rule | Logic (defaults in `config.yaml`) | MITRE | Weight |
|---|---|---|---|
| R1 Brute force | ≥ 8 failures for one account from one source within a 10-min sliding window | T1110.001 | Medium |
| R2 Password spraying | One source IP fails against ≥ 5 distinct accounts within 15 min, median ≤ 3 attempts each | T1110.003 | High |
| R3 Logon after failures | Success for the same account and same source ≤ 60 min *after* the last failure of an R1/R2/R12/R13 burst. Full weight up to 15 min, then linearly down to 0.4× at 60 min; a late success is labelled "not confirmed compromise". It always joins its burst's incident (derived link). | T1078 | High (decayed) |
| R4 Unusual time | No prior logon within ±1 h of this hour; only with a confident baseline; service accounts excluded | T1078 | Low, context |
| R5 New device / IP | Host or source IP never seen for this account (needs ≥ 3 prior logons; low-confidence label) | T1078 | Low, context |
| R6 Privileged group change | 4728/4732/4756 into a privileged group where the actor is not an authorised admin **or** the change is outside an approved change window | T1098 | High |
| R7 Suspicious process | Encoded PowerShell, download cradles, Mimikatz, LSASS dumps, certutil download, Office → shell, wevtutil cl, vssadmin delete | T1059.001, T1003, T1105, T1070.001… | High |
| R8 Audit log cleared | Event 1102; flags preceding suspicious activity on the same host or user within 4 h | T1070.001 | High |
| R9 Lateral movement | ≥ 3 hosts new to the account within 30 min | T1021 | Context |
| R10 Bulk copy / staging | Recursive copy or archive tool writing to a removable drive or UNC path | T1039, T1074 | Medium |
| R11 USB storage | Event 6416 for a disk/USB device | T1052.001 | Context |
| R12 Sustained brute force | Failures R1 did not cover: ≥ 8 in 60 min or ≥ 20 in 24 h for one account from one source that had **never** logged on successfully as that account before | T1110.001 | Medium |
| R13 Small password spray | One source fails against ≥ 3 accounts (below R2) within 30 min, ≥ 80% of its logon attempts in the window fail, and most targets never logged on from it | T1110.003 | Medium |
| R14 Privileged group discovery | `net group "Domain Admins"`, `net localgroup administrators`, Get-ADGroupMember, dsquery, or a 4799 enumeration by net/PowerShell/cmd; low confidence for authorised admins | T1069.001/.002 | Context |
| 4672 | Special privileges at logon: supporting context only, **never** proof of escalation | – | Context |

False-positive controls:
- allowlists for authorised admins, privileged accounts and service accounts;
- approved change windows;
- context-only rules;
- the baseline learning lag;
- every alert records its reason and threshold, so a false positive can be traced back to the setting that caused it.

## Attack Storyline Engine (linking policy)

1. **Ordering.** Primary alerts are processed in time order. An alert may join an open incident if it starts within **30 min** of the incident's last activity and the incident would not exceed **4 h**.
2. **Keys.** Keys are compared against *every* alert already in the incident: account (user/actor/member), host and source IP.
3. **Strong link** = 2 or more keys match. **Weak link** = exactly one key, *and it must be the account*. A shared host or IP alone (a domain controller, a NAT address) **never** links alerts.
4. **Link reasons.** Every link records its reason, e.g. "same account (jdoe) + same host (WS1) + same source IP (203.0.113.5); 1.4 min after ALR-0072 (R1)".
5. **Context alerts.** Context alerts (R4/R5/R9/R11/4672) attach afterwards and may precede the incident by up to the gap. They never start an incident, except the **anomalous logon**: R4 and R5 on the same logon with a confident baseline.
6. **Weak links.** Weakly linked alerts are shown dashed and contribute 0 to severity.

## Severity (0–100) vs. confidence

| Factor | Points |
|---|---|
| Each distinct rule (once per incident) | High +25, Medium +15, Low +5 (low-confidence R4/R5: 0) |
| Log cleared after suspicious activity | +10 |
| Credential dumping observed | +20 (added after the public-data run) |
| Privileged account involved (allowlist, 4672, or member added to a privileged group) | +15 |
| Domain-wide admin group targeted | +10 |
| Critical asset (`assets.critical`) | +10 |
| Chain completeness | +20 for access → escalation → execution/clearing in order, +10 for two stages |
| Low-confidence baseline (only when the incident rests on baselines alone) | −10 |
| Benign context (change window, authorised admin from known devices) | −10 each, max −20 |

Levels: **Critical** 80–100, **High** 60–79, **Medium** 35–59, **Low** 0–34.

Severity measures *how bad it would be*. **Confidence** is reported separately and measures *how strongly the evidence indicates malicious activity*:
- **High:** 2 or more independent high-signal detections.
- **Medium:** one.
- **Low:** behavioural anomalies only.
- Benign context lowers confidence by one step.

## Evidence Contract

1. Code builds the evidence pack. Facts carry structured fields: event IDs, numbers, times, users, hosts, IPs.
2. The SLM receives only the compact pack, never raw logs. The prompt says fact text is untrusted data.
3. The output is schema-constrained JSON: `summary[]`, `supported_conclusions[]`, `hypotheses[]`, `recommended_actions[]`, `open_questions[]`, with fact-ID citations and length limits.
4. The verifier splits multi-sentence items and checks **each sentence**:
   - the cited IDs exist;
   - every number matches a cited fact (counts exactly, durations rounded);
   - every time and date matches;
   - every user, host and IP mentioned is in the cited facts, and no unknown IP or host is named;
   - every event, alert or incident ID mentioned (EVT-/ALR-/INC-) belongs to the cited facts;
   - lexical grounding: the content overlaps with the cited facts;
   - no overclaiming phrases such as "definitely", "confirms the attack" or "attacker".
5. Failing sentences are labelled **Unverified** and kept out of the executive summary. Hypotheses are labelled grounded or ungrounded. Playbook IDs outside the incident's candidate list are rejected.
6. **Typed claims (prompt v7).** Each summary/conclusion item also carries `claim_type` and, when the sentence states them, `count`, `start_time`, `end_time`, `user`, `host`, `source_ip`, `event_ids`. Each typed value must be supported by the cited facts: counts by their numbers, times by their times, entities by their entities, event IDs by their events.
7. **Self-repair.** When claims fail, the specific failures (e.g. "number 987 not found in cited facts (F3 says ...)") are sent back once. The repaired JSON is verified again. It is kept only if it verifies at least as many claims, and any claim that still fails stays Unverified. The model cannot override the verifier.
8. The verification rate, before and after repair, is shown per incident and benchmarked (`evaluation.md`).

## Offline design

- **Model:** pre-pulled in Ollama (`OLLAMA_MODELS=E:\ollama\models` on the dev laptop), served on `127.0.0.1:11434`.
- **No external calls:**
  - no CDNs, remote fonts or scripts; reports use inline CSS only;
  - Streamlit `gatherUsageStats = false`, bound to `127.0.0.1`;
  - MITRE reference and playbooks are local JSON; MITRE URLs are displayed as text only.
- **Checks:**
  - a static test (`tests/test_slm_report_offline.py`) asserts that the runtime code contains no external URLs;
  - another test runs the full pipeline under a connection monitor and asserts there are no external connections;
  - `scripts/offline_check.py` records a full run, including the live SLM, with the network state and connection log;
  - `scripts/ui_check.py` drives the dashboard in Edge with **every non-local request aborted and counted**, and checks the globe and graph interactions.
- **Bundled front-end assets:** globe.gl 2.46.2 (with three.js), vis-network 9.1.9 and Natural Earth outlines live in `sentinel/ui/static/viz/`. Material Symbols and Altair/Vega ship inside Streamlit. No texture or map tile is downloaded.

## Ablation switches

`cfg["features"]` (all on by default) turns design elements off for the ablation study:
- `baselines`: R4/R5/R9 and the known-source checks of R12/R13;
- `context`: context-only alerts become ordinary detections, and the benign-context discount is off;
- `allowlists`: authorised admins, service accounts and change windows are emptied.
