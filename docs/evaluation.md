# Evaluation

Every number here comes from a results file written by a script:

| File | Script |
|---|---|
| `results/metrics.json` | `python scripts/evaluate.py` (synthetic accuracy, naive comparison, ablation, compression, per-scenario Jaccard) |
| `results/before_upgrade_detector.json` | the pre-upgrade detector (git tag `checkpoint-pre-upgrade`) run on the same datasets |
| `results/external_eval.json` | `python scripts/external_eval.py` (public attack recordings) |
| `results/slm_benchmark_*.json` | `python scripts/slm_benchmark.py` (local model, GPU / CPU, self-repair) |
| `results/chat_benchmark.json` | `python scripts/chat_benchmark.py` |
| `results/scale_benchmark.json` | `python scripts/scale_benchmark.py` (126,919 events) |
| `results/offline_runs/*.json`, `results/offline_ui_check.json` | `scripts/offline_check.py`, `scripts/ui_check.py` |

Earlier v1 results (prompt v6, pre-upgrade detector) are kept: `results/metrics_before_upgrade.json` and `results/slm_benchmark_test_seed*_*.json`.

> **Read this first: what these numbers mean.**
> The labelled datasets come from SENTINEL's own synthetic generator, written by the same author as the rules. High scores show that the detector generalises across users, timings and attack speeds *within the attack styles it was designed for*. They are **not** a measurement of real-world accuracy. The fresh seeds, the stress diagnostics and the external recordings are there to show where the design breaks.

## 1. Datasets and their roles

| Set | Seeds | Role | Used for tuning? |
|---|---|---|---|
| Development | 7, and 7 + look-alikes B8–B10 | Threshold and design decisions | **Yes**, the only tuning sets |
| Test | 101, 202, 303 | Held out since the first freeze (22 Nov) | No |
| Stress | 1001–1010 | Out-of-envelope attacks. Held out at the first freeze; their failure analysis **motivated** R12, R13 and the longer R3 window, so they are now **diagnostic**, not held out | Indirectly (motivated the upgrade) |
| **Fresh** | 5001–5010 | Generated after the upgrade's detector freeze (23 Nov). Widened envelope (brute force up to 50 min, sprays from 3 accounts, successes up to 50 min later, longer gaps) plus new look-alikes B8–B10 | **No**. The held-out set for the upgrade |
| Demo | 2024 | Unseen SIEM/EDR format, column-mapper demo, synthetic geo-enrichment columns | No |
| External | 15 public recordings | Real attack logs (section 6) | No |

Each synthetic dataset has 1.4k–2.1k events over 7 days, 23–33 accounts and 21–27 hosts. It contains five attack scenarios:

- S1: brute force → logon → local admin add → encoded PowerShell + certutil
- S2: password spray, sometimes with a successful logon
- S3: an insider adds themself to Domain Admins and runs `net group`
- S4: Mimikatz and log clearing with admin02's credentials
- S5: an off-hours logon from an unfamiliar address

It also contains seven benign look-alikes:

- B1: approved night maintenance
- B2: 2–3 password typos
- B3: a new laptop rollout
- B4: an approved group change
- B5: an admin PowerShell script
- B6: a forgotten password
- B7: a night-time service backup

The fresh seeds add three more look-alikes, which target the new rules:

- B8: an administrator lists the members of Domain Admins (an R14 look-alike)
- B9: a stale saved password retries all day from the user's own PC (an R12 look-alike)
- B10: three people mistype once on a shared meeting-room PC (an R13 look-alike)

Labels are in `ground_truth.json` / `labels.csv` and are never read by the detector.

## 2. Matching procedure (fixed before evaluation)

- **Match:** a detected incident **matches** an attack when it contains **at least 50%** of the attack's events. Events are mapped through `EventRecordID`.
- **False positive:** a detected incident that matches no attack.
- **Flagged look-alike:** a look-alike is **flagged** when any incident contains any of its events (strict).
- **Precision** = matched detections / detections.
- **Recall** = attacks matched / attacks.
- **FPR** = flagged look-alikes / look-alikes.
- **Jaccard** = |predicted ∩ truth| / |predicted ∪ truth| for the best-matching incident of each attack.
- **Severity agreement** = the detected level equals the level the scenario author assigned before evaluation.

## 3. Detection results

| Set | Precision | Recall | F1 | FPR | Jaccard | Severity agreement | Attacks / look-alikes |
|---|---|---|---|---|---|---|---|
| Test 101/202/303 | **1.000** | **1.000** | **1.000** | **0.000** | 1.000 | 1.000 | 15 / 21 |
| **Fresh 5001–5010 (held out)** | **0.942** | **0.980** | **0.961** | **0.030** | **0.971** | **0.898** | 50 / 100 |
| Stress 1001–1010 (diagnostic) | 0.942 | 0.980 | 0.961 | 0.014 | 0.976 | 0.980 | 50 / 70 |

### Before vs after the upgrade (same datasets)

| Set | Metric | Before (v1 detector) | After |
|---|---|---|---|
| Fresh | Precision / Recall / F1 | 0.825 / 0.940 / 0.879 | **0.942 / 0.980 / 0.961** |
| Fresh | FPR | 0.030 | 0.030 |
| Fresh | Jaccard | 0.883 | **0.971** |
| Fresh | Severity agreement | 0.809 | **0.898** |
| Stress | F1 / Jaccard | 0.931 / 0.911 | 0.961 / 0.976 |
| Test | F1 / Jaccard | 1.000 / 0.933 | 1.000 / **1.000** |

The "before" numbers come from running the checkpoint commit's detector unchanged on the same files (`results/before_upgrade_detector.json`). Its stress numbers reproduce the original v1 report exactly. That is a sanity check that the datasets did not change.

What changed:
- **R12** (sustained brute force: 8 in 60 min or 20 in 24 h, from a source never used by the account);
- **R13** (small password spray: at least 3 accounts, at least 80% failures, sources mostly unknown to the targets);
- **R3** now links successes up to 60 min after the failures, with weight decaying to 0.4× and the label "not confirmed compromise";
- **R14** (privileged group discovery, T1069, context only).

R14 lifts S3's Jaccard from 0.667 to 1.0, because the `net group "Domain Admins"` step is now part of the incident.

### Fresh-seed failures (reported, not tuned away)

| Seed | What happened | Cause |
|---|---|---|
| 5009 | S5 (off-hours logon from a new address) **missed** | The victim had 9 earlier logons (10 needed for a confident baseline), so R5 fired with low confidence, R4 was not evaluated, and the R4 + R5 composite could not start an incident |
| 5004 | B1 and B4 (approved admin work in the change window) flagged as Low "anomalous logon" incidents | The admins' baselines did not yet contain the maintenance host/IP. Change-window context lowers the score, but it does not suppress the R4 + R5 composite |
| 5001 | B3 (new laptops) overlaps the S2 spray incident | A rollout user (aditya.bose) was also a spray target, so their new-device R5 alert attached to the spray incident by a weak (account-only) link |
| 5007 | S1 split: its two process alerts formed a separate Low incident (a false positive under the matching rule) | The step gap exceeded the 30-min correlation gap. The main S1 incident still matched (Jaccard 0.895) |
| 5003 | The S2 spray + success merged into the S4 incident, which then scored Critical (expected High) | admin02 was among the spray targets. R2 joined the S4 incident by a weak (account-only) link, and its R3 success followed by a strong link. Weak links add no points, but the R7/R8 points of S4 apply to the merged incident |
| 5004, 5007, 5010 | S2 with a successful logon scored **Critical** instead of High | e.g. 5004: R2 25 + R3 25 + R5 5 + privileged account among the targets 15 + DC01 critical asset 10 = 80 |
| 5008 | S3 scored Critical (85) instead of High | R6 25 + tier-0 group 10 + privileged 15 + critical asset 10 + partial chain 10, plus context R4/R5/R14 (+5 each). The new R14 context alert added the 5 points that crossed the threshold |

### Per-scenario correlation quality (Jaccard, matched runs)

| Scenario | Test (mean / min / missed) | Fresh (mean / min / missed) | Stress (mean / min / missed) |
|---|---|---|---|
| S1 brute-force chain | 1.000 / 1.000 / 0 | 0.989 / 0.895 / 0 | 1.000 / 1.000 / 1 |
| S2 password spray | 1.000 / 1.000 / 0 | 0.949 / 0.824 / 0 | 0.951 / 0.750 / 0 |
| S3 insider group change | 1.000 / 1.000 / 0 | 1.000 / 1.000 / 0 | 0.967 / 0.667 / 0 |
| S4 credential dumping + log clear | 1.000 / 1.000 / 0 | 0.920 / 0.600 / 0 | 0.960 / 0.600 / 0 |
| S5 off-hours new device | 1.000 / 1.000 / 0 | 1.000 / 1.000 / 1 | 1.000 / 1.000 / 0 |

The remaining stress miss is seed 1007's S1. It had five failures in 11 minutes, which is indistinguishable from look-alike B6 (a forgotten password) except for the new source IP. It is left as a documented miss.

### Format robustness and column mapping

- **Format robustness:** test seed 101 gives identical results whether it arrives as CSV + JSON-lines, JSON only or CSV only (P = R = F1 = 1.0).
- **Column mapping on the demo:** precision is 0.571 with automatic guesses only. It rises to 1.0 once the analyst maps "Initiated By" → actor and "Member Added" → target_user. That correction is saved as a mapping profile.

## 4. Naive-detector comparison and ablation

All variants run on **identical held-out data**: test 101/202/303 plus fresh 5001–5010, with 65 attacks and 121 look-alikes.

The **naive detector** (`sentinel/naive.py`) uses the same fixed thresholds and process regexes as SENTINEL. It differs only in what it leaves out:
- no behavioural baselines;
- fixed business hours (08–18 UTC);
- no allowlists, change windows or context handling;
- **no correlation**: every alert is a separate item.

Two matching protocols are reported so that the comparison is fair to a detector without correlation:
- **Strict** = SENTINEL's ≥ 50% rule.
- **Lenient** = any overlap counts.

| Variant | What is disabled | Items to review | Strict P / R / F1 | Lenient P / R / F1 | FPR | Jaccard |
|---|---|---|---|---|---|---|
| **Full SENTINEL** | – | **67** | **0.955 / 0.985 / 0.970** | 0.970 / 0.985 / 0.977 | **0.025** | 0.978 |
| No behavioural baselines | R4/R5/R9; R12/R13 known-source checks | 63 | 0.810 / 0.785 / 0.797 | 0.841 / 0.800 / 0.820 | 0.083 | 0.854 |
| No context handling | context-only alerts may start incidents; no benign discount | 316 | 0.206 / 1.000 / 0.341 | 0.212 / 1.000 / 0.350 | 0.496 | 0.981 |
| No allowlists | authorised admins, service accounts, change windows | 79 | 0.810 / 0.985 / 0.889 | 0.823 / 0.985 / 0.896 | 0.124 | 0.978 |
| Naive detector | all of the above + correlation | **1,651** | 0.030 / 0.569 / 0.058 | 0.108 / 1.000 / 0.196 | 0.628 | – |

What this shows:
- **Each design element helps on this data.** The largest single effect is context handling. Promoting R4/R5/R9/R14 to ordinary detections finds every attack, but produces 316 items and flags half of the look-alikes.
- **Baselines matter for recall.** Without them, R5/R4 stop supporting S5, and R12/R13 lose their known-source checks.
- **Allowlists matter for false positives.**
- **The naive detector finds every attack under lenient matching**, but gives the analyst 1,651 alerts, of which 89% touch no attack.

### Alert compression

On the same held-out data, **571 raw alerts become 67 incidents: 88.3% fewer items to triage**. Compression = (1 − incidents / alerts) × 100, where alerts exclude the informational 4672 records.

This measures **analyst workload reduction, not accuracy**. Accuracy is measured separately above.

## 5. Local SLM and the Evidence Contract

The SLM benchmarks below use the 15 incidents of the test seeds, prompt v7 (typed claims), no cache, and the RTX 4060 Laptop unless marked CPU. The CPU/GPU placement was read from Ollama `/api/ps` while the model was loaded. CPU mode means Ollama option `num_gpu = 0`, which gives 0 bytes in VRAM.

### Verification and self-repair (qwen2.5:3b, GPU)

| | Value |
|---|---|
| Factual claims verified, first attempt | 22 / 30 = **73.3%** |
| After one self-repair round | 25 / 30 = **83.3%** (5 claims still failing; they stay Unverified) |
| Incidents that needed repair | 8 of 15; repaired output kept in all 8 (never fewer verified claims) |
| Extra latency when a repair runs | 5.2 s mean |
| Mean latency per incident (incl. repairs) / generation speed | 8.1 s / 93 tokens/s |
| Template fallbacks | 0 / 15 |

**Run-to-run variation is real.** An earlier run of the same configuration the same morning gave 76.7% → 86.7%. GPU inference is not bit-deterministic, so treat the effect as roughly **+10 percentage points** from one repair round, not as a precise constant.

The repaired output is used only if it verifies at least as many claims as the first attempt. The verifier, not the model, decides what is shown as fact.

**Typed claims** let the verifier check structured values (`count`, `start_time`, `end_time`, `user`, `host`, `source_ip`, `event_ids`) directly against the cited facts, instead of relying only on parsing the sentence.

### GPU vs CPU-only, and model size (same prompts: first 2 incidents of each test seed, no repair, 6 incidents)

| Model · mode | Placement (from `/api/ps`) | Mean latency / incident | Tokens/s | Prompt / output tokens | Ollama CPU (share of 20 threads) | Ollama RAM peak | Verified claims |
|---|---|---|---|---|---|---|---|
| **qwen2.5:3b · GPU** (default) | 2.16 GB, 100% in VRAM | **6.4 s** | 91.6 | 2,497 / 496 | about 1% | 0.4 GB (weights in VRAM) | 9 / 14 |
| **qwen2.5:3b · CPU only** | 0 GB in VRAM | **45.6 s** | 15.7 | 2,497 / 417 | about 49% | 2.7 GB | 7 / 12 |
| qwen2.5:1.5b · GPU | 1.17 GB, 100% in VRAM | 3.4 s | 153.5 | 2,497 / 384 | about 5% | 1.0 GB | 3 / 19 |
| qwen2.5:1.5b · CPU only | 0 GB in VRAM | 26.4 s | 27.9 | 2,497 / 460 | about 49% | 1.6 GB | 6 / 24 |

How to read this table:
- **Sample size.** It covers 6 incidents with no repair, so the verification counts are small samples. Compare latency and speed here; for verification, use the 15-incident run above.
- **CPU-only works on this laptop.** The 3B model needs about 46 s per incident and about 2.7 GB of RAM. Ollama used about half of the 20 hardware threads, its default.
- **1.5B model.** It is about 1.7× faster on CPU, but it verified only 16–32% of its claims across the runs, including 15/47 with repair on the full 15 incidents. It is offered as a low-resource option, not the default.
- **7B model** (earlier v6 run, same verifier family): 78% verified, about 10.3 s and 48 tokens/s on GPU, using 2.2× the VRAM of 3B.

**How the sampling was done.** CPU and RAM were sampled every 0.5 s across the Ollama server and the `llama-server.exe` model runner. A first sampling attempt missed the runner process. It was fixed and the CPU runs were repeated with nothing else running.

### Incident chat (`chat_benchmark.py`, demo dataset, 5 incidents × 7 questions)

| | Value |
|---|---|
| Questions | 35 |
| **Silent replies** | **0** (was 6 of 25 in v1) |
| Answered by local Qwen with verified sentences | 20 |
| Answered by the deterministic evidence fallback (labelled) | 6 |
| Explicit "cannot answer from the evidence" | 9, e.g. the attacker's home country |
| Sentences verified | 53 / 54 = 98.1% |
| Mean answer time | 0.8 s |

The deterministic fallback recognises the common analyst intents:
- why the severity is high;
- which devices or accounts are involved;
- what happened next / the timeline;
- which events support the conclusion;
- what contradicts it;
- what to investigate.

It answers by quoting the relevant facts, so its sentences pass the verifier by construction.

**Known limitation:** the verifier is lexical and structural. It does not understand meaning, so an unsupported qualifier phrased in the facts' own words can still pass.

## 6. External attack recordings (real logs)

Fifteen public recordings are analysed one at a time through the normal pipeline. EVTX files go through the offline converter. The sources are:
- **EVTX-ATTACK-SAMPLES** (Samir Bousseaden, GPL-3.0): 13 recordings;
- **OTRF Security-Datasets** (MIT): 2 recordings.

The raw files are not redistributed. `scripts/get_external_data.py` downloads them to `data/public/`.

These datasets label a whole recording with an ATT&CK technique. They do **not** label events or incidents, so **no precision or recall is computed**. The measure is **scenario detection**: did one of the rules expected for that behaviour fire?

| ID | Recording | Technique | Events | Expected | Result |
|---|---|---|---|---|---|
| X01 | Kerberos password spraying (4768/4771) | T1110.003 | 12 | R2/R13 | **Detected** (R2; also R8) |
| X02 | Security log cleared (1102) | T1070.001 | 112 | R8 | **Detected** |
| X03 | System log cleared (104) | T1070.001 | 1 | R8 | **Detected** |
| X04 | Account added to local Administrators (4732) | T1098 | 2 | R6 | **Detected** |
| X05 | LSASS dump via comsvcs MiniDump (Sysmon 1) | T1003.001 | 6 | R7 | **Detected** |
| X06 | SAM hash dump from Meterpreter (Sysmon 10/8 only) | T1003.002 | 9 | R7 | Missed: only process-access events, outside the schema |
| X07 | Local group enumeration (4799) | T1069.001 | 3 | R14 | **Detected** |
| X08 | `net group "Domain Admins"` seen on the target DC (4661) | T1069.002 | 63 | R14 | Missed: object-access events on the DC, no command line |
| X09 | Reverse shell: cmd.exe spawned by svchost (Sysmon 1) | T1059.003 | 4 | R7 | Missed: no pattern for a bare cmd.exe under svchost |
| X10 | Pass-the-hash with Mimikatz (source machine) | T1550.002 | 6 | R7 | Missed: 4688 events without command lines (auditing not enabled) |
| X11 | Mimikatz via PowerShell (script-block logging) | T1003.001 | 33 | R7 | Missed: PowerShell 4104 logs are not analysed |
| X12 | WMI remote execution on the target (4624/4688) | T1047 | 8 | none | Control: no alert raised |
| X13 | Atomic Red Team run captured by Sysmon | multiple | 565 | R7 | **Detected** (3 R7 alerts) |
| X14 | LSASS dump via comsvcs from PowerShell (OTRF) | T1003.001 | 175 | R7 | **Detected** (R7 ×2, R8) |
| X15 | Empire Invoke-Mimikatz (OTRF, in-memory PowerShell) | T1003.001 | 6,026 | R7 | Missed: activity only in PowerShell module logs (4103/800) |

**Summary: 8 of 14 recordings with an expected rule were detected. The control raised no alert.** All six misses come from telemetry SENTINEL does not analyse:
- Sysmon process-access (event 10);
- object access (4661);
- PowerShell script-block and module logs;
- 4688 events without command lines;

and, in X09, one pattern gap.

X01 also raised an R8 alert, because that recording contains a real 1102 log clear. It was not a false alarm.

The EVTX converter parsed all 13 EVTX files with 0 unreadable records.

## 7. Processing performance

All timings are wall-clock measurements on the development laptop (i7-13650HX, 20 threads, 23.7 GB RAM, RTX 4060 Laptop 8 GB). They are not estimates.

### 100k-event scale test (`scale_benchmark.py`, single run, no SLM)

126,919 events (420 accounts × 35 days: 3.6 MB auth CSV + 32 MB endpoint JSON-lines):

| Stage | Seconds |
|---|---|
| Parse (CSV/JSON → frames) | 1.30 |
| Normalise (mapping, timestamps, schema) | 6.87 |
| Ingestion total (incl. merge, dedupe, IDs) | 8.54 |
| Detection (14 rules + baselines) | 8.48 |
| Correlation | 0.03 |
| Severity | < 0.01 |
| Evidence packs | 0.40 |
| **End to end** | **17.45 s (7,272 events/s)** |
| Peak RAM (SENTINEL process) | 529 MB |
| Alerts → incidents | 527 → 5 (2 Critical, 1 High, 1 Medium, 1 Low) |

SLM inference is not run per event. It runs per incident and on demand: about 6–10 s per incident on the GPU, and about 46 s per incident on CPU only, as measured above.

### Typical dataset (1.4k–2.1k events)

| Step | Time |
|---|---|
| Ingestion + normalisation | 0.12–0.24 s |
| Detection + correlation + severity + evidence packs | about 0.25–0.34 s |
