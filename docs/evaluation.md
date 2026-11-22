# Evaluation

Every number here comes from `results/metrics.json` (written by `python scripts/evaluate.py`) or `results/slm_benchmark_*.json` (written by `python scripts/slm_benchmark.py`). The synthetic data is regenerated deterministically by the same script, so the numbers can be reproduced.

> **Read this first: what these numbers mean.**
> The labelled datasets come from SENTINEL's own synthetic generator, written by the same author as the rules. High scores on the test seeds show that the detector generalises across users, timings and attack speeds *within the attack styles it was designed for*. They are **not** a measurement of real-world accuracy. The stress suite (below) and the public-data sanity run are there to expose where the design breaks.

## 1. Datasets

| Set | Seeds | Purpose | Used for tuning? |
|---|---|---|---|
| Development | 7 | Threshold and scoring decisions | **Yes**, the only tuning set |
| Held-out test | 101, 202, 303 | Reported accuracy | No. Evaluated after the detector was frozen |
| Stress | 1001–1010 | Out-of-envelope attack parameters: slow brute force, small sprays, long gaps between steps | No. Generated after the freeze, never tuned on |
| Demo (unseen format) | 2024 | Column-mapper demonstration (SIEM-style CSV with IST timestamps + EDR JSON-lines) | No |
| Public sanity | OTRF Security-Datasets | Real Windows logs (no labels) | No. Qualitative only |

Each synthetic dataset has 1,437–1,936 events over 7 days, 23–29 accounts (regular, night-shift, admin, service) and 21–24 hosts. Each one contains:

- **5 attack scenarios:**
  - S1: brute force → logon → local admin add → encoded PowerShell + certutil
  - S2: password spraying (sometimes with a success)
  - S3: insider self-adds to Domain Admins
  - S4: Mimikatz + audit-log clearing with admin02 credentials
  - S5: off-hours logon from an unfamiliar address
- **7 benign look-alikes:**
  - B1: approved night maintenance
  - B2: 2–3 password typos
  - B3: new laptop rollout
  - B4: approved group change in the change window
  - B5: legitimate admin PowerShell script
  - B6: forgotten password, 5–7 retries
  - B7: scheduled service-account backup at night

Labels live in `ground_truth.json` / `labels.csv` and are never read by the detector.

## 2. Matching procedure (fixed before evaluation)

- **Event mapping:** events are mapped to ground truth through their source record ID (`EventRecordID`).
- **Match:** a detected incident **matches** a ground-truth attack when it contains **at least 50%** of that attack's events.
- **False positive:** a detected incident that matches no attack.
- **Benign flagged:** a benign look-alike counts as **flagged** when *any* detected incident contains *any* of its events. This is deliberately strict.
- **Incident precision** = matched detections / all detections. **Recall** = attacks matched / all attacks. **FPR** = flagged look-alikes / all look-alikes.
- **Correlation quality** = Jaccard overlap between a matched incident's events and the attack's events.
- **Severity agreement** = detected level equals the level the scenario author assigned before evaluation (S1 Critical, S2 Medium, or High when a spray login succeeds, S3 High, S4 Critical, S5 Low).

## 3. Results

### Held-out test seeds (101, 202, 303)

| Metric | Value |
|---|---|
| Attacks / benign look-alikes | 15 / 21 |
| Incident precision | **1.000** (15/15) |
| Incident recall | **1.000** (15/15) |
| F1 | **1.000** |
| False-positive rate (look-alikes) | **0.000** (0/21) |
| Correlation quality (mean Jaccard) | 0.933 |
| Severity agreement | 1.000 |
| Event-level precision / recall | 1.000 / 0.977–0.980 |

The one missed malicious event per seed is the insider's `net group "Domain Admins" /domain` reconnaissance command. No rule targets it, and that is also why S3's Jaccard is 0.667.

### Stress seeds (1001–1010): out-of-envelope, never tuned on

| Metric | Value |
|---|---|
| Attacks / benign look-alikes | 50 / 70 |
| Incident precision | **0.922** (47/51) |
| Incident recall | **0.940** (47/50) |
| F1 | **0.931** |
| False-positive rate | **0.014** (1/70) |
| Correlation quality | 0.911 |
| Severity agreement | 0.957 |

Failure analysis:

| Seed | What happened | Cause |
|---|---|---|
| 1005, 1007 | S1 missed: the brute-force burst was spread out | The failure density stayed below R1's 8-in-10-minutes threshold, so there was no R1 and no R3. The privilege change + PowerShell were still detected as a separate Critical/High incident, but it covers under 50% of the attack's events, so it counts as one miss plus one unmatched detection. |
| 1007 | S2 missed | The spray hit fewer accounts than R2's threshold of 5 |
| 1006 | B1 (approved admin night maintenance) flagged as a Low "anomalous logon" | admin01's baseline did not yet include the maintenance workstation/IP; the change-window context is not applied to the R4+R5 composite |
| 1009 | Low/Medium anomalous-logon incident for admin02 with no matching attack | Legitimate admin activity at an unusual hour from a new host |
| 1006, 1008 | S2 (spray *with* a successful logon) scored Medium instead of High | The success came more than R3's 15-minute window after the failures, so R3 did not fire: detected as spraying, but the access was not linked |

These were **not** tuned away. They are the trade-offs of the current thresholds.

### Format robustness

The same test seed (101) gives identical results via `auth CSV + endpoint JSON-lines`, `JSON only` and `CSV only` (P = R = F1 = 1.0, FPR = 0).

### Column-mapper demonstration (demo_unseen, seed 2024)

| Mapping | Precision | Recall | FPR |
|---|---|---|---|
| Automatic guesses only (actor/member columns unmapped) | 0.571 | 0.80 | 0.143 |
| After the analyst maps "Initiated By" → actor and "Member Added" → target_user | 1.000 | 1.000 | 0.000 |

The UI warns when group-membership events are present but the actor/member columns are unmapped.

### Per-rule alert precision (test seeds, event level)

| Rule | Alerts | Flagged events | Malicious share |
|---|---|---|---|
| R1 Brute force | 3 | 63 | 1.00 |
| R2 Password spraying | 3 | 36 | 1.00 |
| R3 Logon after failures | 4 | 4 | 1.00 |
| R4 Unusual time (context only) | 32 | 32 | 0.34 |
| R5 New device/IP (context only) | 50 | 50 | 0.32 |
| R6 Privileged group change | 6 | 6 | 1.00 |
| R7 Suspicious process | 12 | 12 | 1.00 |
| R8 Audit log cleared | 3 | 3 | 1.00 |

R4 and R5 are noisy on their own, as expected. That is why they are context-only and never create an incident by themselves, except as the R4 + R5 "anomalous logon" composite with a confident baseline.

## 4. Evidence validity (SLM output)

`scripts/slm_benchmark.py` runs the local SLM (qwen2.5:3b, Q4_K_M) on every incident and verifies each output sentence. No cache was used.

| Dataset | Incidents | SLM answers / fallbacks | Factual sentences | Verified | Rate | Mean latency | Mean tokens/s |
|---|---|---|---|---|---|---|---|
| test_seed101 | 5 | 5 / 0 | 13 | 10 | 0.769 | 6.0 s | 90.3 |
| test_seed202 | 5 | 5 / 0 | 17 | 13 | 0.765 | 6.4 s | 90.9 |
| test_seed303 | 5 | 5 / 0 | 14 | 8 | 0.571 | 6.6 s | 91.1 |
| **Total (test, final prompt v6 + final verifier)** | 15 | 15 / 0 | 44 | **31** | **0.705** | ~6.3 s | ~91 |

**Run-to-run variation is real.** GPU inference is not bit-deterministic even with a fixed seed. Fresh runs of the same final configuration today gave 0.705 and 0.800 (44/55) on the same 15 incidents; earlier prompt versions gave 0.733 and 0.771. Treat the rate as roughly **70–80%**, not a precise constant. The latest run is saved in `results/slm_benchmark_*.json`.

Unverified sentences are **not** shown as facts. They are moved to an "Unverified" section with the failing checks. Typical failures were:
- a count that does not appear in the cited facts;
- a sentence cut off at the length limit;
- a sentence citing no fact;
- a vague claim with no content overlap with its citations.

The deterministic template explanation verifies at 100% by construction and is used when the SLM is unavailable.

**Incident chat** (`scripts/chat_benchmark.py`, demo dataset, 5 incidents × 5 questions, including one unanswerable question: "attacker's home country"):
- 15 of 18 answer sentences verified (0.833).
- 6 of 25 questions got no answer from the model; the UI says so.
- Mean answer time 0.6 s.
- The model declined the unanswerable question and did not follow an embedded instruction to call the incident benign (manual check).

**Known limitation:** the verifier checks citations, numbers, times, dates, users/hosts/IPs, lexical grounding and overclaiming phrases. It does **not** understand meaning, so an unsupported qualifier phrased in the facts' own words can still pass. Example seen: "…without prior warning or escalation controls in place."

### Model choice: 3B vs 7B (same prompt, same 15 test incidents, both fully in VRAM)

| Model | Verified / factual sentences | Rate | Mean latency | Mean tokens/s | VRAM |
|---|---|---|---|---|---|
| **qwen2.5:3b** (selected) | 31 / 44 | 0.705 (0.80 in another run) | **~6.3 s** | **~91** | ~2.2 GB |
| qwen2.5:7b | 32 / 41 | 0.780 | ~10.3 s | ~48 | ~4.8 GB |

Same final prompt (v6) and verifier. Across all runs the two models overlap: 3B 0.70–0.80, 7B 0.76–0.78. The 7B model may verify slightly better on average, but it takes about 1.7× the time and about 2.2× the VRAM. The prompt was developed against the 3B model's dev-seed outputs, which may favour 3B slightly. The 3B model stays the default for responsiveness on a laptop; `config.yaml → slm.model` switches models without code changes.

## 5. Processing performance

These are measured by the scripts: wall-clock time on the development laptop (i7-13650HX, 24 GB RAM, RTX 4060 Laptop 8 GB). They are not estimates. See `docs/offline_validation.md` for the offline run.

| Step | Typical time (1.4–1.9k events) |
|---|---|
| Ingestion + normalisation (2 files) | 0.12–0.15 s |
| Detection + baselines | ~0.20 s for 1,865 events (0.47 s before the R4/R5 optimisation) |
| Correlation + severity + evidence packs | ~0.05 s |
| **Whole deterministic analysis** | **~0.25 s** (all timings grow several-fold if the CPU is busy, e.g. during concurrent model inference) |
| SLM explanation per incident (GPU) | 5.9–7.5 s, about 90–95 tokens/s, 100% of the model in VRAM |
| Model size | qwen2.5:3b Q4_K_M, 1.93 GB on disk, about 2.2 GB VRAM when loaded |
