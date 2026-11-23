# SENTINEL progress log

Times are IST. Build window: 22 Nov 16:30 to 24 Nov 06:00.

## Completed modules (each executed, tested and integrated)

| Module | Status | Tests |
|---|---|---|
| Ingestion + column mapper (`ingest.py`) | Done: CSV/JSON/JSONL, nested flattening, UTC with day-first inference, rejects, duplicates, SHA-256, Sysmon/Security per-row fallbacks | 11 |
| Synthetic generator (`data/generator.py`) | Done: dev 7, test 101/202/303, stress 1001–1010, demo_unseen 2024 | via evaluation |
| Baselines + rules R1–R11 (`baselines.py`, `rules.py`) | Done | 17 |
| Storyline engine + severity (`correlate.py`, `severity.py`) | Done | 9 |
| Evidence pack + verifier (`evidence.py`, `verifier.py`) | Done | 10 |
| SLM client, chat, template fallback (`slm.py`) | Done: qwen2.5:3b on GPU | 3 (+ live benchmarks) |
| HTML/PDF report (`report.py`) | Done (PDF via local Edge) | 1 |
| Perf/offline monitor (`perf.py`, `scripts/offline_check.py`) | Done; online rehearsal recorded | 3 |
| Streamlit app (6 pages) + workspace (SQLite) | Done | 6 (headless render) |
| Evaluation + benchmarks (`scripts/evaluate.py`, `slm_benchmark.py`, `chat_benchmark.py`, `public_sanity.py`) | Done | – |
| Docs (README, architecture, evaluation, traceability, offline, demo, credits) | Done | – |
| Presentation (`scripts/build_pptx.py`) | Built from results files | – |

## Log

### 22 Nov
- **21:35** Environment verified:
  - Python 3.13.5 venv on D:; pip cache and temp on D:.
  - Ollama 0.40.16, qwen2.5:3b already on E:.
  - RTX 4060 8 GB, 24 GB RAM.
- **Core pipeline built.** Dev-seed tuning:
  - S5 scenario placed after baseline history exists.
  - Low-confidence R4/R5 score 0.
  - Baseline learning lag of 4 h, because an attack was learning itself into its baseline.
- **Held-out test (first run after freeze):** P/R/F1 1.0, FPR 0/21.
- **Stress (10 out-of-envelope seeds):** P 0.922, R 0.94, F1 0.931, FPR 0.014.
- **Bugs found by tests and fixed:**
  - empty-file ingestion crash;
  - severity double counting of repeated rules;
  - IP regex missing a trailing full stop.
  - After the double-counting fix, the evaluation was re-run. Test results are unchanged; stress severity agreement went from 0.957 to 0.936, then back to 0.957 after the credential-dumping factor.
- **Public OTRF sanity run exposed:**
  - an overly coarse duplicate key;
  - mixed Sysmon/Security fields;
  - a low score for a lone LSASS dump.
  - All three fixed; test metrics unchanged.
- **Unseen-format demo dataset** (SIEM CSV in IST + EDR JSONL). Added day-first date inference and domain-prefixed group names. Precision 0.571 with auto-mapping only → 1.0 after two manual mappings.
- **Additional rules:**
  - R9 lateral movement: made context-only after an admin false positive in stress seed 1001.
  - R10 bulk copy and R11 USB: unit-tested.
- **SLM:**
  - Prompt iterated on dev outputs only.
  - Fixed a repetition loop with length limits, a repeat penalty and a retry seed.
  - Fixed an empty chat reply caused by an over-tight citation cap.
  - Verifier made per-sentence, with dates and a no-content check.
- **Performance:** detection optimised 0.47 s → 0.20 s for 1.9k events.
- **Verifier strengthened:**
  - EVT-/ALR-/INC- identifiers named in a sentence must belong to the cited facts. Found from a chat screenshot citing alert IDs.
  - Content-free sentences are rejected.
  - Neutral filler words no longer count against grounding.
- **SLM benchmarks** regenerated from scratch on the final prompt (v6) and verifier, with no cache. Each benchmark is run with nothing else on the machine, because a concurrent test run measurably lowered tokens/s.
- **Extras:** wheels for an offline reinstall downloaded to `wheels/` (132 MB, git-ignored). A clean clone of the repository passes the tests.
- **Encoding:** PowerShell `Set-Content` corrupted UTF-8 in 4 files (mojibake); repaired with Python.

### 23 Nov (upgrade)
- **06:04** Disconnected offline test recorded by the participant: internet unreachable, 0 external connections (`results/offline_runs/20261123_060435.json`). Checkpoint commit + tag `checkpoint-pre-upgrade`; work continued on branch `upgrade`.
- **Detection:** R12 sustained brute force, R13 small spray, R3 up to 60 min with decaying weight and a derived causal link, R14 group discovery (T1069; context). Tuned on dev seed 7 (+ B8–B10) and the stress seeds, which are now labelled diagnostic.
- **Fresh held-out seeds 5001–5010** generated after the freeze: P 0.942, R 0.980, F1 0.961, FPR 0.030. The v1 detector on the same files scored F1 0.879. Failures are listed in `evaluation.md`.
- **EVTX converter** (offline, `evtx` package) and the **external evaluation** (13 EVTX-ATTACK-SAMPLES + 2 OTRF recordings): 8/14 detected, misses explained.
- **Comparison:**
  - naive detector: 1,651 items, strict F1 0.058;
  - ablation: no baselines 0.797, no allowlists 0.889, no context 0.341, full 0.970;
  - alert compression 88.3%.
- **Evidence Contract v7:** typed claims and one bounded self-repair round (73% → 83% verified). Chat gets a deterministic evidence fallback (0 silent replies in 35 questions). Handoff notes added.
- **Verifier bug** found by a new test: tokens like "LOW-CONFIDENCE" that appear in the cited fact were rejected as unknown host names. Fixed.
- **Benchmarks:**
  - qwen2.5:3b CPU-only, about 46 s per incident vs about 6 s on GPU; placement confirmed by `/api/ps`;
  - qwen2.5:1.5b pulled (986 MB, to E:): fast but low verification;
  - 126,919-event scale test: 17.5 s, 529 MB.
- **Benchmark harness issues found and fixed:**
  - Ollama reused a CPU-loaded runner for a "GPU" run; caught by the placement check, fixed by unloading models first.
  - The CPU sampler missed `llama-server.exe` (the model runner) and used fresh process objects each tick.
- **New UI:** 9 pages; interactive offline globe (globe.gl/three.js, bundled) and attack graph (vis-network, bundled); global search, dataset and time filters; analyst status/notes/dispositions; Report Studio; System & Settings. Browser check: 0 external requests; globe and graph interactions pass.

## Outstanding

- **Disconnected re-test of the v2 feature set.** The participant turns Wi-Fi off; then run `scripts/offline_check.py` and `scripts/ui_check.py`, and update `docs/offline_validation.md`. The v1 disconnected test is done (06:04).
- **Push to GitHub** and check the public link (needs the user's authorisation).
- **Official PPT format and submission form** have not been released yet.

## Known limitations

See README → Limitations and `docs/evaluation.md`.
