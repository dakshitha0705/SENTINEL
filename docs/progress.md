# SENTINEL progress log

Times are IST. Build window: 22 Nov 16:30 to 24 Nov 06:00.

## 22 Nov
- 21:35 Environment verified (Python 3.13.5 venv on D:, Ollama 0.40.16 with qwen2.5:3b already on E:, RTX 4060 8 GB, 24 GB RAM). pip cache and temp redirected to `D:\SENTINEL\.cache`.
- Implemented: `config.yaml` + validation, `ingest.py` (CSV / JSON / JSONL, flattening, column mapper, rejects, duplicates, SHA-256), `data/generator.py` (dev, 3 test and 10 stress seeds, ground truth), `baselines.py`, `rules.py` (R1-R8 + 4672 context), `correlate.py`, `severity.py`, `evidence.py`, `verifier.py`, `metrics.py`, `scripts/evaluate.py`.
- Dev-seed tuning (seed 7 only):
  - S5 moved to day 4 so a baseline exists.
  - Low-confidence R4/R5 now score 0, and the -10 penalty applies only when the incident is baseline-driven.
  - Baseline learning lag = max incident span (4 h), which fixed an attack being learned into its own baseline.
- **Held-out test (seeds 101/202/303), first run after freeze:** P 1.0, R 1.0, F1 1.0, FPR 0/21, Jaccard 0.933, severity agreement 1.0.
- **Stress suite (10 out-of-envelope seeds, never tuned on):** P 0.922, R 0.94, F1 0.931, FPR 0.014 (1/70), Jaccard 0.911, severity agreement 0.957.
- Known misses (stress), recorded and not tuned away:
  - Slow brute force below the R1 density threshold. The privilege-change + execution part is still detected as a separate incident, with coverage under 50%.
  - A spray against fewer accounts than the R2 threshold.
  - An approved night-maintenance login (admin, change window) triggered the anomalous-logon composite.

## Next
SLM client + Evidence Contract run, template fallback, HTML report, Streamlit UI, pytest suite.
