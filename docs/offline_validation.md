# Offline validation

SENTINEL claims offline operation only for runs that were actually recorded. Every run of `scripts/offline_check.py` writes `results/offline_run.json` (latest) and `results/offline_runs/<timestamp>.json`, with these fields:

- `internet_reachable`: probed with one TCP connection attempt to a public DNS resolver, **before** monitoring starts and **after** it ends. The probe is outside the monitored window, so it never shows up as SENTINEL traffic.
- `test_type`: `"offline test"` only when the internet was **not** reachable; otherwise `"online rehearsal"`.
- `monitor.connections`: every remote endpoint opened by the SENTINEL Python process or Ollama processes during the run (sampled every 0.2 s with psutil), classified `loopback` or `EXTERNAL`.
- **Measured** timings, SLM tokens/s, peak RAM and GPU state.

## What the run does

1. Checks the Ollama server and model on 127.0.0.1.
2. Ingests the unseen-format demo logs: a CSV auth export and a JSON-lines EDR export, with the analyst's two mapping corrections.
3. Detects, correlates and scores the incidents, and builds the evidence packs.
4. Runs the **live** local SLM, with no cache, on the top 3 incidents and verifies every sentence.
5. Exports the HTML report of the top incident to `reports/`.
6. Re-runs the accuracy evaluation on the three held-out test seeds.

## Static offline safeguards

| Safeguard | Implementation |
|---|---|
| No CDNs, remote fonts or scripts | Reports use inline CSS only. A test asserts that no `<script src=http…>` or `<link href=http…>` appears and that runtime code contains no external URLs. |
| Streamlit telemetry off | `.streamlit/config.toml`: `gatherUsageStats = false`, server bound to `127.0.0.1` (tested) |
| Model pre-downloaded | `qwen2.5:3b` pulled before the build; `ollama list` shows it; nothing is pulled at runtime |
| Local reference data | `data/mitre.json` and `data/playbooks.json`; MITRE URLs are text only |
| Charts | Altair/Vega-Lite assets ship inside the Streamlit package |
| Dependencies | Installed in `.venv`. Optional: `python -m pip download -r requirements.txt -d wheels/` for a fully offline reinstall |

## Recorded runs

| When (local) | Type | Internet reachable | External connections | Loopback connections | Total time | Peak RAM (SENTINEL / Ollama server) | SLM tokens/s |
|---|---|---|---|---|---|---|---|
| 2026-11-22 22:3x | online rehearsal | yes | **0** | 5 | 40.2 s | 179 MB / 97 MB | 91.6–93.1 |
| *(pending)* | **offline test (Wi-Fi disconnected)** | – | – | – | – | – | – |

> The Ollama server process stays small because the model weights live in GPU memory: `ollama ps` / the monitor page report 100% of qwen2.5:3b in VRAM (about 2.2 GB).

The rehearsal shows that even **with** internet available, the full workflow opened no external connections. The disconnected run is recorded separately, and this table is updated only from its results file.

## How to reproduce

```powershell
# 1. Disconnect Wi-Fi / unplug Ethernet
# 2. Make sure Ollama is running (system tray), then:
.\.venv\Scripts\python.exe scripts\offline_check.py
# 3. Optionally start the dashboard offline and open the "Offline system monitor" page
.\scripts\run.ps1
```
