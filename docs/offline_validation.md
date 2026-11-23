# Offline validation

SENTINEL claims offline operation only for runs that were actually recorded. Every run of `scripts/offline_check.py` writes `results/offline_run.json` (latest) and `results/offline_runs/<timestamp>.json`, with these fields:

- `internet_reachable`: probed with one TCP connection attempt to a public DNS resolver, **before** monitoring starts and **after** it ends. The probe is outside the monitored window, so it never shows up as SENTINEL traffic.
- `test_type`: `"offline test"` only when the internet was **not** reachable; otherwise `"online rehearsal"`.
- `monitor.connections`: every remote endpoint opened by the SENTINEL Python process or Ollama processes during the run (sampled every 0.2 s with psutil), classified `loopback` or `EXTERNAL`.
- **Measured** timings, SLM tokens/s, peak RAM and GPU state.

## What the run does (v2, 23 Nov)

1. Checks the Ollama server and model on 127.0.0.1.
2. Ingests the unseen-format demo logs: a CSV auth export and a JSON-lines EDR export, with the analyst's two mapping corrections.
3. Detects, correlates and scores the incidents, and builds the evidence packs.
4. Runs the **live** local SLM, with no cache and with the self-repair round, on the top 3 incidents, and verifies every sentence.
5. Asks the incident chat three questions, one of them unanswerable, and counts silent replies (the target is 0). Generates a handoff note and verifies it.
6. Exports the HTML report of the top incident plus JSON/CSV of all incidents.
7. Converts and analyses a public EVTX recording (Kerberos spraying), if it was downloaded.
8. Re-runs the accuracy evaluation on the three held-out test seeds.

`scripts/ui_check.py` complements this. With the dashboard running, it drives it in the local Edge and **aborts and counts every request to a host other than 127.0.0.1/localhost**. It also checks:
- the globe: drag rotates, the wheel zooms in and out, reset restores the default view, and clicking a marker opens its records;
- the attack graph: the wheel zooms, and clicking a node opens the inspector;
- all nine pages, for Streamlit exceptions.

The result is written to `results/offline_ui_check.json`.

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
| 2026-11-23 06:04 | **offline test (Wi-Fi disconnected)** | **no** (before and after) | **0** | 6 | 25.9 s | 181 MB / 342 MB | 91.9–94.0 |
| 2026-11-23 07:21 | online rehearsal, v2 feature set (self-repair, chat fallback, handoff, exports, EVTX) | yes | **0** | 10 | 33.4 s | 185 MB / 103 MB | 90.5–92.3 |
| *(pending)* | **offline test of the v2 feature set (Wi-Fi disconnected)** | – | – | – | – | – | – |

**UI check (online, 23 Nov 07:16):** 0 external requests out of 191 (every non-local request would have been aborted). All 9 pages rendered without exceptions, and all globe and graph interaction checks passed. The disconnected UI check is recorded with the pending offline run.

> The Ollama server process stays small because the model weights live in GPU memory: `ollama ps` / the monitor page report 100% of qwen2.5:3b in VRAM (about 2.2 GB).

The rehearsal shows that even **with** internet available, the full workflow opened no external connections. The disconnected run (`results/offline_runs/20261123_060435.json`) repeated the same workflow with the internet unreachable before and after the run: Ollama and the model loaded from local disk, 3 live SLM explanations completed (verified 3/4, 2/2, 2/4 sentences), the HTML report was written, and the held-out evaluation reproduced P = R = F1 = 1.0. This table is updated only from results files.

## How to reproduce

```powershell
# 1. Disconnect Wi-Fi / unplug Ethernet
# 2. Make sure Ollama is running (system tray), then:
.\.venv\Scripts\python.exe scripts\offline_check.py
# 3. Optionally start the dashboard offline and open the "Offline system monitor" page
.\scripts\run.ps1
```
