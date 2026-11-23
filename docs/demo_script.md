# Five-minute offline demo (judging day)

## Before the panel arrives (about 10 minutes before)

1. Get the laptop ready:
   - Plug the laptop in.
   - Make sure Ollama is running in the tray.
   - Turn Wi-Fi **off**.
2. Run `powershell -ExecutionPolicy Bypass -File scripts\start_demo.ps1`. All three checks must say *healthy*.
3. Open the browser tabs and windows:
   - **Tab 1:** SENTINEL live, `http://127.0.0.1:8501/?live=1`.
   - **Tab 2:** NEXUS portal, `http://127.0.0.1:8502/login`.
   - **Tab 3:** the scenario controller, `http://127.0.0.1:8502/demo`. Keep it side by side with Tab 1 if you can.
4. In the controller, press **Start demo**. This starts a new session with 231 synthetic baseline logons.
5. Warm the model: run `.\.venv\Scripts\python.exe scripts\offline_check.py` once, or explain any incident in the AI Investigation Lab.
6. Keep this document open, along with a NEXUS password from the controller's identity table (for example `arjun.rao`).

## The five minutes

| # | Time | Action on screen | What to say |
|---|---|---|---|
| 1 | 0:00–0:30 | **Tab 1, Command Center.** Point at the chips: *0 external connections*, *qwen2.5:3b ready*, *LIVE MONITORING*. Drag the globe, scroll to zoom, then press *Reset view*. | "Everything runs on this laptop with Wi-Fi off: the dashboard, the detection engine, and a 3-billion-parameter Qwen model. The globe only shows locations the logs themselves contain; it never guesses from an IP address." |
| 2 | 0:30–1:00 | **Tab 2, NEXUS.** Log in as `arjun.rao` with the password from the controller, open the dashboard, log out. Back in Tab 1, the live event stream shows the 4624/4634 events tagged `[APP]`. Optionally press **A · Normal activity** in the controller. | "NEXUS is a fictional company portal. Every sign-in it handles is written as a security event and streamed to SENTINEL. Normal activity produces events, not incidents." |
| 3 | 1:00–1:45 | **Tab 3:** press **G · Complete attack storyline**. Watch the step log, then switch to Tab 1. In about 15 s the mode strip turns to **INCIDENT INVESTIGATION** and a toast appears. | "This controller sends real HTTP logins to NEXUS from a simulated attacker address: brute force, then a successful logon, sensitive pages, a self-add to Administrators. The endpoint steps (encoded PowerShell, log clearing) are synthetic and clearly labelled; nothing is executed. SENTINEL reads the stream incrementally and re-detects in under a couple of seconds." |
| 4 | 1:45–2:30 | **Tab 1:** severity panel and urgent incident (Critical 100); the detection latency in the mode strip. Click **Investigate**, then show the *Attack storyline* and *Severity breakdown* tabs. | "Six rules fired. The storyline engine chained them because they share the account, the host and the source, in time order. Each link says why. The score is a list of factors, not a black box, and the incident was detected about a second after its triggering event." |
| 5 | 2:30–3:30 | **Evidence** tab: open the original NEXUS record (`event_uid`, `origin`). **AI Investigation Lab** → *Explain with local Qwen*, then *Ask SENTINEL*: "What happened after the successful logon?" | "Qwen only sees numbered facts and must return typed claims. The verifier checks every count, time, user, host and IP against the cited facts; failures are sent back once, and anything still failing stays Unverified. The chat answer cites the fact on the right." |
| 6 | 3:30–4:15 | **Evaluation & Benchmarks:** *Accuracy* (fresh held-out F1 0.961, FPR 0.03); *Naive & ablation* (1,651 items vs 67); *External recordings* (8 of 14). | "Accuracy is measured on held-out data generated after we froze the detector, and on 14 public attack recordings. Their misses are listed: telemetry we don't read yet." |
| 7 | 4:15–5:00 | **Report Studio:** *Download HTML report* or *Export PDF*; scroll to the handoff note. | "One click gives a self-contained report with only verified statements, the original rows and file hashes. That's live detection, investigation and reporting, fully offline." |

## Fallbacks

| Problem | What to do |
|---|---|
| Live services do not start, or NEXUS is unreachable | **Use upload mode.** Pick `demo_unseen` in the dataset selector (its mapping profile is applied automatically) and run steps 4–7 on its Critical incident. Say: "The same engine on a recorded export." Detection, correlation and reporting code are identical in both modes. |
| The incident does not appear within about 20 s | Check the controller panel. If *ingested by SENTINEL* is not increasing, the worker is not running. Run `scripts\start_demo.ps1` again; it starts only what is missing. The dashboard also falls back to an in-process engine automatically. |
| Local inference is slow or Ollama is down | Press **Deterministic template**. It is built from the facts and verified by construction. Detection and reports do not depend on the model. If the model was used earlier in the session, its cached explanation is reused. |
| A scenario was run twice, or incidents merged | Press **Reset demo session** (it affects only `demo_data`), then **Start demo**, then run the scenario again. |
| The globe renders slowly | Switch the *Quality* toggle to *low*. |

## Likely questions

**Is the attack real?**
The NEXUS authentication, access and group-change events are produced by NEXUS's own code handling real HTTP requests. The attacker's address is simulated and flagged. The process and log-clearing events are synthetic and labelled `simulated-endpoint`, because running them for real on a laptop would be unsafe. SENTINEL's processing of all of them is genuine; no incident is pre-written.

**How fast is detection?**
We measured 0.7–1.3 s from the triggering event to the incident when the laptop is not also rendering a headless browser. Under heavy load it was up to about 5 s.

**Why do you need an SLM if the rules find the attacks?**
The rules produce facts. The model:
- turns them into a narrative;
- weighs supporting and contradicting evidence;
- tailors the playbooks;
- answers questions.

The Evidence Contract stops it from adding facts.

**How do you prevent hallucinations?**
- Typed claims, verified against the cited facts.
- One bounded repair round.
- Anything still failing is labelled Unverified.
- Deterministic fallbacks.

Limitation: the verifier is lexical and structural, not semantic.

**How do you know it's accurate?**
- Tuning used the development seed only.
- Ten fresh seeds were generated after the freeze.
- We also ran public EVTX and OTRF recordings, which carry technique labels only.
- We compared against a naive detector and ran an ablation study.

All of it is in `docs/evaluation.md`.

**Can it run without a GPU?**
Yes. qwen2.5:3b on CPU only takes about 46 s per incident (measured); the deterministic pipeline is unaffected.

**Limitations?**
- The labelled data is synthetic.
- The live endpoint events are simulated.
- No PowerShell script-block or Sysmon process-access analysis.
- The verifier is lexical.
- There is no IP geolocation, by design.
