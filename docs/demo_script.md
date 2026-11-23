# Five-minute offline demo (judging day)

Click-by-click version for presenters: [user_guide.md](user_guide.md).

## Before the panel arrives (about 10 minutes before)

1. Get the laptop ready:
   - Plug the laptop in.
   - Make sure Ollama is running in the tray.
   - Turn Wi-Fi **off**.
2. Run `powershell -ExecutionPolicy Bypass -File scripts\start_demo.ps1`. Both health checks must say *healthy*.
3. Open **http://127.0.0.1:8501/?live=1**. The top bar must show **LIVE · monitoring**.
4. **Live Demo → New demo session.** This starts an empty session with 7 days of labelled synthetic baseline sign-ins.
5. Switch on **Presentation mode** on the Live Demo page. It shows the eight steps and ticks each one only when it really happens.
6. Warm the model: explain any incident once (**Investigation Studio → AI investigation → Explain with local Qwen**), or run `scripts\offline_check.py`.
7. Copy an employee password: **Live Demo → Demo accounts**, then *Copy* next to `arjun.rao`. Keep that panel closed while sharing the screen.

## The five minutes

| # | Time | Action on screen | What to say |
|---|---|---|---|
| 1 | 0:00–0:30 | **Command Center.** The story card, the globe (drag, zoom, *Reset view*), the four counters. Open the **System status** button (top right): 0 external connections, qwen2.5:3b ready. | "Everything runs on this laptop with Wi-Fi off: the dashboard, the detection engine and a 3-billion-parameter Qwen model. The globe only shows locations the logs contain; it never guesses from an IP address." |
| 2 | 0:30–1:00 | **Live Demo → Open NEXUS login.** Sign in as `arjun.rao`, then sign out. Presentation mode ticks *Demonstrate a normal login*. | "NEXUS is a fictional company portal. Every sign-in it handles is written as a security event and streamed to SENTINEL. Normal activity produces events, not incidents." |
| 3 | 1:00–1:45 | **Live Demo → Start the full attack.** Watch *events generated* vs *events ingested* and the scenario steps. | "The controller sends real HTTP logins to NEXUS from a simulated attacker address: brute force, a successful login, sensitive pages, a self-add to Administrators. The endpoint steps (encoded PowerShell, log clearing) are synthetic and labelled; nothing is executed." |
| 4 | 1:45–2:30 | Notifications: **New incident detected**, then **Incident escalated** Low → Medium → Critical. Open the bell → **Investigate**. | "SENTINEL raised one incident and escalated it as each new piece of evidence arrived, about a second after the triggering event. It detects and escalates; it does not block." |
| 5 | 2:30–3:30 | **Investigation Studio:** *Story* (open a stage; *Playback*), *Evidence* (the original NEXUS record), then **AI investigation → Explain with local Qwen** and **Ask SENTINEL** → *Why is this incident critical?* | "Qwen only sees numbered facts and must return typed claims. The verifier checks every count, time, user, host and IP; failures go back once, and anything still failing stays unverified. Hypotheses are kept apart from facts." |
| 6 | 3:30–4:15 | **Reports & Evaluation → Evaluation:** *Accuracy* (fresh held-out F1 0.961, FPR 0.03); *Naive & ablation*; *External recordings* (8 of 14). | "Accuracy is measured on held-out data generated after we froze the detector, and on 14 public attack recordings. The misses are listed." |
| 7 | 4:15–5:00 | **Reports & Evaluation → Report → Download HTML report.** Scroll to the handoff note. | "One click gives a self-contained report with only verified statements, the original records and file hashes. Live detection, investigation and reporting, fully offline." |

## Fallbacks

| Problem | What to do |
|---|---|
| Live services do not start, or NEXUS is unreachable | **Use upload mode.** Pick `demo_unseen` in the dataset selector (its mapping profile is applied automatically) and run steps 4–7 on its Critical incident. Say: "The same engine on a recorded export." Detection, correlation and reporting code are identical in both modes. |
| The incident does not appear within about 20 s | Check Live Demo: if *events ingested by SENTINEL* is not increasing, or the top bar says *detection stopped*, the worker is not running. Run `scripts\start_demo.ps1` again; it starts only what is missing. The dashboard also falls back to an in-process engine automatically. |
| Local inference is slow or Ollama is down | Press **Deterministic template**. It is built from the facts and verified by construction. Detection and reports do not depend on the model. If the model was used earlier in the session, its cached explanation is reused. |
| A scenario was run twice, or incidents merged | **Live Demo → New demo session** (it affects only `demo_data`), then run the scenario again. |
| The globe renders slowly | Press *Rotate* to stop the auto-rotation; the rest of the page is unaffected. |

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
