# Five-minute offline demo (judging day)

**Before the panel arrives:**
- Laptop charged; Wi-Fi **off**; Ollama running in the tray.
- `.\scripts\run.ps1` started.
- Browser open at `http://127.0.0.1:8501`.
- Warm the model once: run `.\.venv\Scripts\python.exe scripts\offline_check.py`, or press *Run Analysis* in the Command Center.

**Reset shortcut:** `http://127.0.0.1:8501/?sample=demo_unseen&page=0` reloads the demo dataset (its saved mapping profile is applied) and opens the Command Center.

| # | Time | Action on screen | What to say |
|---|---|---|---|
| 1 | 0:00 | **Command Center.** Point at the chips: *Offline-safe*, *qwen2.5:3b ready*. Drag the globe, scroll to zoom, press *Reset view*. Click the Tokyo marker. The records panel opens; click *Investigate INC-…*. | "Everything here runs on this laptop with Wi-Fi off. The globe only shows locations the logs themselves contain: this SIEM export has geo-enrichment columns. When logs have no coordinates, the globe switches to exploration mode and places nothing. We never guess a location from an IP." |
| 2 | 0:30 | **Log Intelligence.** Show the two unfamiliar files (SIEM CSV in IST, EDR JSON-lines). Open the mapping: *Initiated By → actor*, *Member Added → target_user* (saved profile). Optionally upload `kerberos_pwd_spray_4771.evtx` → *Use uploaded files* → *Run analysis*: EVTX converted offline, spraying detected. | "SENTINEL maps unseen schemas: it guesses from names and value patterns and warns when a field rules need is missing. Without these two mappings precision was 0.57; with them, 1.0. EVTX is converted locally too." |
| 3 | 1:15 | **Incident Investigation.** Top Critical incident → *Attack storyline*, then *Severity breakdown*, then *Evidence* (events behind a fact, original record). | "Each step says *why* it joined: same account plus same host, minutes later. A host or IP alone never links. A success 40 minutes after failures still links, with less weight, and is labelled 'not confirmed compromise'. The score is a list of factors, not a black box." |
| 4 | 2:00 | **Attack Graph** (optional, 15 s): click the incident node, then *Open investigation*. | "Every edge here comes from the correlation engine." |
| 5 | 2:15 | **AI Investigation Lab.** *Explain with local Qwen* (streams). Show the self-repair card and the verified / unverified labels. Then *Ask SENTINEL*: "Why is the severity high?", and "What is the attacker's home country?" | "The model sees only numbered facts and must return typed claims: counts, times, users, hosts. The verifier checks each one. Failing claims go back to the model once with the exact errors, and whatever still fails stays Unverified. On held-out incidents that lifted verified claims from 73% to 83%. Chat never goes silent: if the model can't give a verifiable answer, SENTINEL answers from the facts, or says what is missing." |
| 6 | 3:00 | **Evaluation & Benchmarks.** *Accuracy* → before/after table; *Naive & ablation*; *External recordings*. | "On ten fresh held-out seeds generated after the freeze: F1 0.96, false-positive rate 3%. The upgrade raised fresh F1 from 0.88. A naive detector finds the attacks but hands the analyst 1,651 alerts; SENTINEL gives 67 incidents, 88% fewer. On 14 real public attack recordings, 8 are detected. The 6 misses are telemetry we don't analyse, such as PowerShell script-block logs, and we list them." |
| 7 | 3:45 | *Local SLM* tab, then *Scale & performance*; then **System & Settings → Offline validation**. | "Limited compute: the same 3B model runs CPU-only at about 46 s per incident, against about 6 s on this GPU. The deterministic pipeline processed 127,000 events in 17 seconds with 529 MB of RAM. Here is the recorded disconnected run: zero external connections." |
| 8 | 4:30 | **Report Studio.** *Download HTML report* (or *Export PDF*); scroll the preview to the handoff note. | "A self-contained report with only verified statements, the storyline, original log rows, MITRE, actions, a shift-handoff note and file hashes. JSON and CSV exports are here too. That's an analyst's triage done offline, with every claim traceable to a log line." |

## Likely questions

**Is the globe real data?**
Only coordinates present in the logs are plotted: here, the SIEM export's source and device geo columns. The demo dataset is synthetic, and its external addresses are documentation IP ranges with illustrative locations. Arcs are individual logged events of an incident whose source and device locations differ. Without location columns the globe shows nothing, and it says so.

**Why do you need an SLM if the rules find the attacks?**
The rules produce facts. The SLM:
- turns those facts into a narrative;
- proposes hypotheses with supporting *and* contradicting facts;
- tailors playbooks to the incident;
- answers questions.

Because of the Evidence Contract, it can only do this from verified facts.

**How do you prevent hallucinations?**
- The model never sees raw logs.
- Its claims are typed, and every typed value and sentence is verified.
- One bounded repair round runs with the exact errors.
- Anything still failing is labelled Unverified and kept out of the summary.
- If the model fails, a deterministic template or answer is used instead.

Limitation: the verifier is lexical and structural, so it cannot understand meaning.

**Does self-repair always help?**
No, so we measured it: 73% → 83% in the saved run, and 77% → 87% in an earlier run. The repaired output is kept only if it verifies at least as many claims.

**Can it run without a GPU?**
Yes. CPU-only is measured, with placement confirmed by Ollama (0 bytes in VRAM). The 1.5B model is faster but verified far fewer claims, so 3B stays the default.

**How do you know it's accurate?**
- Tuning used the development seed only.
- The test seeds were held out at the first freeze.
- Ten fresh seeds were generated after the upgrade freeze; their failures are listed in the docs.
- We also ran 15 public attack recordings. They only carry technique labels, so we report scenario detection, not precision.

**What did the ablation show?**
Every design element helped on this data. Context handling matters most: without it, there are 316 items and half the look-alikes are flagged. Baselines drive recall, and allowlists cut false positives.

**How is offline operation verified?**
- `offline_check.py` runs the whole workflow with the network disconnected and logs every remote connection.
- `ui_check.py` drives the dashboard in a browser that aborts every non-local request and counts them: 0.

**Limitations?**
- Synthetic labelled data.
- External recordings give scenario detection only.
- No PowerShell script-block or Sysmon process-access analysis.
- The verifier is lexical.
- No IP geolocation database (by design).
- Timestamps without a timezone are treated as UTC.
