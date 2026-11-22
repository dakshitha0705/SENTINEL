# Five-minute offline demo (judging day)

**Before the panel arrives:**
- Laptop charged; Wi-Fi **off**; Ollama running in the tray.
- `.\scripts\run.ps1` started.
- Browser open at `http://127.0.0.1:8501`.
- Run `.\.venv\Scripts\python.exe scripts\offline_check.py` once to warm the model.

**Reset shortcut:** `http://127.0.0.1:8501/?sample=demo_unseen&corrected=1&page=0` loads the demo straight into the queue with the mapping already corrected.

| # | Time | Action on screen | What to say |
|---|---|---|---|
| 1 | 0:00 | Show the Wi-Fi icon (disconnected). Open **Offline system monitor**: model loaded, 100% in VRAM, external connections 0. | "Everything you see runs on this laptop. The model is a 3-billion-parameter Qwen running locally through Ollama; the only connections are to 127.0.0.1." |
| 2 | 0:30 | **Log upload & mapping** → sample `demo_unseen` → *Load sample*. The two files are a SIEM CSV with IST timestamps and an EDR JSON-lines export. | "These are logs in a format SENTINEL has never seen: different column names, Indian Standard Time, one CSV and one JSON-lines." |
| 3 | 0:50 | Open the expander for `siem_auth_export.csv`. Point at the yellow warning; set **actor = Initiated By** and **target_user = Member Added**. | "The mapper guessed most fields from names and value patterns. It warns that group changes have no actor mapped. Without this, an approved change would be flagged. We measured it: precision 0.57 without the correction, 1.0 with it." |
| 4 | 1:15 | *Run analysis* (with "Explain top incidents with local SLM" ticked). Show the validation summary: 1,716 accepted, 0 rejected. | "Every record keeps its file and row. Rejected or duplicate records are listed, never silently dropped." |
| 5 | 1:35 | **Incident queue**: 5 incidents ranked; the severity chart. | "Eight deterministic rules found alerts; the storyline engine grouped them into five incidents, ranked by an explainable score." |
| 6 | 1:50 | Open the top **Critical** incident → **Attack storyline**. Expand one step's evidence rows. | "Each step says why it was linked: same account plus same host, 1.4 minutes later. Weak links on only a shared account are dashed and never raise severity. Here are the original log rows behind this step." |
| 7 | 2:30 | **Severity breakdown** tab. | "100 is not a black box: each factor is listed. Severity is impact; confidence that it is malicious is shown separately." |
| 8 | 2:50 | **Evidence vs. hypothesis** tab. | "The SLM only saw these numbered facts. It must cite a fact ID for every sentence. Our verifier checks each sentence's numbers, times, names, IPs and citations. Here's a sentence it rejected and why. Hypotheses are separate from facts, contradicting evidence is computed by code, and next steps come only from our playbook library." |
| 9 | 3:40 | **Report export** → *Download HTML report* (optionally *Export PDF*). Scroll the preview. | "A self-contained report: verified summary, breakdown, storyline, original log rows, MITRE, actions, verification rate, limitations and file hashes. It opens offline." |
| 10 | 4:10 | **Accuracy & evaluation**. | "Held-out test seeds: 15 of 15 attacks found, 0 of 21 benign look-alikes flagged. Those seeds come from our own generator, so we also ran stress seeds outside the tuned envelope: F1 0.93, with the misses listed here. And about three-quarters of the model's sentences pass verification; the rest are labelled Unverified and kept out of the summary." |
| 11 | 4:40 | **Offline system monitor**: measured latency, tokens/s, the connection table and the recorded offline test. | "Analysis takes under a second; the model explains an incident in about 6 seconds at around 90 tokens per second on this GPU. The recorded offline run shows zero external connections." |

## Likely questions

**Why do you need an SLM if the rules find the attacks?**
The rules produce facts; analysts still have to turn twenty facts into a story, weigh alternatives and decide what to do next. The SLM:
- writes that narrative;
- proposes hypotheses with supporting *and* contradicting facts;
- tailors playbooks to the incident;
- answers follow-up questions.

Because of the Evidence Contract, it can only do this from verified facts.

**Why not a cloud model?**
PS 02 requires offline operation, and real SOCs often cannot send security logs to a third party. A 3B model in 2 GB of VRAM answers in about 6 s on a laptop GPU. We measured a 7B model as well (see the evaluation docs).

**How do you prevent hallucinations?**
1. The model never sees raw logs, only numbered facts.
2. The output is schema-constrained JSON with fact citations.
3. The verifier checks every sentence; anything failing is labelled Unverified and removed from the summary.
4. If the model fails, a deterministic template is used.

Limitation: the verifier is lexical, so it cannot catch every subtly unsupported qualifier.

**How do you correlate events?**
Alerts are processed in time order. They join an incident within a 30-minute gap and 4-hour span when they share 2+ keys (account, host, source IP) — a strong link — or only the account — a weak link. A host or IP alone never links alerts. Every link stores its reason.

**How do you reduce false positives?**
- Per-user baselines with explicit confidence.
- A 4-hour learning lag, so an attack can't become its own baseline.
- Context-only rules: unusual time, new device, 4672, lateral movement.
- Allowlists and approved change windows.
- Seven kinds of benign look-alikes in every dataset to measure it.

**How is severity calculated?**
Rule weights counted once per rule, plus:
- privileged account, critical asset, credential dumping;
- attack-chain completeness;
- log clearing after activity;

minus benign context and low-confidence baselines. Capped at 0–100. Every line is shown.

**How do you know it's accurate?**
Thresholds were tuned on one development seed only. Reported numbers come from three held-out seeds evaluated after the freeze, plus ten stress seeds never tuned on. Incident matching requires at least 50% of the attack's events. We also ran it on public OTRF Windows logs. The honest caveat: the synthetic data is ours, which is why we show the stress failures.

**How is offline operation verified?**
`scripts/offline_check.py` runs the whole workflow, including live SLM inference, with the network disconnected. It logs every remote connection of SENTINEL and Ollama, and records whether the internet was reachable, so a rehearsal can't be passed off as a test. Tests also assert there are no external URLs or connections.

**What happens if the model fails?**
Timeouts, invalid JSON, or an unreachable server fall back to the template explanation, which is fully verified. The pipeline never depends on the model (tested with fake slow and garbage servers).

**What are the limitations?**
- Synthetic evaluation data.
- Slow brute force below the density threshold is missed.
- Lexical verification.
- No PowerShell script-block (4103/4104) analysis.
- R10/R11 are unit-tested only.
- Timestamps without a timezone are assumed to be UTC.

**How is this different from a simple rule-based SIEM?**
- A storyline with reasons instead of an alert list.
- An explainable score with confidence kept separate.
- An evidence-checked natural-language explanation with hypotheses *and* counter-evidence.
- Measured accuracy and verification rate.
- Fully offline on a laptop.
