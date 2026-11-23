# Live attack demonstration: NEXUS → SENTINEL

SENTINEL can watch a running application and detect an attack while it happens. For the demo, the application is **NEXUS, a fictional Corporate Access Portal**. It runs on this laptop only and generates real security events from its own code.

```
NEXUS portal (Flask, 127.0.0.1:8502)        scenario controller (/demo, bounded scripts)
        │  real HTTP logins / page access / group changes        │ synthetic endpoint events (labelled)
        ▼                                                         ▼
 demo_data/sessions/<session>/events.jsonl   (append-only JSON-lines, fsync per event)
        │  durable byte-offset cursor, complete lines only, de-duplicated by event_uid
        ▼
 live worker  (python -m sentinel.live, separate process, polls every 0.5 s)
        │  normal SENTINEL ingestion → rules → storyline → severity → evidence packs
        ▼
 live snapshot (demo_data/live_snapshot.pkl) + sentinel_status.json
        │                                                         │
        ▼                                                         ▼
 SENTINEL dashboard (127.0.0.1:8501/?live=1)        NEXUS controller live status panel
        └─ local Qwen explanation, Evidence Contract, chat, handoff, reports (same code as upload mode)
```

## Running it

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_demo.ps1   # checks venv + Ollama, starts NEXUS, worker, SENTINEL
# SENTINEL live:        http://127.0.0.1:8501/?live=1
# NEXUS portal:         http://127.0.0.1:8502/login
# scenario controller:  http://127.0.0.1:8502/demo
powershell -ExecutionPolicy Bypass -File scripts\stop_demo.ps1    # stops ONLY the processes recorded in demo_data\pids.json
```

The start script records the processes it starts in `demo_data\pids.json` and does not start duplicates. It does not need internet. It launches the services through `Win32_Process.Create`, so it also returns when its own output is captured. Logs are written to `demo_data\logs\`.

## Where events come from (provenance)

Every event carries `origin`, `simulated` and `source_address_simulated` fields. Reports and the dashboard keep these labels.

| `origin` | Produced by | Examples | `simulated` |
|---|---|---|---|
| `nexus-app` | NEXUS application code handling a real HTTP request | 4624 logon, 4625 failure, 4634 logoff, 4740 lockout, 4732 group member added, 4663/4656 resource access (allowed/denied) | false |
| `simulated-endpoint` | The scenario controller writes these directly. **Nothing is executed and no log is cleared.** | 4688 process start (encoded PowerShell, certutil, wevtutil), 1102 audit log cleared | true |
| `baseline-backfill` | Seven days of synthetic prior logons (three per account per day, 07:30–22:30 IST; the service account around the clock), written when a session starts, so per-user baselines exist | 4624 | true |

**Attacker addresses.** Attacker addresses come from RFC 5737 documentation ranges (`203.0.113.x`, `198.51.100.x`, `192.0.2.x`). The controller supplies them in a header, which NEXUS honours only together with the controller's per-process secret token. Those events are flagged `source_address_simulated: true`. A normal browser cannot choose its address; it is recorded as `127.0.0.1`.

**Locations.** Coordinates come from a documented fixed table in `demo_target/events.py`: fictional company sites, plus illustrative locations for the documentation ranges. Addresses that are not in the table, such as `127.0.0.1`, get no location.

**Event IDs.** The Windows-style event IDs are NEXUS-generated, Windows-*style* records. They are not emitted by the Windows operating system.

## Event schema

Each event has these provenance and bookkeeping fields:

| Field | Meaning |
|---|---|
| `event_uid` | Unique ID: `NX-<session>-<seq>` |
| `EventRecordID` | Per-session sequence number |
| `TimeCreated` | Time the event describes (UTC) |
| `emitted_at` | Wall-clock time it was written; used for latency |
| `EventID`, `event_type`, `source_app`, `origin`, `simulated`, `source_address_simulated` | What happened and where the record came from (see above) |
| `scenario_id`, `session_id` | Which scenario and demo session caused it |
| `outcome` | success / failure |
| `payload` | The original application payload |

Each event also carries the Windows-style fields that SENTINEL's normal ingestion maps:
- `Computer`, `TargetUserName`, `SubjectUserName`, `MemberName`, `IpAddress`, `LogonType`, `Status`;
- `NewProcessName`, `ParentProcessName`, `CommandLine`;
- optional source and device coordinates.

## Fictional identities

NEXUS has 11 accounts:
- 8 employees;
- `admin01`, the IT administrator;
- `analyst.kiran`, the security analyst;
- `svc_reporting`, a service account with no interactive logon.

Passwords are generated randomly on first start and hashed with Werkzeug (scrypt). They are stored in `demo_data/nexus_credentials.json` (git-ignored) and shown on the controller page for the presenter.

Two accounts are *delegated group managers*: the team leads `maya.fernandes` and `omar.khan`. NEXUS does not restrict *which* groups they can change. This is a deliberate, realistic misconfiguration that the storyline scenario abuses.

Accounts lock for 15 minutes after 15 failures. There is no bypass, and every scenario stays below that limit.

## Scenarios (bounded step lists; pause, resume and stop act between steps)

| ID | Scenario | What SENTINEL should report |
|---|---|---|
| A | Normal activity: 3 employees and the admin log on, browse and log off from their usual workstations | No incident |
| B | Brute force: 12 failures against `arjun.rao` from one simulated external source | R1, Low (attempts only, no access) |
| C | Password spraying: 8 failures across 6 accounts from one source | R2, Medium |
| D | Suspicious success: 10 failures, then a successful logon from the same source, then sensitive pages | R1 + R3 (+ R5 context): severity rises as evidence accumulates |
| E | Privilege change: `admin01` makes an approved change inside a registered change ticket (`CHG-4471`), then `omar.khan` adds himself to Administrators | Only the unauthorised change: R6 |
| F | Synthetic endpoint activity: encoded PowerShell, then `wevtutil cl Security` and 1102, on NEXUS-APP02 | R7 + R8 |
| G | Complete storyline on `maya.fernandes`, in six stages (see below) | One Critical incident (R1, R3, R5, R6, R7, R8) |
| H | Benign look-alikes: approved maintenance with ticket `CHG-4480` (`admin01` adds the analyst to Administrators), a new laptop in the HQ range, a user who mistypes twice | No incident |

Scenario G's six stages:
1. Brute force (11 failures).
2. A successful logon.
3. Access to the finance ledger and the payroll export.
4. A self-add to Administrators.
5. Encoded PowerShell and a certutil download (synthetic).
6. Log clearing (synthetic).

Change tickets are written to `change_windows.json` in the session folder. The live engine adds them as approved change windows (absolute start and end times); `rules.in_change_window` supports both recurring and ticket windows.

Scenarios that share an account and run within the correlation window can merge, as real alerts would. Each attack scenario therefore uses its own target accounts. **Run them in a fresh session (Start demo), or one at a time.**

One documented interaction: running H right after C attaches H's new-laptop context alert to the spray incident, because that user was a spray target.

## Measured results

All measurements are in `results/live_demo_check.json` and `tests/test_live_demo.py`.

| Measurement | Value |
|---|---|
| Events ingested vs emitted (scenario G, fresh session; `results/live_demo_check.json`, 23 Nov 18:38) | 250 / 250 (231 baseline + 19 scenario) |
| Detection latency: triggering event → incident visible to the engine, scenarios B, D, G, no browser load | 0.71 s, 0.98 s, 1.33 s |
| Same, with the dashboard and a headless browser rendering on the same laptop | 0.9–5.2 s across seven runs with the worker process (1.0 s in the saved run); 5.6 s in one earlier run with the in-process engine |
| Local Qwen explanation of the live Critical incident (GPU) | 8.9–16.9 s across runs (9.0 s in the saved run), with verification labels shown |
| External requests during the browser-driven live check | 0 |

The engine-side analysis of a 180-event session takes about 0.06–0.75 s, depending on load.

**How latency is measured.** It is the time the engine first saw the incident, minus the latest `emitted_at` among the incident's events at that moment. It covers file write, poll interval, read, ingestion, detection, correlation and severity. It does not include UI rendering (the Command Center refreshes every 2 s).

## Reliability and isolation

**Incremental, durable ingestion**
- Only bytes after the persisted offset are read, and only complete lines.
- A half-written line waits for the next poll. A repeated `event_uid` is skipped and counted.

**Restart recovery**
- A new engine reloads the lines before the persisted offset, without re-counting them, and continues from there.
- A NEXUS restart continues the same session's sequence numbers.
- Both are tested.

**Worker and fallback**
- The live worker writes a heartbeat. If it is missing, the dashboard falls back to an in-process engine running the same code.

**Session isolation**
- Every run has its own session folder under `demo_data/sessions/`.
- *Reset* starts a new, empty session. Old sessions stay on disk.
- Nothing is written to `data/samples`, `results/` metrics or the analyst workspace's evaluation data, and live events never enter any evaluation.

**Process hygiene**
- `start_demo.ps1` launches each service hidden, through `Win32_Process.Create`. A visible console window had let one test run's services be stopped by a Ctrl+C. Each service's output goes to its own log.
- `stop_demo.ps1` stops only the recorded process trees.

**Safety**
- Both services bind to 127.0.0.1.
- There is no command execution, no real log clearing, and no change to Windows accounts or groups.
- Only fictional accounts are used, with security headers on every NEXUS response.
- Input lengths are bounded, and the session cookie is HttpOnly and SameSite=Strict.

## Fallback: upload mode

If the live services cannot be started, every feature remains available on recorded data:
1. Choose `demo_unseen` (or any bundled or uploaded dataset) in the dataset selector.
2. Use the same investigation, Qwen, Evidence Contract and report steps.

If local inference is slow, use the *Deterministic template* button (verified by construction) or a cached explanation.

The detection and correlation logic is identical in both modes.
