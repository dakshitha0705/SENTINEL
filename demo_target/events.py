"""NEXUS security event stream: append-only JSON-lines, one file per demo session.

Layout (all under D:\\SENTINEL\\demo_data, git-ignored, never mixed with evaluation data):

    demo_data/current_session.json          {"session_id": ..., "started_at": ...}
    demo_data/sessions/<id>/events.jsonl    the event stream (append-only)
    demo_data/sessions/<id>/change_windows.json   approved change tickets registered for the session
    demo_data/sessions/<id>/sentinel_status.json  written by SENTINEL's live engine (read by the controller)

Every record carries Windows-Security-style fields (so SENTINEL's normal ingestion understands it) plus
provenance fields:

    event_uid        unique ID (NX-<session>-<seq>)
    EventRecordID    per-session sequence number
    TimeCreated      UTC ISO-8601 time the event describes
    emitted_at       wall-clock epoch seconds when it was written (for latency measurement)
    event_type       e.g. auth.login_failure
    source_app       "NEXUS Corporate Access Portal" or "NEXUS endpoint simulator"
    origin           "nexus-app"          - produced by NEXUS application code handling a real HTTP request
                     "simulated-endpoint" - synthetic endpoint telemetry written by the scenario controller
                     "baseline-backfill"  - synthetic prior history so per-user baselines exist
    simulated        True for synthetic records (simulated-endpoint, baseline-backfill)
    source_address_simulated  True when the client address was supplied by the scenario controller
    scenario_id      scenario that caused the event (None for manual use)
    session_id
    payload          original application payload
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO_ROOT = Path(os.environ.get("SENTINEL_DEMO_ROOT", ROOT / "demo_data"))
APP_NAME = "NEXUS Corporate Access Portal"
SIM_NAME = "NEXUS endpoint simulator"
PORTAL_HOST = "NEXUS-WEB01"

# Documented demo geo table (RFC 5737 documentation ranges and fictional company sites). Coordinates are
# attached only to addresses in this table; anything else (e.g. 127.0.0.1) gets no location.
GEO = [("10.20.", "NEXUS HQ Bengaluru (IN)", 12.97, 77.59), ("10.30.", "NEXUS data centre Mumbai (IN)", 19.08, 72.88),
       ("203.0.113.", "Singapore (SG) [simulated source]", 1.35, 103.82),
       ("198.51.100.", "Frankfurt (DE) [simulated source]", 50.11, 8.68),
       ("192.0.2.", "Sao Paulo (BR) [simulated source]", -23.55, -46.63)]
HOST_SITE = {"NEXUS-WEB01": "10.30.0.10", "NEXUS-APP02": "10.30.0.12"}


def geo_of(ip: str):
    for prefix, label, lat, lon in GEO:
        if ip and ip.startswith(prefix):
            return label, lat, lon
    return None


def now_iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts if ts is not None else time.time(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class EventStream:
    """Thread-safe appender for one session's events.jsonl."""

    def __init__(self, root: Path | None = None):
        self.root = Path(root or DEMO_ROOT)
        self.lock = threading.Lock()
        self.session_id = None
        self.seq = 0
        self.root.mkdir(parents=True, exist_ok=True)
        cur = self.root / "current_session.json"
        if cur.exists():
            self._open(json.loads(cur.read_text(encoding="utf-8"))["session_id"])
        else:
            self.new_session()

    # ----------------------------------------------------------------- sessions
    @property
    def dir(self) -> Path:
        return self.root / "sessions" / self.session_id

    @property
    def path(self) -> Path:
        return self.dir / "events.jsonl"

    def _open(self, sid: str):
        self.session_id = sid
        self.dir.mkdir(parents=True, exist_ok=True)
        self.seq = 0
        if self.path.exists():
            with open(self.path, "rb") as fh:
                self.seq = sum(1 for line in fh if line.strip())

    def new_session(self) -> str:
        """Start a fresh demo session. Previous sessions stay on disk (only demo_data is touched)."""
        with self.lock:
            sid = datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
            self._open(sid)
            (self.root / "current_session.json").write_text(json.dumps({"session_id": sid, "started_at": now_iso()}),
                                                            encoding="utf-8")
            return sid

    # ----------------------------------------------------------------- change tickets
    def register_change_window(self, minutes: int, ticket: str, approver: str) -> dict:
        p = self.dir / "change_windows.json"
        wins = json.loads(p.read_text(encoding="utf-8")) if p.exists() else []
        t0 = time.time()
        w = {"ticket": ticket, "approver": approver, "start": now_iso(t0 - 60), "end": now_iso(t0 + minutes * 60)}
        wins.append(w)
        p.write_text(json.dumps(wins, indent=1), encoding="utf-8")
        return w

    def change_windows(self) -> list:
        p = self.dir / "change_windows.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []

    # ----------------------------------------------------------------- emit
    def emit(self, event_id: str, event_type: str, *, user="", actor="", member="", host=PORTAL_HOST, ip="",
             outcome="success", origin="nexus-app", scenario_id=None, ts: float | None = None, logon_type="",
             status="0x0", process="", parent="", command="", group="", ip_simulated=False, payload=None) -> dict:
        with self.lock:
            self.seq += 1
            emitted = time.time()
            t = emitted if ts is None else ts
            rec = {
                "event_uid": f"NX-{self.session_id}-{self.seq:06d}", "EventRecordID": self.seq,
                "TimeCreated": now_iso(t), "emitted_at": round(emitted, 3), "EventID": str(event_id),
                "event_type": event_type, "source_app": APP_NAME if origin == "nexus-app" else SIM_NAME,
                "origin": origin, "simulated": origin != "nexus-app", "source_address_simulated": bool(ip_simulated),
                "scenario_id": scenario_id, "session_id": self.session_id,
                "Computer": host, "TargetUserName": group or user, "SubjectUserName": actor or (user if process or event_id == "1102" else ""),
                "MemberName": member, "IpAddress": ip or "-", "LogonType": logon_type, "Status": status,
                "outcome": outcome, "NewProcessName": process, "ParentProcessName": parent, "CommandLine": command,
                "payload": payload or {},
            }
            g = geo_of(ip)
            if g:
                rec.update({"SrcLocation": g[0], "SrcLatitude": g[1], "SrcLongitude": g[2]})
            d = geo_of(HOST_SITE.get(host, ""))
            if d:
                rec.update({"DeviceLocation": d[0], "DeviceLatitude": d[1], "DeviceLongitude": d[2]})
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return rec

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        with open(self.path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]
