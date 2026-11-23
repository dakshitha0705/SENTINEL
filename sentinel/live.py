"""Live monitoring: incremental ingestion of the NEXUS demo event stream with a durable cursor.

Data flow:  NEXUS action -> demo_data/sessions/<id>/events.jsonl (append-only)
            -> LiveEngine.poll(): read only bytes after the persisted offset, complete lines only
            -> de-duplicate by event_uid -> normal SENTINEL ingestion/normalisation
            -> detection -> correlation -> severity -> evidence packs (over this session's window)
            -> live state + sentinel_status.json (read by the NEXUS controller) + UI refresh

The cursor (byte offset and the count of accepted events) is persisted after every batch, so a restart
resumes exactly where it stopped: lines before the offset are re-loaded from the same file (not
re-counted), lines after it are processed as new. Analysis runs over the current session only, which is
bounded (at most `max_events`, oldest dropped), never over historical datasets or evaluation data.
"""
from __future__ import annotations

import copy
import json
import os
import pickle
import threading
import time
from pathlib import Path

from .config import ROOT
from .ingest import ingest
from .pipeline import analyze_dataset

DEMO_ROOT = Path(os.environ.get("SENTINEL_DEMO_ROOT", ROOT / "demo_data"))
STREAM_NAME = "nexus_events.jsonl"
MAPPING = {"timestamp": "TimeCreated", "event_code": "EventID", "record_id": "EventRecordID", "action": None,
           "user": "TargetUserName", "actor": "SubjectUserName", "target_user": "MemberName", "host": "Computer",
           "src_ip": "IpAddress", "group": None, "process": "NewProcessName", "parent_process": "ParentProcessName",
           "command_line": "CommandLine", "outcome": "outcome", "log_type": None,
           "src_lat": "SrcLatitude", "src_lon": "SrcLongitude", "src_geo": "SrcLocation",
           "dst_lat": "DeviceLatitude", "dst_lon": "DeviceLongitude", "dst_geo": "DeviceLocation"}
LEVELS = ["Low", "Medium", "High", "Critical"]

# Plain-language phrases for notifications (what the detection means, not how it is implemented)
RULE_PHRASE = {
    "R1": "repeated failed logins against one account", "R2": "failed logins spread across many accounts",
    "R3": "a successful login right after those failures", "R4": "a login at an unusual hour",
    "R5": "a login from a new device or address", "R6": "an account added to a privileged group",
    "R7": "a suspicious command on an endpoint", "R8": "an audit log being cleared",
    "R9": "one account reaching several new hosts", "R10": "bulk copying to removable or shared storage",
    "R11": "an external storage device", "R12": "slow, sustained failed logins", "R13": "a small password spray",
    "R14": "enumeration of privileged groups",
}


def _replace(tmp: Path, dst: Path, attempts: int = 20):
    """os.replace with short retries: on Windows a reader holding the destination open makes it fail briefly."""
    for k in range(attempts):
        try:
            os.replace(tmp, dst)
            return
        except PermissionError:
            if k == attempts - 1:
                raise
            time.sleep(0.02)


def plain_summary(inc: dict, kind: str = "new") -> str:
    """One readable sentence describing an incident for a notification."""
    rules = [r for r in inc["rules"] if r != "CTX"]
    phrases = [RULE_PHRASE[r] for r in rules if r in RULE_PHRASE][:3]
    who = ", ".join(list(inc["users"])[:2]) or ", ".join(list(inc["hosts"])[:2])
    what = (", ".join(phrases[:-1]) + " and " + phrases[-1]) if len(phrases) > 1 else (phrases[0] if phrases else "suspicious activity")
    lead = "New evidence raised the severity: " if kind == "escalated" else "Detected "
    return f"{lead}{what}" + (f" involving {who}." if who else ".")


class LiveEngine:
    def __init__(self, cfg: dict, root: Path | None = None, max_events: int = 20000):
        self.cfg = cfg
        self.root = Path(root or DEMO_ROOT)
        self.max_events = max_events
        self.lock = threading.RLock()
        self.thread = None
        self.stop_ev = threading.Event()
        self.publish = False          # True in the worker process: publish snapshots for the dashboard
        self._reset(None)

    # ----------------------------------------------------------------- state
    def _reset(self, sid):
        self.session_id = sid
        self.offset = 0
        self.lines: list[bytes] = []
        self.records: dict[str, dict] = {}       # event_uid -> parsed record
        self.by_rid: dict[str, dict] = {}        # EventRecordID -> parsed record
        self.analysis = None
        self.tracked: dict[str, dict] = {}       # incident key -> tracking info
        self.notifications: list[dict] = []
        self.duplicates = 0
        self.malformed = 0
        self.last_batch = 0
        self.last_poll = None
        self.analysis_s = None
        self.error = None
        self.batches = 0

    def current_session(self):
        p = self.root / "current_session.json"
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))["session_id"]
        except (ValueError, KeyError):
            return None

    def sdir(self) -> Path:
        return self.root / "sessions" / self.session_id

    def _cursor_path(self):
        return self.sdir() / "sentinel_cursor.json"

    def _load_session(self, sid):
        """Switch to a session; resume from a persisted cursor if one exists (restart recovery)."""
        self._reset(sid)
        cp = self._cursor_path()
        if cp.exists():
            cur = json.loads(cp.read_text(encoding="utf-8"))
            resume_to = int(cur.get("offset", 0))
            if resume_to:
                self._read(stop_at=resume_to)        # rebuild in-memory state from already-ingested lines
                self.resumed_from = resume_to
                self._analyze()

    # ----------------------------------------------------------------- reading
    def _read(self, stop_at: int | None = None) -> int:
        p = self.sdir() / "events.jsonl"
        if not p.exists():
            return 0
        with open(p, "rb") as fh:
            fh.seek(self.offset)
            data = fh.read() if stop_at is None else fh.read(max(0, stop_at - self.offset))
        end = data.rfind(b"\n")
        if end < 0:
            return 0                                   # no complete line yet
        chunk = data[: end + 1]
        new = 0
        for line in chunk.splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                uid = rec["event_uid"]
            except (ValueError, KeyError):
                self.malformed += 1
                continue
            if uid in self.records:
                self.duplicates += 1
                continue
            self.records[uid] = rec
            self.by_rid[str(rec.get("EventRecordID"))] = rec
            self.lines.append(line)
            new += 1
        self.offset += len(chunk)
        if len(self.lines) > self.max_events:
            self.lines = self.lines[-self.max_events:]
        return new

    def _persist_cursor(self):
        tmp = self._cursor_path().with_suffix(".tmp")
        tmp.write_text(json.dumps({"session_id": self.session_id, "offset": self.offset, "events": len(self.records),
                                   "updated": time.strftime("%Y-%m-%d %H:%M:%S")}), encoding="utf-8")
        _replace(tmp, self._cursor_path())

    # ----------------------------------------------------------------- analysis
    def live_cfg(self) -> dict:
        cfg = copy.deepcopy(self.cfg)
        p = self.sdir() / "change_windows.json"
        if p.exists():
            tickets = json.loads(p.read_text(encoding="utf-8"))
            cfg["allowlists"]["change_windows"] = list(cfg["allowlists"]["change_windows"]) + [
                {"start": t["start"], "end": t["end"], "ticket": t.get("ticket")} for t in tickets]
        return cfg

    def _analyze(self):
        t0 = time.perf_counter()
        ds = ingest([(STREAM_NAME, b"\n".join(self.lines) + b"\n")], {STREAM_NAME: dict(MAPPING)})
        a = analyze_dataset(ds, self.live_cfg())
        self.analysis_s = round(time.perf_counter() - t0, 3)
        self.analysis = a
        now = time.time()
        rid = a.events.set_index("event_id")["record_id"].astype(str)
        for inc in a.incidents:
            rids = [rid[e] for e in inc["event_ids"]]
            key = min(rids, key=lambda r: int(r) if r.isdigit() else 0)
            sev = inc["severity"]
            emitted = [self.by_rid[r]["emitted_at"] for r in rids if r in self.by_rid]
            t = self.tracked.get(key)
            if t is None:
                trig = max(emitted) if emitted else None
                t = {"key": key, "first_seen": now, "latency_s": round(now - trig, 2) if trig else None,
                     "history": []}
                self.tracked[key] = t
                self._notify("new", inc, key=key)
            elif t["level"] in LEVELS and LEVELS.index(sev["level"]) > LEVELS.index(t["level"]):
                self._notify("escalated", inc, t["level"], key=key)
            if not t["history"] or t["history"][-1]["score"] != sev["score"] or t["history"][-1]["events"] != len(rids):
                t["history"].append({"t": round(now, 2), "score": sev["score"], "level": sev["level"], "events": len(rids),
                                     "rules": inc["rules"]})
            t.update(incident_id=inc["incident_id"], level=sev["level"], score=sev["score"], title=inc["title"])
        live_keys = {min((rid[e] for e in i["event_ids"]), key=lambda r: int(r) if r.isdigit() else 0) for i in a.incidents}
        for k in list(self.tracked):
            if k not in live_keys:
                self.tracked[k]["level"] = "merged"

    def _notify(self, kind, inc, prev=None, key=None):
        sev = inc["severity"]
        stages = " -> ".join(inc["stages"]) or inc["title"]
        if kind == "new":
            text = f"New {sev['level'].lower()}-severity incident detected: {stages} ({inc['title'].split('(')[-1].rstrip(')')})"
        else:
            text = f"{inc['incident_id']} escalated from {prev} to {sev['level']}: {stages}"
        self.notifications.append({"id": len(self.notifications) + 1, "t": time.time(), "kind": kind,
                                   "level": sev["level"], "prev_level": prev, "score": sev["score"],
                                   "incident_id": inc["incident_id"], "key": key, "session_id": self.session_id,
                                   "users": list(inc["users"])[:3], "hosts": list(inc["hosts"])[:3],
                                   "rules": [r for r in inc["rules"] if r != "CTX"],
                                   "summary": plain_summary(inc, kind), "text": text})

    def _write_status(self):
        a = self.analysis
        st = {"session_id": self.session_id, "events_ingested": len(self.records), "offset": self.offset,
              "duplicates_skipped": self.duplicates, "malformed": self.malformed, "last_batch": self.last_batch,
              "last_poll": self.last_poll, "analysis_s": self.analysis_s, "batches": self.batches, "error": self.error,
              "alerts": sum(1 for x in a.alerts if x["rule"] != "CTX") if a else 0,
              "incidents": [{"incident_id": i["incident_id"], "title": i["title"], "level": i["severity"]["level"],
                             "score": i["severity"]["score"], "rules": i["rules"],
                             "latency_s": self._track_of(i).get("latency_s")} for i in (a.incidents if a else [])]}
        p = self.sdir() / "sentinel_status.json"
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, default=str), encoding="utf-8")
        _replace(tmp, p)

    def _track_of(self, inc):
        a = self.analysis
        rid = a.events.set_index("event_id")["record_id"].astype(str)
        key = min((rid[e] for e in inc["event_ids"]), key=lambda r: int(r) if r.isdigit() else 0)
        return self.tracked.get(key, {})

    # ----------------------------------------------------------------- public API
    def poll(self) -> int:
        """Process newly appended events. Returns the number of new events ingested."""
        with self.lock:
            try:
                sid = self.current_session()
                if sid is None:
                    return 0
                if sid != self.session_id:
                    self._load_session(sid)
                new = self._read()
                self.last_poll = time.strftime("%H:%M:%S")
                self.last_batch = new
                if new:
                    self.batches += 1
                    self._persist_cursor()
                    self._analyze()
                if new or not (self.sdir() / "sentinel_status.json").exists():
                    self._write_status()
                    if self.publish:
                        self._publish()
                self.error = None
                return new
            except Exception as exc:  # noqa: BLE001  (never kill the loop; report instead)
                self.error = f"{type(exc).__name__}: {exc}"
                return 0

    def start(self, interval: float = 1.0):
        if self.thread and self.thread.is_alive():
            return
        self.stop_ev.clear()

        def loop():
            while not self.stop_ev.wait(interval):
                self.poll()
        self.poll()
        self.thread = threading.Thread(target=loop, daemon=True, name="sentinel-live")
        self.thread.start()

    def stop(self):
        self.stop_ev.set()

    def _publish(self):
        """Atomically write the latest snapshot for the dashboard process (trusted local file, same user)."""
        snap = self.snapshot()
        snap["recent"] = self.recent_events(40)
        snap["track_by_incident"] = {i["incident_id"]: self._track_of(i) for i in (self.analysis.incidents if self.analysis else [])}
        p = self.root / "live_snapshot.pkl"
        tmp = p.with_suffix(".tmp")
        with open(tmp, "wb") as fh:
            pickle.dump(snap, fh, protocol=pickle.HIGHEST_PROTOCOL)
        _replace(tmp, p)

    def recent_events(self, n=40) -> list[dict]:
        with self.lock:
            return list(self.records.values())[-n:][::-1]

    def snapshot(self) -> dict:
        with self.lock:
            return {"session_id": self.session_id, "analysis": self.analysis, "events": len(self.records),
                    "last_poll": self.last_poll, "last_batch": self.last_batch, "analysis_s": self.analysis_s,
                    "tracked": copy.deepcopy(self.tracked), "notifications": list(self.notifications),
                    "error": self.error, "duplicates": self.duplicates, "running": bool(self.thread and self.thread.is_alive())}


# --------------------------------------------------------------------------- worker process + dashboard reader

HEARTBEAT = "live_worker.json"


def run_worker(interval: float = 0.5, root: Path | None = None):
    """Run the live engine in its own process (started by scripts/start_demo.ps1), so detection latency is
    not affected by dashboard rendering. Writes a heartbeat every loop."""
    from .config import load_config
    eng = LiveEngine(load_config(local=True), root=root)
    eng.publish = True
    hb = eng.root / HEARTBEAT
    eng.root.mkdir(parents=True, exist_ok=True)
    while True:
        eng.poll()
        if eng.session_id and not (eng.root / "live_snapshot.pkl").exists():
            eng._publish()
        hb.write_text(json.dumps({"pid": os.getpid(), "t": time.time(), "session_id": eng.session_id}), encoding="utf-8")
        time.sleep(interval)


class LiveReader:
    """Dashboard-side view of the worker's latest snapshot (reloaded only when the file changes)."""

    def __init__(self, root: Path | None = None):
        self.root = Path(root or DEMO_ROOT)
        self._mtime = None
        self._snap = {"session_id": None, "analysis": None, "events": 0, "last_poll": None, "last_batch": 0,
                      "analysis_s": None, "tracked": {}, "notifications": [], "error": None, "duplicates": 0,
                      "running": False, "recent": [], "track_by_incident": {}}

    @staticmethod
    def worker_alive(root: Path | None = None, max_age: float = 5.0) -> bool:
        p = Path(root or DEMO_ROOT) / HEARTBEAT
        try:
            return time.time() - json.loads(p.read_text(encoding="utf-8"))["t"] < max_age
        except (OSError, ValueError, KeyError):
            return False

    def snapshot(self) -> dict:
        p = self.root / "live_snapshot.pkl"
        try:
            m = p.stat().st_mtime
            if m != self._mtime:
                with open(p, "rb") as fh:
                    self._snap = pickle.load(fh)
                self._mtime = m
        except (OSError, EOFError, pickle.UnpicklingError):
            pass
        snap = dict(self._snap)
        snap["running"] = self.worker_alive(self.root)
        return snap

    def recent_events(self, n=40):
        return self.snapshot().get("recent", [])[:n]

    def _track_of(self, inc):
        return self.snapshot().get("track_by_incident", {}).get(inc["incident_id"], {})

    def poll(self):
        return 0


if __name__ == "__main__":
    run_worker()
