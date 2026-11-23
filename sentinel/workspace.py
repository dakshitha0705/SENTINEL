"""Analyst workspace: dispositions, notes, audit trail and reviewable suppression proposals (SQLite).

Nothing is ever deleted: dispositions are append-only history, and suppressions only *tag* matching
incidents (they are never hidden) and can be revoked.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .config import ROOT

DB = ROOT / "workspace" / "analyst.db"
DISPOSITIONS = ["Needs investigation", "Confirmed", "Benign"]
STATUSES = ["New", "In progress", "Escalated", "Closed"]


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def connect(path: Path | None = None) -> sqlite3.Connection:
    p = Path(path or DB)
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(p)
    con.execute("""CREATE TABLE IF NOT EXISTS dispositions (id INTEGER PRIMARY KEY, incident_key TEXT, incident_id TEXT,
                   disposition TEXT, note TEXT, analyst TEXT, ts TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, ts TEXT, incident_key TEXT, action TEXT,
                   detail TEXT, analyst TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, incident_key TEXT, incident_id TEXT,
                   note TEXT, analyst TEXT, ts TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS status (id INTEGER PRIMARY KEY, incident_key TEXT, incident_id TEXT,
                   status TEXT, analyst TEXT, ts TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS suppressions (id INTEGER PRIMARY KEY, rule TEXT, match_json TEXT, reason TEXT,
                   status TEXT, created TEXT, decided TEXT, analyst TEXT)""")
    return con


def incident_key(analysis, inc) -> str:
    fp = "|".join(sorted(f["sha256"] for f in analysis.dataset.files))
    first = analysis.events.set_index("event_id").loc[inc["event_ids"][0]]
    basis = f"{fp}|{first['source_file']}:{first['source_row']}|{','.join(inc['rules'])}"
    return hashlib.sha256(basis.encode()).hexdigest()[:20]


def audit(con, key, action, detail, analyst="analyst"):
    con.execute("INSERT INTO audit (ts, incident_key, action, detail, analyst) VALUES (?,?,?,?,?)",
                (_now(), key, action, detail, analyst))
    con.commit()


def set_disposition(con, key, incident_id, disposition, note="", analyst="analyst"):
    if disposition not in DISPOSITIONS:
        raise ValueError(f"unknown disposition {disposition}")
    prev = current_disposition(con, key)
    con.execute("INSERT INTO dispositions (incident_key, incident_id, disposition, note, analyst, ts) VALUES (?,?,?,?,?,?)",
                (key, incident_id, disposition, note, analyst, _now()))
    con.commit()
    audit(con, key, "disposition", f"{prev or 'none'} -> {disposition}" + (f" | note: {note}" if note else ""), analyst)


def current_disposition(con, key):
    r = con.execute("SELECT disposition FROM dispositions WHERE incident_key=? ORDER BY id DESC LIMIT 1", (key,)).fetchone()
    return r[0] if r else None


def add_note(con, key, incident_id, note, analyst="analyst"):
    note = str(note).strip()
    if not note:
        raise ValueError("empty note")
    con.execute("INSERT INTO notes (incident_key, incident_id, note, analyst, ts) VALUES (?,?,?,?,?)",
                (key, incident_id, note[:4000], analyst, _now()))
    con.commit()
    audit(con, key, "note", note[:200], analyst)


def notes(con, key):
    rows = con.execute("SELECT ts, note, analyst FROM notes WHERE incident_key=? ORDER BY id", (key,)).fetchall()
    return [{"ts": r[0], "note": r[1], "analyst": r[2]} for r in rows]


def set_status(con, key, incident_id, status, analyst="analyst"):
    if status not in STATUSES:
        raise ValueError(f"unknown status {status}")
    prev = current_status(con, key)
    con.execute("INSERT INTO status (incident_key, incident_id, status, analyst, ts) VALUES (?,?,?,?,?)",
                (key, incident_id, status, analyst, _now()))
    con.commit()
    audit(con, key, "status", f"{prev} -> {status}", analyst)


def current_status(con, key):
    r = con.execute("SELECT status FROM status WHERE incident_key=? ORDER BY id DESC LIMIT 1", (key,)).fetchone()
    return r[0] if r else "New"


def history(con, key=None):
    q = "SELECT ts, incident_key, action, detail, analyst FROM audit"
    rows = con.execute(q + (" WHERE incident_key=? ORDER BY id DESC" if key else " ORDER BY id DESC LIMIT 200"),
                       (key,) if key else ()).fetchall()
    return [dict(zip(["ts", "incident_key", "action", "detail", "analyst"], r)) for r in rows]


def propose_suppression(con, rule, match: dict, reason, analyst="analyst") -> int:
    """Narrow proposal: rule + exact user/host/ip values. Must be reviewed before it has any effect."""
    if not match:
        raise ValueError("a suppression must be narrowed by at least one exact field")
    cur = con.execute("INSERT INTO suppressions (rule, match_json, reason, status, created, analyst) VALUES (?,?,?,?,?,?)",
                      (rule, json.dumps(match, sort_keys=True), reason, "proposed", _now(), analyst))
    con.commit()
    audit(con, None, "suppression proposed", f"SUP-{cur.lastrowid}: {rule} {match} ({reason})", analyst)
    return cur.lastrowid


def decide_suppression(con, sid, status, analyst="analyst"):
    if status not in ("approved", "rejected", "revoked"):
        raise ValueError(status)
    con.execute("UPDATE suppressions SET status=?, decided=? WHERE id=?", (status, _now(), sid))
    con.commit()
    audit(con, None, f"suppression {status}", f"SUP-{sid}", analyst)


def suppressions(con):
    rows = con.execute("SELECT id, rule, match_json, reason, status, created, decided FROM suppressions ORDER BY id DESC").fetchall()
    return [{"id": r[0], "rule": r[1], "match": json.loads(r[2]), "reason": r[3], "status": r[4], "created": r[5],
             "decided": r[6]} for r in rows]


def matching_suppressions(con, inc, alerts_by_id) -> list[str]:
    """Approved suppressions that match an incident. Matching incidents are TAGGED, never hidden."""
    hits = []
    for s in suppressions(con):
        if s["status"] != "approved":
            continue
        for aid in inc["alert_ids"]:
            a = alerts_by_id[aid]
            if a["rule"] != s["rule"]:
                continue
            m = s["match"]
            if all(v in a.get({"user": "users", "host": "hosts", "ip": "ips"}[k], []) for k, v in m.items()):
                hits.append(f"SUP-{s['id']}")
                break
    return hits
