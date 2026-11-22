"""Log ingestion: CSV / JSON array / JSON-lines loading, column mapping and normalisation.

Every accepted record keeps its source file, source row and original content (``raw``) so that
every later conclusion can be traced back to the exact input line. Rejected and duplicate
records are never silently dropped: they are returned with a reason.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
from dataclasses import dataclass, field

import pandas as pd

SCHEMA_FIELDS = [
    "event_id", "source_file", "source_row", "record_id", "timestamp", "log_type", "event_code",
    "action", "user", "target_user", "actor", "host", "src_ip", "group", "process",
    "parent_process", "command_line", "outcome", "raw",
]

# Fields the analyst can map from input columns (order = assignment priority).
MAPPABLE_FIELDS = [
    "timestamp", "event_code", "record_id", "action", "user", "actor", "target_user", "host",
    "src_ip", "group", "process", "parent_process", "command_line", "outcome", "log_type",
]

ACTIONS = [
    "login_success", "login_failure", "logout", "privilege_logon", "group_add",
    "process_start", "log_cleared", "other",
]

EVENT_CODE_ACTIONS = {
    "4624": "login_success", "4625": "login_failure", "4634": "logout", "4647": "logout",
    "4672": "privilege_logon", "4728": "group_add", "4732": "group_add", "4756": "group_add",
    "4688": "process_start", "1102": "log_cleared",
}
GROUP_ADD_CODES = {"4728", "4732", "4756"}
AUTH_ACTIONS = {"login_success", "login_failure", "logout", "privilege_logon", "group_add"}

_SYNONYMS = {
    "timestamp": ["timestamp", "timecreated", "eventtime", "utctime", "systemtime", "timegenerated",
                  "datetime", "time", "date", "ts", "logtime", "createdat", "eventtimestamp"],
    "event_code": ["eventcode", "eventid", "winlogeventid", "eventidentifier", "code", "eventnumber"],
    "record_id": ["recordid", "eventrecordid", "recordnumber", "record", "sequence", "seq"],
    "action": ["action", "eventaction", "activity", "operation", "eventtype", "eventname"],
    "user": ["targetusername", "username", "user", "account", "accountname", "login", "useridentity"],
    "actor": ["subjectusername", "actor", "initiator", "changedby", "performedby", "subjectuser"],
    "target_user": ["membername", "targetuser", "member", "targetmember", "targetaccount", "addeduser"],
    "host": ["computer", "computername", "hostname", "host", "device", "devicename", "machine",
             "machinename", "workstation", "endpoint", "agentname"],
    "src_ip": ["ipaddress", "sourceip", "srcip", "sourceaddress", "sourceipaddress", "clientip",
               "remoteip", "ip", "ipaddr", "srcaddr"],
    "group": ["groupname", "group", "targetgroup", "securitygroup"],
    "process": ["newprocessname", "processname", "process", "image", "processexecutable",
                "executable", "processpath", "exe"],
    "parent_process": ["parentprocessname", "parentprocess", "parentimage", "processparentname",
                       "processparentexecutable", "parentname", "parentexecutable"],
    "command_line": ["commandline", "processcommandline", "cmdline", "cmd", "command"],
    "outcome": ["outcome", "eventoutcome", "status", "result"],
    "log_type": ["logtype", "channel", "logsource", "eventdataset", "eventcategory", "category",
                 "source", "type"],
}

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]{3,39}$", re.I)
_TS_HINT_RE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}")


def _norm_col(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


@dataclass
class FileLoad:
    name: str
    sha256: str
    fmt: str
    frame: pd.DataFrame                  # flattened original records, all strings
    rejected: list = field(default_factory=list)   # [{"source_row":..,"reason":..,"content":..}]


@dataclass
class Dataset:
    events: pd.DataFrame
    files: list                         # [{"name","sha256","format","rows","accepted",...}]
    rejected: pd.DataFrame
    duplicates: pd.DataFrame
    mappings: dict
    summary: dict


# --------------------------------------------------------------------------- loading

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _records_from_json(text: str, rejected: list) -> list[dict]:
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            obj = json.loads(text)
            if isinstance(obj, list):
                out = []
                for i, rec in enumerate(obj):
                    if isinstance(rec, dict):
                        out.append(rec)
                    else:
                        rejected.append({"source_row": i + 1, "reason": "JSON item is not an object",
                                         "content": str(rec)[:300]})
                return out
            if isinstance(obj, dict):
                # {"events": [...]} style wrapper or a single record
                for v in obj.values():
                    if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                        return v
                return [obj]
        except json.JSONDecodeError:
            pass  # fall through to JSON-lines
    out = []
    for i, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            rejected.append({"source_row": i, "reason": f"invalid JSON: {exc.msg}", "content": line[:300]})
            continue
        if isinstance(rec, dict):
            out.append(rec)
        else:
            rejected.append({"source_row": i, "reason": "JSON line is not an object", "content": line[:300]})
    return out


def read_file(name: str, data: bytes) -> FileLoad:
    """Load one CSV / JSON / JSON-lines file into a flat string DataFrame."""
    digest = sha256_bytes(data)
    text = data.decode("utf-8-sig", errors="replace")
    rejected: list = []
    lower = name.lower()
    is_json = lower.endswith((".json", ".jsonl", ".ndjson")) or text.lstrip()[:1] in ("[", "{")
    if is_json:
        records = _records_from_json(text, rejected)
        frame = pd.json_normalize(records, sep=".") if records else pd.DataFrame()
        # keep 1-based position in the file for traceability
        frame.insert(0, "__row", range(1, len(frame) + 1))
        fmt = "jsonl" if not text.lstrip().startswith("[") else "json"
    else:
        bad_lines: list = []

        def _bad(line):
            bad_lines.append(line)
            return None

        frame = pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False,
                            on_bad_lines=_bad, engine="python")
        for b in bad_lines:
            rejected.append({"source_row": None, "reason": "malformed CSV line (column count)",
                             "content": ",".join(map(str, b))[:300]})
        frame.insert(0, "__row", range(2, len(frame) + 2))  # +1 header, 1-based
        fmt = "csv"
    frame = frame.fillna("")
    for c in frame.columns:
        if c != "__row":
            frame[c] = frame[c].map(lambda v: json.dumps(v) if isinstance(v, (list, dict)) else str(v))
    return FileLoad(name=name, sha256=digest, fmt=fmt, frame=frame, rejected=rejected)


# --------------------------------------------------------------------------- column mapper

def _looks_like(series: pd.Series, kind: str) -> float:
    vals = [v for v in series.astype(str).head(200) if v and v != "-"]
    if not vals:
        return 0.0
    if kind == "timestamp":
        hits = sum(bool(_TS_HINT_RE.search(v)) for v in vals)
    elif kind == "ip":
        hits = sum(bool(_IP_RE.match(v.strip())) and "." in v or v.count(":") >= 2 for v in vals)
    elif kind == "code":
        hits = sum(v.strip().isdigit() and len(v.strip()) <= 5 for v in vals)
    else:
        return 0.0
    return hits / len(vals)


def guess_mapping(frame: pd.DataFrame) -> dict:
    """Suggest a column for each schema field from column names, then value patterns."""
    cols = [c for c in frame.columns if c != "__row"]
    normed = {c: _norm_col(c) for c in cols}
    used: set = set()
    mapping: dict = {f: None for f in MAPPABLE_FIELDS}
    for fld in MAPPABLE_FIELDS:
        for syn in _SYNONYMS[fld]:
            match = next((c for c in cols if c not in used and normed[c] == syn), None)
            if match is None:  # nested keys: compare the trailing part e.g. "event.data.CommandLine"
                match = next((c for c in cols if c not in used and "." in c
                              and _norm_col(c.split(".")[-1]) == syn), None)
            if match is not None:
                if fld == "event_code" and _looks_like(frame[match], "code") < 0.8:
                    continue
                if fld == "timestamp" and _looks_like(frame[match], "timestamp") < 0.5:
                    continue
                mapping[fld] = match
                used.add(match)
                break
    # value-pattern fallbacks
    for fld, kind in (("timestamp", "timestamp"), ("src_ip", "ip"), ("event_code", "code")):
        if mapping[fld] is None:
            best = max(((c, _looks_like(frame[c], kind)) for c in cols if c not in used),
                       key=lambda t: t[1], default=(None, 0))
            if best[0] is not None and best[1] >= 0.8:
                mapping[fld] = best[0]
                used.add(best[0])
    return mapping


# --------------------------------------------------------------------------- normalisation helpers

def norm_user(v: str) -> str:
    v = (v or "").strip().strip('"').lower()
    if v in ("", "-", "n/a", "none", "null", "nan"):
        return ""
    if "\\" in v:
        v = v.split("\\")[-1]
    if "@" in v:
        v = v.split("@")[0]
    if v.startswith("cn="):
        v = v[3:].split(",")[0]
    return v.strip()


def norm_host(v: str) -> str:
    v = (v or "").strip().strip("\\").strip()
    if v in ("", "-", "nan", "null", "none"):
        return ""
    if not _IP_RE.match(v) and "." in v:
        v = v.split(".")[0]
    return v.upper()


def norm_ip(v: str) -> str:
    v = (v or "").strip()
    if v in ("", "-", "nan", "null", "none"):
        return ""
    if v.lower().startswith("::ffff:"):
        v = v[7:]
    return v


def norm_proc(v: str) -> str:
    v = (v or "").strip().strip('"')
    if v in ("", "-", "nan"):
        return ""
    return re.split(r"[\\/]", v)[-1].lower()


def norm_code(v: str) -> str:
    v = (v or "").strip()
    if re.fullmatch(r"\d+(\.0)?", v):
        return str(int(float(v)))
    return v


def action_from_text(text: str) -> str | None:
    t = (text or "").strip().lower().replace("-", "_").replace(" ", "_")
    if not t:
        return None
    if t in ACTIONS:
        return t
    if "clear" in t and "log" in t:
        return "log_cleared"
    if "special" in t and "priv" in t:
        return "privilege_logon"
    if ("member" in t and "add" in t) or t in ("group_add", "add_group_member", "groupadd"):
        return "group_add"
    if "process" in t and any(k in t for k in ("creat", "start", "launch", "exec")):
        return "process_start"
    if any(k in t for k in ("logoff", "logout", "log_off", "sign_out", "signout")):
        return "logout"
    if any(k in t for k in ("logon", "login", "log_in", "sign_in", "signin", "auth")):
        if any(k in t for k in ("fail", "denied", "invalid", "bad", "reject")):
            return "login_failure"
        return "login_success"
    return None


def outcome_from_text(text: str) -> str:
    t = (text or "").strip().lower()
    if not t:
        return ""
    if any(k in t for k in ("fail", "denied", "invalid", "error", "reject", "0xc000")):
        return "failure"
    if any(k in t for k in ("success", "succeed", "ok", "allow", "pass", "audit success")) or t == "0x0":
        return "success"
    return ""


def parse_timestamps(series: pd.Series) -> pd.Series:
    s = series.astype(str).str.strip()
    numeric = s.str.fullmatch(r"\d{9,13}(\.\d+)?")
    out = pd.Series(pd.NaT, index=s.index, dtype="datetime64[ns, UTC]")
    if numeric.any():
        nums = s[numeric].astype(float)
        unit_ms = nums > 1e11
        out.loc[numeric & unit_ms.reindex(s.index, fill_value=False)] = pd.to_datetime(
            nums[unit_ms], unit="ms", utc=True)
        out.loc[numeric & ~unit_ms.reindex(s.index, fill_value=False)] = pd.to_datetime(
            nums[~unit_ms], unit="s", utc=True)
    rest = ~numeric
    if rest.any():
        out.loc[rest] = pd.to_datetime(s[rest], utc=True, errors="coerce", format="mixed")
    return out


# --------------------------------------------------------------------------- normalise

def normalize(load: FileLoad, mapping: dict) -> tuple[pd.DataFrame, list]:
    """Map one loaded file to the SENTINEL schema. Returns (events, rejected_rows)."""
    f = load.frame
    rejected = list(load.rejected)
    if f.empty:
        return pd.DataFrame(columns=[c for c in SCHEMA_FIELDS if c != "event_id"]), rejected

    def col(fld):
        c = mapping.get(fld)
        if c and c in f.columns:
            return f[c].astype(str)
        return pd.Series([""] * len(f), index=f.index)

    out = pd.DataFrame(index=f.index)
    out["source_file"] = load.name
    out["source_row"] = f["__row"].astype(int)
    out["record_id"] = col("record_id").str.strip()
    out["timestamp"] = parse_timestamps(col("timestamp"))
    out["event_code"] = col("event_code").map(norm_code)
    channel = col("log_type").str.lower()

    act_text = col("action").map(action_from_text)
    act_code = out["event_code"].map(EVENT_CODE_ACTIONS)
    sysmon_proc = channel.str.contains("sysmon") & (out["event_code"] == "1")
    act_code = act_code.where(~sysmon_proc, "process_start")
    out["action"] = act_code.fillna(act_text).fillna("other")
    has_code_or_action = (out["event_code"] != "") | col("action").str.strip().ne("")

    out["user"] = col("user").map(norm_user)
    out["actor"] = col("actor").map(norm_user)
    out["target_user"] = col("target_user").map(norm_user)
    out["host"] = col("host").map(norm_host)
    out["src_ip"] = col("src_ip").map(norm_ip)
    out["group"] = col("group").str.strip()
    out["process"] = col("process").map(norm_proc)
    out["parent_process"] = col("parent_process").map(norm_proc)
    out["command_line"] = col("command_line").str.strip().replace({"-": ""})

    oc = col("outcome").map(outcome_from_text)
    by_action = out["action"].map({"login_failure": "failure", "login_success": "success"})
    out["outcome"] = by_action.fillna(oc.where(oc != "", None)).fillna("success")
    # A generic "login" with failure outcome is a failed login.
    fail_login = (out["action"] == "login_success") & (oc == "failure") & (out["event_code"] == "")
    out.loc[fail_login, "action"] = "login_failure"
    out.loc[fail_login, "outcome"] = "failure"

    # Windows-native field semantics ------------------------------------------------
    grp = out["action"] == "group_add"
    # In 4728/4732/4756, TargetUserName is the *group* and SubjectUserName the actor.
    mapped_user_raw = col("user").str.strip()
    out.loc[grp & (out["group"] == ""), "group"] = mapped_user_raw[grp & (out["group"] == "")]
    out.loc[grp & (out["actor"] != ""), "user"] = out.loc[grp & (out["actor"] != ""), "actor"]
    # Process / log-clear events carry the account in SubjectUserName.
    subj_events = out["action"].isin(["process_start", "log_cleared", "privilege_logon"])
    fill = subj_events & (out["user"] == "") & (out["actor"] != "")
    out.loc[fill, "user"] = out.loc[fill, "actor"]

    out["log_type"] = out["action"].map(lambda a: "auth" if a in AUTH_ACTIONS else "endpoint")
    out.loc[out["action"] == "other", "log_type"] = channel[out["action"] == "other"].where(
        channel[out["action"] == "other"] != "", "unknown")
    orig_cols = [c for c in f.columns if c != "__row"]
    out["raw"] = f[orig_cols].apply(
        lambda r: json.dumps({k: v for k, v in r.items() if v not in ("",)}, ensure_ascii=False), axis=1)

    bad_ts = out["timestamp"].isna()
    no_type = ~has_code_or_action
    bad = bad_ts | no_type
    for idx in out.index[bad]:
        reason = "unparseable or missing timestamp" if bad_ts[idx] else "no event code or action"
        rejected.append({"source_row": int(out.at[idx, "source_row"]), "reason": reason,
                         "content": out.at[idx, "raw"][:300]})
    good = out[~bad].copy()
    return good, [dict(r, source_file=load.name) for r in rejected]


def _dedupe_key(df: pd.DataFrame) -> pd.Series:
    rec = df["record_id"].fillna("")
    with_id = rec != ""
    k_id = df["host"] + "|" + df["event_code"] + "|" + rec
    k_full = (df["timestamp"].astype(str) + "|" + df["event_code"] + "|" + df["action"] + "|" + df["user"]
              + "|" + df["host"] + "|" + df["src_ip"] + "|" + df["process"] + "|" + df["command_line"]
              + "|" + df["target_user"] + "|" + df["group"])
    return k_id.where(with_id, k_full)


def ingest(files: list[tuple[str, bytes]], mappings: dict | None = None) -> Dataset:
    """Load, map and normalise several files into one event table."""
    mappings = dict(mappings or {})
    frames, rejected, infos = [], [], []
    for name, data in files:
        load = read_file(name, data)
        mp = mappings.get(name) or guess_mapping(load.frame)
        mappings[name] = mp
        ev, rej = normalize(load, mp)
        frames.append(ev)
        rejected.extend(rej)
        infos.append({"name": name, "sha256": load.sha256, "format": load.fmt,
                      "rows": int(len(load.frame)) + len(load.rejected),
                      "accepted": int(len(ev)), "rejected": len(rej)})
    frames = [f for f in frames if len(f)]
    events = (pd.concat(frames, ignore_index=True) if frames
              else pd.DataFrame(columns=[c for c in SCHEMA_FIELDS if c != "event_id"]))
    events = events.sort_values(["timestamp", "source_file", "source_row"], kind="stable").reset_index(drop=True)
    key = _dedupe_key(events) if len(events) else pd.Series(dtype=str)
    dup_mask = key.duplicated(keep="first") if len(events) else pd.Series(dtype=bool)
    duplicates = events[dup_mask].copy()
    if len(duplicates):
        first_src = events[~dup_mask].assign(_k=key[~dup_mask]).set_index("_k")
        duplicates["duplicate_of"] = key[dup_mask].map(
            lambda k: f"{first_src.at[k, 'source_file']}:{first_src.at[k, 'source_row']}"
            if k in first_src.index else "")
    events = events[~dup_mask].reset_index(drop=True)
    events.insert(0, "event_id", [f"EVT-{i:06d}" for i in range(1, len(events) + 1)])
    events = events[SCHEMA_FIELDS]
    for info in infos:
        info["duplicates"] = int((duplicates["source_file"] == info["name"]).sum()) if len(duplicates) else 0
    unevaluable = int((events["action"] == "other").sum())
    summary = {
        "files": len(infos),
        "records_read": int(sum(i["rows"] for i in infos)),
        "accepted": int(len(events)),
        "rejected": len(rejected),
        "duplicates": int(len(duplicates)),
        "unevaluable": unevaluable,
        "by_action": events["action"].value_counts().to_dict(),
        "time_range": [str(events["timestamp"].min()), str(events["timestamp"].max())] if len(events) else [],
    }
    return Dataset(events=events, files=infos, rejected=pd.DataFrame(rejected), duplicates=duplicates,
                   mappings=mappings, summary=summary)


def ingest_paths(paths, mappings: dict | None = None) -> Dataset:
    from pathlib import Path
    files = [(Path(p).name, Path(p).read_bytes()) for p in paths]
    return ingest(files, mappings)
