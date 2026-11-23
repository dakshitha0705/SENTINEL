"""Offline EVTX -> flat JSON records converter.

Uses the ``evtx`` package (Rust parser with Python bindings, MIT/Apache-2.0); no network access, no
Windows API. Each record keeps:

* System fields: EventID, TimeCreated (UTC), Computer, Channel, Provider, EventRecordID, Level
* every EventData / UserData field, flattened (e.g. TargetUserName, IpAddress, CommandLine)
* the source file name and the original record identifier

The output is a list of flat dicts that the normal ingestion/column mapper understands; ``to_jsonl``
serialises them so the converted file can be exported, hashed and re-loaded like any JSON-lines log.
"""
from __future__ import annotations

import io
import json
from dataclasses import dataclass, field


class EvtxError(Exception):
    pass


@dataclass
class EvtxResult:
    name: str
    records: list
    diagnostics: dict = field(default_factory=dict)

    def to_jsonl(self) -> bytes:
        return "\n".join(json.dumps(r, ensure_ascii=False) for r in self.records).encode("utf-8")


def available() -> bool:
    try:
        import evtx  # noqa: F401
        return True
    except ImportError:
        return False


def _flatten_data(node, out: dict):
    """Collect leaf fields of EventData/UserData under their own names (first occurrence wins).

    Handles {"Name": value}, nested UserData wrappers ({"LogFileCleared": {...}}) and the classic
    {"Data": [{"#attributes": {"Name": n}, "#text": v}, ...]} layout."""
    if isinstance(node, dict):
        attrs = node.get("#attributes")
        if isinstance(attrs, dict) and "Name" in attrs and "#text" in node:
            out.setdefault(attrs["Name"], "" if node["#text"] is None else str(node["#text"]))
            return
        for k, v in node.items():
            if k in ("#attributes", "xmlns"):
                continue
            if isinstance(v, (dict, list)):
                _flatten_data(v, out)
            else:
                out.setdefault(k, "" if v is None else str(v))
    elif isinstance(node, list):
        for item in node:
            _flatten_data(item, out)


def flatten_record(data: dict) -> dict:
    ev = data.get("Event", data)
    sysn = ev.get("System", {}) or {}
    rec = {}
    eid = sysn.get("EventID")
    if isinstance(eid, dict):
        eid = eid.get("#text", "")
    rec["EventID"] = "" if eid is None else str(eid)
    tc = sysn.get("TimeCreated", {})
    rec["TimeCreated"] = (tc.get("#attributes", {}) or {}).get("SystemTime", "") if isinstance(tc, dict) else str(tc)
    rec["Computer"] = str(sysn.get("Computer") or "")
    rec["Channel"] = str(sysn.get("Channel") or "")
    prov = sysn.get("Provider", {})
    rec["Provider"] = (prov.get("#attributes", {}) or {}).get("Name", "") if isinstance(prov, dict) else ""
    rec["EventRecordID"] = str(sysn.get("EventRecordID") or "")
    rec["Level"] = str(sysn.get("Level") or "")
    payload: dict = {}
    for part in ("EventData", "UserData"):
        if ev.get(part):
            _flatten_data(ev[part], payload)
    for k, v in payload.items():
        if k not in rec:
            rec[k] = v
    return rec


def convert_evtx(data: bytes | str, name: str = "file.evtx", limit: int | None = None) -> EvtxResult:
    """Parse EVTX bytes (or a path). Raises EvtxError with a readable diagnostic on failure."""
    try:
        import evtx
    except ImportError as exc:
        raise EvtxError("EVTX support needs the 'evtx' package (pip install evtx); "
                        "alternatively export the log to CSV/JSON with Event Viewer or wevtutil") from exc
    if isinstance(data, str):
        with open(data, "rb") as fh:
            data = fh.read()
    if data[:8] != b"ElfFile\x00":
        raise EvtxError(f"{name}: not an EVTX file (missing 'ElfFile' signature)")
    try:
        parser = evtx.PyEvtxParser(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001
        raise EvtxError(f"{name}: EVTX header could not be parsed ({exc})") from exc
    records, bad, recovered = [], 0, 0
    codes: dict = {}
    try:
        for r in parser.records_json():
            try:
                rec = flatten_record(json.loads(r["data"]))
            except (ValueError, KeyError, TypeError):
                bad += 1
                continue
            if r.get("recovered"):
                recovered += 1
            rec["SourceFile"] = name
            records.append(rec)
            codes[rec["EventID"]] = codes.get(rec["EventID"], 0) + 1
            if limit and len(records) >= limit:
                break
    except Exception as exc:  # noqa: BLE001  (corrupt chunk: keep what was read)
        if not records:
            raise EvtxError(f"{name}: no readable records ({exc})") from exc
        bad += 1
    diag = {"records": len(records), "unreadable_records": bad, "recovered_records": recovered,
            "event_codes": dict(sorted(codes.items(), key=lambda kv: -kv[1])[:15]),
            "channels": sorted({r["Channel"] for r in records if r["Channel"]}),
            "computers": sorted({r["Computer"] for r in records if r["Computer"]})[:10]}
    return EvtxResult(name=name, records=records, diagnostics=diag)
