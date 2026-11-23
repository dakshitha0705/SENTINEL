"""Session state, dataset switching and analysis runs for the dashboard (shared by all pages)."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pandas as pd
import streamlit as st

from ..config import ROOT, load_config
from ..evidence import known_entities
from ..ingest import ingest
from ..pipeline import analyze_dataset
from ..slm import explain, status as slm_status, template_explanation
from ..verifier import verify_output

SAMPLES = ROOT / "data" / "samples"
PUBLIC = ROOT / "data" / "public"
RESULTS = ROOT / "results"
REPORTS = ROOT / "reports"

PAGES = ["Command Center", "Live Demo", "Log Intelligence", "Investigation Studio", "Threat Hunting",
         "Reports & Evaluation"]
ICONS = {"Command Center": "public", "Live Demo": "sensors", "Log Intelligence": "database",
         "Investigation Studio": "policy", "Threat Hunting": "travel_explore", "Reports & Evaluation": "description"}
# Older page names (still used by deep links / buttons) -> (page, view inside that page)
ALIASES = {"Incident Investigation": ("Investigation Studio", "Story"), "Attack Graph": ("Investigation Studio", "Attack graph"),
           "AI Investigation Lab": ("Investigation Studio", "AI investigation"),
           "Threat Intelligence": ("Threat Hunting", None), "Report Studio": ("Reports & Evaluation", "Report"),
           "Evaluation & Benchmarks": ("Reports & Evaluation", "Evaluation")}
VIEW_KEY = {"Investigation Studio": "studio_view", "Reports & Evaluation": "re_view"}
TIME_RANGES = {"All data": None, "Last 24 h": 24, "Last 72 h": 72, "Last 7 days": 168}
UPLOADED = "Uploaded files"
LIVE = "LIVE · NEXUS demo stream"
NEXUS_URL = "http://127.0.0.1:8502"

S = st.session_state


def init():
    S.setdefault("cfg", load_config(local=True))
    S.setdefault("files", {})            # name -> bytes
    S.setdefault("mappings", {})
    S.setdefault("analysis", None)
    S.setdefault("dataset", None)
    S.setdefault("explanations", {})     # incident_id -> (result, verification)
    S.setdefault("chat", {})             # incident_id -> [(q, answer_dict)]
    S.setdefault("last_slm_stats", None)
    S.setdefault("selected", None)
    S.setdefault("time_range", "All data")
    S.setdefault("known_entities", set())
    S.setdefault("profile_note", "")


def cfg() -> dict:
    return S.cfg


# --------------------------------------------------------------------------- datasets

def _synthetic(folder: Path) -> list[str]:
    if (folder / "siem_auth_export.csv").exists():
        return ["siem_auth_export.csv", "edr_process_events.jsonl"]
    return [n for n in ("auth_logs.csv", "endpoint_logs.json") if (folder / n).exists()]


def list_datasets() -> list[str]:
    names = []
    if SAMPLES.exists():
        found = sorted(p.name for p in SAMPLES.iterdir() if p.is_dir() and _synthetic(p))
        order = lambda n: (0 if n == "demo_unseen" else 1 if n.startswith("test") else 2 if n.startswith("dev")
                           else 3 if n.startswith("fresh") else 4 if n.startswith("stress") else 5, n)
        names += sorted(found, key=order)
    for label in external_datasets():
        names.append(label)
    if S.get("dataset") == UPLOADED:
        names.insert(0, UPLOADED)
    names.insert(0, LIVE)
    return names


# --------------------------------------------------------------------------- live monitoring

@st.cache_resource(show_spinner=False)
def _inprocess_engine():
    from ..live import LiveEngine
    eng = LiveEngine(load_config(local=True))
    eng.start(interval=1.0)
    return eng


@st.cache_resource(show_spinner=False)
def _reader():
    from ..live import LiveReader
    return LiveReader()


def live_engine():
    """The live worker process (scripts/start_demo.ps1 starts `python -m sentinel.live`) when it is running;
    otherwise an in-process engine (same code, shares the dashboard's Python interpreter)."""
    from ..live import LiveReader
    if LiveReader.worker_alive():
        return _reader()
    return _inprocess_engine()


def is_live() -> bool:
    return S.get("dataset") == LIVE


def refresh_live() -> dict:
    """Point the session at the live engine's latest analysis (no re-analysis here; the engine does it)."""
    snap = live_engine().snapshot()
    a = snap["analysis"]
    if a is not None and a is not S.get("analysis"):
        old = {iid: v for iid, v in S.get("explanations", {}).items()}
        S.analysis = a
        S.known_entities = known_entities(a.events)
        # keep explanations only where the incident's evidence pack is unchanged
        S.explanations = {iid: v for iid, v in old.items() if iid in a.packs and v[2:3] == (a.packs[iid]["hash"],)}
        if S.selected not in [i["incident_id"] for i in a.incidents]:
            S.selected = a.incidents[0]["incident_id"] if a.incidents else None
    return snap


def select_live():
    S.dataset = LIVE
    try:
        st.query_params["live"] = "1"
        st.query_params.pop("sample", None)
    except Exception:  # noqa: BLE001
        pass
    S.files, S.mappings, S.profile_note = {}, {}, ""
    S.analysis = None
    S.explanations, S.chat = {}, {}
    refresh_live()


def external_datasets() -> dict:
    """Public attack recordings present on disk (downloaded with scripts/get_external_data.py)."""
    cat_p = ROOT / "data" / "external_catalog.json"
    out = {}
    if not cat_p.exists():
        return out
    cat = json.loads(cat_p.read_text(encoding="utf-8"))
    for r in cat["recordings"]:
        name = Path(r["path"]).name
        if r["source"] == "evtx_attack_samples":
            files = [PUBLIC / "evtx_attack_samples" / name]
        else:
            d = PUBLIC / "otrf" / name.removesuffix(".zip")
            files = sorted(d.glob("*.json")) if d.exists() else []
        if files and all(f.exists() for f in files):
            out[f"external {r['id']}: {r['behaviour']}"] = files
    return out


def dataset_files(name: str) -> dict:
    ext = external_datasets()
    if name in ext:
        return {p.name: p.read_bytes() for p in ext[name]}
    folder = SAMPLES / name
    return {n: (folder / n).read_bytes() for n in _synthetic(folder)}


def mapping_profile(name: str) -> dict:
    p = SAMPLES / name / "mapping_profile.json"
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8")).get("files", {})
    return {}


def load_dataset(name: str, run: bool = True):
    from ..ingest import guess_mapping, read_file
    if name == LIVE:
        select_live()
        return
    S.files = dataset_files(name)
    S.dataset = name
    try:                                    # an explicit switch leaves live mode (also in the URL)
        st.query_params.pop("live", None)
    except Exception:  # noqa: BLE001
        pass
    prof = mapping_profile(name)
    S.mappings = {}
    notes = []
    for fname, fixes in prof.items():
        if fname in S.files:
            g = guess_mapping(read_file(fname, S.files[fname]).frame)
            g.update(fixes)
            S.mappings[fname] = g
            notes.append(f"{fname}: " + ", ".join(f"'{v}' -> {k}" for k, v in fixes.items()))
    S.profile_note = ("Saved mapping profile applied (" + "; ".join(notes) + ")") if notes else ""
    if run:
        run_analysis(auto_explain=False)


def run_analysis(auto_explain: bool = False, progress=None):
    files = list(S.files.items())
    t0 = time.perf_counter()
    if progress:
        progress(0.05, "Normalising logs")
    ds = ingest(files, S.mappings)
    t_ing = time.perf_counter() - t0
    if progress:
        progress(0.4, "Detecting, correlating and scoring")
    a = analyze_dataset(ds, S.cfg)
    a.timings["ingest_s"] = t_ing
    S.analysis = a
    S.known_entities = known_entities(ds.events)
    S.explanations = {}
    S.chat = {}
    S.mappings = dict(ds.mappings)
    if S.selected not in [i["incident_id"] for i in a.incidents]:
        S.selected = a.incidents[0]["incident_id"] if a.incidents else None
    if auto_explain and a.incidents:
        st_ = slm_status(S.cfg)
        if st_["reachable"] and st_["model_installed"]:
            top = a.incidents[: S.cfg["slm"]["auto_explain_top_n"]]
            for k, inc in enumerate(top):
                if progress:
                    progress(0.5 + 0.5 * k / len(top), f"Local SLM explaining {inc['incident_id']}")
                explanation_for(inc["incident_id"])
    if progress:
        progress(1.0, f"Done in {time.perf_counter() - t0:.1f} s")
    return a


def time_window(a):
    hours = TIME_RANGES.get(S.time_range)
    if not hours or a is None or a.events.empty:
        return None
    hi = a.events["timestamp"].max()
    return (hi - pd.Timedelta(hours=hours), hi)


def visible_incidents(a=None):
    a = a or S.analysis
    if a is None:
        return []
    w = time_window(a)
    if not w:
        return a.incidents
    lo, hi = w
    return [i for i in a.incidents if i["end"] >= lo and i["start"] <= hi]


# --------------------------------------------------------------------------- SLM explanations

def explanation_for(iid, use_slm=True, on_token=None, force=False):
    a = S.analysis
    if iid in S.explanations and not force:
        return S.explanations[iid][:2]
    pack = a.packs[iid]
    if use_slm:
        res = explain(pack, S.cfg, use_cache=not force, on_token=on_token, known=S.known_entities)
    else:
        res = {"source": "template", "output": template_explanation(pack), "stats": {},
               "error": "template selected by analyst"}
    ver = verify_output(res["output"], pack, S.known_entities)
    S.explanations[iid] = (res, ver, pack["hash"])
    if res.get("stats"):
        S.last_slm_stats = {**res["stats"], "incident": iid, "source": res["source"], "model": res.get("model")}
    return S.explanations[iid][:2]


def goto(page: str, incident: str | None = None, view: str | None = None):
    """Navigate to a page (old page names are mapped to the new six destinations) and optionally an incident/view."""
    if incident:
        S.selected = incident
    if page in ALIASES:
        page, v = ALIASES[page]
        view = view or v
    if view and page in VIEW_KEY:
        S["_goto_view"] = (VIEW_KEY[page], view)
    S.goto = page


# --------------------------------------------------------------------------- live notifications

def live_status() -> dict:
    """Honest description of where live data comes from right now."""
    from ..live import LiveReader
    worker = LiveReader.worker_alive()
    snap = live_engine().snapshot()
    return {"worker": worker, "engine": "worker process" if worker else "in-process engine",
            "running": bool(snap.get("running")), "session_id": snap.get("session_id"), "events": snap.get("events", 0),
            "last_poll": snap.get("last_poll"), "error": snap.get("error")}


def sync_notifications(snap: dict) -> list[dict]:
    """Record the live engine's real `new`/`escalated` notifications in this browser session.
    Returns the ones not shown before (each notification is shown once; history keeps the last 25)."""
    seen = S.setdefault("notif_seen", set())
    hist = S.setdefault("notif_history", [])
    fresh = []
    for n in snap.get("notifications", []):
        k = (n.get("session_id") or snap.get("session_id"), n["id"])
        if k in seen:
            continue
        seen.add(k)
        n = dict(n)
        n["uid"] = f"{k[0]}:{k[1]}"
        hist.insert(0, n)
        if time.time() - n["t"] < 15:          # pop up only fresh ones: a page reload starts a new session; history keeps all
            fresh.append(n)
    del hist[25:]
    return fresh


def notify_tick(snap: dict):
    """Inside a live auto-refresh fragment: if the engine produced new notifications, refresh the whole page once
    (bell, counters, incident list) and show them as toasts there. One auto-refresh fragment per page only."""
    fresh = sync_notifications(snap)
    if fresh:
        S._pending_toasts = S.get("_pending_toasts", []) + fresh
        st.rerun(scope="app")


def unread_notifications() -> list[dict]:
    ack = S.setdefault("notif_ack", set())
    return [n for n in S.get("notif_history", []) if n["uid"] not in ack]


def resolve_incident(n: dict) -> str | None:
    """Current incident id for a notification (ids are re-ranked as incidents grow; the tracking key is stable)."""
    a = S.get("analysis")
    if a is None:
        return None
    ids = [i["incident_id"] for i in a.incidents]
    if n.get("key"):
        t = live_engine().snapshot().get("tracked", {}).get(n["key"])
        if t and t.get("incident_id") in ids and t.get("level") != "merged":
            return t["incident_id"]
    return n.get("incident_id") if n.get("incident_id") in ids else (ids[0] if ids else None)


def selected_incident(a, candidates=None):
    incs = candidates if candidates is not None else a.incidents
    ids = [i["incident_id"] for i in incs]
    if not ids:
        return None
    return S.selected if S.selected in ids else ids[0]
