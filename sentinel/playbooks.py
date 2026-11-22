"""Offline playbook library and MITRE ATT&CK reference."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"


@lru_cache(maxsize=1)
def load_playbooks() -> dict:
    with open(DATA / "playbooks.json", encoding="utf-8") as fh:
        return {p["id"]: p for p in json.load(fh)["playbooks"]}


@lru_cache(maxsize=1)
def load_mitre() -> dict:
    with open(DATA / "mitre.json", encoding="utf-8") as fh:
        return json.load(fh)["techniques"]


def mitre_info(tid: str) -> dict:
    t = load_mitre().get(tid)
    url = "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
    if not t:
        return {"id": tid, "name": "(not in offline reference)", "tactics": [], "summary": "", "url": url}
    return {"id": tid, **t, "url": url}


def candidates_for(incident: dict) -> list[dict]:
    """Playbooks relevant to the incident's rules (the SLM may only choose from these)."""
    rules = set(incident["rules"])
    if incident.get("seed_kind") == "anomalous_logon":
        rules.add("ANOM")
    if incident.get("severity", {}).get("level") == "Critical":
        rules.add("CRITICAL")
    return [p for p in load_playbooks().values() if rules & set(p["applies_to"])]
