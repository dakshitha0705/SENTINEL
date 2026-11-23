"""Deterministic analyst answers and shift-handoff notes, built only from the evidence pack.

Every sentence produced here is copied from (or assembled from the fields of) pack facts and cites
them, so it passes the same verifier the SLM output goes through. These are used when the SLM is
unavailable or returns nothing, so the chat never replies with silence.
"""
from __future__ import annotations

import re

INTENTS = [
    ("severity", r"\b(severity|severe|score|why .*(high|critical|medium|low)|priority|how bad|urgent)"),
    ("contradicting", r"\b(contradict|against|benign|legit|false positive|innocent|counter)"),
    ("hosts", r"\b(device|host|machine|computer|endpoint|server|workstation|asset)s?\b"),
    ("accounts", r"\b(account|user|who|identity|identities|username)s?\b"),
    ("ips", r"\b(ip|address|source|where .* from|origin)\b"),
    ("next_steps", r"\b(investigate|next step|what should|recommend|do now|action|respond|remediat|playbook)"),
    ("timeline", r"\b(what happened|timeline|sequence|then|next|after|order|story|first|when)\b"),
    ("evidence", r"\b(evidence|event|support|prove|show|which logs|conclusion|why do you think|basis)\b"),
    ("mitre", r"\b(mitre|att&?ck|technique|tactic|ttp)\b"),
]


def classify(question: str) -> str | None:
    q = question.lower()
    for name, rx in INTENTS:
        if re.search(rx, q):
            return name
    return None


def _facts(pack, kind):
    return [f for f in pack["facts"] if f["kind"] == kind]


def _first_sentence(text: str) -> str:
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    return m.group(1) if m else text


def deterministic_answer(pack: dict, question: str) -> dict:
    """{'answer': [{'text','fact_ids'}], 'cannot_answer': str, 'intent': str|None}."""
    intent = classify(question)
    facts = {f["id"]: f for f in pack["facts"]}
    scope = facts[pack["scope_fact"]]
    sev = facts[pack["severity"]["fact_id"]]
    det = [f for f in pack["facts"] if f["kind"] in ("detection", "context") and "[weak link" not in f["text"]]
    ans = []
    if intent == "severity":
        ans.append({"text": sev["text"], "fact_ids": [sev["id"]]})
    elif intent == "hosts":
        if scope["hosts"]:
            ans.append({"text": f"Hosts involved: {', '.join(scope['hosts'])}.", "fact_ids": [scope["id"]]})
    elif intent == "accounts":
        if scope["users"]:
            ans.append({"text": f"Accounts involved: {', '.join(scope['users'])}.", "fact_ids": [scope["id"]]})
    elif intent == "ips":
        if scope["ips"]:
            ans.append({"text": f"Source IPs involved: {', '.join(scope['ips'])}.", "fact_ids": [scope["id"]]})
        else:
            return {"answer": [], "intent": intent,
                    "cannot_answer": "The events in this incident carry no source IP address."}
    elif intent == "timeline" or intent == "evidence":
        for f in det[:5]:
            ans.append({"text": f["text"], "fact_ids": [f["id"]]})
    elif intent == "contradicting":
        con = [facts[c] for c in pack["contradicting_fact_ids"] if c in facts]
        if not con:
            return {"answer": [], "intent": intent,
                    "cannot_answer": "SENTINEL found no contradicting evidence for this incident in the supplied logs."}
        for f in con[:4]:
            ans.append({"text": f["text"], "fact_ids": [f["id"]]})
    elif intent == "next_steps":
        books = pack["playbooks"]
        for f in det[:2]:
            ans.append({"text": f["text"], "fact_ids": [f["id"]]})
        if books:
            return {"answer": ans, "cannot_answer": "", "intent": intent,
                    "note": "Recommended offline playbooks (analyst-approved, nothing runs automatically): "
                            + "; ".join(f"{p['id']} {p['title']}" for p in books[:4]) + "."}
    elif intent == "mitre":
        if pack["mitre"]:
            return {"answer": [], "intent": intent,
                    "cannot_answer": "", "note": "MITRE ATT&CK techniques mapped by the rules: " + ", ".join(pack["mitre"])}
    if not ans:
        return {"answer": [], "intent": intent,
                "cannot_answer": "The evidence pack does not contain information that answers this question. "
                                 "Try asking about severity, hosts, accounts, the timeline, the evidence, "
                                 "contradicting evidence or next steps."}
    return {"answer": ans, "cannot_answer": "", "intent": intent}


def handoff_note(pack: dict, inc: dict, status: str = "New", disposition: str | None = None,
                 notes: list | None = None, verification: dict | None = None) -> dict:
    """Concise shift-change note. Factual lines cite facts (verifiable); workflow lines come from the
    analyst workspace and are labelled as such."""
    facts = {f["id"]: f for f in pack["facts"]}
    scope = facts[pack["scope_fact"]]
    sev = facts[pack["severity"]["fact_id"]]
    det = [f for f in pack["facts"] if f["kind"] == "detection" and "[weak link" not in f["text"]]
    findings = [{"text": _first_sentence(f["text"]).rstrip(".") + ".", "fact_ids": [f["id"]]} for f in det[:4]]
    if not findings:
        findings = [{"text": f["text"], "fact_ids": [f["id"]]}
                    for f in pack["facts"] if f["kind"] == "context"][:3]
    unresolved = list(pack["limitations"][:2])
    if pack["contradicting_fact_ids"]:
        unresolved.append(f"Contradicting evidence to rule out: {', '.join(pack['contradicting_fact_ids'][:4])}.")
    if not disposition or disposition == "Needs investigation":
        unresolved.insert(0, "Disposition not decided: is this activity authorised?")
    actions = [f"{p['id']} {p['title']}" for p in pack["playbooks"][:4]]
    note = {
        "incident_id": inc["incident_id"], "title": inc["title"],
        "summary": {"text": scope["text"], "fact_ids": [scope["id"]]},
        "severity": {"text": _first_sentence(sev["text"]), "fact_ids": [sev["id"]]},
        "key_findings": findings,
        "affected": {"accounts": scope["users"], "hosts": scope["hosts"], "source_ips": scope["ips"]},
        "progress": {"status": status, "disposition": disposition or "Not set",
                     "notes": [n["note"] for n in (notes or [])][-3:],
                     "slm_verification": (f"{verification['verified']}/{verification['factual_claims']} SLM claims verified"
                                          if verification and verification.get("factual_claims") else "not run")},
        "unresolved_questions": unresolved,
        "next_actions": actions,
        "evidence_references": sorted({e for f in det for e in f["event_ids"]})[:20],
        "mitre": pack["mitre"],
    }
    return note


def handoff_claims(note: dict) -> list[dict]:
    """Factual parts of a handoff note, in the form verify_output() expects."""
    return [note["summary"], note["severity"], *note["key_findings"]]


def handoff_text(note: dict) -> str:
    a = note["affected"]
    lines = [f"SHIFT HANDOFF - {note['incident_id']}: {note['title']}",
             f"Severity: {note['severity']['text']}",
             f"Summary: {note['summary']['text']}",
             "Key verified findings:"] + [f"  - {k['text']} [{', '.join(k['fact_ids'])}]" for k in note["key_findings"]] + [
             f"Affected accounts: {', '.join(a['accounts']) or 'none'} | hosts: {', '.join(a['hosts']) or 'none'} | "
             f"source IPs: {', '.join(a['source_ips']) or 'none'}",
             f"Progress: status {note['progress']['status']}; disposition {note['progress']['disposition']}; "
             f"{note['progress']['slm_verification']}"] + [f"  note: {n}" for n in note["progress"]["notes"]] + [
             "Unresolved:"] + [f"  - {q}" for q in note["unresolved_questions"]] + [
             "Next actions:"] + [f"  - {x}" for x in note["next_actions"]] + [
             f"Evidence: {', '.join(note['evidence_references'])}",
             f"MITRE ATT&CK: {', '.join(note['mitre']) or 'none'}"]
    return "\n".join(lines)
