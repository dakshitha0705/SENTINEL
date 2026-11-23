"""Evidence Contract verifier.

Every factual sentence produced by the SLM must cite fact IDs from the evidence pack. A sentence is
labelled **Verified** only if *all* of the following hold:

1. it cites at least one fact ID and every cited ID exists in the pack;
2. every number it states matches a number recorded in the cited facts;
3. every clock time it states matches a time recorded in the cited facts;
4. every user, host and IP it mentions appears in the cited facts (and no unknown IP/host is named),
   and every EVT-/ALR-/INC- identifier it names belongs to the cited facts;
5. typed fields the model returned (entities / numbers) match the cited facts;
6. its content is grounded in the cited facts (word overlap), so a valid citation attached to an
   unrelated sentence does not pass;
7. it does not assert certainty about intent or attribution that logs cannot establish.

Otherwise it is **Unverified**, with the failing checks listed, and is moved out of the factual summary.
"""
from __future__ import annotations

import re

ID_RE = re.compile(r"\b(?:EVT-\d+|ALR-\d+|INC-\d+|F\d+|PB-\d+|T\d{4}(?:\.\d{3})?|R[1-8])\b", re.I)
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)")
DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
TIME_RE = re.compile(r"\b([01]?\d|2[0-3]):([0-5]\d)(?::[0-5]\d(?:\.\d+)?)?\s*(am|pm|AM|PM)?(?![\d])")
NUM_RE = re.compile(r"(?<![\w.:/-])\d+(?:\.\d+)?(?![\w:/])")
HOSTLIKE_RE = re.compile(r"\b[A-Z]{2,}(?:-[A-Z0-9]+)+\b")
EVENT_CODES = {"4624", "4625", "4634", "4647", "4672", "4688", "4728", "4732", "4756", "1102"}

NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
                "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
                "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20}

STOP = set("""a an the and or of to in on at by for from with within after before during this that these those
is are was were be been being it its as into over under than then there their they them he she his her
which who whom whose what when where while also any all each both more most other some such no not only
own same so very can could may might should would will shall has have had do does did using used via per
about against between through same up down out off again further once here why how incident activity
account accounts user users host hosts event events log logs logon logons login logins observed indicates
indicate suggests suggest shows show showing occurred recorded detected detection detections evidence
potential possible possibly likely appears appear seems device devices involved involving involve security
related mentioned mention based fact facts multiple alerts alert stated states state listed list including
includes include occurred occur specifically""".split())

OVERCLAIM_RE = re.compile(
    r"\b(definitely|certainly|undoubtedly|without (a )?doubt|proves? (that )?|proof that|"
    r"confirm(?:ed|s)? (?:that )?(?:the )?(?:attack|compromise|breach|malicious)|"
    r"(?:is|was) (?:definitely |clearly )?(?:an? )?(?:attacker|threat actor|malicious insider)|"
    r"apt\d*|nation[- ]state|ransomware gang)\b", re.I)


# --------------------------------------------------------------------------- extraction helpers

def norm_time(h: str, m: str, ampm: str | None) -> str:
    hh = int(h)
    if ampm:
        a = ampm.lower()
        if a == "pm" and hh < 12:
            hh += 12
        if a == "am" and hh == 12:
            hh = 0
    return f"{hh:02d}:{m}"


def extract_times(text: str) -> set[str]:
    return {norm_time(h, m, ap) for h, m, ap in TIME_RE.findall(text or "")}


MONTHS = {m: i for i, m in enumerate(["january", "february", "march", "april", "may", "june", "july", "august",
                                      "september", "october", "november", "december"], start=1)}
MONTH_DATE_RE = re.compile(r"\b(?:(\d{1,2})(?:st|nd|rd|th)?\s+)?(" + "|".join(MONTHS) + r"|"
                           + "|".join(m[:3] for m in MONTHS) + r")\.?\s*(\d{1,2})?(?:st|nd|rd|th)?,?\s*(\d{4})\b", re.I)


def extract_dates(text: str) -> set[str]:
    out = set(DATE_RE.findall(text or ""))
    for d1, mon, d2, yr in MONTH_DATE_RE.findall(text or ""):
        mon_n = next((v for k, v in MONTHS.items() if k.startswith(mon.lower()[:3])), None)
        day = d1 or d2
        if mon_n and day:
            out.add(f"{yr}-{mon_n:02d}-{int(day):02d}")
    return out


def _strip_known(text: str, entities) -> str:
    t = MONTH_DATE_RE.sub(" ", text or "")
    t = DATE_RE.sub(" ", t)
    t = TIME_RE.sub(" ", t)
    t = IP_RE.sub(" ", t)
    t = ID_RE.sub(" ", t)
    for e in sorted(entities, key=len, reverse=True):
        if e:
            t = re.sub(re.escape(e), " ", t, flags=re.I)
    return t


def extract_numbers(text: str, entities=()) -> set[float]:
    t = _strip_known(text, entities)
    nums = {float(n) for n in NUM_RE.findall(t)}
    for w in re.findall(r"[a-z]+", t.lower()):
        if w in NUMBER_WORDS:
            nums.add(float(NUMBER_WORDS[w]))
    return nums


def find_entities(text: str, entities) -> set[str]:
    found = set()
    low = (text or "").lower()
    for e in entities:
        if not e or len(e) < 3:
            continue
        if re.search(r"(?<![\w.-])" + re.escape(e.lower()) + r"(?![\w-])", low):
            found.add(e.lower())
    return found


def content_words(text: str, entities=()) -> set[str]:
    t = _strip_known(text, entities).lower()
    words = re.findall(r"[a-z][a-z\-]{3,}", t)
    out = set()
    for w in words:
        if w in STOP:
            continue
        out.add(w[:6])  # crude stemming: compare 6-char prefixes
    return out


def fact_index(fact: dict, entities) -> dict:
    """Precomputed verification index for one fact."""
    text = fact["text"]
    nums = extract_numbers(text, entities)
    nums |= {float(x) for x in fact.get("numbers", [])}
    nums |= {float(len(fact.get(k, []))) for k in ("users", "hosts", "ips", "event_ids")}
    ents = {e.lower() for k in ("users", "hosts", "ips") for e in fact.get(k, [])}
    ents |= find_entities(text, entities)
    times = extract_times(text) | set(fact.get("times", []))
    return {"numbers": nums, "entities": ents, "times": times, "words": content_words(text, entities)}


# --------------------------------------------------------------------------- claim checks

def verify_claim(claim: dict, pack: dict, known_entities: set, require_grounding=True,
                 check_overclaim=True) -> dict:
    text = str(claim.get("text", "")).strip()
    cited = [str(c).strip().upper() for c in (claim.get("fact_ids") or claim.get("supporting_fact_ids") or [])]
    facts = {f["id"]: f for f in pack["facts"]}
    problems, checks = [], []
    if not text:
        problems.append("empty statement")
    elif len(re.findall(r"[A-Za-z0-9]", text)) < 8:
        problems.append("statement has no checkable content")
    if not cited:
        problems.append("no fact IDs cited")
    missing = [c for c in cited if c not in facts]
    if missing:
        problems.append(f"cites unknown fact IDs: {', '.join(missing)}")
    valid = [facts[c] for c in cited if c in facts]
    idx = pack.setdefault("_index", {})
    for f in valid:
        if f["id"] not in idx:
            idx[f["id"]] = fact_index(f, known_entities)
    nums = set().union(*(idx[f["id"]]["numbers"] for f in valid)) if valid else set()
    ents = set().union(*(idx[f["id"]]["entities"] for f in valid)) if valid else set()
    times = set().union(*(idx[f["id"]]["times"] for f in valid)) if valid else set()
    words = set().union(*(idx[f["id"]]["words"] for f in valid)) if valid else set()
    all_known = set(known_entities)

    # numbers
    claim_nums = extract_numbers(text, all_known)
    claim_nums = {n for n in claim_nums if str(int(n)) not in EVENT_CODES or n != int(n)}
    for n in claim_nums:
        # counts must match exactly; fractional measurements (e.g. 3.2 min) may be rounded
        if n not in nums and not any(f != int(f) and abs(n - f) < 1 for f in nums):
            problems.append(f"number {n:g} not found in cited facts")
    checks.append(f"numbers checked: {len(claim_nums)}")
    for n in claim.get("numbers") or []:
        try:
            if float(n) not in nums:
                problems.append(f"typed number {n} not found in cited facts")
        except (TypeError, ValueError):
            problems.append(f"typed number {n!r} is not numeric")
    # times
    claim_times = extract_times(text)
    for t in claim_times:
        if t not in times:
            problems.append(f"time {t} not found in cited facts")
    checks.append(f"times checked: {len(claim_times)}")
    fact_dates = set().union(*(extract_dates(f["text"]) for f in valid)) if valid else set()
    for d in extract_dates(text):
        if d not in fact_dates:
            problems.append(f"date {d} not found in cited facts")
    # entities
    mentioned = find_entities(text, all_known)
    for e in mentioned:
        if e not in ents:
            problems.append(f"'{e}' is not in the cited facts")
    for ip in IP_RE.findall(text):
        if ip.lower() not in ents:
            problems.append(f"IP {ip} is not in the cited facts")
    for h in HOSTLIKE_RE.findall(text):
        if h.lower() not in ents and h.lower() not in {e.lower() for e in all_known} and not h.startswith(("EVT", "ALR", "INC", "PB")):
            problems.append(f"unknown host/name '{h}'")
    # event / alert / incident IDs named in the sentence must belong to the cited facts
    cited_ids = set()
    for f in valid:
        cited_ids |= {x.upper() for x in f.get("event_ids", [])}
        cited_ids |= {x.upper() for x in re.findall(r"\b(?:EVT|ALR|INC)-\d+\b", f["text"])}
        if f.get("ref"):
            cited_ids.add(str(f["ref"]).upper())
    for rid in set(re.findall(r"\b(?:EVT|ALR|INC)-\d+\b", text, re.I)):
        if rid.upper() not in cited_ids:
            problems.append(f"{rid.upper()} is not referenced by the cited facts")
    for e in claim.get("entities") or []:
        if str(e).lower() not in ents:
            problems.append(f"typed entity '{e}' not in cited facts")
    # typed claim fields (Evidence Contract v7): each value must be supported by the cited facts
    typed = 0
    for key in ("user", "host", "source_ip"):
        v = str(claim.get(key) or "").strip()
        if v and v.lower() not in ("none", "null", "n/a", "-"):
            typed += 1
            if v.lower() not in ents:
                problems.append(f"typed {key} '{v}' not in cited facts")
    if claim.get("count") not in (None, "", 0):
        typed += 1
        try:
            if float(claim["count"]) not in nums:
                problems.append(f"typed count {claim['count']} not found in cited facts")
        except (TypeError, ValueError):
            problems.append(f"typed count {claim['count']!r} is not numeric")
    for key in ("start_time", "end_time"):
        v = str(claim.get(key) or "").strip()
        if v:
            typed += 1
            tt = extract_times(v) or ({v} if re.fullmatch(r"\d{2}:\d{2}", v) else set())
            if not tt:
                problems.append(f"typed {key} '{v}' is not a HH:MM time")
            for t in tt:
                if t not in times:
                    problems.append(f"typed {key} {t} not found in cited facts")
    fact_events = {x.upper() for f in valid for x in f.get("event_ids", [])}
    for e in claim.get("event_ids") or []:
        typed += 1
        if str(e).upper() not in fact_events:
            problems.append(f"typed event {e} is not an event of the cited facts")
    if typed:
        checks.append(f"typed fields checked: {typed}")
    checks.append(f"entities checked: {len(mentioned)}")
    # grounding
    if require_grounding and valid and text:
        cw = content_words(text, all_known)
        if cw:
            overlap = len(cw & words) / len(cw)
            checks.append(f"content overlap {overlap:.0%}")
            if overlap < 0.25 and not (mentioned or claim_nums or claim_times):
                problems.append(f"statement content not supported by cited facts (overlap {overlap:.0%})")
            elif overlap < 0.15:
                problems.append(f"statement content weakly related to cited facts (overlap {overlap:.0%})")
    if check_overclaim:
        m = OVERCLAIM_RE.search(text)
        if m:
            problems.append(f"asserts certainty/attribution the logs cannot establish ('{m.group(0)}')")
    return {"text": text, "fact_ids": cited, "status": "Verified" if not problems else "Unverified",
            "problems": problems, "checks": checks}


SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z(\"'])")


def split_sentences(text: str) -> list[str]:
    return [s.strip() for s in SENT_SPLIT.split(str(text or "")) if s.strip()]


def _claims(items) -> list[dict]:
    """Each sentence of a multi-sentence item is verified on its own (with the item's citations)."""
    out = []
    for c in items or []:
        c = c if isinstance(c, dict) else {"text": str(c), "fact_ids": []}
        ids = c.get("fact_ids") or []
        for s in split_sentences(c.get("text", "")) or [""]:
            out.append({**c, "text": s, "fact_ids": ids})
    return out


def verify_output(out: dict, pack: dict, known_entities: set) -> dict:
    """Verify a full SLM (or template) explanation against its evidence pack, sentence by sentence."""
    res = {"summary": [], "conclusions": [], "hypotheses": [], "actions": [], "questions": [], "rejected_actions": []}
    for c in _claims(out.get("summary")):
        res["summary"].append(verify_claim(c, pack, known_entities))
    for c in _claims(out.get("supported_conclusions")):
        res["conclusions"].append(verify_claim(c, pack, known_entities))
    fact_ids = {f["id"] for f in pack["facts"]}
    seen_h = set()
    for h in out.get("hypotheses") or []:
        if not isinstance(h, dict):
            h = {"text": str(h)}
        key = str(h.get("text", "")).strip().lower()
        if key in seen_h:
            continue
        seen_h.add(key)
        sup = [str(x).upper() for x in h.get("supporting_fact_ids") or []]
        con = [str(x).upper() for x in h.get("contradicting_fact_ids") or []]
        v = verify_claim({"text": h.get("text", ""), "fact_ids": sup + con}, pack, known_entities,
                         require_grounding=False, check_overclaim=True)
        bad = [x for x in sup + con if x not in fact_ids]
        res["hypotheses"].append({"text": v["text"], "supporting_fact_ids": sup, "contradicting_fact_ids": con,
                                  "how_to_confirm": str(h.get("how_to_confirm", "")),
                                  "status": "Grounded hypothesis" if v["status"] == "Verified" and sup else "Ungrounded hypothesis",
                                  "problems": v["problems"] + ([] if sup else ["no supporting fact cited"]) +
                                  ([f"unknown IDs {bad}"] if bad and not any('unknown fact' in p for p in v['problems']) else [])})
    allowed = {p["id"] for p in pack["playbooks"]}
    seen = set()
    for a in out.get("recommended_actions") or []:
        if not isinstance(a, dict):
            a = {"playbook_id": str(a)}
        pid = str(a.get("playbook_id", "")).upper().strip()
        if pid in allowed and pid not in seen:
            seen.add(pid)
            adapt = str(a.get("adaptation", ""))
            unknown = [e for e in find_entities(adapt, known_entities)
                       if e not in {x.lower() for f in pack["facts"] for k in ("users", "hosts", "ips") for x in f.get(k, [])}]
            res["actions"].append({"playbook_id": pid, "adaptation": adapt,
                                   "status": "OK" if not unknown else "Adaptation mentions entities outside this incident",
                                   "problems": [f"'{u}' not in this incident" for u in unknown]})
        else:
            res["rejected_actions"].append({"playbook_id": pid or "(none)",
                                            "reason": "duplicate" if pid in seen else "not in the offline playbook library for this incident"})
    for q in out.get("open_questions") or []:
        res["questions"].append(str(q.get("text", q)) if isinstance(q, dict) else str(q))
    factual = res["summary"] + res["conclusions"]
    verified = sum(1 for c in factual if c["status"] == "Verified")
    res["stats"] = {"factual_claims": len(factual), "verified": verified, "unverified": len(factual) - verified,
                    "verification_rate": (verified / len(factual)) if factual else None,
                    "hypotheses": len(res["hypotheses"]),
                    "grounded_hypotheses": sum(1 for h in res["hypotheses"] if h["status"] == "Grounded hypothesis"),
                    "actions_accepted": len(res["actions"]), "actions_rejected": len(res["rejected_actions"])}
    return res
