"""Self-contained HTML incident report (no external fonts, scripts or CDNs)."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

import pandas as pd
from jinja2 import Environment, select_autoescape

from . import __version__
from .correlate import storyline
from .playbooks import load_playbooks, mitre_info

TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ inc.incident_id }} - SENTINEL incident report</title>
<style>
:root{--ink:#1b2430;--muted:#5b6675;--line:#d9dee5;--bg:#ffffff;--panel:#f5f7fa;--crit:#b42318;--high:#c4520f;--med:#a77b06;--low:#3d6b8c;--ok:#1f7a4d;--bad:#b42318}
*{box-sizing:border-box}body{font-family:"Segoe UI",system-ui,-apple-system,Arial,sans-serif;color:var(--ink);background:var(--bg);margin:0;font-size:14px;line-height:1.5}
.wrap{max-width:1080px;margin:0 auto;padding:28px 24px 60px}
h1{font-size:22px;margin:0 0 6px}h2{font-size:16px;margin:28px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.meta{color:var(--muted);font-size:12.5px}.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-weight:600;font-size:12px;color:#fff}
.Critical{background:var(--crit)}.High{background:var(--high)}.Medium{background:var(--med)}.Low{background:var(--low)}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:14px}.kpi{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.kpi b{display:block;font-size:18px}.kpi span{color:var(--muted);font-size:12px}
table{width:100%;border-collapse:collapse;font-size:12.5px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--panel);font-weight:600}td.num{text-align:right;font-variant-numeric:tabular-nums}
.v{color:var(--ok);font-weight:600}.u{color:var(--bad);font-weight:600}.muted{color:var(--muted)}
.claim{padding:6px 0;border-bottom:1px dashed var(--line)}.cite{font-family:Consolas,monospace;font-size:11.5px;color:var(--muted)}
code,.mono{font-family:Consolas,"Courier New",monospace;font-size:12px;word-break:break-all}
.box{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin:8px 0}
.weak{color:var(--muted);font-style:italic}details summary{cursor:pointer;color:var(--muted)}
.note{font-size:12px;color:var(--muted)}@media print{.wrap{padding:0}h2{break-after:avoid}tr{break-inside:avoid}}
@media (max-width:700px){.grid{grid-template-columns:repeat(2,1fr)}}
</style></head><body><div class="wrap">
<div class="meta">SENTINEL v{{ version }} &middot; Offline Security Incident Triage Assistant &middot; Tinyverse PS 02</div>
<h1>{{ inc.incident_id }} &mdash; {{ inc.title }}</h1>
<div><span class="pill {{ sev.level }}">{{ sev.level }} &middot; {{ sev.score }}/100</span>
 <span class="meta">&nbsp; Confidence malicious: <b>{{ sev.confidence.level }}</b> ({{ sev.confidence.reason }})</span></div>
<div class="grid">
 <div class="kpi"><b>{{ start }}</b><span>First activity (UTC)</span></div>
 <div class="kpi"><b>{{ end }}</b><span>Last activity (UTC)</span></div>
 <div class="kpi"><b>{{ inc.event_ids|length }}</b><span>Supporting log events</span></div>
 <div class="kpi"><b>{{ inc.alert_ids|length }}</b><span>Correlated alerts</span></div>
</div>
<p class="meta">Accounts: <b>{{ inc.users|join(', ') or '-' }}</b> &middot; Hosts: <b>{{ inc.hosts|join(', ') or '-' }}</b> &middot; Source IPs: <b>{{ inc.ips|join(', ') or '-' }}</b><br>
Report generated {{ generated }} &middot; Explanation source: <b>{{ source_label }}</b>{% if model %} &middot; Model: {{ model }}{% endif %}</p>

<h2>Executive summary (verified statements only)</h2>
{% for c in verified_summary %}<div class="claim">{{ c.text }} <span class="cite">[{{ c.fact_ids|join(', ') }}]</span></div>{% else %}<p class="muted">No statement passed verification.</p>{% endfor %}

<h2>Severity breakdown</h2>
<table><tr><th>Factor</th><th>Detail</th><th style="text-align:right">Points</th></tr>
{% for l in sev.breakdown %}<tr><td>{{ l.factor }}</td><td class="muted">{{ l.detail }}</td><td class="num">{{ '%+d'|format(l.points) }}</td></tr>{% endfor %}
<tr><th>Total{% if sev.raw_score != sev.score %} (raw {{ sev.raw_score }}, capped){% endif %}</th><th></th><th style="text-align:right">{{ sev.score }}</th></tr></table>
<p class="note">Levels: Critical 80-100, High 60-79, Medium 35-59, Low 0-34. Severity is potential impact; confidence (above) is how strongly the evidence indicates malicious activity.</p>

<h2>Detection findings and attack storyline</h2>
<table><tr><th>Time (UTC)</th><th>Alert</th><th>Finding</th><th>Link into incident</th></tr>
{% for s in steps %}<tr class="{{ 'weak' if s.membership=='weak' else '' }}"><td class="mono">{{ s.t }}</td><td><b>{{ s.rule }}</b> {{ s.name }}<br><span class="cite">{{ s.alert_id }}</span></td>
<td>{{ s.reason }}<br><span class="cite">{{ s.events }}</span></td>
<td>{% if s.link %}<b>{{ s.link.strength }}</b>: {{ s.link.reason }}{% else %}<span class="muted">incident seed</span>{% endif %}</td></tr>{% endfor %}</table>

<h2>Evidence vs. hypothesis</h2>
<div class="box"><b>Supported conclusions</b>
{% for c in conclusions %}<div class="claim"><span class="{{ 'v' if c.status=='Verified' else 'u' }}">{{ c.status }}</span> &mdash; {{ c.text }} <span class="cite">[{{ c.fact_ids|join(', ') }}]</span>
{% if c.problems %}<div class="note">{{ c.problems|join('; ') }}</div>{% endif %}</div>{% else %}<p class="muted">None.</p>{% endfor %}</div>
<div class="box"><b>Hypotheses requiring investigation</b>
{% for h in hypotheses %}<div class="claim">{{ h.text }} <span class="cite">supports [{{ h.supporting_fact_ids|join(', ') }}]{% if h.contradicting_fact_ids %} &middot; contradicts [{{ h.contradicting_fact_ids|join(', ') }}]{% endif %}</span>
<div class="note">{{ h.status }}{% if h.how_to_confirm %} &middot; How to confirm: {{ h.how_to_confirm }}{% endif %}</div></div>{% else %}<p class="muted">None.</p>{% endfor %}</div>
<div class="box"><b>Contradicting evidence (computed from the logs, not by the model)</b>
{% for f in contradicting %}<div class="claim">{{ f.text }} <span class="cite">[{{ f.id }}]</span></div>{% else %}<p class="muted">No contradicting evidence found.</p>{% endfor %}</div>
{% if questions %}<div class="box"><b>Open questions</b><ul>{% for q in questions %}<li>{{ q }}</li>{% endfor %}</ul></div>{% endif %}
{% if unverified %}<div class="box"><b>Unverified statements (removed from the summary)</b>
{% for c in unverified %}<div class="claim"><span class="u">Unverified</span> &mdash; {{ c.text }}<div class="note">{{ c.problems|join('; ') }}</div></div>{% endfor %}</div>{% endif %}

<h2>MITRE ATT&amp;CK techniques</h2>
<table><tr><th>ID</th><th>Technique</th><th>Tactics</th><th>Reference</th></tr>
{% for t in mitre %}<tr><td class="mono">{{ t.id }}</td><td>{{ t.name }}<div class="note">{{ t.summary }}</div></td><td>{{ t.tactics|join(', ') }}</td><td class="mono">{{ t.url }}</td></tr>{% endfor %}</table>

<h2>Recommended response actions</h2>
{% for a in actions %}<div class="box"><b>{{ a.id }} &middot; {{ a.title }}</b>{% if a.adaptation %}<div>{{ a.adaptation }}</div>{% endif %}
<ol>{% for s in a.steps %}<li>{{ s }}</li>{% endfor %}</ol></div>{% endfor %}
<p class="note">Recommendations come only from SENTINEL's offline playbook library. Nothing is executed automatically; every action requires analyst approval.</p>

<h2>Evidence verification</h2>
<p>{{ stats.verified }} of {{ stats.factual_claims }} factual statements verified{% if stats.verification_rate is not none %} ({{ '%.0f'|format(100*stats.verification_rate) }}%){% endif %};
{{ stats.grounded_hypotheses }} of {{ stats.hypotheses }} hypotheses grounded in cited facts; {{ stats.actions_rejected }} recommended action(s) rejected as outside the playbook library.</p>
{% if error %}<p class="note">SLM note: {{ error }}</p>{% endif %}
<details><summary>Evidence pack facts ({{ facts|length }})</summary><table><tr><th>ID</th><th>Kind</th><th>Fact</th></tr>
{% for f in facts %}<tr><td class="mono">{{ f.id }}</td><td>{{ f.kind }}</td><td>{{ f.text }}</td></tr>{% endfor %}</table></details>

<h2>Original log evidence</h2>
<table><tr><th>Event</th><th>Time (UTC)</th><th>Source</th><th>Action</th><th>Account</th><th>Host</th><th>Source IP</th><th>Process / command</th></tr>
{% for e in evidence %}<tr><td class="mono">{{ e.event_id }}</td><td class="mono">{{ e.time }}</td><td class="mono">{{ e.source }}</td><td>{{ e.action }} <span class="cite">{{ e.code }}</span></td><td>{{ e.user }}</td><td>{{ e.host }}</td><td class="mono">{{ e.ip }}</td>
<td class="mono">{{ e.proc }}<details><summary>original record</summary><code>{{ e.raw }}</code></details></td></tr>{% endfor %}</table>

<h2>Analysis limitations</h2><ul>{% for l in limitations %}<li>{{ l }}</li>{% endfor %}
<li>Detection thresholds were tuned on synthetic development data; see the README for measured accuracy.</li></ul>

<h2>Input files and integrity</h2>
<table><tr><th>File</th><th>Format</th><th>Records</th><th>SHA-256</th></tr>
{% for f in files %}<tr><td>{{ f.name }}</td><td>{{ f.format }}</td><td class="num">{{ f.accepted }}</td><td class="mono">{{ f.sha256 }}</td></tr>{% endfor %}</table>
<p class="note">Original files were read without modification. "Source" column = file:row of the original record. Normalised fields are derived; the original record is shown verbatim.</p>
</div></body></html>"""

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
_tpl = _env.from_string(TEMPLATE)


EDGE_PATHS = [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
              r"C:\Program Files\Google\Chrome\Application\chrome.exe"]


def pdf_available() -> str | None:
    from pathlib import Path
    return next((p for p in EDGE_PATHS if Path(p).exists()), None)


def html_to_pdf(html_path, pdf_path, timeout=60) -> bool:
    """Print a local HTML report to PDF with the locally installed Edge/Chrome (headless, offline)."""
    import subprocess
    from pathlib import Path
    exe = pdf_available()
    if not exe:
        return False
    html_path, pdf_path = Path(html_path).resolve(), Path(pdf_path).resolve()
    prof = Path(html_path).parent / ".pdf-profile"
    subprocess.run([exe, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--user-data-dir={prof}",
                    f"--print-to-pdf={pdf_path}", html_path.as_uri()], timeout=timeout, capture_output=True)
    return pdf_path.exists() and pdf_path.stat().st_size > 0


def _ts(x):
    return pd.Timestamp(x).strftime("%Y-%m-%d %H:%M:%S")


def render_report(analysis, incident_id: str, explanation: dict, verification: dict) -> str:
    inc = analysis.incident(incident_id)
    pack = analysis.packs[incident_id]
    ev = analysis.events.set_index("event_id")
    steps = []
    for s in storyline(inc, analysis.alerts_by_id):
        eids = s["event_ids"]
        steps.append({**s, "t": _ts(s["time"]),
                      "events": ", ".join(eids) if len(eids) <= 4 else f"{eids[0]} ... {eids[-1]} ({len(eids)})"})
    evidence = []
    for e in inc["event_ids"]:
        r = ev.loc[e]
        proc = " ".join(x for x in [r["process"], ("<- " + r["parent_process"]) if r["parent_process"] else "",
                                    r["command_line"]] if x)
        if r["group"]:
            proc = f"group: {r['group']}; member: {r['target_user']}; actor: {r['actor']}"
        evidence.append({"event_id": e, "time": _ts(r["timestamp"]), "source": f"{r['source_file']}:{r['source_row']}",
                         "action": r["action"], "code": r["event_code"], "user": r["user"], "host": r["host"],
                         "ip": r["src_ip"], "proc": proc, "raw": r["raw"]})
    pb = load_playbooks()
    adapt = {a["playbook_id"]: a["adaptation"] for a in verification["actions"]}
    action_ids = [a["playbook_id"] for a in verification["actions"]] or [p["id"] for p in pack["playbooks"][:3]]
    actions = [{**pb[i], "adaptation": adapt.get(i, "")} for i in action_ids if i in pb]
    facts = {f["id"]: f for f in pack["facts"]}
    src = explanation.get("source")
    source_label = {"slm": "local SLM (live)", "cache": "local SLM (cached result)",
                    "template": "deterministic template (SLM not used)"}.get(src, src)
    return _tpl.render(
        version=__version__, inc=inc, sev=inc["severity"], start=_ts(inc["start"]), end=_ts(inc["end"]),
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"), source_label=source_label,
        model=explanation.get("model") if src in ("slm", "cache") else None,
        verified_summary=[c for c in verification["summary"] + verification["conclusions"] if c["status"] == "Verified"][:6],
        conclusions=verification["conclusions"], hypotheses=verification["hypotheses"],
        contradicting=[facts[i] for i in pack["contradicting_fact_ids"] if i in facts],
        questions=verification["questions"],
        unverified=[c for c in verification["summary"] + verification["conclusions"] if c["status"] != "Verified"],
        mitre=[mitre_info(t) for t in inc["mitre"]], actions=actions, stats=verification["stats"],
        error=explanation.get("error"), facts=pack["facts"], steps=steps, evidence=evidence,
        limitations=pack["limitations"], files=analysis.dataset.files)
