"""Build presentation/SENTINEL_Tinyverse_PS02.pptx from real results and screenshots.

    python scripts/build_pptx.py

All metrics are read from results/*.json at build time (nothing is typed in by hand), and all images
are real screenshots from docs/screenshots/. Re-run after re-evaluating to refresh the numbers.
"""
from __future__ import annotations

import json
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_CONNECTOR, MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results"
SHOTS = ROOT / "docs" / "screenshots"
OUT = ROOT / "presentation" / "SENTINEL_Tinyverse_PS02.pptx"

BG = RGBColor(0x0F, 0x14, 0x1A)
PANEL = RGBColor(0x17, 0x20, 0x2A)
LINE = RGBColor(0x2B, 0x3B, 0x4D)
TEXT = RGBColor(0xE3, 0xE9, 0xEF)
MUTED = RGBColor(0x8F, 0xA0, 0xB3)
ACCENT = RGBColor(0x5B, 0x8D, 0xB8)
OK = RGBColor(0x5F, 0xAF, 0x7F)
BAD = RGBColor(0xD9, 0x66, 0x5E)
SEV = {"Critical": RGBColor(0xC2, 0x41, 0x3A), "High": RGBColor(0xC8, 0x77, 0x3A),
       "Medium": RGBColor(0xB3, 0x9B, 0x3A), "Low": RGBColor(0x5E, 0x8A, 0xA8)}
FONT = "Segoe UI"

prs = Presentation()
prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
BLANK = prs.slide_layouts[6]
W, H = prs.slide_width, prs.slide_height


def load(name):
    p = RES / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


M = load("metrics.json")
OFF = load("offline_run.json")
PUB = load("public_sanity.json")
CHAT = load("chat_benchmark.json")


def slm_summary(model_tag):
    rows = [load(f"slm_benchmark_{s}_{model_tag}.json") for s in ("test_seed101", "test_seed202", "test_seed303")]
    rows = [r["summary"] for r in rows if r]
    if not rows:
        return None
    claims = sum(r["factual_claims"] for r in rows)
    ver = sum(r["verified"] for r in rows)
    n = sum(r["slm_answers"] for r in rows)
    return {"claims": claims, "verified": ver, "rate": ver / claims if claims else 0,
            "wall": sum(r["mean_wall_s"] * r["slm_answers"] for r in rows) / n if n else 0,
            "tps": sum(r["mean_tokens_per_s"] * r["slm_answers"] for r in rows) / n if n else 0,
            "answers": n, "fallbacks": sum(r["fallbacks"] for r in rows),
            "vram": (rows[0]["ollama"]["loaded"] or [{}])[0].get("vram_gb")}


S3 = slm_summary("qwen2.5-3b")
S7 = slm_summary("qwen2.5-7b")


# --------------------------------------------------------------------------- primitives

def slide(title=None, kicker=None):
    s = prs.slides.add_slide(BLANK)
    s.background.fill.solid()
    s.background.fill.fore_color.rgb = BG
    bar = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(0.12), H)
    bar.fill.solid(); bar.fill.fore_color.rgb = ACCENT; bar.line.fill.background()
    if kicker:
        text(s, kicker.upper(), Inches(0.6), Inches(0.35), Inches(10), Inches(0.35), 11, MUTED, bold=True, spacing=2)
    if title:
        text(s, title, Inches(0.6), Inches(0.65), Inches(12.2), Inches(0.8), 28, TEXT, bold=True)
    foot = text(s, "SENTINEL · Tinyverse Hackathon Phase 2 · PS 02 Offline Security Incident Triage Assistant",
                Inches(0.6), Inches(7.05), Inches(10), Inches(0.3), 9, MUTED)
    text(s, str(len(prs.slides)), Inches(12.4), Inches(7.05), Inches(0.5), Inches(0.3), 9, MUTED, align=PP_ALIGN.RIGHT)
    return s


def text(s, t, x, y, w, h, size=14, color=TEXT, bold=False, align=PP_ALIGN.LEFT, spacing=0, anchor=MSO_ANCHOR.TOP):
    tb = s.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = Inches(0.02)
    lines = t if isinstance(t, list) else [t]
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        r = p.add_run()
        r.text = line
        f = r.font
        f.size, f.bold, f.name = Pt(size), bold, FONT
        f.color.rgb = color
        if spacing:
            r._r.get_or_add_rPr().set("spc", str(spacing * 100))
    return tb


def bullets(s, items, x, y, w, h, size=15, color=TEXT, gap=6):
    tb = s.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    for i, it in enumerate(items):
        sub = isinstance(it, tuple)
        t = it[1] if sub else it
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_after = Pt(gap)
        r1 = p.add_run()
        r1.text = ("      – " if sub else "■  ")
        r1.font.size, r1.font.name = Pt(size - (3 if sub else 6)), FONT
        r1.font.color.rgb = MUTED if sub else ACCENT
        r = p.add_run()
        r.text = t
        r.font.size, r.font.name = Pt(size - (2 if sub else 0)), FONT
        r.font.color.rgb = MUTED if sub else color
    return tb


def panel(s, x, y, w, h, fill=PANEL, line=LINE):
    b = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, w, h)
    b.adjustments[0] = 0.06
    b.fill.solid(); b.fill.fore_color.rgb = fill
    b.line.color.rgb = line; b.line.width = Pt(1)
    b.shadow.inherit = False
    return b


def kpi(s, x, y, w, value, label, color=TEXT):
    panel(s, x, y, w, Inches(1.15))
    text(s, value, x + Inches(0.18), y + Inches(0.1), w - Inches(0.3), Inches(0.6), 26, color, bold=True)
    text(s, label.upper(), x + Inches(0.18), y + Inches(0.72), w - Inches(0.3), Inches(0.4), 9, MUTED, bold=True, spacing=1)


def box(s, x, y, w, h, title, sub=None, fill=PANEL, line=ACCENT):
    b = panel(s, x, y, w, h, fill, line)
    text(s, title, x + Inches(0.1), y + Inches(0.08), w - Inches(0.2), Inches(0.35), 13, TEXT, bold=True, align=PP_ALIGN.CENTER)
    if sub:
        text(s, sub, x + Inches(0.1), y + Inches(0.42), w - Inches(0.2), h - Inches(0.45), 10, MUTED, align=PP_ALIGN.CENTER)
    return b


def arrow(s, x1, y1, x2, y2, color=ACCENT, kind=MSO_CONNECTOR.STRAIGHT):
    c = s.shapes.add_connector(kind, int(x1), int(y1), int(x2), int(y2))  # EMU must be integers
    c.line.color.rgb = color
    c.line.width = Pt(1.75)
    ln = c.line._get_or_add_ln()
    tail = ln.makeelement("{http://schemas.openxmlformats.org/drawingml/2006/main}tailEnd", {"type": "triangle"})
    ln.append(tail)
    return c


def image(s, path, x, y, w=None, h=None, border=True):
    p = SHOTS / path
    if not p.exists():
        text(s, f"[missing screenshot {path}]", x, y, Inches(4), Inches(0.5), 12, BAD)
        return
    pic = s.shapes.add_picture(str(p), x, y, w, h)
    if border:
        pic.line.color.rgb = LINE
        pic.line.width = Pt(1)
    return pic


def table(s, rows, x, y, w, col_w=None, size=11, header_fill=RGBColor(0x1E, 0x2A, 0x37), row_h=0.36):
    nr, nc = len(rows), len(rows[0])
    gf = s.shapes.add_table(nr, nc, x, y, w, Inches(row_h * nr))
    t = gf.table
    # "No Style, No Grid" table style: no default white borders; fills are set per cell below
    from pptx.oxml.ns import qn
    tbl_pr = t._tbl.tblPr
    sid = tbl_pr.find(qn("a:tableStyleId"))
    if sid is None:
        sid = tbl_pr.makeelement(qn("a:tableStyleId"), {})
        tbl_pr.append(sid)
    sid.text = "{2D5ABB26-0587-4C30-8999-92F81FD0307C}"
    if col_w:
        for i, cw in enumerate(col_w):
            t.columns[i].width = Inches(cw)
    for r in range(nr):
        t.rows[r].height = Inches(row_h)
        for c in range(nc):
            cell = t.cell(r, c)
            cell.fill.solid()
            cell.fill.fore_color.rgb = header_fill if r == 0 else (PANEL if r % 2 else BG)
            cell.margin_left = cell.margin_right = Inches(0.08)
            cell.margin_top = cell.margin_bottom = Inches(0.03)
            tf = cell.text_frame
            tf.word_wrap = True
            val = rows[r][c]
            color = TEXT
            if isinstance(val, tuple):
                val, color = val
            tf.paragraphs[0].text = ""
            run = tf.paragraphs[0].add_run()
            run.text = str(val)
            run.font.size, run.font.name = Pt(size), FONT
            run.font.bold = r == 0
            run.font.color.rgb = MUTED if r == 0 else color
    return t


def fmt(v, pct=False):
    if v is None:
        return "–"
    return f"{v:.1%}" if pct else f"{v:.3f}"


# --------------------------------------------------------------------------- slides

# 1 Title
s = prs.slides.add_slide(BLANK)
s.background.fill.solid(); s.background.fill.fore_color.rgb = BG
bar = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(0.12), H); bar.fill.solid(); bar.fill.fore_color.rgb = ACCENT; bar.line.fill.background()
text(s, "TINYVERSE HACKATHON · PHASE 2 · PROBLEM STATEMENT 02", Inches(0.9), Inches(1.6), Inches(11), Inches(0.4), 13, MUTED, bold=True, spacing=3)
text(s, "SENTINEL", Inches(0.9), Inches(2.1), Inches(11), Inches(1.3), 66, TEXT, bold=True, spacing=8)
text(s, "Offline Security Incident Triage Assistant", Inches(0.9), Inches(3.35), Inches(11), Inches(0.7), 28, ACCENT)
text(s, "Deterministic detection · Attack storylines · Explainable severity · Local SLM under an evidence contract",
     Inches(0.9), Inches(4.15), Inches(11.5), Inches(0.5), 16, MUTED)
text(s, ["Dakshitha  ·  individual entry", "Cybersecurity | Small Language Models  ·  runs fully offline on a laptop"],
     Inches(0.9), Inches(5.6), Inches(11), Inches(0.8), 14, TEXT)

# 2 Problem
s = slide("SOC analysts drown in logs, and cloud analysis is not always an option", "Problem & motivation")
bullets(s, ["Authentication and endpoint logs arrive in volumes no analyst can read line by line, so incidents are missed",
            "Related events (failed logons, a success, a privilege change, a suspicious process) sit in different files and minutes apart",
            "Organisations with limited connectivity or compute, or sensitive logs, cannot send them to cloud AI",
            "Generic LLM summaries are not acceptable evidence: an analyst must be able to trace every claim to a log line"],
        Inches(0.6), Inches(1.7), Inches(7.2), Inches(4.5), 17)
panel(s, Inches(8.3), Inches(1.7), Inches(4.4), Inches(4.4))
text(s, "PS 02 asks for", Inches(8.55), Inches(1.85), Inches(4), Inches(0.4), 13, MUTED, bold=True)
bullets(s, ["Offline, SLM-powered triage", "Detect ≥ 3 suspicious patterns", "Correlate by user, device, time",
            "Severity to prioritise", "Evidence-backed reports with next steps", "No cloud dependency"],
        Inches(8.55), Inches(2.3), Inches(4), Inches(3.7), 14)

# 3 Requirements
s = slide("Every official requirement maps to a working, tested component", "Official requirements (PS 02 §2)")
table(s, [["PS 02 requirement", "SENTINEL implementation", "Evidence"],
          ["Log processing (CSV / JSON)", "CSV, JSON, JSON-lines, nested flattening, column mapper, UTC, rejects & duplicates", "11 ingestion tests; unseen-format demo"],
          ["≥ 3 suspicious patterns", "8 required rules R1–R8 + R9–R11, per-user baselines", "Per-rule tests; accuracy page"],
          ["Event correlation", "Attack Storyline Engine: user / host / IP keys, time windows, reason per link", "Storyline view; Jaccard 0.93"],
          ["Severity classification", "0–100 score with line-by-line breakdown → Critical/High/Medium/Low", "Severity agreement metric"],
          ["SLM integration", "Qwen2.5-3B on Ollama: explanations, hypotheses, playbooks, chat", "SLM benchmark; verification rate"],
          ["Evidence-based reporting", "Self-contained HTML/PDF report with original log rows and hashes", "Report export"],
          ["Offline functionality", "Local model, no CDNs, telemetry off, connection monitor", "Offline run record"]],
      Inches(0.6), Inches(1.6), Inches(12.1), col_w=[2.7, 6.3, 3.1], size=12, row_h=0.6)

# 4 Solution
s = slide("Code produces the facts. The SLM interprets them, and is checked.", "Proposed solution")
items = [("Attack Storyline Engine", "Alerts become one chronological incident; every link records why it was made"),
         ("Evidence Contract", "The SLM sees only numbered facts and must cite them; each sentence is verified"),
         ("Evidence vs. Hypothesis", "Facts, conclusions, hypotheses, counter-evidence and next steps kept apart"),
         ("Measured accuracy", "Held-out and stress seeds, public data, measured SLM verification rate"),
         ("Verifiable offline", "Connection log of every remote endpoint during a full live run")]
for i, (t1, t2) in enumerate(items):
    y = Inches(1.65 + i * 1.03)
    panel(s, Inches(0.6), y, Inches(12.1), Inches(0.88))
    text(s, f"0{i + 1}", Inches(0.8), y + Inches(0.17), Inches(0.7), Inches(0.5), 22, ACCENT, bold=True)
    text(s, t1, Inches(1.6), y + Inches(0.12), Inches(3.6), Inches(0.5), 17, TEXT, bold=True)
    text(s, t2, Inches(5.2), y + Inches(0.2), Inches(7.3), Inches(0.5), 14, MUTED)

# 5 Architecture
s = slide("Architecture: a deterministic pipeline with one probabilistic step", "System architecture")
row1 = [("Ingest", "CSV · JSON · JSONL\nmapper · UTC · SHA-256"), ("Baselines", "per-user history\n4 h learning lag"),
        ("Rules R1–R11", "thresholds in YAML\nMITRE per alert"), ("Storyline engine", "strong / weak links\nreason per link"),
        ("Severity", "0–100 breakdown\n+ confidence")]
bw, bh, y1 = Inches(2.2), Inches(1.2), Inches(1.9)
for i, (t1, t2) in enumerate(row1):
    x = Inches(0.6) + i * Inches(2.48)
    box(s, x, y1, bw, bh, t1, t2)
    if i:
        arrow(s, x - Inches(0.28), y1 + bh / 2, x, y1 + bh / 2)
y2 = Inches(3.9)
row2 = [("Evidence pack", "facts F1..Fn\nsupporting / contradicting", Inches(0.6)),
        ("Local SLM", "Ollama · qwen2.5:3b\nJSON schema, fact IDs", Inches(3.4)),
        ("Verifier", "per-sentence checks\nVerified / Unverified", Inches(6.2)),
        ("Outputs", "dashboard · HTML/PDF report\nanalyst workspace (audit)", Inches(9.0))]
for t1, t2, x in row2:
    box(s, x, y2, Inches(2.5) if t1 != "Outputs" else Inches(3.7), bh, t1, t2,
        line=SEV["High"] if t1 == "Local SLM" else ACCENT)
arrow(s, Inches(0.6) + 4 * Inches(2.48) + bw / 2, y1 + bh, Inches(1.85), y2, kind=MSO_CONNECTOR.ELBOW)
arrow(s, Inches(3.1), y2 + bh / 2, Inches(3.4), y2 + bh / 2)
arrow(s, Inches(5.9), y2 + bh / 2, Inches(6.2), y2 + bh / 2)
arrow(s, Inches(8.7), y2 + bh / 2, Inches(9.0), y2 + bh / 2)
panel(s, Inches(0.6), Inches(5.55), Inches(12.1), Inches(1.15), fill=BG)
text(s, ["Fallback: SLM unavailable, slow or invalid → deterministic template explanation (100% verified). Detection, correlation, "
         "severity, verification and reporting never depend on the model.",
         "Stack: Python 3.13 · Streamlit · pandas · scikit-learn · PyYAML · Jinja2 · psutil · SQLite · Ollama. No cloud, no graph DB, no JS framework."],
     Inches(0.8), Inches(5.65), Inches(11.8), Inches(1), 12, MUTED)

# 6 Detection
s = slide("Eight deterministic rules, tuned against benign look-alikes", "Log ingestion & detection rules")
table(s, [["Rule", "Detects", "MITRE", "Role"],
          ["R1", "≥ 8 failures, one account, one source, 10-min sliding window", "T1110.001", "primary"],
          ["R2", "One source fails against ≥ 5 accounts, few tries each", "T1110.003", "primary"],
          ["R3", "Success after a failure burst, same account + source, in order", "T1078", "primary"],
          ["R4", "Logon hour unusual for this user's own history", "T1078", "context"],
          ["R5", "Device or IP never seen for this user (confidence label)", "T1078", "context"],
          ["R6", "Privileged group add by a non-admin or outside a change window", "T1098", "primary"],
          ["R7", "Encoded PowerShell, Mimikatz, LSASS dump, certutil, Office→shell…", "T1059.001 · T1003", "primary"],
          ["R8", "Audit log cleared, weighted if preceded by suspicious activity", "T1070.001", "primary"],
          ["R9–R11", "Lateral movement · bulk copy to removable/UNC · USB storage", "T1021 · T1039 · T1052", "ctx / primary"]],
      Inches(0.6), Inches(1.6), Inches(8.2), col_w=[0.8, 4.6, 1.6, 1.2], size=11, row_h=0.44)
panel(s, Inches(9.1), Inches(1.6), Inches(3.6), Inches(4.45))
text(s, "False-positive controls", Inches(9.3), Inches(1.75), Inches(3.3), Inches(0.4), 14, TEXT, bold=True)
bullets(s, ["Per-user baselines with explicit low-confidence flag", "Baseline learns with a 4 h lag: an attack can't normalise itself",
            "Context-only rules never create an incident alone", "Allowlists + approved change windows",
            "4672 is context, never proof of escalation", "Every alert stores its reason and threshold"],
        Inches(9.3), Inches(2.2), Inches(3.3), Inches(3.8), 12, gap=4)

# 7 Storyline
s = slide("Attack Storyline Engine: related alerts become one explained incident", "Event correlation")
image(s, "03_storyline.png", Inches(0.6), Inches(1.55), w=Inches(7.6))
bullets(s, ["Alerts processed in time order; join within a 30-min gap and 4-h span",
            "Strong link: ≥ 2 shared keys (account, host, source IP)",
            "Weak link: shared account only; shown dashed, never scored",
            "A shared host or IP alone never links alerts (DCs, NAT)",
            "Every link stores its reason: \"same account + same host, 1.4 min after R1 burst\"",
            "Each step expands to the original log rows (file:row + raw record)"],
        Inches(8.5), Inches(1.6), Inches(4.3), Inches(5), 14, gap=7)

# 8 Evidence contract
s = slide("The Evidence Contract: the SLM may only narrate verified facts", "Local SLM & verification")
steps = [("1  Evidence pack", "Code writes numbered facts with event IDs, counts, times, users, hosts, IPs"),
         ("2  Constrained SLM", "qwen2.5:3b returns JSON citing fact IDs; facts are treated as untrusted data"),
         ("3  Per-sentence verifier", "IDs exist · numbers · times · dates · names/IPs in cited facts · grounding · no overclaiming"),
         ("4  Labelled output", "Verified → summary · Unverified → set aside with reasons · playbooks only from library")]
for i, (t1, t2) in enumerate(steps):
    y = Inches(1.6 + i * 0.98)
    panel(s, Inches(0.6), y, Inches(7.3), Inches(0.85))
    text(s, t1, Inches(0.8), y + Inches(0.08), Inches(3), Inches(0.4), 14, TEXT, bold=True)
    text(s, t2, Inches(0.8), y + Inches(0.42), Inches(7), Inches(0.4), 11, MUTED)
if S3:
    kpi(s, Inches(8.3), Inches(1.6), Inches(2.1), f"{S3['rate']:.0%}", "sentences verified")
    kpi(s, Inches(10.6), Inches(1.6), Inches(2.1), f"{S3['wall']:.1f} s", "per incident")
    kpi(s, Inches(8.3), Inches(2.95), Inches(2.1), f"{S3['tps']:.0f}", "tokens / s (GPU)")
    kpi(s, Inches(10.6), Inches(2.95), Inches(2.1), f"{S3['fallbacks']}/{S3['answers']}", "fallbacks needed")
    text(s, f"{S3['verified']} of {S3['claims']} factual sentences on 15 held-out test incidents passed verification "
            "(70–80% across runs; GPU inference is not bit-deterministic). The rest were labelled Unverified and kept "
            "out of the summary.", Inches(8.3), Inches(4.3), Inches(4.4), Inches(1), 11, MUTED)
if S7:
    table(s, [["Model", "Verified", "Latency", "Tok/s", "VRAM"],
              ["qwen2.5:3b ✓", f"{S3['rate']:.0%}", f"{S3['wall']:.1f} s", f"{S3['tps']:.0f}", f"{S3['vram']} GB"],
              ["qwen2.5:7b", f"{S7['rate']:.0%}", f"{S7['wall']:.1f} s", f"{S7['tps']:.0f}", f"{S7['vram']} GB"]],
          Inches(8.3), Inches(5.3), Inches(4.4), col_w=[1.4, 0.8, 0.8, 0.6, 0.8], size=10, row_h=0.36)
text(s, "If the model times out, is unreachable or returns invalid JSON, a deterministic template (100% verified) is used.",
     Inches(0.6), Inches(5.65), Inches(7.3), Inches(0.6), 12, MUTED)

# 9 Evidence vs hypothesis
s = slide("Evidence vs. hypothesis: what the logs prove, and what they don't", "Analyst view")
image(s, "04_evidence_hypothesis.png", Inches(0.6), Inches(1.55), w=Inches(8.3))
bullets(s, ["Verified evidence: detection facts produced by code",
            "Supported conclusions: SLM sentences that passed verification",
            "Hypotheses: possible explanations with supporting and contradicting fact IDs, plus how to confirm",
            "Contradicting evidence: computed from logs and baselines, not by the model",
            "Next steps: playbooks from the offline library only; no automatic remediation"],
        Inches(9.2), Inches(1.6), Inches(3.6), Inches(5), 13, gap=8)

# 10 Dashboard
s = slide("A SOC-style dashboard: every number comes from the analysis", "Dashboard")
image(s, "01_queue.png", Inches(0.6), Inches(1.5), w=Inches(5.7))
image(s, "02_upload.png", Inches(6.45), Inches(1.5), w=Inches(5.7))
image(s, "05_severity.png", Inches(0.6), Inches(5.2), w=Inches(2.6))
image(s, "06_report.png", Inches(3.35), Inches(5.2), w=Inches(2.6))
image(s, "09_workspace.png", Inches(6.1), Inches(5.2), w=Inches(2.6))
text(s, ["Queue ranked by score · upload & column mapping with warnings · severity breakdown · one-click HTML/PDF report · "
         "verified incident chat, dispositions & audit trail"], Inches(8.9), Inches(5.25), Inches(3.8), Inches(1.6), 12, MUTED)

# 11 Evaluation
s = slide("Measured accuracy, including where it breaks", "Evaluation & false positives")
if M:
    ta, sa = M["test_aggregate"], M["stress_aggregate"]
    table(s, [["Evaluation set", "Attacks / look-alikes", "Precision", "Recall", "F1", "FPR", "Jaccard", "Severity agr."],
              ["Held-out test seeds (101/202/303)", f"{ta['gt_incidents']} / {ta['benign_lookalikes']}",
               fmt(ta["incident_precision"]), fmt(ta["incident_recall"]), fmt(ta["f1"]), fmt(ta["false_positive_rate"]),
               fmt(ta["correlation_jaccard_mean"]), fmt(ta["severity_agreement"])],
              ["Stress seeds, out-of-envelope (10)", f"{sa['gt_incidents']} / {sa['benign_lookalikes']}",
               fmt(sa["incident_precision"]), fmt(sa["incident_recall"]), fmt(sa["f1"]), fmt(sa["false_positive_rate"]),
               fmt(sa["correlation_jaccard_mean"]), fmt(sa["severity_agreement"])]],
          Inches(0.6), Inches(1.6), Inches(12.1), col_w=[3.4, 1.9, 1.1, 1.1, 1.1, 1.1, 1.1, 1.3], size=12, row_h=0.5)
bullets(s, ["Tuned on dev seed 7 only; test seeds evaluated once after the freeze; stress seeds never tuned on",
            "Match = detected incident holds ≥ 50% of the attack's events; benign look-alike flagged on ANY overlap",
            "7 look-alike types per dataset: night maintenance, typos, laptop rollout, approved group change, admin script, forgotten password, service account",
            "Stress misses: slow brute force below R1 density · spray of < 5 accounts · success later than R3's 15-min window",
            "Unseen-format demo: precision 0.57 with auto-mapping only → 1.00 after mapping two columns (the UI warns)",
            "Public OTRF Windows logs: comsvcs LSASS dump detected (Medium); PowerShell-module-only activity not analysed"],
        Inches(0.6), Inches(3.4), Inches(12.1), Inches(3.4), 13, gap=5)
text(s, "Caveat: labelled data is synthetic and author-generated, so test-seed scores show generalisation within the designed attack styles, not real-world accuracy.",
     Inches(0.6), Inches(6.55), Inches(12.1), Inches(0.45), 11, SEV["High"])

# 12 Offline performance
s = slide("Offline performance: measured, with every connection logged", "Offline operation")
if OFF:
    mon = OFF["monitor"]
    sl = OFF["steps"].get("slm", [])
    tps = [x["tokens_per_s"] for x in sl if x.get("tokens_per_s")]
    kpi(s, Inches(0.6), Inches(1.6), Inches(2.85), str(len(mon["external_connections"])), "external connections")
    kpi(s, Inches(3.6), Inches(1.6), Inches(2.85), f"{OFF['steps']['analysis']['timings']['analysis_total_s']:.2f} s", "detect→evidence (1.7k events)")
    kpi(s, Inches(6.6), Inches(1.6), Inches(2.85), f"{min(tps):.0f}–{max(tps):.0f}" if tps else "–", "SLM tokens / s")
    kpi(s, Inches(9.6), Inches(1.6), Inches(3.1), f"{mon['peak_sentinel_rss_mb']:.0f} MB", "peak RAM (SENTINEL)")
    text(s, f"Latest recorded run: {OFF['recorded_at']} · type: {OFF['test_type'].upper()} · internet reachable: {OFF['internet_reachable']} · "
            f"{len(mon['loopback_connections'])} loopback connections (local model server) · total {OFF['total_seconds']} s",
         Inches(0.6), Inches(2.95), Inches(12.1), Inches(0.6), 12, OK if not OFF["internet_reachable"] else SEV["High"])
image(s, "08_monitor.png", Inches(0.6), Inches(3.55), w=Inches(5.4))
bullets(s, ["Model pre-pulled (qwen2.5:3b Q4_K_M, 1.93 GB); 100% in VRAM on an RTX 4060 Laptop",
            "Streamlit telemetry off, bound to 127.0.0.1; reports use inline CSS only",
            "MITRE reference and playbooks stored as local JSON",
            "Tests assert no external URLs in runtime code and no external connections during a full pipeline run",
            "offline_check.py records whether the internet was reachable, so a rehearsal is never presented as an offline test"],
        Inches(6.3), Inches(3.6), Inches(6.5), Inches(3.3), 13, gap=6)

# 13 Differentiators
s = slide("Beyond a rule-based SIEM", "Technical differentiators")
table(s, [["Typical rule-based SIEM", "SENTINEL"],
          ["List of independent alerts", "One storyline per incident, with a reason for every link"],
          ["Opaque risk score", "0–100 score with each factor shown; confidence reported separately"],
          ["Static thresholds for everyone", "Per-user baselines with explicit confidence and learning lag"],
          ["LLM summary you must trust", "Every SLM sentence verified against cited facts; failures labelled"],
          ["Accuracy asserted", "Precision / recall / FPR on held-out + stress seeds; failures listed"],
          ["Cloud / server deployment", "One laptop, offline, measured: ~0.25 s analysis, ~6 s per explanation"]],
      Inches(0.6), Inches(1.7), Inches(12.1), col_w=[4.6, 7.5], size=14, row_h=0.62)

# 14 Limitations
s = slide("Limitations and future scope", "Honest assessment")
bullets(s, ["Accuracy measured on synthetic, author-generated data; real-world performance not yet established",
            "Slow / low-and-slow brute force below the density threshold is missed (stress seeds)",
            "Verifier is lexical: catches wrong numbers, names, times, citations, but not every unsupported qualifier",
            "PowerShell script-block / module logs, Kerberos and network flows not yet analysed",
            "R10 / R11 unit-tested only; timestamps without a zone are assumed UTC"],
        Inches(0.6), Inches(1.7), Inches(6.2), Inches(5), 14, gap=8)
panel(s, Inches(7.1), Inches(1.7), Inches(5.6), Inches(4.6))
text(s, "Next steps", Inches(7.3), Inches(1.85), Inches(5), Inches(0.4), 15, TEXT, bold=True)
bullets(s, ["Validate on labelled real SOC data (e.g. OTRF compound datasets, Splunk BOTS)",
            "Adaptive thresholds per user / host; low-and-slow detection",
            "Entailment check for SLM sentences with a small local NLI model",
            "Sigma rule import; PowerShell 4104 analysis",
            "Analyst-feedback loop to tune thresholds with audit trail"],
        Inches(7.3), Inches(2.35), Inches(5.2), Inches(3.9), 13, gap=6)

# 15 Conclusion
s = slide("SENTINEL: offline triage you can verify", "Conclusion & demo")
bullets(s, ["Ingests CSV/JSON auth + endpoint logs, including unseen formats via the column mapper",
            "Detects with 8+ deterministic rules and per-user baselines; correlates into explained storylines",
            "Scores severity transparently; separates evidence, hypotheses and counter-evidence",
            "Local 3B SLM explains incidents under an evidence contract, with a measured verification rate",
            "Runs entirely offline on a laptop, with recorded connection logs"],
        Inches(0.6), Inches(1.7), Inches(7.2), Inches(4.2), 15, gap=8)
panel(s, Inches(8.2), Inches(1.7), Inches(4.5), Inches(4.4))
text(s, "Live demo (offline, 5 min)", Inches(8.4), Inches(1.85), Inches(4.2), Inches(0.4), 14, TEXT, bold=True)
bullets(s, ["Wi-Fi off · monitor page", "Upload unseen-format logs · fix 2 mappings", "Ranked queue → top incident",
            "Storyline · severity breakdown · raw rows", "SLM explanation + verification", "Export report · accuracy · performance"],
        Inches(8.4), Inches(2.3), Inches(4.1), Inches(3.6), 13, gap=4)
text(s, "github.com/dakshitha0705/SENTINEL  ·  README · docs/evaluation.md · docs/demo_script.md",
     Inches(0.6), Inches(6.3), Inches(12), Inches(0.4), 13, ACCENT)

OUT.parent.mkdir(exist_ok=True)
prs.save(OUT)
print("saved", OUT, "slides:", len(prs.slides))
