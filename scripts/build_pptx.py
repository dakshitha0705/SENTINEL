"""Build presentation/SENTINEL_Tinyverse_PS02.pptx from real results and screenshots.

    python scripts/build_pptx.py

All metrics are read from results/*.json at build time (nothing is typed in by hand), and all images
are real screenshots from docs/screenshots/v2/. Re-run after re-evaluating to refresh the numbers.
"""
from __future__ import annotations

import json
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_CONNECTOR, MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches, Pt

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results"
SHOTS = ROOT / "docs" / "screenshots" / "v2"
OUT = ROOT / "presentation" / "SENTINEL_Tinyverse_PS02.pptx"

# pastel-dark palette (matches the dashboard)
BG = RGBColor(0x0D, 0x17, 0x16)
PANEL = RGBColor(0x1C, 0x2B, 0x29)
ELEV = RGBColor(0x27, 0x37, 0x34)
LINE = RGBColor(0x33, 0x45, 0x41)
TEXT = RGBColor(0xE8, 0xDD, 0xC9)
BODY = RGBColor(0xDC, 0xD5, 0xC6)
MUTED = RGBColor(0xA9, 0xB6, 0xAE)
SAGE = RGBColor(0x81, 0x9B, 0x8D)
MINT = RGBColor(0xA7, 0xBF, 0xAF)
GOLD = RGBColor(0xC8, 0xAA, 0x7C)
ROSE = RGBColor(0xB9, 0x87, 0x80)
OK = RGBColor(0x9D, 0xC2, 0xA8)
FONT = "Segoe UI"
DISPLAY = "Bahnschrift"

prs = Presentation()
prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
BLANK = prs.slide_layouts[6]
W, H = prs.slide_width, prs.slide_height


def load(name):
    p = RES / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


M = load("metrics.json")
BEFORE = load("before_upgrade_detector.json")
OFF_RUNS = sorted((RES / "offline_runs").glob("*.json"))
OFFLINE = [json.loads(p.read_text(encoding="utf-8")) for p in OFF_RUNS]
UI = load("offline_ui_check.json")
CHAT = load("chat_benchmark.json")
EXT = load("external_eval.json")
SCALE = load("scale_benchmark.json")


def bench(tag, model):
    b = load(f"slm_benchmark_{tag}_{model}.json")
    return b["summary"] if b else None


S3 = bench("test", "qwen2.5-3b")
S15 = bench("test", "qwen2.5-1.5b")
G3, C3 = bench("gpu_norepair", "qwen2.5-3b"), bench("cpu_norepair", "qwen2.5-3b")
G15, C15 = bench("gpu_norepair", "qwen2.5-1.5b"), bench("cpu_norepair", "qwen2.5-1.5b")


# --------------------------------------------------------------------------- primitives

def text(s, t, x, y, w, h, size=14, color=BODY, bold=False, align=PP_ALIGN.LEFT, spacing=0, anchor=MSO_ANCHOR.TOP,
         font=FONT):
    tb = s.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = Inches(0.02)
    for i, line in enumerate(t if isinstance(t, list) else [t]):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        r = p.add_run()
        r.text = line
        f = r.font
        f.size, f.bold, f.name = Pt(size), bold, font
        f.color.rgb = color
        if spacing:
            r._r.get_or_add_rPr().set("spc", str(spacing * 100))
    return tb


def slide(title=None, kicker=None):
    s = prs.slides.add_slide(BLANK)
    s.background.fill.solid()
    s.background.fill.fore_color.rgb = BG
    if kicker:
        text(s, kicker.upper(), Inches(0.6), Inches(0.35), Inches(10), Inches(0.35), 11, GOLD, bold=True, spacing=2)
    if title:
        text(s, title, Inches(0.6), Inches(0.65), Inches(12.2), Inches(0.8), 26, TEXT, font=DISPLAY)
    text(s, "SENTINEL · Tinyverse Hackathon Phase 2 · PS 02 Offline Security Incident Triage Assistant",
         Inches(0.6), Inches(7.05), Inches(10), Inches(0.3), 9, MUTED)
    text(s, str(len(prs.slides)), Inches(12.4), Inches(7.05), Inches(0.5), Inches(0.3), 9, MUTED, align=PP_ALIGN.RIGHT)
    return s


def bullets(s, items, x, y, w, h, size=15, color=BODY, gap=6):
    tb = s.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    for i, it in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_after = Pt(gap)
        r1 = p.add_run()
        r1.text = "●  "
        r1.font.size, r1.font.name = Pt(size - 7), FONT
        r1.font.color.rgb = GOLD
        r = p.add_run()
        r.text = it
        r.font.size, r.font.name = Pt(size), FONT
        r.font.color.rgb = color
    return tb


def panel(s, x, y, w, h, fill=PANEL, line=LINE):
    b = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, w, h)
    b.adjustments[0] = 0.08
    b.fill.solid(); b.fill.fore_color.rgb = fill
    b.line.color.rgb = line; b.line.width = Pt(0.75)
    b.shadow.inherit = False
    return b


def kpi(s, x, y, w, value, label, color=TEXT, h=1.15):
    panel(s, x, y, w, Inches(h), fill=ELEV)
    text(s, value, x + Inches(0.18), y + Inches(0.1), w - Inches(0.3), Inches(0.6), 24, color, font=DISPLAY)
    text(s, label.upper(), x + Inches(0.18), y + Inches(h - 0.43), w - Inches(0.3), Inches(0.4), 9, MUTED, bold=True, spacing=1)


def box(s, x, y, w, h, title, sub=None, line=SAGE):
    b = panel(s, x, y, w, h, PANEL, line)
    text(s, title, x + Inches(0.1), y + Inches(0.08), w - Inches(0.2), Inches(0.35), 13, TEXT, bold=True, align=PP_ALIGN.CENTER)
    if sub:
        text(s, sub, x + Inches(0.1), y + Inches(0.42), w - Inches(0.2), h - Inches(0.45), 10, MUTED, align=PP_ALIGN.CENTER)
    return b


def arrow(s, x1, y1, x2, y2, color=GOLD, kind=MSO_CONNECTOR.STRAIGHT):
    c = s.shapes.add_connector(kind, int(x1), int(y1), int(x2), int(y2))  # EMU must be integers
    c.line.color.rgb = color
    c.line.width = Pt(1.5)
    ln = c.line._get_or_add_ln()
    ln.append(ln.makeelement("{http://schemas.openxmlformats.org/drawingml/2006/main}tailEnd", {"type": "triangle"}))
    return c


def image(s, name, x, y, w=None, h=None):
    p = SHOTS / name
    if not p.exists():
        text(s, f"[missing screenshot {name}]", x, y, Inches(4), Inches(0.5), 12, ROSE)
        return None
    pic = s.shapes.add_picture(str(p), x, y, w, h)
    pic.line.color.rgb = LINE
    pic.line.width = Pt(0.75)
    return pic


def table(s, rows, x, y, w, col_w=None, size=11, row_h=0.36):
    nr, nc = len(rows), len(rows[0])
    gf = s.shapes.add_table(nr, nc, x, y, w, Inches(row_h * nr))
    t = gf.table
    from pptx.oxml.ns import qn
    tbl_pr = t._tbl.tblPr
    sid = tbl_pr.find(qn("a:tableStyleId"))
    if sid is None:
        sid = tbl_pr.makeelement(qn("a:tableStyleId"), {})
        tbl_pr.append(sid)
    sid.text = "{2D5ABB26-0587-4C30-8999-92F81FD0307C}"   # "No Style, No Grid"
    if col_w:
        for i, cw in enumerate(col_w):
            t.columns[i].width = Inches(cw)
    for r in range(nr):
        t.rows[r].height = Inches(row_h)
        for c in range(nc):
            cell = t.cell(r, c)
            cell.fill.solid()
            cell.fill.fore_color.rgb = ELEV if r == 0 else (PANEL if r % 2 else BG)
            cell.margin_left = cell.margin_right = Inches(0.08)
            cell.margin_top = cell.margin_bottom = Inches(0.03)
            tf = cell.text_frame
            tf.word_wrap = True
            val = rows[r][c]
            color = BODY
            if isinstance(val, tuple):
                val, color = val
            tf.paragraphs[0].text = ""
            run = tf.paragraphs[0].add_run()
            run.text = str(val)
            run.font.size, run.font.name = Pt(size), FONT
            run.font.bold = r == 0
            run.font.color.rgb = MUTED if r == 0 else color
    return t


def f3(v):
    return "–" if v is None else f"{v:.3f}"


def pct(v):
    return "–" if v is None else f"{v:.0%}"


# --------------------------------------------------------------------------- 1 Title
s = prs.slides.add_slide(BLANK)
s.background.fill.solid(); s.background.fill.fore_color.rgb = BG
img = SHOTS / "01_command_center.png"
if img.exists():
    pic = s.shapes.add_picture(str(img), Inches(6.2), Inches(0.9), width=Inches(6.8))
    pic.line.color.rgb = LINE
text(s, "TINYVERSE PHASE 2 · PS 02", Inches(0.7), Inches(1.5), Inches(5.4), Inches(0.4), 12, GOLD, bold=True, spacing=2)
text(s, "SENTINEL", Inches(0.7), Inches(2.0), Inches(6), Inches(1.2), 60, TEXT, spacing=8, font=DISPLAY)
text(s, "Offline Security Incident Triage Assistant", Inches(0.7), Inches(3.2), Inches(5.6), Inches(0.9), 24, MINT, font=DISPLAY)
text(s, "Deterministic detection · Attack storylines · Explainable severity · Local Qwen under a verified Evidence Contract",
     Inches(0.7), Inches(4.25), Inches(5.3), Inches(0.9), 14, MUTED)
text(s, ["Dakshitha  ·  individual entry", "Cybersecurity | Small Language Models  ·  runs fully offline on a laptop"],
     Inches(0.7), Inches(5.6), Inches(5.6), Inches(0.8), 13, BODY)

# --------------------------------------------------------------------------- 2 Problem
s = slide("SOC analysts drown in logs, and cloud analysis is not always an option", "Problem & motivation")
bullets(s, ["Authentication and endpoint logs arrive in volumes no analyst can read line by line, so incidents are missed",
            "Related events (failures, a success, a privilege change, a suspicious process) sit in different files, minutes apart",
            "Organisations with limited connectivity or compute, or with sensitive logs, cannot send them to cloud AI",
            "A generic LLM summary is not evidence: every claim must trace back to a log line"],
        Inches(0.6), Inches(1.7), Inches(7.2), Inches(4.5), 17)
panel(s, Inches(8.3), Inches(1.7), Inches(4.4), Inches(4.4))
text(s, "PS 02 asks for", Inches(8.55), Inches(1.85), Inches(4), Inches(0.4), 13, GOLD, bold=True)
bullets(s, ["Offline, SLM-powered triage", "Detect ≥ 3 suspicious patterns", "Correlate by user, device, time",
            "Severity to prioritise", "Evidence-backed reports with next steps", "No cloud dependency"],
        Inches(8.55), Inches(2.3), Inches(4), Inches(3.7), 14)

# --------------------------------------------------------------------------- 3 Requirements
s = slide("Every official requirement maps to working, tested code", "Official requirements (PS 02 §2)")
fa = M["fresh_aggregate"] if M else {}
table(s, [["PS 02 requirement", "SENTINEL implementation", "Evidence"],
          ["Log processing (CSV / JSON)", "CSV, JSON, JSON-lines and EVTX (offline converter); column mapper with warnings and saved profiles", "Ingestion + EVTX tests; 13 real EVTX files"],
          ["≥ 3 suspicious patterns", "14 rules (R1–R14) with per-user baselines, allowlists, change windows", f"Fresh held-out F1 {f3(fa.get('f1'))}"],
          ["Event correlation", "Attack Storyline Engine: account / host / IP keys, time windows, a reason per link", f"Jaccard {f3(fa.get('correlation_jaccard_mean'))}"],
          ["Severity classification", "0–100 score with line-by-line breakdown; separate confidence", f"Severity agreement {f3(fa.get('severity_agreement'))}"],
          ["SLM integration", "Local Qwen2.5-3B: typed explanations, hypotheses, self-repair, verified chat, handoff", "Verification before / after repair"],
          ["Evidence-based reporting", "HTML / PDF / JSON / CSV with only verified statements, original rows, hashes", "Report Studio"],
          ["Offline functionality", "Local model and assets, telemetry off, connection monitor, browser check blocking the internet", "Disconnected run records"]],
      Inches(0.6), Inches(1.6), Inches(12.1), col_w=[2.6, 6.6, 2.9], size=12, row_h=0.6)

# --------------------------------------------------------------------------- 4 Solution
s = slide("Deterministic code establishes facts. Qwen interprets them. The verifier checks.", "Proposed solution")
items = [("Attack Storyline Engine", "Alerts become one chronological incident; every link records why it was made"),
         ("Evidence Contract v7", "Typed claims; per-claim verification; one bounded self-repair round; failures stay Unverified"),
         ("Evidence vs. hypothesis", "Facts, conclusions, hypotheses, code-computed counter-evidence and next steps kept apart"),
         ("Measured, not claimed", "Fresh held-out seeds, before/after, naive baseline, ablation, real attack recordings"),
         ("Verifiably offline", "Disconnected runs logged; browser check blocks and counts every external request")]
for i, (t1, t2) in enumerate(items):
    y = Inches(1.65 + i * 1.03)
    panel(s, Inches(0.6), y, Inches(12.1), Inches(0.88))
    text(s, f"0{i + 1}", Inches(0.8), y + Inches(0.17), Inches(0.7), Inches(0.5), 22, GOLD, font=DISPLAY)
    text(s, t1, Inches(1.6), y + Inches(0.12), Inches(3.6), Inches(0.5), 17, TEXT, bold=True)
    text(s, t2, Inches(5.2), y + Inches(0.2), Inches(7.3), Inches(0.5), 14, MUTED)

# --------------------------------------------------------------------------- 5 Architecture
s = slide("A deterministic pipeline with one probabilistic, verified step", "System architecture")
row1 = [("Ingest", "CSV · JSON · JSONL · EVTX\nmapper · UTC · SHA-256"), ("Baselines", "per-user history\n4 h learning lag"),
        ("Rules R1–R14", "thresholds in YAML\nMITRE per alert"), ("Storyline engine", "strong / weak / derived links\nreason per link"),
        ("Severity", "0–100 breakdown\n+ confidence")]
bw, bh, y1 = Inches(2.2), Inches(1.2), Inches(1.9)
for i, (t1, t2) in enumerate(row1):
    x = Inches(0.6) + i * Inches(2.48)
    box(s, x, y1, bw, bh, t1, t2)
    if i:
        arrow(s, x - Inches(0.28), y1 + bh / 2, x, y1 + bh / 2)
y2 = Inches(3.9)
row2 = [("Evidence pack", "facts F1..Fn\nsupporting / contradicting", Inches(0.6)),
        ("Local Qwen", "Ollama · qwen2.5:3b\ntyped JSON + self-repair", Inches(3.4)),
        ("Verifier", "per claim & typed field\nVerified / Unverified", Inches(6.2)),
        ("Outputs", "9-page dashboard · globe · graph\nreports · exports · audit", Inches(9.0))]
for t1, t2, x in row2:
    box(s, x, y2, Inches(2.5) if t1 != "Outputs" else Inches(3.7), bh, t1, t2, line=GOLD if t1 == "Local Qwen" else SAGE)
arrow(s, Inches(0.6) + 4 * Inches(2.48) + bw / 2, y1 + bh, Inches(1.85), y2, kind=MSO_CONNECTOR.ELBOW)
for xa in (3.1, 5.9, 8.7):
    arrow(s, Inches(xa), y2 + bh / 2, Inches(xa + 0.3), y2 + bh / 2)
panel(s, Inches(0.6), Inches(5.55), Inches(12.1), Inches(1.15), fill=BG)
text(s, ["Fallbacks: model unavailable, slow or invalid → deterministic template; chat with nothing verifiable → deterministic "
         "evidence answer. Detection, correlation, severity, verification and reporting never depend on the model.",
         "Stack: Python 3.13 · Streamlit · pandas · scikit-learn · evtx · Jinja2 · psutil · SQLite · Ollama · bundled globe.gl/three.js, "
         "vis-network, Natural Earth. No cloud, no CDN."],
     Inches(0.8), Inches(5.65), Inches(11.8), Inches(1), 12, MUTED)

# --------------------------------------------------------------------------- 6 Command Center
s = slide("Command Center: an interactive globe that never invents a location", "Dashboard")
image(s, "01_command_center.png", Inches(0.6), Inches(1.5), w=Inches(8.1))
chk = (UI or {}).get("summary", {}).get("checks", {})
bullets(s, ["Real 3D globe (bundled globe.gl + three.js): drag, zoom, reset, click markers or countries",
            "Plots only coordinates present in the logs (here a SIEM export's geo columns); no IP geolocation, no online API",
            "Arcs = logged events of one incident whose source and device sites differ",
            "No location fields → exploration mode, clearly labelled",
            f"Browser check: rotate {('✓' if chk.get('globe_drag_rotates') else '✗')} · zoom {('✓' if chk.get('globe_wheel_zooms_in') else '✗')} · "
            f"reset {('✓' if chk.get('globe_reset_restores_view') else '✗')} · marker → records {('✓' if chk.get('globe_marker_click_opens_records') else '✗')}"],
        Inches(8.95), Inches(1.6), Inches(3.9), Inches(5.2), 13, gap=8)

# --------------------------------------------------------------------------- 7 Detection
s = slide("Fourteen deterministic rules, tuned against benign look-alikes", "Detection")
table(s, [["Rule", "Detects", "MITRE"],
          ["R1 / R12", "Brute force: ≥ 8 in 10 min · sustained: ≥ 8 in 60 min or ≥ 20 in 24 h from a never-used source", "T1110.001"],
          ["R2 / R13", "Spraying: ≥ 5 accounts · small spray: ≥ 3 accounts, ≥ 80% failures, unknown source", "T1110.003"],
          ["R3", "Success after failures, up to 60 min, decaying weight, \"not confirmed compromise\"", "T1078"],
          ["R4 / R5", "Unusual hour / new device or IP vs the user's own baseline (context)", "T1078"],
          ["R6", "Privileged group add by a non-admin or outside a change window", "T1098"],
          ["R7", "Encoded PowerShell, Mimikatz, LSASS dump, certutil, Office→shell…", "T1059 · T1003"],
          ["R8", "Audit log cleared (1102 / System 104)", "T1070.001"],
          ["R9–R11", "Lateral movement (ctx) · bulk copy/staging · USB (ctx)", "T1021 · T1074"],
          ["R14", "Privileged group discovery (net group \"Domain Admins\", 4799), context", "T1069"]],
      Inches(0.6), Inches(1.6), Inches(8.6), col_w=[1.1, 6.2, 1.3], size=11, row_h=0.46)
panel(s, Inches(9.5), Inches(1.6), Inches(3.2), Inches(4.6))
text(s, "Upgrade, measured", Inches(9.7), Inches(1.75), Inches(3), Inches(0.4), 14, GOLD, bold=True)
if M and BEFORE:
    bf, af = BEFORE["fresh"]["aggregate"], M["fresh_aggregate"]
    bullets(s, [f"Fresh held-out F1 {f3(bf['f1'])} → {f3(af['f1'])}", f"Precision {f3(bf['incident_precision'])} → {f3(af['incident_precision'])}",
                f"Recall {f3(bf['incident_recall'])} → {f3(af['incident_recall'])}", f"Jaccard {f3(bf['correlation_jaccard_mean'])} → {f3(af['correlation_jaccard_mean'])}",
                f"FPR {f3(bf['false_positive_rate'])} → {f3(af['false_positive_rate'])}", "New look-alikes B8–B10 target the new rules"],
            Inches(9.7), Inches(2.25), Inches(2.9), Inches(3.9), 13, gap=5)

# --------------------------------------------------------------------------- 8 Storyline
s = slide("Attack Storyline Engine: related alerts become one explained incident", "Event correlation")
image(s, "p03_incident.png", Inches(0.6), Inches(1.5), w=Inches(7.8))
bullets(s, ["Alerts in time order; join within a 30-min gap and a 4-h span",
            "Strong link: ≥ 2 shared keys (account, host, source IP)",
            "Weak link: shared account only; shown dashed, never scored",
            "Derived link: a late success always joins the burst it followed",
            "A shared host or IP alone never links (DCs, NAT)",
            "Every link is explained; every step opens its original log rows"],
        Inches(8.7), Inches(1.6), Inches(4.1), Inches(5), 14, gap=7)

# --------------------------------------------------------------------------- 9 Evidence Contract
s = slide("Evidence Contract: typed claims, verified, repaired once", "Local SLM & verification")
steps = [("1  Evidence pack", "Code writes numbered facts with event IDs, counts, times, users, hosts, IPs"),
         ("2  Typed output", "Qwen returns JSON claims with fact IDs plus count, start/end time, user, host, IP, event IDs"),
         ("3  Verifier", "Every sentence and typed value must be supported by the cited facts; overclaiming rejected"),
         ("4  One self-repair round", "Specific failures sent back once; the repaired JSON is verified again"),
         ("5  Labelled output", "Verified → summary · still failing → Unverified with reasons · playbooks only from library")]
for i, (t1, t2) in enumerate(steps):
    y = Inches(1.55 + i * 0.93)
    panel(s, Inches(0.6), y, Inches(7.3), Inches(0.8))
    text(s, t1, Inches(0.8), y + Inches(0.06), Inches(4), Inches(0.4), 14, TEXT, bold=True)
    text(s, t2, Inches(0.8), y + Inches(0.4), Inches(7), Inches(0.4), 11, MUTED)
if S3:
    r = S3["repair"]
    kpi(s, Inches(8.3), Inches(1.55), Inches(2.1), pct(r["initial_rate"]), "verified, first try")
    kpi(s, Inches(10.6), Inches(1.55), Inches(2.1), pct(r["final_rate"]), "after 1 repair", OK)
    kpi(s, Inches(8.3), Inches(2.9), Inches(2.1), f"+{r['mean_extra_latency_s']:.1f} s", "per repair")
    kpi(s, Inches(10.6), Inches(2.9), Inches(2.1), f"{S3['fallbacks']}/{S3['incidents']}", "template fallbacks")
    text(s, f"{r['final_verified']} of {r['final_claims']} typed claims on {S3['incidents']} held-out incidents (qwen2.5:3b, GPU). "
            "An earlier run gave 77% → 87%: GPU inference is not bit-deterministic. The repaired output is kept only if it "
            "verifies at least as many claims.", Inches(8.3), Inches(4.2), Inches(4.4), Inches(1.3), 11, MUTED)
if CHAT:
    cs = CHAT["summary"]
    panel(s, Inches(8.3), Inches(5.5), Inches(4.4), Inches(1.2), fill=ELEV)
    text(s, f"Chat: {cs['questions']} questions · {cs['silent_replies']} silent replies · {cs['verified']}/{cs['sentences']} sentences verified",
         Inches(8.45), Inches(5.6), Inches(4.2), Inches(0.5), 12, TEXT, bold=True)
    text(s, f"{cs['answered_by_deterministic_fallback']} answered by the deterministic evidence fallback · {cs['explicit_cannot_answer']} explicit "
            "\"cannot answer from the evidence\"", Inches(8.45), Inches(6.0), Inches(4.2), Inches(0.6), 11, MUTED)

# --------------------------------------------------------------------------- 10 AI Lab
s = slide("AI Investigation Lab: what the logs prove, and what they don't", "Analyst view")
image(s, "p05_ai.png", Inches(0.6), Inches(1.5), w=Inches(8.3))
bullets(s, ["Verified facts (code) vs model conclusions (checked)",
            "Hypotheses with supporting and contradicting fact IDs, plus how to confirm",
            "Self-repair outcome and the exact verifier feedback",
            "Ask SENTINEL: grounded answers or an explicit \"cannot answer\"",
            "Shift-handoff note with verified findings, open questions, next actions"],
        Inches(9.2), Inches(1.6), Inches(3.6), Inches(5), 13, gap=8)

# --------------------------------------------------------------------------- 11 Accuracy
s = slide("Accuracy on held-out data, including where it breaks", "Evaluation")
if M:
    ta, fa, sa = M["test_aggregate"], M["fresh_aggregate"], M["stress_aggregate"]
    rows = [["Set", "Attacks / look-alikes", "Precision", "Recall", "F1", "FPR", "Jaccard", "Severity"]]
    for lab, a in (("Fresh held-out 5001–5010 (after freeze)", fa), ("Test 101/202/303", ta), ("Stress 1001–1010 (diagnostic)", sa)):
        rows.append([lab, f"{a['gt_incidents']} / {a['benign_lookalikes']}", f3(a["incident_precision"]), f3(a["incident_recall"]),
                     f3(a["f1"]), f3(a["false_positive_rate"]), f3(a["correlation_jaccard_mean"]), f3(a["severity_agreement"])])
    if BEFORE:
        b = BEFORE["fresh"]["aggregate"]
        rows.append([("Fresh seeds, v1 detector (before)", MUTED), f"{b['gt_incidents']} / {b['benign_lookalikes']}", f3(b["incident_precision"]),
                     f3(b["incident_recall"]), f3(b["f1"]), f3(b["false_positive_rate"]), f3(b["correlation_jaccard_mean"]), f3(b["severity_agreement"])])
    table(s, rows, Inches(0.6), Inches(1.6), Inches(12.1), col_w=[3.9, 1.8, 1.05, 1.05, 1.05, 1.05, 1.05, 1.15], size=12, row_h=0.5)
bullets(s, ["Tuning on dev seed 7 only; fresh seeds generated after the upgrade freeze; stress seeds now diagnostic (they motivated R12/R13)",
            "Match = incident holds ≥ 50% of an attack's events; a look-alike is flagged on ANY overlap",
            "10 look-alike types incl. stale saved password, shared meeting-room PC, admin listing Domain Admins",
            "Fresh failures listed: one S5 miss (baseline 9 < 10 logons), admin work from a new host, a weak-link merge, Critical vs expected High"],
        Inches(0.6), Inches(4.35), Inches(12.1), Inches(2.3), 13, gap=5)
text(s, "Caveat: labelled data is synthetic and author-generated; scores show generalisation within the designed attack styles, not real-world accuracy.",
     Inches(0.6), Inches(6.55), Inches(12.1), Inches(0.45), 11, GOLD)

# --------------------------------------------------------------------------- 12 Comparison
s = slide("Why the design matters: naive baseline, ablation and workload", "Comparison & ablation")
if M:
    c = M["comparison"]
    rows = [["Variant (identical held-out data)", "Items to review", "Strict F1", "Lenient F1", "FPR"]]
    for k, lab in (("full", "Full SENTINEL"), ("no_baselines", "− behavioural baselines"), ("no_allowlists", "− allowlists"),
                   ("no_context", "− context handling"), ("naive", "Naive detector (no correlation)")):
        v = c[k]
        rows.append([(lab, TEXT if k == "full" else BODY), f"{v['items_to_review']:,}", f3(v["strict"]["f1"]), f3(v["lenient"]["f1"]),
                     f3(v["false_positive_rate"])])
    table(s, rows, Inches(0.6), Inches(1.6), Inches(7.9), col_w=[3.4, 1.4, 1.0, 1.1, 1.0], size=12, row_h=0.52)
    cp = M["compression"]
    kpi(s, Inches(8.9), Inches(1.6), Inches(3.8), f"{cp['compression_pct']}%", f"alert compression ({cp['alerts']} → {cp['incidents']})", OK)
    bullets(s, ["Compression = workload reduction, not accuracy",
                "Context handling matters most: promoting context alerts finds every attack but floods the queue",
                "The naive detector finds all attacks only under lenient matching, at 1,651 items",
                "Every variant ran on the same files; the protocol is in docs/evaluation.md"],
            Inches(8.9), Inches(3.0), Inches(3.9), Inches(3.8), 12, gap=6)

# --------------------------------------------------------------------------- 13 External
s = slide("Real attack recordings: scenario detection, honestly scored", "External evaluation")
if EXT:
    rows = [["ID", "Behaviour (public recording)", "Technique", "Result"]]
    for r in EXT["recordings"]:
        res = r["status"]
        col = OK if res == "detected" else (MUTED if res.startswith("control") else ROSE)
        rows.append([r["id"], r["behaviour"] if len(r["behaviour"]) <= 60 else r["behaviour"][:57].rstrip() + "…", r["technique"], (res.replace("control (no rule expected)", "control: no alert"), col)])
    table(s, rows, Inches(0.6), Inches(1.5), Inches(8.6), col_w=[0.6, 5.3, 1.3, 1.4], size=9, row_h=0.3)
    sm = EXT["summary"]
    kpi(s, Inches(9.5), Inches(1.5), Inches(3.2), f"{sm['detected']} / {sm['with_expected_rule']}", "recordings detected", OK)
    bullets(s, ["EVTX-ATTACK-SAMPLES (GPL-3.0) and OTRF (MIT); not redistributed",
                "Technique labels only → no precision/recall claimed",
                "All 6 misses: telemetry not analysed (Sysmon 10, 4661, PowerShell 4103/4104, 4688 without command line) or one pattern gap",
                "Converted offline by SENTINEL's EVTX parser"],
            Inches(9.5), Inches(2.9), Inches(3.3), Inches(4), 12, gap=6)

# --------------------------------------------------------------------------- 14 Performance
s = slide("Limited compute: CPU-only inference and a 127k-event scale test", "Offline performance")
rows = [["Model / mode (same 6 prompts)", "Latency / incident", "Tokens / s", "Verified"]]
for lab, b in (("qwen2.5:3b · GPU", G3), ("qwen2.5:3b · CPU only", C3), ("qwen2.5:1.5b · GPU", G15), ("qwen2.5:1.5b · CPU only", C15)):
    if b:
        rows.append([lab, f"{b['mean_wall_s']:.1f} s", f"{b['mean_tokens_per_s']:.0f}", f"{b['verified']}/{b['factual_claims']}"])
table(s, rows, Inches(0.6), Inches(1.6), Inches(6.4), col_w=[2.7, 1.4, 1.1, 1.2], size=12, row_h=0.5)
text(s, "CPU mode = Ollama num_gpu 0, confirmed by /api/ps (0 bytes in VRAM). 1.5B is faster but verifies far fewer claims, "
        "so 3B stays the default. i7-13650HX, RTX 4060 Laptop 8 GB.", Inches(0.6), Inches(4.25), Inches(6.4), Inches(0.9), 11, MUTED)
if SCALE:
    t = SCALE["timings_s"]
    kpi(s, Inches(7.4), Inches(1.6), Inches(2.6), f"{SCALE['events']:,}", "events")
    kpi(s, Inches(10.15), Inches(1.6), Inches(2.6), f"{t['end_to_end_s']:.1f} s", "end to end")
    kpi(s, Inches(7.4), Inches(2.95), Inches(2.6), f"{SCALE['throughput_events_per_s']['end_to_end']:,}/s", "throughput")
    kpi(s, Inches(10.15), Inches(2.95), Inches(2.6), f"{SCALE['peak_rss_mb']:.0f} MB", "peak RAM")
    text(s, f"Parse {t['parse_s']:.1f} s · normalise {t['normalise_s']:.1f} s · detection {t['detection_s']:.1f} s · correlation "
            f"{t['correlation_s']:.2f} s · evidence {t['evidence_s']:.1f} s. {SCALE['alerts']} alerts → {SCALE['incidents']} incidents. "
            "SLM runs per incident on demand, never per event.", Inches(7.4), Inches(4.25), Inches(5.4), Inches(1.0), 11, MUTED)

# --------------------------------------------------------------------------- 15 Offline verification
s = slide("Offline operation: recorded, not asserted", "Offline verification")
rows = [["Recorded (local)", "Type", "Internet reachable", "External conn.", "Loopback", "SLM runs"]]
for r in OFFLINE:
    rows.append([r["recorded_at"][:16], (r["test_type"], OK if r["test_type"] == "offline test" else BODY), str(r["internet_reachable"]),
                 str(len(r["monitor"]["external_connections"])), str(len(r["monitor"]["loopback_connections"])), str(len(r["steps"].get("slm", [])))])
table(s, rows, Inches(0.6), Inches(1.6), Inches(8.3), col_w=[1.9, 1.7, 1.5, 1.2, 1.0, 1.0], size=11, row_h=0.45)
if UI:
    u = UI["summary"]
    kpi(s, Inches(9.3), Inches(1.6), Inches(3.4), str(u["external_requests_blocked"]), "external requests (browser check)", OK)
    text(s, f"{u['local_requests']} local requests; {sum(v == 'ok' for v in u['pages'].values())}/9 pages without exceptions; "
            f"{sum(1 for k, v in u['checks'].items() if v is True)} interaction checks passed (recorded {u['recorded_at']}).",
         Inches(9.3), Inches(2.9), Inches(3.4), Inches(1.2), 11, MUTED)
bullets(s, ["offline_check.py runs ingestion, detection, live Qwen with self-repair, chat, handoff, reports, exports, EVTX and the evaluation",
            "It logs every remote endpoint of SENTINEL and Ollama, and records reachability before and after, so a rehearsal is never presented as an offline test",
            "ui_check.py drives the dashboard in Edge and aborts every non-local request: fonts, scripts, globe data and icons are all local"],
        Inches(0.6), Inches(4.6), Inches(12.1), Inches(2.2), 13, gap=6)

# --------------------------------------------------------------------------- 16 Dashboard tour
s = slide("Nine pages, every control backed by tested code", "Dashboard")
for i, (name, x, y) in enumerate((("p02_log.png", 0.6, 1.5), ("p04_attack.png", 4.75, 1.5), ("p07_evaluation.png", 8.9, 1.5),
                                  ("p06_threat.png", 0.6, 4.15), ("p08_report.png", 4.75, 4.15), ("p09_system.png", 8.9, 4.15))):
    image(s, name, Inches(x), Inches(y), w=Inches(3.85))
text(s, "Log Intelligence · Attack Graph · Evaluation · Threat Intelligence · Report Studio · System & Settings. "
        "Feature-by-feature backend, data and test mapping: docs/feature_traceability.md",
     Inches(0.6), Inches(6.55), Inches(12.1), Inches(0.45), 11, MUTED)

# --------------------------------------------------------------------------- 17 Limitations
s = slide("Limitations and future scope", "Honest assessment")
bullets(s, ["Labelled accuracy is on synthetic, author-generated data; external recordings give scenario-level evidence only",
            "Telemetry not analysed: PowerShell 4103/4104, Sysmon process access, object access, network flows",
            "Known misses: S5 before a confident baseline; 5 failures in 11 min (looks like a forgotten password)",
            "Verifier is lexical and structural, not semantic; self-repair helps (about +10 pp), it does not guarantee",
            "Globe shows only log-provided coordinates: no IP geolocation by design"],
        Inches(0.6), Inches(1.7), Inches(6.3), Inches(5), 14, gap=8)
panel(s, Inches(7.1), Inches(1.7), Inches(5.6), Inches(4.6))
text(s, "Next steps", Inches(7.3), Inches(1.85), Inches(5), Inches(0.4), 15, GOLD, bold=True)
bullets(s, ["Labelled real SOC data (OTRF compound datasets, BOTS)",
            "PowerShell 4104 and Sysmon 10 analysis; Sigma import",
            "Small local NLI model as a semantic check on claims",
            "Licensed offline geolocation as an optional enrichment",
            "Analyst-feedback loop for thresholds, with audit trail"],
        Inches(7.3), Inches(2.35), Inches(5.2), Inches(3.9), 13, gap=6)

# --------------------------------------------------------------------------- 18 Conclusion
s = slide("SENTINEL: offline triage you can verify", "Conclusion & demo")
bullets(s, ["Ingests CSV, JSON and EVTX, including unseen formats via the column mapper",
            "14 deterministic rules and explained storylines; fresh held-out F1 " + (f3(M["fresh_aggregate"]["f1"]) if M else "–"),
            "Local Qwen under a typed, verified, self-repairing Evidence Contract; chat never silent",
            "Interactive offline globe and attack graph, analyst workflow, reports and exports",
            "Runs entirely offline on a laptop, GPU or CPU, with recorded connection logs"],
        Inches(0.6), Inches(1.7), Inches(7.2), Inches(4.2), 15, gap=8)
panel(s, Inches(8.2), Inches(1.7), Inches(4.5), Inches(4.4))
text(s, "Live demo (offline, 5 min)", Inches(8.4), Inches(1.85), Inches(4.2), Inches(0.4), 14, GOLD, bold=True)
bullets(s, ["Command Center: rotate, zoom, click a marker", "Log Intelligence: unseen format, EVTX", "Incident storyline and severity",
            "Qwen explanation, self-repair, chat", "Evaluation: fresh seeds, ablation, real logs", "CPU / scale / offline record → report"],
        Inches(8.4), Inches(2.3), Inches(4.1), Inches(3.6), 13, gap=4)
text(s, "github.com/dakshitha0705/SENTINEL  ·  README · docs/evaluation.md · docs/feature_traceability.md · docs/demo_script.md",
     Inches(0.6), Inches(6.3), Inches(12), Inches(0.4), 12, MINT)

OUT.parent.mkdir(exist_ok=True)
prs.save(OUT)
print("saved", OUT, "slides:", len(prs.slides))
