"""Global CSS: cinematic, muted cyberpunk command-center theme (local system fonts only, no external assets)."""

CSS = """
<style>
:root {
  --void:#050a08; --bg:#070f0c; --obsidian:#0d1513; --graphite:#141d1a; --elev:#1b2622;
  --sage:#86a091; --mint:#b5d3c0; --ivory:#efe6d2; --copper:#b87a55; --amber:#d9a35b; --red:#c0574b;
  --muted:#93a39b; --line:rgba(239,230,210,.075); --line2:rgba(239,230,210,.14); --hud:rgba(184,122,85,.55);
  --ok:#9fc7ad; --bad:#d58c80; --hyp:#d9b27a; --r:14px;
  --display:"Bahnschrift","Segoe UI Variable Display","Segoe UI",system-ui,sans-serif;
  --text:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,sans-serif;
  --mono:"Cascadia Mono","Cascadia Code",Consolas,"Courier New",monospace;
}
html, body, [class*="css"], .stApp { font-family: var(--text); }
.stApp {
  color: #e2dacb;
  background:
    linear-gradient(rgba(239,230,210,.018) 1px, transparent 1px) 0 0/44px 44px,
    linear-gradient(90deg, rgba(239,230,210,.018) 1px, transparent 1px) 0 0/44px 44px,
    radial-gradient(1100px 650px at 58% -12%, rgba(134,160,145,.13), transparent 60%),
    radial-gradient(900px 600px at 100% 110%, rgba(184,122,85,.07), transparent 60%),
    var(--bg);
  background-attachment: fixed;
}
[data-testid="stHeader"] { background: transparent; height: 0; }
[data-testid="stToolbar"], [data-testid="stDecoration"] { display: none; }
.block-container { padding-top: .8rem !important; padding-bottom: 2rem; max-width: 1560px; }
h1, h2, h3, h4 { font-family: var(--display); letter-spacing: .5px; font-weight: 500; color: var(--ivory); }
h1 { font-size: 1.35rem !important; } h2 { font-size: 1.1rem !important; } h3 { font-size: .98rem !important; }
p, li { color: #dcd4c4; }
a { color: var(--amber) !important; }
[data-testid="stVerticalBlock"] { gap: .7rem; }

/* ---------- sidebar ---------- */
[data-testid="stSidebar"] { background: linear-gradient(180deg, #0a1311 0%, #060b09 100%); border-right: 1px solid var(--line); min-width: 236px !important; max-width: 236px !important; }
[data-testid="stSidebarContent"] { padding-top: .3rem; }
.sn-brand { font-family: var(--display); font-weight: 600; font-size: 1.25rem; letter-spacing: 8px; color: var(--ivory); }
.sn-brand-sub { color: var(--copper); font-size: .66rem; letter-spacing: 2.2px; text-transform: uppercase; margin-top: 3px; font-family: var(--mono); }
[data-testid="stSidebar"] [role="radiogroup"] { gap: 1px; }
[data-testid="stSidebar"] [role="radiogroup"] label { padding: 8px 10px; border-radius: 10px; margin: 0; width: 100%; cursor: pointer; transition: background .18s ease; border: 1px solid transparent; }
[data-testid="stSidebar"] [role="radiogroup"] label:hover { background: rgba(239,230,210,.04); }
[data-testid="stSidebar"] [role="radiogroup"] label[data-selected="true"] { background: linear-gradient(90deg, rgba(184,122,85,.18), rgba(184,122,85,.03)); border-color: rgba(184,122,85,.25); box-shadow: inset 2px 0 0 var(--amber); }
[data-testid="stSidebar"] [data-testid="stRadioOption"] > div > div:first-child:not([data-testid]) { display: none; }
[data-testid="stSidebar"] [role="radiogroup"] label p { font-size: .86rem; color: #cfc7b7; }
[data-testid="stSidebar"] [role="radiogroup"] label[data-selected="true"] p { color: var(--ivory); font-weight: 600; }
.sn-side-foot { color: var(--muted); font-size: .72rem; line-height: 1.55; font-family: var(--mono); }

/* ---------- HUD cards ---------- */
.sn-card, .sn-kpi, div[class*="st-key-card"] { position: relative; }
.sn-card { background: linear-gradient(180deg, rgba(27,38,34,.72), rgba(13,21,19,.88)); border: 1px solid var(--line); border-radius: var(--r);
  padding: 14px 16px; margin-bottom: 10px; box-shadow: 0 12px 34px rgba(0,0,0,.28), inset 0 1px 0 rgba(239,230,210,.03); }
.sn-card::before, .sn-kpi::before, div[class*="st-key-card"]::before { content: ""; position: absolute; left: -1px; top: -1px; width: 14px; height: 14px;
  border-left: 1px solid var(--hud); border-top: 1px solid var(--hud); border-top-left-radius: var(--r); pointer-events: none; }
.sn-card::after, .sn-kpi::after, div[class*="st-key-card"]::after { content: ""; position: absolute; right: -1px; bottom: -1px; width: 14px; height: 14px;
  border-right: 1px solid var(--hud); border-bottom: 1px solid var(--hud); border-bottom-right-radius: var(--r); pointer-events: none; }
.sn-card h4 { margin: 0 0 9px 0; font-size: .68rem; color: var(--copper); text-transform: uppercase; letter-spacing: 1.8px; font-weight: 600; font-family: var(--mono); }
.sn-kpi { background: linear-gradient(160deg, rgba(134,160,145,.15), rgba(13,21,19,.9) 62%); border: 1px solid var(--line); border-radius: var(--r);
  padding: 12px 15px 11px; margin-bottom: 10px; transition: border-color .25s ease, transform .25s ease; }
.sn-kpi:hover { border-color: var(--line2); transform: translateY(-1px); }
.sn-kpi .l { font-size: .64rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1.6px; font-family: var(--mono); }
.sn-kpi .v { font-family: var(--display); font-size: 1.85rem; color: var(--ivory); font-variant-numeric: tabular-nums; line-height: 1.2; margin-top: 3px; }
.sn-kpi .s { font-size: .74rem; color: var(--muted); margin-top: 1px; }
.sn-kpi.sm .v { font-size: 1.05rem; word-break: break-word; }
.sn-kpi.k2 { background: linear-gradient(160deg, rgba(217,163,91,.14), rgba(13,21,19,.9) 62%); }
.sn-kpi.k3 { background: linear-gradient(160deg, rgba(192,87,75,.13), rgba(13,21,19,.9) 62%); }
.sn-kpi.k4 { background: linear-gradient(160deg, rgba(181,211,192,.12), rgba(13,21,19,.9) 62%); }
div[class*="st-key-card"] { background: linear-gradient(180deg, rgba(27,38,34,.62), rgba(13,21,19,.86)); border: 1px solid var(--line); border-radius: var(--r); padding: 12px 14px; }
.sn-section { margin: 4px 0 8px; } .sn-section .t { font-family: var(--display); font-size: 1.05rem; color: var(--ivory); letter-spacing: .6px; }
.sn-section .d { color: var(--muted); font-size: .8rem; margin-top: 1px; }
.sn-row { display: flex; align-items: center; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid var(--line); font-size: .85rem; }
.sn-row:last-child { border-bottom: 0; }
.sn-row .n { font-family: var(--mono); font-variant-numeric: tabular-nums; color: var(--ivory); }
.sn-bar { height: 4px; border-radius: 4px; background: rgba(239,230,210,.06); overflow: hidden; margin-top: 4px; }
.sn-bar > i { display: block; height: 100%; border-radius: 4px; }
.sn-urgent { padding: 9px 11px; border-radius: 11px; background: rgba(5,10,8,.45); border: 1px solid var(--line); margin-bottom: 7px; }
.sn-urgent .h { display: flex; justify-content: space-between; font-size: .76rem; color: var(--muted); font-family: var(--mono); }
.sn-urgent .b { font-size: .84rem; color: #e6decf; margin-top: 3px; line-height: 1.4; }
.sn-exec { font-family: var(--display); font-size: .98rem; color: var(--ivory); margin-bottom: 7px; }

/* ---------- top bar ---------- */
.sn-top { display:flex; align-items:center; gap: 7px; flex-wrap: wrap; }
.sn-chip { display:inline-flex; align-items:center; gap:7px; padding: 5px 11px; border-radius: 999px; font-size: .72rem; font-family: var(--mono);
  background: rgba(13,21,19,.85); border: 1px solid var(--line); color: #d6cebf; white-space: nowrap; letter-spacing: .3px; }
.sn-chip i { width: 7px; height: 7px; border-radius: 50%; background: var(--sage); display:inline-block; }
.sn-chip.ok i { background: var(--ok); box-shadow: 0 0 0 3px rgba(159,199,173,.12); }
.sn-chip.warn i { background: var(--amber); box-shadow: 0 0 0 3px rgba(217,163,91,.12); }
.sn-chip.bad i { background: var(--red); box-shadow: 0 0 0 3px rgba(192,87,75,.14); }
.sn-chip.live { border-color: rgba(217,163,91,.45); color: var(--ivory); }
.sn-chip.live i { background: var(--amber); animation: snpulse 1.8s ease-in-out infinite; }
.sn-chip.alert { border-color: rgba(192,87,75,.55); color: #f0d9d3; }
.sn-chip.alert i { background: var(--red); animation: snpulse 1.4s ease-in-out infinite; }
@keyframes snpulse { 0%,100% { box-shadow: 0 0 0 0 rgba(217,163,91,.0);} 50% { box-shadow: 0 0 0 5px rgba(217,163,91,.16);} }
.sn-title { font-family: var(--display); font-size: 1.4rem; letter-spacing: 7px; color: var(--ivory); line-height: 1.1; }
.sn-title.page { font-size: .98rem; letter-spacing: 2.4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sn-title-sub { color: var(--copper); font-size: .64rem; letter-spacing: 2px; text-transform: uppercase; font-family: var(--mono); }
.sn-mode { display:flex; align-items:center; gap:10px; padding: 7px 14px; border-radius: 12px; border: 1px solid var(--line);
  background: linear-gradient(90deg, rgba(27,38,34,.8), rgba(13,21,19,.6)); font-family: var(--mono); font-size: .74rem; letter-spacing: 1.4px; text-transform: uppercase; color: var(--muted); }
.sn-mode b { color: var(--ivory); font-weight: 600; }
.sn-mode.incident { border-color: rgba(192,87,75,.45); background: linear-gradient(90deg, rgba(192,87,75,.16), rgba(13,21,19,.6)); transition: all .6s ease; }
.sn-mode.incident b { color: #f1d2cb; }

/* ---------- live feed ---------- */
.sn-feed { font-family: var(--mono); font-size: .72rem; line-height: 1.6; max-height: 250px; overflow: hidden; }
.sn-feed div { display: grid; grid-template-columns: 62px 44px 1fr; gap: 6px; border-bottom: 1px dashed rgba(239,230,210,.05); padding: 2px 0; color: #cfc7b7; animation: snin .5s ease; }
.sn-feed .f { color: var(--bad); } .sn-feed .s { color: var(--ok); } .sn-feed .x { color: var(--muted); }
.sn-feed .tag { color: var(--copper); }
@keyframes snin { from { opacity: 0; transform: translateY(-3px);} to { opacity: 1; transform: none;} }

/* ---------- pills / tags / claims ---------- */
.sn-pill { display:inline-flex; align-items:center; gap:6px; padding: 1px 9px; border-radius: 999px; font-size: .72rem; font-weight: 600; font-family: var(--mono);
  color: var(--c); background: color-mix(in srgb, var(--c) 14%, transparent); border: 1px solid color-mix(in srgb, var(--c) 40%, transparent); }
.sn-pill i { width:6px; height:6px; border-radius:50%; background: var(--c); }
.sn-tag { display:inline-block; padding: 1px 7px; margin: 1px 4px 1px 0; border-radius: 7px; font-size: .7rem; background: rgba(239,230,210,.05);
  border: 1px solid var(--line); color: #cdc5b5; font-family: var(--mono); }
.sn-tag.gold { color: var(--amber); border-color: rgba(217,163,91,.3); }
.sn-claim { padding: 7px 2px; border-bottom: 1px solid var(--line); font-size: .88rem; line-height: 1.5; }
.sn-claim:last-child { border-bottom: 0; }
.sn-ok { color: var(--ok); font-weight: 700; font-size: .66rem; letter-spacing: 1px; font-family: var(--mono); }
.sn-bad { color: var(--bad); font-weight: 700; font-size: .66rem; letter-spacing: 1px; font-family: var(--mono); }
.sn-hyp { color: var(--hyp); font-weight: 700; font-size: .66rem; letter-spacing: 1px; font-family: var(--mono); }
.sn-cite { font-family: var(--mono); font-size: .7rem; color: var(--muted); }
.sn-muted { color: var(--muted); font-size: .8rem; }
.sn-step { position: relative; border-left: 2px solid var(--sage); background: rgba(20,29,26,.65); padding: 9px 13px; margin: 0 0 8px 8px; border-radius: 0 12px 12px 0; }
.sn-step::before { content: ""; position: absolute; left: -6px; top: 13px; width: 10px; height: 10px; border-radius: 50%; background: var(--bg); border: 2px solid var(--sage); }
.sn-step.weak { border-left: 2px dashed #5f6e69; opacity: .88; } .sn-step.ctx { border-left-color: #56665f; }
.sn-step.seed { border-left-color: var(--amber); } .sn-step.seed::before { border-color: var(--amber); }
.sn-step .t { font-family: var(--mono); font-size: .72rem; color: var(--muted); }
.sn-step .r { font-weight: 600; color: var(--ivory); }
.sn-step .why { font-size: .84rem; color: #d4ccbc; margin-top: 2px; }
.sn-step .link { font-size: .75rem; color: var(--muted); margin-top: 4px; }

/* ---------- widgets ---------- */
.stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] > button {
  border-radius: 10px; border: 1px solid var(--line2); background: rgba(27,38,34,.7); color: var(--ivory); transition: all .18s ease; }
.stButton > button:hover, .stDownloadButton > button:hover { border-color: rgba(217,163,91,.55); color: #fbf3e3; background: rgba(27,38,34,.98); }
.stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"] { background: linear-gradient(180deg, #d9b07a, #b8895a); color: #131a17; border: 0; font-weight: 600; }
.stButton > button[kind="primary"] p, .stDownloadButton > button[kind="primary"] p { color: #131a17 !important; font-weight: 600; }
.stButton > button[kind="primary"]:hover { filter: brightness(1.06); }
[data-testid="stTextInput"] input, [data-baseweb="select"] > div, [data-testid="stNumberInput"] input, textarea {
  border-radius: 10px !important; background: rgba(13,21,19,.85) !important; border-color: var(--line2) !important; }
[data-baseweb="tab-list"] { gap: 2px; border-bottom: 1px solid var(--line); }
[data-baseweb="tab"] { border-radius: 9px 9px 0 0; padding: 7px 13px; color: var(--muted); font-size: .86rem; }
[data-baseweb="tab"][aria-selected="true"] { color: var(--ivory); }
[data-baseweb="tab-highlight"] { background: var(--amber) !important; }
[data-testid="stExpander"] { border: 1px solid var(--line) !important; border-radius: 12px !important; background: rgba(13,21,19,.55); }
[data-testid="stDataFrame"] { border-radius: 10px; overflow: hidden; border: 1px solid var(--line); }
[data-testid="stAlert"] { border-radius: 12px; }
[data-testid="stToast"] { background: #121c19 !important; border: 1px solid rgba(217,163,91,.4) !important; color: var(--ivory) !important; }
div[class*="st-key-action"] .stButton > button { height: 92px; width: 100%; border-radius: 16px; text-align: left; justify-content: flex-start; padding: 14px 18px;
  background: linear-gradient(150deg, rgba(134,160,145,.2), rgba(13,21,19,.92) 65%); border: 1px solid var(--line); }
div[class*="st-key-action2"] .stButton > button { background: linear-gradient(150deg, rgba(217,163,91,.17), rgba(13,21,19,.92) 65%); }
div[class*="st-key-action3"] .stButton > button { background: linear-gradient(150deg, rgba(184,122,85,.2), rgba(13,21,19,.92) 65%); }
div[class*="st-key-action4"] .stButton > button { background: linear-gradient(150deg, rgba(181,211,192,.16), rgba(13,21,19,.92) 65%); }
div[class*="st-key-action"] .stButton > button:hover { transform: translateY(-2px); border-color: rgba(217,163,91,.5); }
div[class*="st-key-action"] .stButton > button p { font-size: .98rem; font-family: var(--display); color: var(--ivory); }
iframe { border-radius: 18px; }
hr { border-color: var(--line) !important; }
</style>
"""
