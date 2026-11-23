"""Global CSS for the SENTINEL dashboard (muted pastel-dark theme, local system fonts only)."""

CSS = """
<style>
:root {
  --bg:#0D1716; --sidebar:#14201E; --surface:#1C2B29; --elev:#273734; --sage:#819B8D; --mint:#A7BFAF;
  --cream:#E8DDC9; --gold:#C8AA7C; --rose:#B98780; --muted:#A9B6AE; --line:rgba(232,221,201,.08);
  --line2:rgba(232,221,201,.14); --ok:#9DC2A8; --bad:#D19A90; --hyp:#D2B98E; --r:18px;
  --display:"Bahnschrift","Segoe UI Variable Display","Segoe UI",system-ui,sans-serif;
  --text:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,sans-serif;
  --mono:"Cascadia Mono",Consolas,"Courier New",monospace;
}
html, body, [class*="css"], .stApp { font-family: var(--text); }
.stApp { background: radial-gradient(1200px 700px at 55% -10%, #15231F 0%, var(--bg) 55%) fixed; color: #E3DCCD; }
[data-testid="stHeader"] { background: transparent; height: 0; }
[data-testid="stToolbar"] { display: none; }
.block-container { padding-top: 1.1rem !important; padding-bottom: 3rem; max-width: 1480px; }
h1, h2, h3, h4 { font-family: var(--display); letter-spacing: .3px; font-weight: 500; color: var(--cream); }
h1 { font-size: 1.45rem !important; } h2 { font-size: 1.15rem !important; } h3 { font-size: 1.0rem !important; }
p, li { color: #DCD5C6; }
a { color: var(--gold) !important; }

/* ---------- sidebar navigation ---------- */
[data-testid="stSidebar"] { background: linear-gradient(180deg, #14201E 0%, #111B19 100%); border-right: 1px solid var(--line); }
[data-testid="stSidebar"] .block-container, [data-testid="stSidebarContent"] { padding-top: .6rem; }
.sn-brand { font-family: var(--display); font-weight: 600; font-size: 1.32rem; letter-spacing: 7px; color: var(--cream); }
.sn-brand-sub { color: var(--muted); font-size: .72rem; letter-spacing: 1.6px; text-transform: uppercase; margin-top: 2px; }
[data-testid="stSidebar"] [role="radiogroup"] { gap: 2px; }
[data-testid="stSidebar"] [role="radiogroup"] label { padding: 9px 12px; border-radius: 12px; margin: 0;
  transition: background .18s ease; width: 100%; cursor: pointer; }
[data-testid="stSidebar"] [role="radiogroup"] label:hover { background: rgba(232,221,201,.05); }
[data-testid="stSidebar"] [role="radiogroup"] label[data-selected="true"] { background: linear-gradient(90deg, rgba(200,170,124,.16), rgba(200,170,124,.04));
  box-shadow: inset 2px 0 0 var(--gold); }
[data-testid="stSidebar"] [data-testid="stRadioOption"] > div > div:first-child:not([data-testid]) { display: none; }
[data-testid="stSidebar"] [role="radiogroup"] label p { font-size: .9rem; color: #D7D0C1; }
[data-testid="stSidebar"] [role="radiogroup"] label[data-selected="true"] p { color: var(--cream); font-weight: 600; }
.sn-side-foot { color: var(--muted); font-size: .74rem; line-height: 1.5; }

/* ---------- cards ---------- */
.sn-card { background: linear-gradient(180deg, rgba(39,55,52,.55), rgba(28,43,41,.72)); border: 1px solid var(--line);
  border-radius: var(--r); padding: 16px 18px; box-shadow: 0 10px 30px rgba(0,0,0,.18); margin-bottom: 12px; }
.sn-card h4 { margin: 0 0 10px 0; font-size: .78rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1.4px; font-weight: 600; font-family: var(--text); }
.sn-kpi { background: linear-gradient(160deg, rgba(129,155,141,.20), rgba(28,43,41,.70) 60%); border: 1px solid var(--line);
  border-radius: var(--r); padding: 16px 18px 14px; margin-bottom: 12px; transition: transform .2s ease, border-color .2s ease; }
.sn-kpi:hover { transform: translateY(-1px); border-color: var(--line2); }
.sn-kpi .l { font-size: .72rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1.3px; }
.sn-kpi .v { font-family: var(--display); font-size: 1.9rem; color: var(--cream); font-variant-numeric: tabular-nums; line-height: 1.25; margin-top: 4px; }
.sn-kpi .s { font-size: .76rem; color: var(--muted); margin-top: 2px; }
.sn-kpi.k2 { background: linear-gradient(160deg, rgba(200,170,124,.18), rgba(28,43,41,.70) 60%); }
.sn-kpi.k3 { background: linear-gradient(160deg, rgba(185,135,128,.18), rgba(28,43,41,.70) 60%); }
.sn-kpi.k4 { background: linear-gradient(160deg, rgba(167,191,175,.16), rgba(28,43,41,.70) 60%); }
.sn-section { margin: 8px 0 10px; } .sn-section .t { font-family: var(--display); font-size: 1.12rem; color: var(--cream); }
.sn-section .d { color: var(--muted); font-size: .84rem; margin-top: 2px; }
.sn-row { display: flex; align-items: center; justify-content: space-between; padding: 7px 0; border-bottom: 1px solid var(--line); font-size: .88rem; }
.sn-row:last-child { border-bottom: 0; }
.sn-row .n { font-family: var(--display); font-variant-numeric: tabular-nums; color: var(--cream); }
.sn-bar { height: 6px; border-radius: 6px; background: rgba(232,221,201,.07); overflow: hidden; margin-top: 5px; }
.sn-bar > i { display: block; height: 100%; border-radius: 6px; }
.sn-urgent { padding: 10px 12px; border-radius: 14px; background: rgba(13,23,22,.35); border: 1px solid var(--line); margin-bottom: 8px; }
.sn-urgent .h { display: flex; justify-content: space-between; font-size: .8rem; color: var(--muted); }
.sn-urgent .b { font-size: .86rem; color: #E3DCCD; margin-top: 4px; line-height: 1.4; }
.sn-exec { font-family: var(--display); font-size: 1.02rem; color: var(--cream); margin-bottom: 8px; }

/* ---------- top bar ---------- */
.sn-top { display:flex; align-items:center; gap: 10px; flex-wrap: wrap; }
.sn-chip { display:inline-flex; align-items:center; gap:7px; padding: 6px 12px; border-radius: 999px; font-size: .78rem;
  background: rgba(28,43,41,.8); border: 1px solid var(--line); color: #D9D2C3; white-space: nowrap; }
.sn-chip i { width: 7px; height: 7px; border-radius: 50%; background: var(--sage); display:inline-block; }
.sn-chip.ok i { background: #9DC2A8; box-shadow: 0 0 0 3px rgba(157,194,168,.14); }
.sn-chip.warn i { background: var(--gold); box-shadow: 0 0 0 3px rgba(200,170,124,.14); }
.sn-chip.bad i { background: var(--rose); box-shadow: 0 0 0 3px rgba(185,135,128,.14); }
.sn-title { font-family: var(--display); font-size: 1.5rem; letter-spacing: 6px; color: var(--cream); line-height: 1.1; }
.sn-title.page { font-size: 1.02rem; letter-spacing: 1.6px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sn-kpi.sm .v { font-size: 1.12rem; word-break: break-word; }
.stButton > button[kind="primary"] p, .stDownloadButton > button[kind="primary"] p { color: #18211F !important; font-weight: 600; }
.sn-title-sub { color: var(--muted); font-size: .74rem; letter-spacing: 1.4px; text-transform: uppercase; }

/* ---------- pills / tags / claims ---------- */
.sn-pill { display:inline-flex; align-items:center; gap:6px; padding: 2px 10px; border-radius: 999px; font-size: .74rem; font-weight: 600;
  color: var(--c); background: color-mix(in srgb, var(--c) 16%, transparent); border: 1px solid color-mix(in srgb, var(--c) 40%, transparent); }
.sn-pill i { width:6px; height:6px; border-radius:50%; background: var(--c); }
.sn-tag { display:inline-block; padding: 1px 8px; margin: 1px 4px 1px 0; border-radius: 8px; font-size: .72rem;
  background: rgba(232,221,201,.06); border: 1px solid var(--line); color: #CFC8B9; font-family: var(--mono); }
.sn-tag.gold { color: var(--gold); border-color: rgba(200,170,124,.35); }
.sn-claim { padding: 8px 2px; border-bottom: 1px solid var(--line); font-size: .9rem; line-height: 1.5; }
.sn-claim:last-child { border-bottom: 0; }
.sn-ok { color: var(--ok); font-weight: 700; font-size: .7rem; letter-spacing: .8px; }
.sn-bad { color: var(--bad); font-weight: 700; font-size: .7rem; letter-spacing: .8px; }
.sn-hyp { color: var(--hyp); font-weight: 700; font-size: .7rem; letter-spacing: .8px; }
.sn-cite { font-family: var(--mono); font-size: .72rem; color: var(--muted); }
.sn-muted { color: var(--muted); font-size: .82rem; }
.sn-step { position: relative; border-left: 2px solid var(--sage); background: rgba(28,43,41,.55); padding: 10px 14px; margin: 0 0 10px 8px;
  border-radius: 0 14px 14px 0; }
.sn-step.weak { border-left: 2px dashed #6D7C77; opacity: .88; } .sn-step.ctx { border-left-color: #5F7470; }
.sn-step.seed { border-left-color: var(--gold); }
.sn-step .t { font-family: var(--mono); font-size: .76rem; color: var(--muted); }
.sn-step .r { font-weight: 600; color: var(--cream); }
.sn-step .why { font-size: .86rem; color: #D7D0C1; margin-top: 3px; }
.sn-step .link { font-size: .77rem; color: var(--muted); margin-top: 5px; }

/* ---------- widgets ---------- */
.stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] > button {
  border-radius: 12px; border: 1px solid var(--line2); background: rgba(39,55,52,.65); color: var(--cream);
  transition: all .18s ease; }
.stButton > button:hover, .stDownloadButton > button:hover { border-color: rgba(200,170,124,.55); color: #F3EBDD; background: rgba(39,55,52,.95); }
.stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"] {
  background: linear-gradient(180deg, #CDB089, #B8996C); color: #18211F; border: 0; font-weight: 600; }
.stButton > button[kind="primary"]:hover { filter: brightness(1.05); color: #111; }
[data-testid="stTextInput"] input, [data-baseweb="select"] > div, [data-testid="stNumberInput"] input, textarea {
  border-radius: 12px !important; background: rgba(28,43,41,.75) !important; border-color: var(--line2) !important; }
[data-baseweb="tab-list"] { gap: 4px; border-bottom: 1px solid var(--line); }
[data-baseweb="tab"] { border-radius: 10px 10px 0 0; padding: 8px 14px; color: var(--muted); }
[data-baseweb="tab"][aria-selected="true"] { color: var(--cream); }
[data-baseweb="tab-highlight"] { background: var(--gold) !important; }
[data-testid="stExpander"] { border: 1px solid var(--line) !important; border-radius: 14px !important; background: rgba(28,43,41,.45); }
[data-testid="stDataFrame"] { border-radius: 12px; overflow: hidden; border: 1px solid var(--line); }
[data-testid="stAlert"] { border-radius: 14px; }
[data-testid="stVerticalBlockBorderWrapper"]:has(> div > .st-key-card) { border-radius: var(--r); }
div[class*="st-key-card"] { background: linear-gradient(180deg, rgba(39,55,52,.50), rgba(28,43,41,.70));
  border: 1px solid var(--line); border-radius: var(--r); padding: 14px 16px; }
/* bottom action cards */
div[class*="st-key-action"] .stButton > button { height: 104px; width: 100%; border-radius: 20px; text-align: left; justify-content: flex-start;
  padding: 16px 20px; background: linear-gradient(150deg, rgba(129,155,141,.22), rgba(28,43,41,.85) 65%); border: 1px solid var(--line); }
div[class*="st-key-action2"] .stButton > button { background: linear-gradient(150deg, rgba(200,170,124,.20), rgba(28,43,41,.85) 65%); }
div[class*="st-key-action3"] .stButton > button { background: linear-gradient(150deg, rgba(185,135,128,.20), rgba(28,43,41,.85) 65%); }
div[class*="st-key-action4"] .stButton > button { background: linear-gradient(150deg, rgba(167,191,175,.20), rgba(28,43,41,.85) 65%); }
div[class*="st-key-action"] .stButton > button:hover { transform: translateY(-2px); border-color: rgba(200,170,124,.5); }
div[class*="st-key-action"] .stButton > button p { font-size: 1.02rem; font-family: var(--display); color: var(--cream); }
div[class*="st-key-action"] .stButton > button div[data-testid="stMarkdownContainer"] p + p { font-size: .8rem; color: var(--muted); }
iframe { border-radius: 22px; }
hr { border-color: var(--line) !important; }
</style>
"""
