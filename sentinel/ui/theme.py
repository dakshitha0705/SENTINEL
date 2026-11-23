"""Global CSS: coastal-dark investigation theme (deep petrol shell, warm ivory story cards, peach/terracotta
actions, powder-blue selection, restrained copper accents). Local system fonts only - nothing is fetched."""

CSS = """
<style>
:root {
  --deep:#071a1e; --shell:#0b2226; --shell2:#0f2b31; --midnight:#0e2433; --panel:#12323a; --panel2:#163b44;
  --ivory:#f3ebdd; --beige:#e8dcc6; --sand:#d8c5a5; --ink:#1d2a2c; --ink2:#4a5654;
  --peach:#e3a587; --terra:#c7714f; --powder:#a9c3d1; --copper:#c39a62; --red:#c9655a;
  --text-on-dark:#e7dfd0; --muted:#9db1b2; --line:rgba(243,235,221,.09); --line2:rgba(243,235,221,.17);
  --ok:#9cc7b4; --bad:#e0897d; --hyp:#dcb47e; --r:16px;
  /* legacy names used by older markup */
  --sage:#8fb0ad; --mint:#b7d1cc; --amber:#e3a587; --obsidian:#0b2226; --graphite:#12323a; --bg:#0b2226;
  --display:"Sitka Heading","Sitka Display","Cambria","Georgia",serif;
  --text:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,sans-serif;
  --mono:"Cascadia Mono","Cascadia Code",Consolas,"Courier New",monospace;
}
html, body, [class*="css"], .stApp { font-family: var(--text); }
.stApp {
  color: var(--text-on-dark);
  background:
    radial-gradient(1200px 700px at 70% -10%, rgba(169,195,209,.10), transparent 60%),
    radial-gradient(900px 600px at -10% 110%, rgba(199,113,79,.08), transparent 60%),
    linear-gradient(180deg, var(--shell) 0%, var(--deep) 100%);
  background-attachment: fixed;
}
[data-testid="stHeader"] { background: transparent; height: 0; }
[data-testid="stToolbar"], [data-testid="stDecoration"] { display: none; }
.block-container { padding-top: .9rem !important; padding-bottom: 2rem; max-width: 1580px; }
h1, h2, h3, h4 { font-family: var(--display); font-weight: 600; color: var(--ivory); letter-spacing: .2px; }
h1 { font-size: 1.6rem !important; } h2 { font-size: 1.3rem !important; } h3 { font-size: 1.12rem !important; }
p, li { color: #ddd5c6; }
a { color: var(--peach) !important; }
[data-testid="stVerticalBlock"] { gap: .75rem; }
code { color: var(--sand) !important; background: rgba(243,235,221,.06) !important; }

/* ---------- sidebar ---------- */
[data-testid="stSidebar"] { background: linear-gradient(180deg, #0a2024 0%, #061518 100%); border-right: 1px solid var(--line);
  min-width: 232px !important; max-width: 232px !important; }
[data-testid="stSidebarContent"] { padding-top: .4rem; }
.sn-brand { font-family: var(--display); font-weight: 700; font-size: 1.45rem; letter-spacing: 5px; color: var(--ivory); }
.sn-brand-sub { color: var(--peach); font-size: .7rem; letter-spacing: 1.6px; text-transform: uppercase; margin-top: 2px; }
[data-testid="stSidebar"] [role="radiogroup"] { gap: 3px; }
[data-testid="stSidebar"] [role="radiogroup"] label { padding: 10px 12px; border-radius: 12px; margin: 0; width: 100%; cursor: pointer;
  transition: background .18s ease, transform .18s ease; border: 1px solid transparent; }
[data-testid="stSidebar"] [role="radiogroup"] label:hover { background: rgba(169,195,209,.07); transform: translateX(2px); }
[data-testid="stSidebar"] [role="radiogroup"] label[data-selected="true"], [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
  background: linear-gradient(90deg, rgba(169,195,209,.20), rgba(169,195,209,.04)); border-color: rgba(169,195,209,.28); }
[data-testid="stSidebar"] [data-testid="stRadioOption"] > div > div:first-child:not([data-testid]) { display: none; }
[data-testid="stSidebar"] [role="radiogroup"] label p { font-size: .92rem; color: #d3dad6; }
[data-testid="stSidebar"] [role="radiogroup"] label[data-selected="true"] p { color: var(--ivory); font-weight: 600; }
.sn-side-foot { color: var(--muted); font-size: .74rem; line-height: 1.6; }
.sn-side-foot b { color: var(--ivory); font-weight: 600; }

/* ---------- surfaces ---------- */
.sn-card, div[class*="st-key-card"] { background: linear-gradient(180deg, rgba(22,59,68,.70), rgba(14,38,44,.86));
  border: 1px solid var(--line); border-radius: var(--r); box-shadow: 0 14px 34px rgba(0,0,0,.22); }
.sn-card { padding: 15px 17px; margin-bottom: 10px; }
div[class*="st-key-card"] { padding: 14px 16px; }
.sn-card h4 { margin: 0 0 10px 0; font-size: .72rem; color: var(--powder); text-transform: uppercase; letter-spacing: 1.4px; font-weight: 600;
  font-family: var(--text); }
.sn-section { margin: 4px 0 8px; } .sn-section .t { font-family: var(--display); font-size: 1.25rem; color: var(--ivory); }
.sn-section .d { color: var(--muted); font-size: .84rem; margin-top: 2px; }
.sn-eyebrow { font-size: .7rem; letter-spacing: 1.6px; text-transform: uppercase; color: var(--peach); font-weight: 600; }

/* ivory story card (hero incident, AI cards, scenario cards) */
.sn-hero { background: linear-gradient(160deg, #f5eee2 0%, #e9dcc6 100%); color: var(--ink); border-radius: 20px; padding: 22px 24px 18px;
  box-shadow: 0 20px 44px rgba(0,0,0,.30); border: 1px solid rgba(255,255,255,.4); position: relative; overflow: hidden; }
.sn-hero::after { content: ""; position: absolute; right: -60px; top: -60px; width: 220px; height: 220px; border-radius: 50%;
  border: 1px solid rgba(199,113,79,.22); box-shadow: 0 0 0 26px rgba(199,113,79,.05), 0 0 0 54px rgba(199,113,79,.035); pointer-events: none; }
.sn-hero .eyebrow { font-size: .72rem; letter-spacing: 1.5px; text-transform: uppercase; color: var(--terra); font-weight: 700; }
.sn-hero .h { font-family: var(--display); font-size: 1.75rem; line-height: 1.18; color: #1a2628; margin: 6px 0 8px; font-weight: 700; }
.sn-hero .p { font-size: .98rem; color: #3c4846; line-height: 1.5; max-width: 60ch; }
.sn-hero .meta { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.sn-hero .meta span { font-size: .78rem; padding: 3px 10px; border-radius: 999px; background: rgba(29,42,44,.07); color: #33403e; }
.sn-hero.calm { background: linear-gradient(160deg, #e6eef0 0%, #d5e3e8 100%); }
.sn-hero.calm .eyebrow { color: #3d6b7a; }
.sn-sev { display: inline-flex; align-items: center; gap: 6px; padding: 3px 11px; border-radius: 999px; font-size: .76rem; font-weight: 700;
  color: #fff; background: var(--c); }

/* counters */
.sn-stats { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 10px; }
.sn-stat { background: rgba(243,235,221,.06); border: 1px solid var(--line); border-radius: 14px; padding: 12px 14px; transition: border-color .2s, transform .2s; }
.sn-stat:hover { border-color: var(--line2); transform: translateY(-1px); }
.sn-stat .v { font-family: var(--display); font-size: 1.85rem; color: var(--ivory); line-height: 1.1; font-variant-numeric: tabular-nums; }
.sn-stat .l { font-size: .76rem; color: var(--muted); margin-top: 2px; }
@media (max-width: 1400px) { .sn-stat .v { font-size: 1.5rem; } .sn-hero .h { font-size: 1.45rem; } }

/* older KPI markup (kept for pages that still use it) */
.sn-kpi { background: rgba(243,235,221,.06); border: 1px solid var(--line); border-radius: 14px; padding: 11px 14px; margin-bottom: 10px; }
.sn-kpi .l { font-size: .7rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1.1px; }
.sn-kpi .v { font-family: var(--display); font-size: 1.6rem; color: var(--ivory); line-height: 1.2; margin-top: 2px; }
.sn-kpi .s { font-size: .74rem; color: var(--muted); }
.sn-kpi.sm .v { font-size: 1rem; font-family: var(--text); word-break: break-word; }

.sn-row { display: flex; align-items: center; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid var(--line); font-size: .86rem; }
.sn-row:last-child { border-bottom: 0; }
.sn-row .n { font-variant-numeric: tabular-nums; color: var(--ivory); font-weight: 600; }
.sn-bar { height: 5px; border-radius: 5px; background: rgba(243,235,221,.07); overflow: hidden; margin: 3px 0 4px; }
.sn-bar > i { display: block; height: 100%; border-radius: 5px; transition: width .6s ease; }
.sn-exec { font-family: var(--display); font-size: 1.05rem; color: var(--ivory); margin-bottom: 7px; }

/* activity list */
.sn-act { display: grid; grid-template-columns: 22px 1fr auto; gap: 10px; align-items: center; padding: 8px 2px; border-bottom: 1px solid var(--line);
  animation: snin .45s ease; }
.sn-act:last-child { border-bottom: 0; }
.sn-act .ic { width: 22px; height: 22px; border-radius: 50%; display: grid; place-items: center; font-size: .7rem; font-weight: 700; }
.sn-act .ic.ok { background: rgba(156,199,180,.16); color: var(--ok); }
.sn-act .ic.bad { background: rgba(224,137,125,.16); color: var(--bad); }
.sn-act .ic.sim { background: rgba(169,195,209,.16); color: var(--powder); }
.sn-act .ic.warn { background: rgba(227,165,135,.18); color: var(--peach); }
.sn-act .d { font-size: .86rem; color: var(--text-on-dark); line-height: 1.3; }
.sn-act .d small { display: block; color: var(--muted); font-size: .74rem; }
.sn-act .t { font-size: .72rem; color: var(--muted); font-family: var(--mono); }
@keyframes snin { from { opacity: 0; transform: translateY(-4px);} to { opacity: 1; transform: none;} }

/* top bar */
.sn-top { display:flex; align-items:center; gap: 7px; flex-wrap: wrap; justify-content: flex-end; }
.sn-chip { display:inline-flex; align-items:center; gap:7px; padding: 5px 12px; border-radius: 999px; font-size: .76rem;
  background: rgba(243,235,221,.06); border: 1px solid var(--line); color: #dcd6c9; white-space: nowrap; }
.sn-chip i { width: 7px; height: 7px; border-radius: 50%; background: var(--sage); display:inline-block; }
.sn-chip.ok i { background: var(--ok); } .sn-chip.warn i { background: var(--peach); } .sn-chip.bad i { background: var(--red); }
.sn-chip.live { border-color: rgba(227,165,135,.5); color: var(--ivory); background: rgba(199,113,79,.14); }
.sn-chip.live i { background: var(--peach); animation: snpulse 2s ease-in-out infinite; }
.sn-chip.data { border-color: rgba(169,195,209,.35); }
.sn-chip.alert { border-color: rgba(201,101,90,.55); color: #f6ddd8; }
.sn-chip.alert i { background: var(--red); animation: snpulse 1.6s ease-in-out infinite; }
@keyframes snpulse { 0%,100% { box-shadow: 0 0 0 0 rgba(227,165,135,0);} 50% { box-shadow: 0 0 0 5px rgba(227,165,135,.18);} }
.sn-title { font-family: var(--display); font-size: 1.55rem; color: var(--ivory); line-height: 1.1; font-weight: 700; }
.sn-title-sub { color: var(--muted); font-size: .76rem; margin-top: 2px; }
.sn-mode { display:flex; align-items:center; gap:10px; flex-wrap: wrap; padding: 8px 14px; border-radius: 14px; border: 1px solid var(--line);
  background: rgba(243,235,221,.04); font-size: .82rem; color: var(--muted); }
.sn-mode b { color: var(--ivory); font-weight: 600; }
.sn-mode.incident { border-color: rgba(201,101,90,.45); background: rgba(201,101,90,.10); }

/* notifications */
.sn-notif { border-left: 3px solid var(--c, var(--peach)); background: rgba(243,235,221,.05); border-radius: 0 12px 12px 0; padding: 9px 12px; margin-bottom: 8px;
  animation: snin .5s ease; }
.sn-notif .k { font-size: .7rem; letter-spacing: 1.2px; text-transform: uppercase; color: var(--c, var(--peach)); font-weight: 700; }
.sn-notif .h { font-family: var(--display); font-size: 1.02rem; color: var(--ivory); margin: 2px 0; }
.sn-notif .b { font-size: .84rem; color: #d8d0c1; }
.sn-notif .m { font-size: .72rem; color: var(--muted); margin-top: 3px; }

/* scenario / hunt / case cards */
.sn-scn { background: rgba(243,235,221,.05); border: 1px solid var(--line); border-radius: 14px; padding: 12px 14px; min-height: 118px; transition: all .2s ease; }
.sn-scn:hover { border-color: rgba(227,165,135,.45); transform: translateY(-2px); }
.sn-scn.primary { background: linear-gradient(160deg, #f5eee2, #e7d9c1); border-color: transparent; }
.sn-scn.primary .t, .sn-scn.primary .d { color: var(--ink); } .sn-scn.primary .e { color: var(--terra); }
.sn-scn .t { font-family: var(--display); font-size: 1.05rem; color: var(--ivory); font-weight: 600; }
.sn-scn .d { font-size: .82rem; color: #d2cabc; margin-top: 4px; line-height: 1.4; }
.sn-scn .e { font-size: .74rem; color: var(--powder); margin-top: 6px; }
.sn-scn .id { float: right; font-family: var(--mono); font-size: .72rem; color: var(--muted); }
.sn-case { border-radius: 14px; padding: 10px 12px; border: 1px solid var(--line); background: rgba(243,235,221,.04); margin-bottom: 2px; }
.sn-case.sel { background: rgba(169,195,209,.16); border-color: rgba(169,195,209,.45); }
.sn-case .t { font-size: .9rem; color: var(--ivory); font-weight: 600; line-height: 1.3; }
.sn-case .m { font-size: .74rem; color: var(--muted); margin-top: 3px; }
.sn-progress { display: flex; gap: 6px; margin: 4px 0 10px; }
.sn-progress i { flex: 1; height: 6px; border-radius: 6px; background: rgba(243,235,221,.10); }
.sn-progress i.done { background: var(--ok); } .sn-progress i.now { background: var(--peach); }
.sn-check { padding: 7px 10px; border-radius: 10px; font-size: .88rem; margin-bottom: 4px; color: var(--text-on-dark); }
.sn-check.done { color: var(--ok); } .sn-check.now { background: rgba(227,165,135,.14); color: var(--ivory); border: 1px solid rgba(227,165,135,.35); }
.sn-check.todo { color: var(--muted); }

/* AI cards */
.sn-know { border-radius: 16px; padding: 14px 16px; margin-bottom: 10px; border: 1px solid var(--line); background: rgba(243,235,221,.05); }
.sn-know h4 { margin: 0 0 6px; font-family: var(--display); font-size: 1.08rem; color: var(--ivory); text-transform: none; letter-spacing: 0; }
.sn-know .sub { font-size: .78rem; color: var(--muted); margin-bottom: 6px; }
.sn-know.k1 { border-top: 3px solid var(--ok); } .sn-know.k2 { border-top: 3px solid var(--hyp); }
.sn-know.k3 { border-top: 3px solid var(--bad); } .sn-know.k4 { border-top: 3px solid var(--powder); }

/* pills / tags / claims */
.sn-pill { display:inline-flex; align-items:center; gap:6px; padding: 2px 10px; border-radius: 999px; font-size: .74rem; font-weight: 600;
  color: var(--c); background: color-mix(in srgb, var(--c) 16%, transparent); border: 1px solid color-mix(in srgb, var(--c) 42%, transparent); }
.sn-pill i { width:6px; height:6px; border-radius:50%; background: var(--c); }
.sn-tag { display:inline-block; padding: 1px 8px; margin: 1px 4px 1px 0; border-radius: 8px; font-size: .72rem; background: rgba(243,235,221,.06);
  border: 1px solid var(--line); color: #d6cfc2; }
.sn-tag.gold { color: var(--sand); border-color: rgba(195,154,98,.35); }
.sn-claim { padding: 7px 2px; border-bottom: 1px solid var(--line); font-size: .9rem; line-height: 1.5; }
.sn-claim:last-child { border-bottom: 0; }
.sn-ok { color: var(--ok); font-weight: 700; font-size: .68rem; letter-spacing: .8px; }
.sn-bad { color: var(--bad); font-weight: 700; font-size: .68rem; letter-spacing: .8px; }
.sn-hyp { color: var(--hyp); font-weight: 700; font-size: .68rem; letter-spacing: .8px; }
.sn-cite { font-family: var(--mono); font-size: .7rem; color: var(--muted); }
.sn-muted { color: var(--muted); font-size: .82rem; }
.sn-step { position: relative; border-left: 2px solid var(--powder); background: rgba(243,235,221,.04); padding: 10px 14px; margin: 0 0 8px 8px; border-radius: 0 14px 14px 0; }
.sn-step::before { content: ""; position: absolute; left: -7px; top: 14px; width: 12px; height: 12px; border-radius: 50%; background: var(--shell); border: 2px solid var(--powder); }
.sn-step.weak { border-left: 2px dashed #6d8485; opacity: .9; } .sn-step.ctx { border-left-color: #5d7678; }
.sn-step.seed { border-left-color: var(--peach); } .sn-step.seed::before { border-color: var(--peach); }
.sn-step .t { font-family: var(--mono); font-size: .72rem; color: var(--muted); }
.sn-step .r { font-weight: 600; color: var(--ivory); }
.sn-step .why { font-size: .86rem; color: #d8d0c2; margin-top: 2px; }
.sn-step .link { font-size: .76rem; color: var(--muted); margin-top: 4px; }

/* widgets */
.stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] > button, [data-testid="stPopover"] button {
  border-radius: 12px; border: 1px solid var(--line2); background: rgba(243,235,221,.05); color: var(--ivory); transition: all .18s ease; }
.stButton > button:hover, .stDownloadButton > button:hover, [data-testid="stPopover"] button:hover { border-color: rgba(227,165,135,.6); color: #fff7ea; background: rgba(243,235,221,.09); }
.stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"] { background: linear-gradient(180deg, #eab092, #cf7f5c); color: #1f1712; border: 0; font-weight: 600; }
.stButton > button[kind="primary"] p, .stDownloadButton > button[kind="primary"] p { color: #1f1712 !important; font-weight: 650; }
.stButton > button[kind="primary"]:hover { filter: brightness(1.05); transform: translateY(-1px); }
.stButton > button:disabled { opacity: .45; }
[data-testid="stLinkButton"] a { border-radius: 12px; border: 1px solid var(--line2); background: rgba(243,235,221,.05); color: var(--ivory) !important; }
[data-testid="stLinkButton"] a:hover { border-color: rgba(227,165,135,.6); }
[data-testid="stLinkButton"] a[kind="primary"], [data-testid="stLinkButton"] a[data-testid="stBaseLinkButton-primary"] {
  background: linear-gradient(180deg, #eab092, #cf7f5c); border: 0; color: #1f1712 !important; }
[data-testid="stLinkButton"] a[kind="primary"] p, [data-testid="stLinkButton"] a[data-testid="stBaseLinkButton-primary"] p { color: #1f1712 !important; font-weight: 650; }
[data-testid="stTextInput"] input, [data-baseweb="select"] > div, [data-testid="stNumberInput"] input, textarea {
  border-radius: 12px !important; background: rgba(7,26,30,.75) !important; border-color: var(--line2) !important; }
[data-baseweb="tab-list"] { gap: 4px; border-bottom: 1px solid var(--line); }
[data-baseweb="tab"] { border-radius: 10px 10px 0 0; padding: 8px 14px; color: var(--muted); font-size: .9rem; }
[data-baseweb="tab"][aria-selected="true"] { color: var(--ivory); }
[data-baseweb="tab-highlight"] { background: var(--peach) !important; }
[data-testid="stExpander"] { border: 1px solid var(--line) !important; border-radius: 14px !important; background: rgba(7,26,30,.35); }
[data-testid="stDataFrame"] { border-radius: 12px; overflow: hidden; border: 1px solid var(--line); }
[data-testid="stAlert"] { border-radius: 14px; }
[data-testid="stToast"] { background: #f3ebdd !important; border: 0 !important; color: var(--ink) !important; box-shadow: 0 16px 40px rgba(0,0,0,.35) !important; }
[data-testid="stToast"] p, [data-testid="stToast"] span { color: var(--ink) !important; }
[data-testid="stSegmentedControl"] button, [data-testid="stButtonGroup"] button { border-radius: 999px !important; }
[data-testid="stButtonGroup"] button[aria-checked="true"], [data-testid="stButtonGroup"] button[kind*="Active"] {
  background: rgba(169,195,209,.22) !important; border-color: rgba(169,195,209,.5) !important; color: var(--ivory) !important; }
div[class*="st-key-qa"] .stButton > button { height: 74px; width: 100%; border-radius: 16px; justify-content: flex-start; padding: 12px 16px; text-align: left;
  background: rgba(243,235,221,.05); }
div[class*="st-key-qa"] .stButton > button p { font-size: .95rem; color: var(--ivory); }
div[class*="st-key-qa"] .stButton > button:hover { transform: translateY(-2px); }
div[class*="st-key-hunt"] .stButton > button { min-height: 112px; width: 100%; border-radius: 16px; text-align: left; justify-content: flex-start;
  align-items: flex-start; padding: 14px 16px; background: rgba(243,235,221,.05); white-space: normal; }
div[class*="st-key-hunt"] .stButton > button p { color: var(--ivory); font-size: .9rem; }
div[class*="st-key-hunt"] .stButton > button:hover { transform: translateY(-2px); border-color: rgba(227,165,135,.55); }
div[class*="st-key-huntsel"] .stButton > button { background: linear-gradient(160deg, #f5eee2, #e7d9c1); border: 0; }
div[class*="st-key-huntsel"] .stButton > button p { color: var(--ink) !important; }
div[class*="st-key-case"] .stButton > button { width: 100%; text-align: left; justify-content: flex-start; border-radius: 14px; padding: 10px 12px;
  background: rgba(243,235,221,.04); white-space: normal; min-height: 64px; }
div[class*="st-key-case"] .stButton > button p { font-size: .84rem; color: var(--text-on-dark); }
div[class*="st-key-casesel"] .stButton > button { background: rgba(169,195,209,.18); border-color: rgba(169,195,209,.5); }
iframe { border-radius: 20px; }
hr { border-color: var(--line) !important; }
[data-testid="stButtonGroup"] > div, [data-testid="stButtonGroup"] [role="radiogroup"], [data-testid="stButtonGroup"] [role="group"] { flex-wrap: wrap; row-gap: 6px; }
@media (max-width: 1500px) {
  [data-testid="stSidebar"] { min-width: 200px !important; max-width: 200px !important; }
  .block-container { padding-left: 1.4rem !important; padding-right: 1.4rem !important; }
  [data-testid="stButtonGroup"] button { padding: 4px 10px !important; }
  [data-testid="stButtonGroup"] button p { font-size: .82rem !important; }
  .sn-title { font-size: 1.3rem; } .sn-brand { font-size: 1.2rem; letter-spacing: 4px; }
  [data-testid="stSidebar"] [role="radiogroup"] label { padding: 8px 8px; }
  [data-testid="stSidebar"] [role="radiogroup"] label p { font-size: .84rem; white-space: nowrap; }
  .sn-scn .d { font-size: .78rem; } .sn-hero { padding: 18px 20px 14px; }
}
</style>
"""
