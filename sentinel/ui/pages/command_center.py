"""Command Center: the headline incident as a story, the interactive 3D globe, four real counters, recent
activity, a small detection overview and four quick actions. Live mode refreshes every 2 s."""
from __future__ import annotations

import json
from collections import Counter

import pandas as pd
import streamlit as st

from ... import geospatial
from ...hunting import CATEGORIES
from ...live import RULE_PHRASE, plain_summary
from .. import SEV_COLOR, esc
from .. import components, state
from ..state import S

ACTION_TEXT = {"login_failure": "Failed sign-in", "login_success": "Signed in", "logout": "Signed out",
               "group_add": "Added to a group", "group_enum": "Listed group members", "process_start": "Process started",
               "log_cleared": "Audit log cleared", "privilege_logon": "Privileged sign-in", "file_copy": "Files copied",
               "usb_insert": "USB device connected"}
NEXUS_TEXT = {"auth.login_failure": "Failed sign-in to NEXUS", "auth.login_success": "Signed in to NEXUS",
              "auth.logout": "Signed out of NEXUS", "auth.account_locked": "Account locked", "resource.access": "Opened a resource", "group.change_denied": "Group change refused",
              "resource.access_denied": "Access denied to a resource", "group.member_added": "Added to a privileged group",
              "process.start": "Process started (synthetic)", "audit.log_cleared": "Audit log cleared (synthetic)"}


def headline(inc) -> tuple[str, str]:
    """Human-readable headline and description for an incident."""
    rules = [r for r in inc["rules"] if r != "CTX"]
    phrases = [RULE_PHRASE[r] for r in rules if r in RULE_PHRASE]
    who = (list(inc["users"])[:1] or list(inc["hosts"])[:1] or ["the environment"])[0]
    if len(phrases) >= 3:
        h = f"{phrases[0][0].upper() + phrases[0][1:]}, escalating to {phrases[-1]}"
    elif phrases:
        h = phrases[0][0].upper() + phrases[0][1:] + (f" and {phrases[1]}" if len(phrases) > 1 else "")
    else:
        h = inc["title"]
    return f"{h} — {who}", plain_summary(inc)


def render():
    if state.is_live():
        _live()
    else:
        _body(None)


@st.fragment(run_every=2)
def _live():
    snap = state.refresh_live()
    state.notify_tick(snap)
    _body(snap)


def _body(snap):
    a = S.analysis
    if snap is not None:
        _live_strip(snap)
    if a is None:
        left, right = st.columns([1.05, 1.25], gap="large")
        with left:
            st.markdown('<div class="sn-hero calm"><div class="eyebrow">Monitoring</div>'
                        '<div class="h">Waiting for the first events</div>'
                        '<div class="p">No events have arrived yet. Open <b>Live Demo</b> to start a NEXUS demo session, or '
                        'choose saved data in the selector above.</div></div>', unsafe_allow_html=True)
            _quick_actions(None)
        with right:
            components.globe({"mode": "explore", "markers": [], "arcs": [], "provenance": ""}, height=520, key="cc_globe")
        return
    incs = state.visible_incidents(a)
    win = state.time_window(a)
    ev = a.events if not win else a.events[(a.events["timestamp"] >= win[0]) & (a.events["timestamp"] <= win[1])]
    users = {u for i in incs for u in i["users"]}
    hosts = {h for i in incs for h in i["hosts"]}

    left, right = st.columns([1.05, 1.25], gap="large")
    with left:
        _hero(a, incs, snap)
        st.markdown('<div class="sn-stats">'
                    + "".join(f'<div class="sn-stat"><div class="v">{v}</div><div class="l">{esc(l)}</div></div>'
                              for v, l in ((f"{len(ev):,}", "Total events"), (len(incs), "Incidents"),
                                           (len(users), "Affected users"), (len(hosts), "Affected devices")))
                    + "</div>", unsafe_allow_html=True)
        _quick_actions(incs[0]["incident_id"] if incs else None)
    with right:
        geo = geospatial.markers(a, incidents=incs, time_range=win)
        click = components.globe(geospatial.for_component(geo), height=520, selected=S.get("geo_sel"), key="cc_globe",
                                 quality=S.get("cc_quality", "high"))
        _globe_click(click)
        _selection_panel(a, geo)

    c1, c2 = st.columns([1.6, 1], gap="large")
    with c1:
        _activity(a, snap)
    with c2:
        _detections(a, incs)


def _live_strip(snap):
    ls = state.live_status()
    a = snap["analysis"]
    n_inc = len(a.incidents) if a else 0
    lat = [t.get("latency_s") for t in snap["tracked"].values() if t.get("latency_s") is not None]
    status = "Detection running" if (ls["worker"] or ls["running"]) else "Detection stopped — run scripts\\start_demo.ps1"
    st.markdown(f'<div class="sn-mode{" incident" if n_inc else ""}"><span class="sn-chip live"><i></i>LIVE · NEXUS</span>'
                f'<b>{snap["events"]:,} events</b> received &middot; <b>{n_inc}</b> incident{"s" if n_inc != 1 else ""}'
                + (f' &middot; fastest detection <b>{min(lat):.1f} s</b> after the triggering event' if lat else "")
                + f'<span style="margin-left:auto">{esc(status)}</span></div>', unsafe_allow_html=True)
    if snap.get("error"):
        st.error(f"Live engine error: {snap['error']}")


def _hero(a, incs, snap):
    if not incs:
        st.markdown('<div class="sn-hero calm"><div class="eyebrow">All quiet</div><div class="h">No suspicious activity detected</div>'
                    f'<div class="p">{len(a.events):,} events checked against 14 detection rules. SENTINEL will raise an '
                    'incident here as soon as related suspicious events are found.</div></div>', unsafe_allow_html=True)
        return
    inc = incs[0]
    sev = inc["severity"]
    h, p = headline(inc)
    eyebrow = "Top incident"
    if snap is not None:
        t = state.live_engine()._track_of(inc)
        if t.get("history") and len(t["history"]) > 1 and t["history"][-1]["level"] != t["history"][0]["level"]:
            eyebrow = f"Escalated from {t['history'][0]['level']} as new evidence arrived"
        elif t.get("latency_s") is not None:
            eyebrow = f"Detected {t['latency_s']:.1f} s after its triggering event"
    meta = [f"{len(inc['event_ids'])} events", f"{pd.Timestamp(inc['start']):%d %b %H:%M} – {pd.Timestamp(inc['end']):%H:%M} UTC"]
    if inc["hosts"]:
        meta.append("Devices: " + ", ".join(list(inc["hosts"])[:2]))
    if len(incs) > 1:
        meta.append(f"+{len(incs) - 1} more incident{'s' if len(incs) > 2 else ''}")
    st.markdown(f'<div class="sn-hero"><div class="eyebrow">{esc(eyebrow)}</div>'
                f'<div class="h">{esc(h)}</div><div class="p">{esc(p)}</div>'
                f'<div class="meta"><span class="sn-sev" style="--c:{SEV_COLOR[sev["level"]]}">{esc(sev["level"])} · {sev["score"]}/100</span>'
                + "".join(f"<span>{esc(m)}</span>" for m in meta) + "</div></div>", unsafe_allow_html=True)
    if st.button("Investigate", type="primary", icon=":material/arrow_forward:", key="cc_investigate"):
        state.goto("Investigation Studio", inc["incident_id"], view="Story")
        st.rerun(scope="app")


def _quick_actions(top_iid):
    c = st.columns(2, gap="small")
    acts = [("qa1", "Start Live Demo", ":material/sensors:", lambda: state.goto("Live Demo"), False),
            ("qa2", "Explore Incidents", ":material/policy:", lambda: state.goto("Investigation Studio", top_iid, view="Story"), not top_iid),
            ("qa3", "Generate Report", ":material/description:", lambda: state.goto("Reports & Evaluation", top_iid, view="Report"), not top_iid),
            ("qa4", "Ask SENTINEL", ":material/forum:", lambda: state.goto("Investigation Studio", top_iid, view="AI investigation"), not top_iid)]
    for k, (key, label, icon, fn, dis) in enumerate(acts):
        with c[k % 2]:
            with st.container(key=key):
                if st.button(label, icon=icon, use_container_width=True, disabled=dis, key=f"{key}_b"):
                    fn()
                    st.rerun(scope="app")


def _globe_click(ev_click):
    if ev_click and ev_click.get("t") != S.get("_geo_t"):
        S._geo_t = ev_click.get("t")
        if ev_click["type"] == "marker":
            S.geo_sel, S.geo_region = ev_click["id"], None
        elif ev_click["type"] == "region":
            S.geo_sel, S.geo_region = None, ev_click
        elif ev_click["type"] == "arc":
            state.goto("Investigation Studio", ev_click["incident"], view="Story")
            st.rerun(scope="app")
        elif ev_click["type"] == "clear":
            S.geo_sel, S.geo_region = None, None


def _activity(a, snap):
    rows, recs = [], []
    if snap is not None:
        for e in state.live_engine().recent_events(40):
            if e.get("origin") == "baseline-backfill":
                continue
            fail = e.get("outcome") == "failure"
            sim = e.get("origin") == "simulated-endpoint"
            what = NEXUS_TEXT.get(e.get("event_type"), e.get("event_type", "Event"))
            who = e.get("TargetUserName") or e.get("SubjectUserName") or ""
            if e.get("EventID") == "4732":
                who = f'{e.get("SubjectUserName")} added {e.get("MemberName")} to {e.get("TargetUserName")}'
            where = " · ".join(x for x in (e.get("Computer"), e.get("IpAddress")) if x)
            rows.append(("sim" if sim else "bad" if fail else "ok", "S" if sim else "!" if fail else "✓", what, f"{who} · {where}",
                         e["TimeCreated"][11:19]))
            recs.append((f'{e["TimeCreated"][11:19]} · {what} · {who}', e))
            if len(rows) >= 7:
                break
    else:
        in_inc = {e for i in a.incidents for e in i["event_ids"]}
        ev = a.events[a.events["event_id"].isin(in_inc)].sort_values("timestamp").tail(7).iloc[::-1]
        for _, r in ev.iterrows():
            fail = r["action"] == "login_failure"
            what = ACTION_TEXT.get(r["action"], r["action"] or f"Event {r['event_code']}")
            if r["action"] == "process_start" and r["process"]:
                what = f"Process started: {str(r['process']).split(chr(92))[-1]}"
            who = r["user"] or r["actor"]
            where = " · ".join(x for x in (r["host"], r["src_ip"]) if x)
            rows.append(("bad" if fail or r["action"] in ("log_cleared", "group_add") else "warn", "!" if fail else "•", what,
                         f"{who} · {where}", pd.Timestamp(r["timestamp"]).strftime("%d %b %H:%M")))
            recs.append((f'{pd.Timestamp(r["timestamp"]):%H:%M:%S} · {what} · {who}', json.loads(r["raw"])))
    title = "Live activity from NEXUS" if snap is not None else "Recent activity in incidents"
    body = "".join(f'<div class="sn-act"><div class="ic {c}">{esc(i)}</div><div class="d">{esc(w)}<small>{esc(m)}</small></div>'
                   f'<div class="t">{esc(t)}</div></div>' for c, i, w, m, t in rows) \
        or '<div class="sn-muted">No activity yet. Start a scenario in Live Demo.</div>'
    note = ('<div class="sn-muted" style="margin-top:6px">✓/! = real NEXUS sign-ins (success/failure) · S = synthetic endpoint '
            'event, clearly labelled</div>') if snap is not None else ""
    st.markdown(f'<div class="sn-card"><h4>{esc(title)}</h4>{body}{note}</div>', unsafe_allow_html=True)
    if recs:
        with st.expander("Inspect an original record"):
            pick = st.selectbox("Record", range(len(recs)), format_func=lambda k: recs[k][0], key="cc_rec",
                                label_visibility="collapsed")
            st.json(recs[pick][1], expanded=False)


def _detections(a, incs):
    rules = Counter(r for i in incs for r in i["rules"] if r != "CTX")
    cats = []
    for name, c in CATEGORIES.items():
        n = sum(rules.get(r, 0) for r in c["rules"])
        if n:
            cats.append((name, n))
    cats.sort(key=lambda x: -x[1])
    mx = max([n for _, n in cats] or [1])
    body = "".join(f'<div class="sn-row"><span>{esc(n)}</span><span class="n">{k}</span></div>'
                   f'<div class="sn-bar"><i style="width:{100 * k / mx:.0f}%;background:var(--peach)"></i></div>' for n, k in cats[:4]) \
        or '<div class="sn-muted">No detections in this data.</div>'
    st.markdown(f'<div class="sn-card"><h4>What was detected</h4>{body}'
                '<div class="sn-muted" style="margin-top:6px">Incidents per kind of behaviour. Details in Threat Hunting.</div></div>',
                unsafe_allow_html=True)


def _selection_panel(a, geo):
    sel_ids, title = [], ""
    if S.get("geo_sel"):
        sel_ids = [S.geo_sel]
        m = next((x for x in geo["markers"] if x["id"] == S.geo_sel), None)
        title = m["label"] if m else ""
    elif S.get("geo_region"):
        sel_ids = S.geo_region.get("marker_ids", [])
        title = S.geo_region.get("name", "")
    if not (S.get("geo_sel") or S.get("geo_region")):
        return
    with st.container(key="card_geo"):
        recs = geospatial.marker_records(a, geo, sel_ids)
        markers = [x for x in geo["markers"] if x["id"] in sel_ids]
        incs_here = sorted({i for m in markers for i in m["incidents"]})
        st.markdown(f"**{esc(title)}** · {len(recs):,} located event(s)", unsafe_allow_html=True)
        if recs.empty:
            st.caption("No events with coordinates here.")
        else:
            show = recs.copy()
            show["timestamp"] = show["timestamp"].astype(str)
            st.dataframe(show, hide_index=True, use_container_width=True, height=180)
        bcols = st.columns(min(4, max(1, len(incs_here))))
        for k, iid in enumerate(incs_here[:4]):
            if bcols[k].button(f"Investigate {iid}", key=f"geo_inv_{iid}"):
                state.goto("Investigation Studio", iid, view="Story")
                st.rerun(scope="app")
