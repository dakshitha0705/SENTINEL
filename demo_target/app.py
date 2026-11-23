"""NEXUS - Corporate Access Portal: an isolated, fictional demo target for SENTINEL's live demonstration.

    python -m demo_target.app            # http://127.0.0.1:8502  (bound to loopback only)

Every security-relevant action handled by this application is written to the demo event stream
(demo_target/events.py), which SENTINEL ingests live. The scenario controller (/demo) drives bounded,
simulated scenarios against this portal only.
"""
from __future__ import annotations

import ipaddress
import json
import os
import secrets
import time
from functools import wraps
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for

from .auth import IdentityStore
from .events import DEMO_ROOT, PORTAL_HOST, EventStream
from .simulator import SCENARIOS, ScenarioRunner, backfill_history

RESOURCES = {
    "handbook": ("Employee handbook", {"employee", "admin", "analyst"}, None),
    "finance-ledger": ("Finance ledger Q3", {"employee", "admin"}, "Finance"),
    "payroll-export": ("Payroll export (all staff)", {"employee", "admin"}, None),
    "incident-runbook": ("Security incident runbook", {"analyst", "admin"}, None),
    "it-inventory": ("IT asset inventory", {"admin"}, None),
}


def create_app(root: Path | None = None, base_url: str = "http://127.0.0.1:8502") -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = secrets.token_hex(32)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", MAX_CONTENT_LENGTH=64 * 1024)
    root = Path(root or DEMO_ROOT)
    stream = EventStream(root)
    ids = IdentityStore(root / "nexus_credentials.json")
    sim_token = secrets.token_hex(16)                       # only the in-process controller knows it
    runner = ScenarioRunner(stream, ids, base_url, sim_token)
    app.extensions["nexus"] = {"stream": stream, "ids": ids, "runner": runner, "token": sim_token}

    # ------------------------------------------------------------------ helpers
    def client_ip() -> tuple[str, bool]:
        if request.headers.get("X-NEXUS-Sim-Token") == sim_token:
            ip = request.headers.get("X-NEXUS-Sim-Source", "")
            try:
                ipaddress.ip_address(ip)
                return ip, True
            except ValueError:
                pass
        return request.remote_addr or "127.0.0.1", False

    def scenario():
        return request.headers.get("X-NEXUS-Scenario") if request.headers.get("X-NEXUS-Sim-Token") == sim_token else None

    def emit(code, etype, **kw):
        ip, simulated = client_ip()
        kw.setdefault("ip", ip)
        return stream.emit(code, etype, ip_simulated=simulated, scenario_id=scenario(), **kw)

    def login_required(fn):
        @wraps(fn)
        def wrap(*a, **k):
            if "user" not in session:
                return redirect(url_for("login", next=request.path))
            return fn(*a, **k)
        return wrap

    def me():
        return ids.users.get(session.get("user"))

    # ------------------------------------------------------------------ portal
    @app.get("/")
    def index():
        return redirect(url_for("dashboard") if "user" in session else url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            user = (request.form.get("username") or "").strip().lower()[:64]
            pw = (request.form.get("password") or "")[:128]
            ok, reason = ids.authenticate(user, pw)
            if ok:
                session.clear()
                session["user"] = user
                session["login_at"] = time.time()
                session["ip"] = client_ip()[0]
                emit("4624", "auth.login_success", user=user, logon_type="3", outcome="success",
                     payload={"path": "/login", "user_agent": request.headers.get("User-Agent", "")[:120]})
                nxt = request.args.get("next") or ""
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
            status = {"locked": "0xC0000234", "locked_now": "0xC0000234", "unknown_user": "0xC0000064"}.get(reason, "0xC000006A")
            emit("4625", "auth.login_failure", user=user, logon_type="3", outcome="failure", status=status,
                 payload={"path": "/login", "reason": reason})
            if reason == "locked_now":
                emit("4740", "auth.account_locked", user=user, outcome="success",
                     payload={"threshold": 15, "window_minutes": 15})
            error = "This account is temporarily locked." if reason.startswith("locked") else "Invalid username or password."
            return render_template("login.html", error=error), 401
        return render_template("login.html", error=error)

    @app.get("/logout")
    def logout():
        if "user" in session:
            emit("4634", "auth.logout", user=session["user"], outcome="success", payload={"path": "/logout"})
        session.clear()
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        u = me()
        res = [(k, v[0], u["role"] in v[1] and (v[2] is None or v[2] == u["dept"] or u["role"] == "admin"))
               for k, v in RESOURCES.items()]
        return render_template("dashboard.html", u=u, resources=res, groups=ids.groups_of(u["username"]),
                               session_ip=session.get("ip"), login_at=session.get("login_at"))

    @app.get("/account")
    @login_required
    def account():
        u = me()
        return render_template("account.html", u=u, groups=ids.groups_of(u["username"]), session_ip=session.get("ip"),
                               login_at=session.get("login_at"))

    @app.get("/resources/<name>")
    @login_required
    def resource(name):
        if name not in RESOURCES:
            abort(404)
        u = me()
        title, roles, dept = RESOURCES[name]
        allowed = u["role"] in roles and (dept is None or dept == u["dept"] or u["role"] == "admin")
        emit("4663" if allowed else "4656", "resource.access" if allowed else "resource.access_denied",
             user=u["username"], outcome="success" if allowed else "failure", payload={"resource": name})
        if not allowed:
            return render_template("message.html", title="Access denied",
                                   text=f"You do not have access to {title}. This attempt was logged."), 403
        return render_template("message.html", title=title,
                               text="Fictional demo content. No real company data exists in NEXUS.")

    @app.get("/activity")
    @login_required
    def activity():
        u = me()["username"]
        rows = [e for e in stream.read_all() if u in (e.get("TargetUserName"), e.get("SubjectUserName"), e.get("MemberName"))
                and e["origin"] != "baseline-backfill"][-60:][::-1]
        return render_template("activity.html", rows=rows, u=me())

    @app.get("/admin")
    @login_required
    def admin():
        u = me()
        if not (u["role"] == "admin" or ids.can_manage_groups(u["username"])):
            emit("4656", "resource.access_denied", user=u["username"], outcome="failure", payload={"resource": "admin"})
            return render_template("message.html", title="Access denied", text="Administrators only."), 403
        return render_template("admin.html", u=u, users=ids.users, groups=ids.groups)

    @app.post("/admin/groups/add")
    @login_required
    def add_member():
        u = me()
        group = (request.form.get("group") or "")[:64]
        member = (request.form.get("member") or "").strip().lower()[:64]
        ok, why = ids.add_member(u["username"], group, member)
        if ok:
            emit("4732", "group.member_added", actor=u["username"], member=member, group=group, outcome="success",
                 payload={"group": group, "member": member, "via": "portal admin page"})
        else:
            emit("4656", "group.change_denied", user=u["username"], outcome="failure",
                 payload={"group": group, "member": member, "reason": why})
        return redirect(url_for("admin"))

    # ------------------------------------------------------------------ demo controller
    @app.get("/demo")
    def demo():
        return render_template("demo.html", scenarios=SCENARIOS, creds=ids.passwords, users=ids.users)

    @app.post("/api/demo/start")
    def api_start():
        runner.stop()
        runner.wait(10)
        stream.new_session()
        ids.reset_state()
        n = backfill_history(stream, ids)
        return jsonify(ok=True, session=stream.session_id, backfilled=n)

    @app.post("/api/demo/reset")
    def api_reset():
        return api_start()

    @app.post("/api/demo/run/<sid>")
    def api_run(sid):
        if stream.seq == 0:
            backfill_history(stream, ids)
        ok, msg = runner.start(sid.upper())
        return jsonify(ok=ok, message=msg), (200 if ok else 409)

    @app.post("/api/demo/<action>")
    def api_control(action):
        if action not in ("pause", "resume", "stop"):
            abort(404)
        getattr(runner, action)()
        return jsonify(ok=True, state=runner.status["state"])

    @app.get("/api/demo/status")
    def api_status():
        st = dict(runner.status)
        st["elapsed_s"] = round(((st["finished_at"] or time.time()) - st["started_at"]), 1) if st["started_at"] else 0
        sp = stream.dir / "sentinel_status.json"
        sentinel = None
        if sp.exists():
            try:
                sentinel = json.loads(sp.read_text(encoding="utf-8"))
            except ValueError:
                sentinel = None
        return jsonify(session=stream.session_id, events_emitted=stream.seq, runner=st, sentinel=sentinel)

    @app.get("/api/health")
    def health():
        return jsonify(ok=True, service="NEXUS", host=PORTAL_HOST, session=stream.session_id)

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
        return resp

    return app


def main():
    port = int(os.environ.get("NEXUS_PORT", "8502"))
    app = create_app(base_url=f"http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
