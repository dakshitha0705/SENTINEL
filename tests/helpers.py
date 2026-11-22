"""Small builders for synthetic test events."""
from datetime import datetime, timedelta

from sentinel.config import load_config
from sentinel.ingest import ingest

CFG = load_config()
T0 = datetime(2026, 11, 2, 0, 0, 0)  # Monday

HEADER = "TimeCreated,EventID,EventRecordID,Computer,TargetUserName,SubjectUserName,MemberName,IpAddress\n"


class LogBuilder:
    def __init__(self):
        self.rows = []
        self.proc = []
        self.rid = 1000

    def _r(self):
        self.rid += 1
        return self.rid

    def at(self, day, h, m=0, s=0):
        return T0 + timedelta(days=day, hours=h, minutes=m, seconds=s)

    def logon(self, t, user, host, ip, code="4624"):
        self.rows.append(f"{t:%Y-%m-%d %H:%M:%S},{code},{self._r()},{host},{user},-,,{ip}")
        return self

    def fail(self, t, user, host, ip):
        return self.logon(t, user, host, ip, "4625")

    def priv(self, t, user, host):
        self.rows.append(f"{t:%Y-%m-%d %H:%M:%S},4672,{self._r()},{host},{user},{user},,-")
        return self

    def group_add(self, t, actor, member, group, host, code="4732"):
        self.rows.append(f"{t:%Y-%m-%d %H:%M:%S},{code},{self._r()},{host},{group},{actor},\"CN={member},OU=Users,DC=corp\",-")
        return self

    def process(self, t, user, host, proc, parent, cmd):
        self.proc.append({"@timestamp": f"{t:%Y-%m-%dT%H:%M:%SZ}", "event": {"code": "4688", "record_id": self._r()},
                          "host": {"name": host}, "user": {"name": user},
                          "process": {"name": proc, "command_line": cmd, "parent": {"name": parent}}})
        return self

    def log_clear(self, t, user, host):
        self.proc.append({"@timestamp": f"{t:%Y-%m-%dT%H:%M:%SZ}", "event": {"code": "1102", "record_id": self._r()},
                          "host": {"name": host}, "user": {"name": user}})
        return self

    def history(self, user, host, ip, days=5, hours=(9, 11, 14)):
        for d in range(days):
            for h in hours:
                self.logon(self.at(d, h), user, host, ip)
        return self

    def files(self):
        import json
        out = [("auth.csv", (HEADER + "\n".join(self.rows) + "\n").encode())]
        if self.proc:
            out.append(("endpoint.jsonl", "\n".join(json.dumps(p) for p in self.proc).encode()))
        return out

    def dataset(self):
        return ingest(self.files())

    def analyze(self, cfg=None):
        from sentinel.pipeline import analyze_dataset
        return analyze_dataset(self.dataset(), cfg or CFG)
