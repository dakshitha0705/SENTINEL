"""NEXUS fictional identity store: hashed passwords, groups, delegated group management, lockout.

All accounts are fictional. Passwords are generated randomly on first start and stored (with their
hashes) in demo_data/nexus_credentials.json so the presenter can log in; nothing here is a real credential.
"""
from __future__ import annotations

import json
import secrets
import string
import threading
import time
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

ACCOUNTS = [
    # username, display name, role, department, usual workstation address
    ("maya.fernandes", "Maya Fernandes", "employee", "Finance", "10.20.1.21"),
    ("arjun.rao", "Arjun Rao", "employee", "Finance", "10.20.1.22"),
    ("leela.menon", "Leela Menon", "employee", "HR", "10.20.2.31"),
    ("vikram.shah", "Vikram Shah", "employee", "Engineering", "10.20.3.41"),
    ("nisha.kapoor", "Nisha Kapoor", "employee", "Sales", "10.20.4.51"),
    ("rahul.iyer", "Rahul Iyer", "employee", "Sales", "10.20.4.52"),
    ("divya.pillai", "Divya Pillai", "employee", "Engineering", "10.20.3.42"),
    ("omar.khan", "Omar Khan", "employee", "Operations", "10.20.5.61"),
    ("admin01", "Anita Desai (IT administrator)", "admin", "IT", "10.20.9.10"),
    ("analyst.kiran", "Kiran Bose (security analyst)", "analyst", "Security", "10.20.9.20"),
    ("svc_reporting", "Reporting service account", "service", "IT", "10.30.0.12"),
]
GROUPS = {"Administrators": ["admin01"], "Finance Approvers": ["maya.fernandes", "arjun.rao"],
          "Report Viewers": ["analyst.kiran", "svc_reporting"]}
# Delegated group managers (a deliberate, realistic misconfiguration used by the storyline scenario:
# the Finance and Operations team leads may manage group membership, and the portal does not restrict
# WHICH groups they can change).
GROUP_MANAGERS = {"admin01", "maya.fernandes", "omar.khan"}
LOCKOUT_THRESHOLD = 15
LOCKOUT_WINDOW_S = 15 * 60


def _gen_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Nx-" + "".join(secrets.choice(alphabet) for _ in range(10)) + "!"


class IdentityStore:
    def __init__(self, cred_path: Path):
        self.lock = threading.Lock()
        self.cred_path = Path(cred_path)
        self.cred_path.parent.mkdir(parents=True, exist_ok=True)
        if self.cred_path.exists():
            creds = json.loads(self.cred_path.read_text(encoding="utf-8"))
        else:
            creds = {u: _gen_password() for u, *_ in ACCOUNTS}
            self.cred_path.write_text(json.dumps(creds, indent=1), encoding="utf-8")
        self.passwords = creds                     # demo only: shown on the controller page
        self.users = {u: {"username": u, "name": n, "role": r, "dept": d, "workstation": ip,
                          "hash": generate_password_hash(creds[u])} for u, n, r, d, ip in ACCOUNTS}
        self.reset_state()

    def reset_state(self):
        with self.lock:
            self.groups = {g: list(m) for g, m in GROUPS.items()}
            self.failures: dict[str, list[float]] = {}
            self.locked_until: dict[str, float] = {}

    # ----------------------------------------------------------------- authentication
    def is_locked(self, username: str) -> bool:
        return self.locked_until.get(username, 0) > time.time()

    def authenticate(self, username: str, password: str) -> tuple[bool, str]:
        """Returns (ok, reason). Never reveals whether the account exists beyond the generic failure."""
        username = (username or "").strip().lower()[:64]
        with self.lock:
            if self.is_locked(username):
                return False, "locked"
            u = self.users.get(username)
            ok = bool(u) and u["role"] != "service" and check_password_hash(u["hash"], password or "")
            if ok:
                self.failures.pop(username, None)
                return True, "ok"
            now = time.time()
            f = [t for t in self.failures.get(username, []) if now - t < LOCKOUT_WINDOW_S] + [now]
            self.failures[username] = f
            if len(f) >= LOCKOUT_THRESHOLD:
                self.locked_until[username] = now + LOCKOUT_WINDOW_S
                return False, "locked_now"
            return False, "bad_credentials" if u else "unknown_user"

    # ----------------------------------------------------------------- groups
    def can_manage_groups(self, username: str) -> bool:
        return username in GROUP_MANAGERS

    def add_member(self, actor: str, group: str, member: str) -> tuple[bool, str]:
        with self.lock:
            if not self.can_manage_groups(actor):
                return False, "not permitted"
            if group not in self.groups or member not in self.users:
                return False, "unknown group or user"
            if member in self.groups[group]:
                return False, "already a member"
            self.groups[group].append(member)
            return True, "added"

    def groups_of(self, username: str) -> list[str]:
        return [g for g, m in self.groups.items() if username in m]
