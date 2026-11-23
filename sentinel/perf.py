"""Performance and offline-operation monitoring (psutil + local nvidia-smi)."""
from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
import threading
import time

import psutil


def _is_loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr.split("%")[0]).is_loopback
    except ValueError:
        return False


def related_pids() -> dict:
    """This Python process + children, and any Ollama processes."""
    me = psutil.Process()
    pids = {me.pid: "sentinel (python)"}
    for c in me.children(recursive=True):
        pids[c.pid] = c.name()
    for p in psutil.process_iter(["pid", "name"]):
        n = (p.info["name"] or "").lower()
        if n.startswith("ollama") or n.startswith("llama-server"):   # llama-server = Ollama model runner
            pids[p.info["pid"]] = p.info["name"]
    return pids


def connection_snapshot(pids: dict | None = None) -> list[dict]:
    pids = pids or related_pids()
    out = []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        conns = []
        for pid in pids:
            try:
                conns += [c._replace(pid=pid) if hasattr(c, "_replace") else c
                          for c in psutil.Process(pid).net_connections(kind="inet")]
            except Exception:  # noqa: BLE001
                pass
    for c in conns:
        if c.pid not in pids or not c.raddr:
            continue
        out.append({"process": pids[c.pid], "pid": c.pid, "local": f"{c.laddr.ip}:{c.laddr.port}",
                    "remote": f"{c.raddr.ip}:{c.raddr.port}", "status": c.status,
                    "scope": "loopback" if _is_loopback(c.raddr.ip) else "EXTERNAL"})
    return out


class Monitor:
    """Background sampler: peak RSS of SENTINEL + Ollama, and every distinct remote connection seen."""

    def __init__(self, interval: float = 0.25):
        self.interval = interval
        self.peak_rss_mb = 0.0
        self.peak_ollama_rss_mb = 0.0
        self.connections: dict = {}
        self.samples = 0
        self._stop = threading.Event()
        self._t = None
        self.started = None
        self.ended = None

    def _run(self):
        me = psutil.Process()
        while not self._stop.is_set():
            pids = related_pids()
            try:
                self.peak_rss_mb = max(self.peak_rss_mb, me.memory_info().rss / 2**20)
                oll = 0.0
                for pid, name in pids.items():
                    if name.lower().startswith("ollama"):
                        try:
                            oll += psutil.Process(pid).memory_info().rss / 2**20
                        except psutil.Error:
                            pass
                self.peak_ollama_rss_mb = max(self.peak_ollama_rss_mb, oll)
            except psutil.Error:
                pass
            for c in connection_snapshot(pids):
                key = (c["process"], c["remote"])
                if key not in self.connections:
                    self.connections[key] = {**c, "first_seen": time.strftime("%H:%M:%S")}
            self.samples += 1
            self._stop.wait(self.interval)

    def __enter__(self):
        self.started = time.strftime("%Y-%m-%d %H:%M:%S")
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._t.join(timeout=2)
        self.ended = time.strftime("%Y-%m-%d %H:%M:%S")

    def result(self) -> dict:
        conns = list(self.connections.values())
        return {"started": self.started, "ended": self.ended, "samples": self.samples,
                "peak_sentinel_rss_mb": round(self.peak_rss_mb, 1),
                "peak_ollama_rss_mb": round(self.peak_ollama_rss_mb, 1),
                "connections": conns,
                "external_connections": [c for c in conns if c["scope"] == "EXTERNAL"],
                "loopback_connections": [c for c in conns if c["scope"] == "loopback"]}


def internet_reachable(timeout: float = 1.5) -> bool:
    """Probe used only for the status panel: can a TCP connection to a public resolver be opened?"""
    for host in ("1.1.1.1", "8.8.8.8"):
        try:
            with socket.create_connection((host, 53), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def system_info() -> dict:
    vm = psutil.virtual_memory()
    info = {"cpu": None, "logical_cpus": psutil.cpu_count(), "cpu_percent": psutil.cpu_percent(interval=0.2),
            "ram_total_gb": round(vm.total / 2**30, 1), "ram_used_percent": vm.percent,
            "process_rss_mb": round(psutil.Process().memory_info().rss / 2**20, 1), "gpu": None}
    try:
        import platform
        info["cpu"] = platform.processor()
    except Exception:  # noqa: BLE001
        pass
    smi = shutil.which("nvidia-smi")
    if smi:
        try:
            out = subprocess.run([smi, "--query-gpu=name,memory.used,memory.total,utilization.gpu",
                                  "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=5)
            name, used, total, util = [x.strip() for x in out.stdout.strip().splitlines()[0].split(",")]
            info["gpu"] = {"name": name, "memory_used_mb": int(used), "memory_total_mb": int(total),
                           "utilization_percent": int(util)}
        except Exception:  # noqa: BLE001
            info["gpu"] = None
    return info
