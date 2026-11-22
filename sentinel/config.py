"""Configuration loading and validation."""
from __future__ import annotations

import copy
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ROOT / "config.yaml"


class ConfigError(ValueError):
    pass


def load_config(path: str | Path | None = None) -> dict:
    p = Path(path) if path else DEFAULT_CONFIG
    with open(p, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    validate_config(cfg)
    return cfg


def _positive(cfg: dict, dotted: str):
    node = cfg
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            raise ConfigError(f"missing config value: {dotted}")
        node = node[part]
    if not isinstance(node, (int, float)) or node <= 0:
        raise ConfigError(f"{dotted} must be a positive number, got {node!r}")


def validate_config(cfg: dict) -> None:
    for key in [
        "detection.brute_force.min_failures",
        "detection.brute_force.window_minutes",
        "detection.password_spray.min_distinct_users",
        "detection.password_spray.window_minutes",
        "detection.password_spray.max_attempts_per_user",
        "detection.failure_then_success.max_minutes_after_burst",
        "detection.baseline.min_logins",
        "detection.baseline.min_days",
        "correlation.max_gap_minutes",
        "correlation.max_span_hours",
        "slm.timeout_seconds",
    ]:
        _positive(cfg, key)
    for rule in cfg["detection"]["suspicious_processes"]:
        if rule.get("field") != "parent_child":
            try:
                re.compile(rule["pattern"])
            except (KeyError, re.error) as exc:
                raise ConfigError(f"bad regex in suspicious_processes/{rule.get('id')}: {exc}")
    for w in cfg["allowlists"]["change_windows"]:
        if not (0 <= int(w["weekday"]) <= 6):
            raise ConfigError(f"change window weekday out of range: {w}")
        for k in ("start", "end"):
            if not re.fullmatch(r"\d{2}:\d{2}", str(w[k])):
                raise ConfigError(f"change window {k} must be HH:MM: {w}")
    lv = cfg["severity"]["levels"]
    if not (100 >= lv["critical"] > lv["high"] > lv["medium"] > 0):
        raise ConfigError("severity levels must satisfy 100 >= critical > high > medium > 0")


def override(cfg: dict, **changes) -> dict:
    """Return a copy of cfg with dotted-path overrides, e.g. override(cfg, **{'slm.enabled': False})."""
    new = copy.deepcopy(cfg)
    for dotted, value in changes.items():
        node = new
        parts = dotted.split(".")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = value
    validate_config(new)
    return new
