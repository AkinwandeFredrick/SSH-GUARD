"""
ssh-guard/src/config.py
Loads configuration from YAML file with environment variable overrides.
"""

import os
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("sshguard.config")

# Defaults — every key used elsewhere lives here
DEFAULTS = {
    "log_path":         None,               # auto-detect if None
    "firewall":         "iptables",         # "iptables" | "ufw" | "none"
    "threshold_block":  15,                 # failures before blocking
    "threshold_alert":  8,                  # failures before alerting
    "window_seconds":   600,               # sliding window (10 min)
    "dry_run":          False,              # if True, never run iptables
    "db_path":          "/var/lib/ssh-guard/blocks.json",
    "whitelist":        ["127.0.0.1", "::1"],
    "blacklist":        [],
    # Alerting
    "notify_email":     None,
    "notify_slack":     None,
    "notify_syslog":    True,
    "smtp_host":        "localhost",
    "smtp_port":        25,
    "smtp_from":        "sshguard@localhost",
    "smtp_to":          None,
    # Logging
    "log_level":        "INFO",
    "log_file":         None,               # None = stderr only
}

# Environment variable names map to config keys (SSHGUARD_<KEY>)
_ENV_PREFIX = "SSHGUARD_"


class Config:
    def __init__(self, path: str = None):
        self._data = dict(DEFAULTS)
        if path:
            self._load_yaml(path)
        self._apply_env()
        self._validate()

    def get(self, key: str, fallback: Any = None) -> Any:
        return self._data.get(key, fallback)

    def set(self, key: str, value: Any):
        self._data[key] = value

    # ------------------------------------------------------------------

    def _load_yaml(self, path: str):
        try:
            import yaml
        except ImportError:
            logger.warning("PyYAML not installed — using defaults + env vars only")
            return
        try:
            raw = Path(path).read_text()
            loaded = yaml.safe_load(raw) or {}
            self._data.update(loaded)
            logger.info("Loaded config from %s", path)
        except FileNotFoundError:
            logger.warning("Config file not found: %s — using defaults", path)
        except Exception as e:
            logger.error("Error reading config %s: %s", path, e)

    def _apply_env(self):
        """
        Override any key via environment variable.
        SSHGUARD_DRY_RUN=true  → dry_run = True
        SSHGUARD_THRESHOLD_BLOCK=20 → threshold_block = 20
        """
        for key in list(self._data.keys()):
            env_key = _ENV_PREFIX + key.upper()
            val = os.environ.get(env_key)
            if val is None:
                continue
            current = self._data[key]
            # Cast to same type as default
            if isinstance(current, bool):
                self._data[key] = val.lower() in ("1", "true", "yes")
            elif isinstance(current, int):
                try:
                    self._data[key] = int(val)
                except ValueError:
                    pass
            elif isinstance(current, list):
                self._data[key] = [v.strip() for v in val.split(",")]
            else:
                self._data[key] = val

    def _validate(self):
        if self._data["threshold_alert"] >= self._data["threshold_block"]:
            logger.warning(
                "threshold_alert (%d) should be < threshold_block (%d)",
                self._data["threshold_alert"], self._data["threshold_block"]
            )
        if self._data["firewall"] not in ("iptables", "ufw", "none"):
            raise ValueError(f"Invalid firewall value: {self._data['firewall']}")
