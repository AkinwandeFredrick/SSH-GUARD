"""
ssh-guard/src/actions.py
Enforces firewall rules and sends alerts when thresholds are exceeded.
Supports iptables, ufw, and dry-run mode (--dry-run flag).
"""

import subprocess
import logging
import json
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Set

from .config import Config
from .notifier import Notifier

logger = logging.getLogger("sshguard.actions")


class ActionEngine:
    """
    Decides what to do when an IP exceeds thresholds:
      1. Check whitelist  → skip if trusted
      2. Block via iptables / ufw
      3. Record to block DB (JSON file)
      4. Send alert (email / Slack / syslog)
    """

    def __init__(self, config: Config):
        self._config    = config
        self._notifier  = Notifier(config)
        self._dry_run   = config.get("dry_run", False)
        self._blocked:  Set[str] = set()  # in-memory fast-path
        self._whitelist: list    = self._load_list("whitelist")
        self._db_path   = Path(config.get("db_path", "/var/lib/ssh-guard/blocks.json"))
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._load_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_whitelisted(self, ip: str) -> bool:
        """Return True if *ip* matches any whitelist entry (CIDR-aware)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for entry in self._whitelist:
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                if ip == entry:
                    return True
        return False

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def block(self, ip: str, reason: str = ""):
        """
        Add DROP rule for *ip* via iptables (or ufw if configured).
        Idempotent — calling twice is safe.
        """
        if ip in self._blocked:
            return
        if self.is_whitelisted(ip):
            logger.warning("Refusing to block whitelisted IP %s", ip)
            return

        logger.warning("BLOCKING %s — %s", ip, reason)
        self._blocked.add(ip)

        firewall = self._config.get("firewall", "iptables")
        if firewall == "ufw":
            self._run(["ufw", "deny", "from", ip, "to", "any"])
        else:
            # Insert at top of INPUT chain so it takes priority
            self._run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
            # Also block IPv6 if it looks like one
            if ":" in ip:
                self._run(["ip6tables", "-I", "INPUT", "-s", ip, "-j", "DROP"])

        self._save_block(ip, reason)
        self._notifier.send_block(ip, reason)

    def unblock(self, ip: str):
        """Remove firewall rule and DB entry for *ip*."""
        if ip not in self._blocked:
            logger.info("IP %s is not blocked", ip)
            return

        firewall = self._config.get("firewall", "iptables")
        if firewall == "ufw":
            self._run(["ufw", "delete", "deny", "from", ip, "to", "any"])
        else:
            self._run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            if ":" in ip:
                self._run(["ip6tables", "-D", "INPUT", "-s", ip, "-j", "DROP"])

        self._blocked.discard(ip)
        self._remove_block(ip)
        logger.info("Unblocked %s", ip)

    def alert(self, ip: str, count: int, elapsed: int, username: str):
        """Send a warning alert without blocking."""
        logger.warning(
            "ALERT: %s — %d failures in %ds (latest user: %s)",
            ip, count, elapsed, username
        )
        self._notifier.send_alert(ip, count, elapsed, username)

    def list_blocks(self) -> list:
        """Return list of currently blocked IPs with metadata."""
        try:
            data = json.loads(self._db_path.read_text())
            return data.get("blocks", [])
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run(self, cmd: list):
        if self._dry_run:
            logger.info("[DRY-RUN] Would run: %s", " ".join(cmd))
            return
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.error("Command failed: %s\nstderr: %s", " ".join(cmd), result.stderr)
            else:
                logger.info("Ran: %s", " ".join(cmd))
        except subprocess.TimeoutExpired:
            logger.error("Command timed out: %s", " ".join(cmd))
        except FileNotFoundError:
            logger.error("Command not found: %s (is %s installed?)", cmd[0], cmd[0])

    def _load_list(self, key: str) -> list:
        entries = self._config.get(key, [])
        if isinstance(entries, list):
            return entries
        # Could be a path to a file of IPs
        try:
            path = Path(str(entries))
            if path.exists():
                return [l.strip() for l in path.read_text().splitlines() if l.strip() and not l.startswith("#")]
        except Exception:
            pass
        return []

    def _load_db(self):
        """Load previously blocked IPs from the persistent JSON DB."""
        try:
            data = json.loads(self._db_path.read_text())
            for entry in data.get("blocks", []):
                self._blocked.add(entry["ip"])
            logger.info("Loaded %d blocked IPs from DB", len(self._blocked))
        except FileNotFoundError:
            pass
        except json.JSONDecodeError as e:
            logger.warning("Could not parse block DB: %s", e)

    def _save_block(self, ip: str, reason: str):
        data = self._read_db()
        # Remove existing entry for this IP if present
        data["blocks"] = [b for b in data["blocks"] if b["ip"] != ip]
        data["blocks"].append({
            "ip":      ip,
            "reason":  reason,
            "blocked": datetime.now().isoformat(),
        })
        self._write_db(data)

    def _remove_block(self, ip: str):
        data = self._read_db()
        data["blocks"] = [b for b in data["blocks"] if b["ip"] != ip]
        self._write_db(data)

    def _read_db(self) -> dict:
        try:
            return json.loads(self._db_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {"blocks": []}

    def _write_db(self, data: dict):
        self._db_path.write_text(json.dumps(data, indent=2))
