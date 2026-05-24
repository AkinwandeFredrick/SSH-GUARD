"""
ssh-guard/src/monitor.py
Tails auth.log (or /var/log/secure), parses SSH failures,
tracks per-IP counters, fires actions when thresholds are crossed.
"""

import re
import time
import signal
import logging
import os
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from .parser import parse_line, LogEvent, EventType
from .tracker import IPTracker
from .actions import ActionEngine
from .config import Config

logger = logging.getLogger("sshguard.monitor")


class LogMonitor:
    """
    Tail one or more log files, parse SSH events,
    and drive the action engine.
    """

    def __init__(self, config: Config):
        self.config = config
        self.tracker = IPTracker(config)
        self.actions = ActionEngine(config)
        self._running = False

        # Register clean shutdown on SIGTERM / SIGINT
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signum, frame):
        logger.info("Received signal %d — shutting down", signum)
        self._running = False

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self):
        """Start monitoring. Blocks until stopped."""
        log_path = self._find_log()
        if not log_path:
            raise FileNotFoundError(
                "Cannot find auth log. Set LOG_PATH in config or ensure "
                "/var/log/auth.log or /var/log/secure exists."
            )

        logger.info("Monitoring %s", log_path)
        self._running = True

        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            # Seek to end so we only process new lines
            fh.seek(0, 2)
            inode = os.fstat(fh.fileno()).st_ino

            while self._running:
                line = fh.readline()
                if line:
                    self._process_line(line.rstrip())
                else:
                    time.sleep(0.2)
                    # Detect log rotation (inode changed or file shrank)
                    try:
                        new_inode = os.stat(log_path).st_ino
                        new_size  = os.stat(log_path).st_size
                        cur_pos   = fh.tell()
                        if new_inode != inode or new_size < cur_pos:
                            logger.info("Log rotated — reopening %s", log_path)
                            fh.close()
                            fh = open(log_path, "r", encoding="utf-8", errors="replace")
                            inode = os.fstat(fh.fileno()).st_ino
                    except (OSError, IOError):
                        pass

                    # Periodic cleanup of stale counters
                    self.tracker.expire_old_entries()

        logger.info("Monitor stopped.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_log(self) -> str | None:
        """Return the auth log path: env override → Debian → RHEL."""
        override = self.config.get("log_path")
        if override and Path(override).exists():
            return override
        for candidate in ("/var/log/auth.log", "/var/log/secure"):
            if Path(candidate).exists():
                return candidate
        return None

    def _process_line(self, line: str):
        event = parse_line(line)
        if event is None:
            return

        if event.type == EventType.ACCEPTED:
            logger.debug("Accepted login for %s from %s", event.username, event.ip)
            return

        if event.type in (EventType.FAILED_PASSWORD, EventType.INVALID_USER,
                          EventType.CONNECTION_CLOSED):
            self._handle_failure(event)

    def _handle_failure(self, event: LogEvent):
        ip = event.ip
        if self.actions.is_whitelisted(ip):
            logger.debug("Skipping whitelisted IP %s", ip)
            return

        count, window_start = self.tracker.record_failure(ip, event.username)
        elapsed = (datetime.now() - window_start).seconds

        logger.debug(
            "Failure from %s | user=%s | count=%d in %ds",
            ip, event.username, count, elapsed
        )

        threshold_block = self.config.get("threshold_block", 15)
        threshold_alert = self.config.get("threshold_alert", 8)

        if self.actions.is_blocked(ip):
            return  # Already blocked — just count

        if count >= threshold_block:
            self.actions.block(ip, reason=f"{count} failures in {elapsed}s")
        elif count >= threshold_alert:
            self.actions.alert(ip, count, elapsed, event.username)
