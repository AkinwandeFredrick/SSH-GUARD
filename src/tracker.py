"""
ssh-guard/src/tracker.py
Sliding-window per-IP failure counter with username tracking.
Thread-safe via a simple lock; no external dependencies.
"""

import threading
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Deque, Tuple

from .config import Config

logger = logging.getLogger("sshguard.tracker")


class IPRecord:
    __slots__ = ("timestamps", "usernames")

    def __init__(self):
        self.timestamps: Deque[datetime] = deque()
        self.usernames: Dict[str, int] = defaultdict(int)


class IPTracker:
    def __init__(self, config: Config):
        self._config = config
        self._records: Dict[str, IPRecord] = defaultdict(IPRecord)
        self._lock = threading.Lock()

    def record_failure(self, ip: str, username: str) -> Tuple[int, datetime]:
        window_seconds = self._config.get("window_seconds", 600)
        now = datetime.now()
        cutoff = now - timedelta(seconds=window_seconds)

        with self._lock:
            rec = self._records[ip]
            rec.timestamps.append(now)
            rec.usernames[username] += 1
            while rec.timestamps and rec.timestamps[0] < cutoff:
                rec.timestamps.popleft()
            count = len(rec.timestamps)
            window_start = rec.timestamps[0] if rec.timestamps else now

        return count, window_start

    def get_count(self, ip: str) -> int:
        window_seconds = self._config.get("window_seconds", 600)
        cutoff = datetime.now() - timedelta(seconds=window_seconds)
        with self._lock:
            rec = self._records.get(ip)
            if not rec:
                return 0
            return sum(1 for ts in rec.timestamps if ts >= cutoff)

    def top_usernames(self, ip: str, n: int = 5) -> list:
        with self._lock:
            rec = self._records.get(ip)
            if not rec:
                return []
            return sorted(rec.usernames.items(), key=lambda x: -x[1])[:n]

    def reset(self, ip: str):
        with self._lock:
            self._records.pop(ip, None)
        logger.debug("Reset failure counter for %s", ip)

    def expire_old_entries(self):
        window_seconds = self._config.get("window_seconds", 600)
        cutoff = datetime.now() - timedelta(seconds=window_seconds * 2)
        with self._lock:
            stale = [
                ip for ip, rec in self._records.items()
                if not rec.timestamps or rec.timestamps[-1] < cutoff
            ]
            for ip in stale:
                del self._records[ip]

    def snapshot(self) -> dict:
        window_seconds = self._config.get("window_seconds", 600)
        cutoff = datetime.now() - timedelta(seconds=window_seconds)
        with self._lock:
            return {
                ip: {
                    "failures": sum(1 for ts in rec.timestamps if ts >= cutoff),
                    "top_users": sorted(rec.usernames.items(), key=lambda x: -x[1])[:3],
                }
                for ip, rec in self._records.items()
            }
