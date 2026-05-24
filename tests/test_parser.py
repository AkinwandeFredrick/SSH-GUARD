"""
tests/test_parser.py
Test SSH log line parsing against real OpenSSH output formats.
Run with: python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from src.parser import parse_line, EventType


# ── Real log line samples (collected from production servers) ──────────────

FAILED_PW_LINES = [
    "May 24 14:22:01 srv sshd[12345]: Failed password for root from 185.220.101.47 port 54321 ssh2",
    "May  7 08:01:23 host sshd[999]: Failed password for invalid user admin from 45.33.32.156 port 22222 ssh2",
    "Dec 31 23:59:59 box sshd[1]: Failed password for ubuntu from 10.0.0.1 port 1024 ssh2",
]

INVALID_USER_LINES = [
    "May 24 14:19:44 srv sshd[12346]: Invalid user testuser from 1.2.3.4 port 38400",
    "May 24 14:19:45 srv sshd[12347]: Invalid user pi from 2001:db8::1 port 44000",
]

ACCEPTED_LINES = [
    "May 24 14:30:00 srv sshd[12350]: Accepted publickey for deploy from 192.168.1.50 port 52000 ssh2",
    "May 24 14:31:00 srv sshd[12351]: Accepted password for admin from 10.0.0.5 port 55000 ssh2",
]

CONN_CLOSED_LINES = [
    "May 24 14:20:00 srv sshd[12349]: Connection closed by authenticating user root 185.220.101.47 port 54322 [preauth]",
]

IRRELEVANT_LINES = [
    "May 24 14:22:01 srv CRON[1234]: (root) CMD (/usr/bin/backup.sh)",
    "May 24 14:22:01 srv kernel: eth0: renamed from veth123",
    "",
    "garbage line with no structure",
]


class TestParser:
    # ── Failed password ────────────────────────────────────────────────

    def test_failed_password_root(self):
        e = parse_line(FAILED_PW_LINES[0])
        assert e is not None
        assert e.type == EventType.FAILED_PASSWORD
        assert e.ip == "185.220.101.47"
        assert e.username == "root"
        assert e.port == 54321

    def test_failed_password_invalid_user(self):
        """'Failed password for invalid user X' should still parse."""
        e = parse_line(FAILED_PW_LINES[1])
        assert e is not None
        assert e.type == EventType.FAILED_PASSWORD
        assert e.username == "admin"
        assert e.ip == "45.33.32.156"

    def test_failed_password_ubuntu(self):
        e = parse_line(FAILED_PW_LINES[2])
        assert e is not None
        assert e.ip == "10.0.0.1"
        assert e.username == "ubuntu"

    # ── Invalid user ───────────────────────────────────────────────────

    def test_invalid_user_ipv4(self):
        e = parse_line(INVALID_USER_LINES[0])
        assert e is not None
        assert e.type == EventType.INVALID_USER
        assert e.ip == "1.2.3.4"
        assert e.username == "testuser"

    def test_invalid_user_ipv6(self):
        e = parse_line(INVALID_USER_LINES[1])
        assert e is not None
        assert e.ip == "2001:db8::1"

    # ── Accepted ───────────────────────────────────────────────────────

    def test_accepted_publickey(self):
        e = parse_line(ACCEPTED_LINES[0])
        assert e is not None
        assert e.type == EventType.ACCEPTED
        assert e.username == "deploy"
        assert e.ip == "192.168.1.50"

    def test_accepted_password(self):
        e = parse_line(ACCEPTED_LINES[1])
        assert e is not None
        assert e.type == EventType.ACCEPTED

    # ── Connection closed ──────────────────────────────────────────────

    def test_conn_closed(self):
        e = parse_line(CONN_CLOSED_LINES[0])
        assert e is not None
        assert e.type == EventType.CONNECTION_CLOSED
        assert e.ip == "185.220.101.47"

    # ── Irrelevant lines ───────────────────────────────────────────────

    @pytest.mark.parametrize("line", IRRELEVANT_LINES)
    def test_irrelevant_returns_none(self, line):
        assert parse_line(line) is None

    # ── Timestamp parsing ──────────────────────────────────────────────

    def test_timestamp_month_day_single_digit(self):
        """Syslog pads single-digit days with a space: 'May  7' — must parse."""
        e = parse_line(FAILED_PW_LINES[1])
        assert e is not None
        assert e.timestamp.month == 5
        assert e.timestamp.day == 7


class TestTracker:
    def setup_method(self):
        from src.config import Config
        from src.tracker import IPTracker
        self.cfg = Config()
        self.cfg.set("window_seconds", 60)
        self.tracker = IPTracker(self.cfg)

    def test_single_failure(self):
        count, _ = self.tracker.record_failure("1.2.3.4", "root")
        assert count == 1

    def test_cumulative_failures(self):
        for _ in range(5):
            count, _ = self.tracker.record_failure("1.2.3.4", "admin")
        assert count == 5

    def test_different_ips_independent(self):
        for _ in range(3):
            self.tracker.record_failure("1.1.1.1", "root")
        count, _ = self.tracker.record_failure("2.2.2.2", "root")
        assert count == 1

    def test_reset_clears_counter(self):
        self.tracker.record_failure("1.2.3.4", "root")
        self.tracker.reset("1.2.3.4")
        assert self.tracker.get_count("1.2.3.4") == 0

    def test_top_usernames(self):
        for _ in range(3):
            self.tracker.record_failure("1.2.3.4", "root")
        for _ in range(2):
            self.tracker.record_failure("1.2.3.4", "admin")
        top = self.tracker.top_usernames("1.2.3.4")
        assert top[0][0] == "root"
        assert top[0][1] == 3


class TestWhitelist:
    def setup_method(self):
        from src.config import Config
        from src.actions import ActionEngine
        self.cfg = Config()
        self.cfg.set("dry_run", True)
        self.cfg.set("whitelist", ["127.0.0.1", "::1", "192.168.0.0/16", "10.0.0.0/8"])
        self.engine = ActionEngine(self.cfg)

    def test_localhost_whitelisted(self):
        assert self.engine.is_whitelisted("127.0.0.1")

    def test_ipv6_localhost_whitelisted(self):
        assert self.engine.is_whitelisted("::1")

    def test_cidr_match(self):
        assert self.engine.is_whitelisted("192.168.1.100")
        assert self.engine.is_whitelisted("10.0.0.1")

    def test_external_not_whitelisted(self):
        assert not self.engine.is_whitelisted("185.220.101.47")
        assert not self.engine.is_whitelisted("8.8.8.8")

    def test_block_skipped_for_whitelisted(self):
        """block() on a whitelisted IP should be a no-op."""
        self.engine.block("127.0.0.1", reason="test")
        assert not self.engine.is_blocked("127.0.0.1")
