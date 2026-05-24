"""
ssh-guard/src/parser.py
Parses individual lines from /var/log/auth.log or /var/log/secure
into structured LogEvent objects.
"""

import re
from dataclasses import dataclass
from enum import Enum, auto
from datetime import datetime
from typing import Optional


class EventType(Enum):
    FAILED_PASSWORD   = auto()
    INVALID_USER      = auto()
    CONNECTION_CLOSED = auto()
    ACCEPTED          = auto()
    UNKNOWN           = auto()


@dataclass
class LogEvent:
    type:      EventType
    ip:        str
    username:  str
    port:      Optional[int]
    timestamp: datetime
    raw:       str


# ---------------------------------------------------------------------------
# Compiled regex patterns matching real OpenSSH syslog output
# ---------------------------------------------------------------------------

# May 24 14:22:01 hostname sshd[12345]: ...
_TS_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)

# "Failed password for root from 1.2.3.4 port 54321 ssh2"
# "Failed password for invalid user foo from 1.2.3.4 port 54321 ssh2"
_FAILED_PW = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d\.a-fA-F:]+) port (\d+)"
)

# "Invalid user foo from 1.2.3.4 port 54321"
_INVALID_USER = re.compile(
    r"Invalid user (\S+) from ([\d\.a-fA-F:]+)(?:\s+port (\d+))?"
)

# "Connection closed by authenticating user foo 1.2.3.4 port 54321 [preauth]"
_CONN_CLOSED = re.compile(
    r"Connection closed by (?:authenticating user )?(\S+) ([\d\.a-fA-F:]+) port (\d+)"
)

# "Accepted password for foo from 1.2.3.4 port 54321 ssh2"
# "Accepted publickey for foo from 1.2.3.4 port 54321 ssh2"
_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d\.a-fA-F:]+) port (\d+)"
)

# Syslog timestamp format: "May  7 08:01:23" — no year, so we add current year
_TS_FMT = "%b %d %H:%M:%S"


def _parse_ts(raw_ts: str) -> datetime:
    try:
        # Strip extra spaces that syslog adds for single-digit days
        dt = datetime.strptime(raw_ts.strip(), _TS_FMT)
        return dt.replace(year=datetime.now().year)
    except ValueError:
        return datetime.now()


def parse_line(line: str) -> Optional[LogEvent]:
    """
    Return a LogEvent if the line is a relevant SSH event, else None.
    Works with both Debian (/var/log/auth.log) and RHEL (/var/log/secure)
    syslog formats.
    """
    if "sshd" not in line:
        return None

    # Parse timestamp
    ts_match = _TS_RE.match(line)
    ts = _parse_ts(ts_match.group(1)) if ts_match else datetime.now()

    # Try each pattern
    m = _FAILED_PW.search(line)
    if m:
        return LogEvent(
            type=EventType.FAILED_PASSWORD,
            username=m.group(1),
            ip=m.group(2),
            port=int(m.group(3)),
            timestamp=ts,
            raw=line,
        )

    m = _INVALID_USER.search(line)
    if m:
        return LogEvent(
            type=EventType.INVALID_USER,
            username=m.group(1),
            ip=m.group(2),
            port=int(m.group(3)) if m.group(3) else None,
            timestamp=ts,
            raw=line,
        )

    m = _CONN_CLOSED.search(line)
    if m:
        return LogEvent(
            type=EventType.CONNECTION_CLOSED,
            username=m.group(1),
            ip=m.group(2),
            port=int(m.group(3)),
            timestamp=ts,
            raw=line,
        )

    m = _ACCEPTED.search(line)
    if m:
        return LogEvent(
            type=EventType.ACCEPTED,
            username=m.group(1),
            ip=m.group(2),
            port=int(m.group(3)),
            timestamp=ts,
            raw=line,
        )

    return None
