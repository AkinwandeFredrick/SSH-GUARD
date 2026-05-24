#!/usr/bin/env python3
"""
ssh-guard — CLI entry point.

Usage:
  ssh-guard start   [--config CONFIG] [--dry-run]
  ssh-guard status
  ssh-guard list
  ssh-guard unblock <IP>
  ssh-guard test    [--line "..."]
  ssh-guard -h | --help
"""

import argparse
import json
import logging
import sys
from pathlib import Path


def setup_logging(level: str, log_file: str = None):
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO),
                        format=fmt, handlers=handlers)


def cmd_start(args):
    from src.config import Config
    from src.monitor import LogMonitor

    config = Config(args.config)
    if args.dry_run:
        config.set("dry_run", True)

    setup_logging(config.get("log_level", "INFO"), config.get("log_file"))

    monitor = LogMonitor(config)
    logging.getLogger("sshguard").info(
        "Starting ssh-guard (dry_run=%s)", config.get("dry_run")
    )
    monitor.run()


def cmd_status(args):
    """Show currently blocked IPs from the DB."""
    from src.config import Config
    from src.actions import ActionEngine

    config = Config(args.config)
    engine = ActionEngine(config)
    blocks = engine.list_blocks()

    if not blocks:
        print("No IPs currently blocked.")
        return

    print(f"{'IP':<20} {'Reason':<45} {'Blocked at'}")
    print("-" * 80)
    for b in blocks:
        print(f"{b['ip']:<20} {b.get('reason','')[:44]:<45} {b.get('blocked','')}")


def cmd_list(args):
    """Alias for status."""
    cmd_status(args)


def cmd_unblock(args):
    from src.config import Config
    from src.actions import ActionEngine
    from src.tracker import IPTracker

    config = Config(args.config)
    engine = ActionEngine(config)
    tracker = IPTracker(config)

    ip = args.ip
    engine.unblock(ip)
    tracker.reset(ip)
    print(f"Unblocked {ip}")


def cmd_test(args):
    """
    Parse one log line and show what ssh-guard would do with it.
    Useful for verifying your regex patterns work on your actual log format.

    Examples:
      ssh-guard test --line "May 24 14:01:22 srv sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2"
      echo "..." | ssh-guard test
    """
    from src.parser import parse_line

    if args.line:
        line = args.line
    else:
        print("Paste a log line (Ctrl-D when done):")
        line = sys.stdin.read().strip()

    event = parse_line(line)
    if event is None:
        print("→ Not recognised as an SSH auth event.")
    else:
        print(f"→ EventType : {event.type.name}")
        print(f"   IP       : {event.ip}")
        print(f"   Username : {event.username}")
        print(f"   Port     : {event.port}")
        print(f"   Timestamp: {event.timestamp}")


def cmd_snapshot(args):
    """Dump tracker in-memory state as JSON (must be running as same process — for debugging)."""
    # This is mainly useful when embedded; standalone it shows the DB
    cmd_status(args)


# ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="ssh-guard",
        description="SSH brute force detector and auto-blocker",
    )
    parser.add_argument("--config", default="/etc/ssh-guard/config.yaml",
                        help="Path to config.yaml (default: /etc/ssh-guard/config.yaml)")

    sub = parser.add_subparsers(dest="command")
    sub.required = True

    # start
    p_start = sub.add_parser("start", help="Start monitoring")
    p_start.add_argument("--dry-run", action="store_true",
                         help="Parse and log but never run iptables")
    p_start.set_defaults(func=cmd_start)

    # status / list
    p_status = sub.add_parser("status", help="Show blocked IPs")
    p_status.set_defaults(func=cmd_status)

    p_list = sub.add_parser("list", help="Alias for status")
    p_list.set_defaults(func=cmd_list)

    # unblock
    p_unblock = sub.add_parser("unblock", help="Unblock an IP")
    p_unblock.add_argument("ip", help="IP address to unblock")
    p_unblock.set_defaults(func=cmd_unblock)

    # test
    p_test = sub.add_parser("test", help="Test-parse a log line")
    p_test.add_argument("--line", "-l", default=None,
                        help="Log line to parse (reads stdin if omitted)")
    p_test.set_defaults(func=cmd_test)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
