"""
ssh-guard/src/notifier.py
Sends alerts via email (SMTP), Slack webhook, and/or syslog.
All channels are optional — configure what you need in config.yaml.
"""

import json
import logging
import smtplib
import urllib.request
import urllib.error
from email.message import EmailMessage
from datetime import datetime

from .config import Config

logger = logging.getLogger("sshguard.notifier")


class Notifier:
    def __init__(self, config: Config):
        self._config = config

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def send_block(self, ip: str, reason: str):
        subject = f"[ssh-guard] BLOCKED {ip}"
        body = (
            f"ssh-guard has automatically blocked {ip}.\n\n"
            f"Reason : {reason}\n"
            f"Time   : {datetime.now().isoformat()}\n\n"
            f"To unblock:\n"
            f"  sudo ssh-guard unblock {ip}\n"
        )
        self._dispatch(subject, body, level="BLOCK", ip=ip)

    def send_alert(self, ip: str, count: int, elapsed: int, username: str):
        subject = f"[ssh-guard] ALERT {ip} — {count} failures"
        body = (
            f"Warning: {ip} has {count} failed SSH attempts "
            f"in the last {elapsed} seconds.\n\n"
            f"Latest username : {username}\n"
            f"Time            : {datetime.now().isoformat()}\n\n"
            f"No action taken yet (threshold not reached).\n"
        )
        self._dispatch(subject, body, level="ALERT", ip=ip)

    # ------------------------------------------------------------------
    # Internal dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, subject: str, body: str, level: str, ip: str):
        if self._config.get("notify_syslog", True):
            self._syslog(subject)

        slack_url = self._config.get("notify_slack")
        if slack_url:
            self._slack(slack_url, subject, body, level)

        smtp_to = self._config.get("smtp_to") or self._config.get("notify_email")
        if smtp_to:
            self._email(subject, body, smtp_to)

    def _syslog(self, msg: str):
        """Write to system logger (shows up in auth.log / journald)."""
        try:
            import syslog
            syslog.syslog(syslog.LOG_WARNING, msg)
        except ImportError:
            logger.warning("syslog module not available: %s", msg)

    def _slack(self, webhook_url: str, subject: str, body: str, level: str):
        emoji = ":rotating_light:" if level == "BLOCK" else ":warning:"
        payload = {
            "text": f"{emoji} *{subject}*\n```{body}```"
        }
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    logger.warning("Slack webhook returned %d", resp.status)
        except urllib.error.URLError as e:
            logger.error("Slack notification failed: %s", e)

    def _email(self, subject: str, body: str, to: str):
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"]    = self._config.get("smtp_from", "sshguard@localhost")
        msg["To"]      = to
        msg.set_content(body)

        host = self._config.get("smtp_host", "localhost")
        port = self._config.get("smtp_port", 25)
        try:
            with smtplib.SMTP(host, port, timeout=10) as s:
                s.send_message(msg)
            logger.info("Alert email sent to %s", to)
        except (smtplib.SMTPException, OSError) as e:
            logger.error("Email notification failed: %s", e)
