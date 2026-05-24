# ssh-guard

A real SSH brute force detector. Tails `/var/log/auth.log`, detects attack patterns, and blocks offending IPs with `iptables` or `ufw`. No false positives by design — whitelist your own IPs before deploying.

## What it does

- **Parses** OpenSSH log lines in real time (works on both Debian and RHEL-based systems)
- **Tracks** failed login attempts per source IP in a sliding time window
- **Blocks** IPs automatically via `iptables` or `ufw` once the failure threshold is crossed
- **Alerts** via Slack webhook, email (SMTP), or syslog
- **Whitelists** your own IPs and internal ranges so you never lock yourself out
- **Persists** blocked IPs across restarts in a JSON database

---

## Quick start

### 1. Clone and install

```bash
git clone https://github.com/AkinwandeFredrick/SSH-GUARD.git
cd SSH-GUARD
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Edit the config

```bash
sudo mkdir -p /etc/SSH-GUARD
sudo cp config/config.yaml /etc/ssh-guard/config.yaml
sudo nano /etc/ssh-guard/config.yaml
```

**Critical — add your own IP to the whitelist before starting:**

```yaml
whitelist:
  - 127.0.0.1
  - 10.0.0.0/8
  - 192.168.0.0/16
  - YOUR.HOME.IP.HERE        # <-- add this
```

### 3. Test your log format first

```bash
# Paste a line from your own auth.log to verify parsing works
sudo tail -1 /var/log/auth.log | python3 ssh_guard.py test

# Or manually:
python3 ssh_guard.py test --line "May 24 14:22:01 srv sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2"
```

### 4. Dry run (no actual iptables rules)

```bash
sudo python3 ssh_guard.py --config /etc/ssh-guard/config.yaml start --dry-run
```

Watch the output — you'll see what it *would* block. When it looks right, remove `--dry-run`.

### 5. Run for real

```bash
sudo python3 ssh_guard.py --config /etc/ssh-guard/config.yaml start
```

---

## Deploy as a systemd service

```bash
# Install
sudo cp systemd/ssh-guard.service /etc/systemd/system/
sudo nano /etc/systemd/system/ssh-guard.service   # update WorkingDirectory path

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable ssh-guard
sudo systemctl start ssh-guard

# Check it's running
sudo systemctl status ssh-guard
sudo journalctl -u ssh-guard -f
```

---

## CLI commands

```bash
# Show currently blocked IPs
sudo python3 ssh_guard.py status

# Unblock an IP (also removes the iptables rule)
sudo python3 ssh_guard.py unblock 185.220.101.47

# Test a log line against the parser
python3 ssh_guard.py test --line "..."
```

---

## Configuration reference

All values can be overridden with environment variables: `SSHGUARD_<KEY>=value`

| Key | Default | Description |
|-----|---------|-------------|
| `log_path` | auto-detect | Path to auth log. Auto-detects `/var/log/auth.log` or `/var/log/secure` |
| `threshold_block` | `15` | Failures in window before blocking |
| `threshold_alert` | `8` | Failures in window before sending alert only |
| `window_seconds` | `600` | Sliding window length (10 minutes) |
| `firewall` | `iptables` | `iptables`, `ufw`, or `none` |
| `dry_run` | `false` | Log actions without running iptables |
| `whitelist` | RFC1918 + localhost | IPs/CIDRs that are never blocked |
| `notify_slack` | — | Slack webhook URL |
| `smtp_to` | — | Email address for alerts |
| `log_level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

---

## Avoiding false positives

1. **Whitelist your IP first.** Every IP in `whitelist` is completely immune from blocking.
2. **Use `--dry-run`** to observe for a day before enabling real blocking.
3. **Tune `threshold_block`** — default is 15 failures per 10 minutes. Legitimate users rarely hit this; bots always do.
4. **Check `ssh-guard status`** after a day to review what was blocked.

---

## Running tests

```bash
python -m pytest tests/ -v
```

---

## How it works

```
/var/log/auth.log
      │
      ▼
  parser.py          — regex → LogEvent (IP, username, type, timestamp)
      │
      ▼
  tracker.py         — sliding-window counter per IP
      │
      ├── count < threshold_alert  → nothing
      ├── count >= threshold_alert → notifier.send_alert()
      └── count >= threshold_block → actions.block() + notifier.send_block()
                                          │
                                          ├── iptables -I INPUT -s <ip> -j DROP
                                          ├── blocks.json (persist across restart)
                                          ├── Slack webhook POST
                                          └── SMTP email
```

---

## Security notes

- Run as root (required for iptables). The systemd service includes basic hardening.
- The block database at `/var/lib/ssh-guard/blocks.json` is readable only by root.
- ssh-guard never blocks IPs in the whitelist, even if they exceed the threshold.
- For production, prefer key-based SSH auth (`PasswordAuthentication no` in `/etc/ssh/sshd_config`) — ssh-guard is a complement, not a substitute.
# SSH-GUARD
