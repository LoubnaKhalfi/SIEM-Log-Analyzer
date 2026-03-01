# 🛡️ SIEM Log Analyzer

A detection-focused log analysis tool that parses real Linux, Apache, and Windows logs and fires alerts for known attack patterns — brute force, credential stuffing, privilege escalation, web attacks, and more.

---

## Detection Rules

| Rule | Source | Severity |
|---|---|---|
| SSH Brute Force (≥5 failures from same IP) | auth.log | HIGH |
| Credential Stuffing (brute force → success) | auth.log | CRITICAL |
| Off-Hours Login (00:00–06:00) | auth.log | MEDIUM |
| Sudo Command Execution | auth.log | MEDIUM |
| Su Privilege Escalation | auth.log | HIGH |
| SQL Injection | Apache | HIGH |
| XSS Attempt | Apache | HIGH |
| Local File Inclusion (LFI) | Apache | HIGH |
| Remote Code Execution (RCE) | Apache | HIGH |
| Directory Scan / Enumeration (≥6 404s) | Apache | MEDIUM |
| Windows Brute Force (EventID 4625) | Windows | HIGH |
| Privileged Logon (EventID 4672) | Windows | HIGH |
| Account Created (EventID 4720) | Windows | HIGH |
| Added to Administrators (EventID 4732) | Windows | CRITICAL |
| Suspicious Scheduled Task (EventID 4698) | Windows | HIGH |
| Malicious Service Installed (EventID 7045) | Windows | HIGH |

---

## Setup

```bash
pip install -r requirements.txt
```

No other dependencies. Works with real log files out of the box.

---

## Usage

```bash
# Analyze all sample logs
python analyzer.py --all

# Analyze specific log files
python analyzer.py --auth /var/log/auth.log
python analyzer.py --apache /var/log/apache2/access.log
python analyzer.py --windows events.log

# Combine sources
python analyzer.py --auth /var/log/auth.log --apache /var/log/apache2/access.log

# Export report
python analyzer.py --all --report markdown
python analyzer.py --all --report json
```

---

## Sample Output

```
[*] Parsing AUTH: samples/auth.log
[*] Parsing APACHE: samples/apache.log
[*] Parsing WINDOWS: samples/windows.log

────────────────────────────────────────────────────────────
 Linux Auth — 8 alerts
────────────────────────────────────────────────────────────

  SEV        TYPE                                          IP                 USER            TIME
  ----------  ---------------------------------------------  ------------------  ---------------  --------------------
  [CRITICAL] Credential Stuffing — Brute Force Succeeded   192.168.1.105      root            Dec 10 02:15:07
             → Login succeeded after 6 failures
  [HIGH]     SSH Brute Force                               192.168.1.105      root            Dec 10 02:15:01
             → 6 failed login attempts
  [HIGH]     Su Privilege Escalation                       local              www-data        Dec 10 02:21:00
             → www-data switched to root
  ...

════════════════════════════════════════════════════════════
  SUMMARY — 24 total alerts
════════════════════════════════════════════════════════════
  CRITICAL   3
  HIGH       14
  MEDIUM     7
```

---

## Log Format Support

**Linux auth.log** — standard syslog format (OpenSSH, sudo, su)
```
Dec 10 02:15:01 server sshd[1234]: Failed password for root from 192.168.1.105 port 22
```

**Apache access.log** — Combined Log Format
```
10.0.0.33 - - [10/Dec/2024:08:01:00 +0000] "GET /login.php?id=1' OR '1'='1 HTTP/1.1" 200 512
```

**Windows Event Log** — text export format
```
2024-12-10 02:10:00 EventID=4625 AccountName=Administrator IpAddress=192.168.1.105
```

---

## Project Structure

```
siem-log-analyzer/
├── analyzer.py           # CLI entrypoint
├── modules/
│   ├── parser.py         # Log parsers (regex-based)
│   ├── detections.py     # Detection rules engine
│   ├── alerts.py         # Alert display with severity colors
│   └── report.py         # JSON / Markdown report export
├── samples/
│   ├── auth.log          # Sample Linux auth log
│   ├── apache.log        # Sample Apache access log
│   └── windows.log       # Sample Windows Event Log
└── requirements.txt
```

