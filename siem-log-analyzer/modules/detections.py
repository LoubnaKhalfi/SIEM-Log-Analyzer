from collections import defaultdict
import re

BRUTE_THRESHOLD   = 5   # failed logins before alert
SCAN_THRESHOLD    = 6   # 404s before directory scan alert
OFF_HOURS         = range(0, 6)  # midnight to 6am

# Web attack signatures
WEB_SIGNATURES = {
    "SQLi":  re.compile(r"('|--|;|union\s+select|or\s+'1'='1|drop\s+table)", re.I),
    "XSS":   re.compile(r"(<script|javascript:|onerror=|onload=|alert\()", re.I),
    "LFI":   re.compile(r"(\.\./|etc/passwd|etc/shadow|proc/self)", re.I),
    "RCE":   re.compile(r"(cmd=|exec=|system=|passthru=|%60|%7C)", re.I),
    "Recon": re.compile(r"(\.env|\.git|wp-admin|phpmyadmin|backup\.sql|\.htaccess)", re.I),
}

# Windows high-value Event IDs
WIN_EVENTS = {
    4625: ("Brute Force",        "MEDIUM"),
    4624: ("Successful Logon",   "INFO"),
    4672: ("Privileged Logon",   "HIGH"),
    4720: ("Account Created",    "HIGH"),
    4732: ("Added to Admins",    "CRITICAL"),
    4698: ("Scheduled Task",     "HIGH"),
    7045: ("Service Installed",  "HIGH"),
}

def detect_auth(entries):
    alerts = []

    # Brute force: N failed logins per IP
    failed_by_ip = defaultdict(list)
    for e in entries["failed"]:
        failed_by_ip[e["ip"]].append(e)

    for ip, attempts in failed_by_ip.items():
        if len(attempts) >= BRUTE_THRESHOLD:
            alerts.append({
                "type":     "SSH Brute Force",
                "severity": "HIGH",
                "ip":       ip,
                "user":     attempts[0]["user"],
                "count":    len(attempts),
                "time":     attempts[0]["time"],
                "detail":   f"{len(attempts)} failed login attempts"
            })

    # Credential stuffing: brute force followed by success from same IP
    success_ips = {e["ip"] for e in entries["success"]}
    for ip in failed_by_ip:
        if ip in success_ips and len(failed_by_ip[ip]) >= BRUTE_THRESHOLD:
            success = next(e for e in entries["success"] if e["ip"] == ip)
            alerts.append({
                "type":     "Credential Stuffing — Brute Force Succeeded",
                "severity": "CRITICAL",
                "ip":       ip,
                "user":     success["user"],
                "count":    len(failed_by_ip[ip]),
                "time":     success["time"],
                "detail":   f"Login succeeded after {len(failed_by_ip[ip])} failures"
            })

    # Off-hours logins
    for e in entries["success"]:
        try:
            hour = int(e["time"].split(":")[0].split()[-1])
            if hour in OFF_HOURS:
                alerts.append({
                    "type":     "Off-Hours Login",
                    "severity": "MEDIUM",
                    "ip":       e["ip"],
                    "user":     e["user"],
                    "count":    1,
                    "time":     e["time"],
                    "detail":   f"Login at {e['time']} (off-hours)"
                })
        except Exception:
            pass

    # Privilege escalation via sudo/su
    for e in entries["sudo"]:
        alerts.append({
            "type":     "Sudo Command Executed",
            "severity": "MEDIUM",
            "ip":       "local",
            "user":     e["user"],
            "count":    1,
            "time":     e["time"],
            "detail":   f"Command: {e['cmd']}"
        })
    for e in entries["su"]:
        alerts.append({
            "type":     "Su Privilege Escalation",
            "severity": "HIGH",
            "ip":       "local",
            "user":     e["by"],
            "count":    1,
            "time":     e["time"],
            "detail":   f"{e['by']} switched to {e['target']}"
        })

    return alerts

def detect_apache(entries):
    alerts = []

    # Web attack signatures
    for e in entries:
        for attack, pattern in WEB_SIGNATURES.items():
            if pattern.search(e["path"]):
                alerts.append({
                    "type":     f"Web Attack — {attack}",
                    "severity": "HIGH" if attack != "Recon" else "MEDIUM",
                    "ip":       e["ip"],
                    "user":     "-",
                    "count":    1,
                    "time":     e["time"],
                    "detail":   f"{e['method']} {e['path']}"
                })

    # Directory scanning: many 404s from same IP
    scan_by_ip = defaultdict(list)
    for e in entries:
        if e["status"] == 404:
            scan_by_ip[e["ip"]].append(e)

    for ip, reqs in scan_by_ip.items():
        if len(reqs) >= SCAN_THRESHOLD:
            alerts.append({
                "type":     "Directory Scan / Enumeration",
                "severity": "MEDIUM",
                "ip":       ip,
                "user":     "-",
                "count":    len(reqs),
                "time":     reqs[0]["time"],
                "detail":   f"{len(reqs)} 404 responses"
            })

    return alerts

def detect_windows(entries):
    alerts = []
    failed_by_ip = defaultdict(list)

    for e in entries:
        eid = e["event_id"]

        if eid == 4625:
            ip = e.get("IpAddress", "unknown")
            failed_by_ip[ip].append(e)

        elif eid in WIN_EVENTS:
            label, severity = WIN_EVENTS[eid]
            alerts.append({
                "type":     f"Windows: {label} (EventID {eid})",
                "severity": severity,
                "ip":       e.get("IpAddress", "local"),
                "user":     e.get("AccountName", "unknown"),
                "count":    1,
                "time":     e["time"],
                "detail":   " | ".join(f"{k}={v}" for k, v in e.items()
                                        if k not in ("time", "event_id"))
            })

    for ip, attempts in failed_by_ip.items():
        if len(attempts) >= BRUTE_THRESHOLD:
            alerts.append({
                "type":     "Windows: Brute Force (EventID 4625)",
                "severity": "HIGH",
                "ip":       ip,
                "user":     attempts[0].get("AccountName", "unknown"),
                "count":    len(attempts),
                "time":     attempts[0]["time"],
                "detail":   f"{len(attempts)} failed logon attempts"
            })

    return alerts
