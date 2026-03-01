import re
from datetime import datetime

# ── Auth.log ──────────────────────────────────────────────────────────────────

AUTH_FAILED  = re.compile(r"(\w+ \d+ \d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\S+)")
AUTH_SUCCESS = re.compile(r"(\w+ \d+ \d+:\d+:\d+).*Accepted password for (\S+) from (\S+)")
SUDO_CMD     = re.compile(r"(\w+ \d+ \d+:\d+:\d+).*sudo.*?(\w+)\s*:.*COMMAND=(.*)")
SU_CMD       = re.compile(r"(\w+ \d+ \d+:\d+:\d+).*su\[.*\]: Successful su for (\S+) by (\S+)")

def parse_auth(path):
    entries = {"failed": [], "success": [], "sudo": [], "su": []}
    with open(path) as f:
        for line in f:
            m = AUTH_FAILED.search(line)
            if m:
                entries["failed"].append({"time": m.group(1), "user": m.group(2), "ip": m.group(3)})
                continue
            m = AUTH_SUCCESS.search(line)
            if m:
                entries["success"].append({"time": m.group(1), "user": m.group(2), "ip": m.group(3)})
                continue
            m = SUDO_CMD.search(line)
            if m:
                entries["sudo"].append({"time": m.group(1), "user": m.group(2), "cmd": m.group(3).strip()})
                continue
            m = SU_CMD.search(line)
            if m:
                entries["su"].append({"time": m.group(1), "target": m.group(2), "by": m.group(3)})
    return entries

# ── Apache access.log ─────────────────────────────────────────────────────────

APACHE_LINE = re.compile(
    r'(\S+) \S+ \S+ \[(.+?)\] "(\S+) (\S+) \S+" (\d+) \S+'
)

def parse_apache(path):
    entries = []
    with open(path) as f:
        for line in f:
            m = APACHE_LINE.match(line)
            if m:
                entries.append({
                    "ip":     m.group(1),
                    "time":   m.group(2),
                    "method": m.group(3),
                    "path":   m.group(4),
                    "status": int(m.group(5))
                })
    return entries

# ── Windows Event Log ─────────────────────────────────────────────────────────

WIN_LINE = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) EventID=(\d+) (.*)")
WIN_KV   = re.compile(r"(\w+)=([^\s]+)")

def parse_windows(path):
    entries = []
    with open(path) as f:
        for line in f:
            m = WIN_LINE.match(line.strip())
            if m:
                entry = {"time": m.group(1), "event_id": int(m.group(2))}
                entry.update({k: v for k, v in WIN_KV.findall(m.group(3))})
                entries.append(entry)
    return entries
