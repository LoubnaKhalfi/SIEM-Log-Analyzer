try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

COLORS = {
    "CRITICAL": "\033[1;35m",  # bold magenta
    "HIGH":     "\033[1;31m",  # bold red
    "MEDIUM":   "\033[1;33m",  # bold yellow
    "INFO":     "\033[1;34m",  # bold blue
    "RESET":    "\033[0m"
}

def _color(severity, text):
    c = COLORS.get(severity, "")
    return f"{c}{text}{COLORS['RESET']}"

def print_alerts(alerts, source):
    if not alerts:
        print(f"  No alerts from {source}.\n")
        return

    sorted_alerts = sorted(alerts, key=lambda a: SEVERITY_ORDER.get(a["severity"], 99))
    print(f"\n  {'SEV':<10} {'TYPE':<45} {'IP':<18} {'USER':<15} {'TIME'}")
    print(f"  {'-'*10}  {'-'*45}  {'-'*18}  {'-'*15}  {'-'*20}")

    for a in sorted_alerts:
        sev  = _color(a["severity"], f"[{a['severity']}]")
        line = f"  {sev:<20} {a['type']:<45} {a['ip']:<18} {a['user']:<15} {a['time']}"
        print(line)
        print(f"  {'':10}  → {a['detail']}")

    print()

def summarize(all_alerts):
    total = sum(len(v) for v in all_alerts.values())
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for alerts in all_alerts.values():
        for a in alerts:
            counts[a["severity"]] = counts.get(a["severity"], 0) + 1

    print("=" * 60)
    print(f"  SUMMARY — {total} total alerts")
    print("=" * 60)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
        if counts[sev]:
            print(f"  {_color(sev, sev):<20}  {counts[sev]}")
    print()
