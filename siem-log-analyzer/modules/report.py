import json
import os
from datetime import datetime

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

def export(all_alerts, fmt):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"siem_report_{timestamp}.{'json' if fmt == 'json' else 'md'}"
    all_flat  = sorted(
        [a for alerts in all_alerts.values() for a in alerts],
        key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)
    )

    if fmt == "json":
        with open(filename, "w") as f:
            json.dump({"generated": timestamp, "total": len(all_flat), "alerts": all_flat}, f, indent=2)

    elif fmt == "markdown":
        with open(filename, "w") as f:
            f.write(f"# SIEM Analysis Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
            f.write(f"**Total Alerts:** {len(all_flat)}\n\n")

            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
            for a in all_flat:
                counts[a["severity"]] = counts.get(a["severity"], 0) + 1

            f.write("## Summary\n\n")
            f.write("| Severity | Count |\n|---|---|\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
                f.write(f"| {sev} | {counts[sev]} |\n")

            for source, alerts in all_alerts.items():
                if not alerts:
                    continue
                f.write(f"\n## {source}\n\n")
                f.write("| Severity | Type | IP | User | Time |\n|---|---|---|---|---|\n")
                for a in sorted(alerts, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)):
                    f.write(f"| {a['severity']} | {a['type']} | {a['ip']} | {a['user']} | {a['time']} |\n")
                f.write("\n### Details\n\n")
                for a in sorted(alerts, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)):
                    f.write(f"**[{a['severity']}] {a['type']}**  \n")
                    f.write(f"IP: `{a['ip']}` | User: `{a['user']}` | Time: `{a['time']}`  \n")
                    f.write(f"→ {a['detail']}\n\n")

    print(f"[+] Report saved: {filename}")
