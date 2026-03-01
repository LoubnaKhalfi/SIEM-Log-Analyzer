#!/usr/bin/env python3
import argparse
import sys
import os
from modules import parser, detections, alerts, report

def analyze_file(path, ftype):
    if not os.path.isfile(path):
        print(f"[!] File not found: {path}")
        return []

    print(f"\n[*] Parsing {ftype.upper()}: {path}")

    if ftype == "auth":
        entries = parser.parse_auth(path)
        return detections.detect_auth(entries)
    elif ftype == "apache":
        entries = parser.parse_apache(path)
        return detections.detect_apache(entries)
    elif ftype == "windows":
        entries = parser.parse_windows(path)
        return detections.detect_windows(entries)
    return []

def main():
    p = argparse.ArgumentParser(description="SIEM Log Analyzer")
    p.add_argument("--auth",    help="Path to auth.log")
    p.add_argument("--apache",  help="Path to Apache access.log")
    p.add_argument("--windows", help="Path to Windows Event Log")
    p.add_argument("--all",     action="store_true", help="Analyze all sample logs")
    p.add_argument("--report",  choices=["json", "markdown"], help="Export report")
    args = p.parse_args()

    if not any([args.auth, args.apache, args.windows, args.all]):
        p.print_help()
        sys.exit(1)

    all_alerts = {}

    if args.all:
        args.auth    = args.auth    or "samples/auth.log"
        args.apache  = args.apache  or "samples/apache.log"
        args.windows = args.windows or "samples/windows.log"

    if args.auth:
        found = analyze_file(args.auth, "auth")
        all_alerts["Linux Auth (auth.log)"] = found
        print(f"\n{'─'*60}")
        print(f" Linux Auth — {len(found)} alerts")
        print(f"{'─'*60}")
        alerts.print_alerts(found, "auth.log")

    if args.apache:
        found = analyze_file(args.apache, "apache")
        all_alerts["Web Server (Apache)"] = found
        print(f"\n{'─'*60}")
        print(f" Apache Access Log — {len(found)} alerts")
        print(f"{'─'*60}")
        alerts.print_alerts(found, "apache.log")

    if args.windows:
        found = analyze_file(args.windows, "windows")
        all_alerts["Windows Event Log"] = found
        print(f"\n{'─'*60}")
        print(f" Windows Event Log — {len(found)} alerts")
        print(f"{'─'*60}")
        alerts.print_alerts(found, "windows.log")

    alerts.summarize(all_alerts)

    if args.report:
        report.export(all_alerts, args.report)

if __name__ == "__main__":
    main()
