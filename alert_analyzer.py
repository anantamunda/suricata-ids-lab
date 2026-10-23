#!/usr/bin/env python3
"""
alert_analyzer.py - Suricata eve.json alert summarizer

Reads Suricata's eve.json log (one JSON object per line), keeps only the
"alert" events, and summarizes them by signature, source IP and severity.
Results are printed as tables, saved to CSV, and optionally drawn as a chart.

Usage:
    python alert_analyzer.py --file sample_data/sample_eve.json
    python alert_analyzer.py --file /var/log/suricata/eve.json --output report.csv --chart
"""

import argparse
import csv
import json
import sys
from collections import Counter

# tabulate and matplotlib are optional: the script still works without them.
try:
    from tabulate import tabulate
except ImportError:
    tabulate = None

try:
    import matplotlib
    matplotlib.use("Agg")  # draw to a file, no window needed
    import matplotlib.pyplot as plt
except ImportError:
    plt = None

SEVERITY_NAMES = {1: "High", 2: "Medium", 3: "Low"}


def load_alerts(path):
    """Read eve.json line by line and return a list of alert events."""
    alerts = []
    bad_lines = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    bad_lines += 1  # skip broken lines instead of crashing
                    continue
                if event.get("event_type") == "alert":
                    alerts.append(event)
    except FileNotFoundError:
        sys.exit(f"Error: file not found: {path}")
    except PermissionError:
        sys.exit(f"Error: no permission to read {path} (try sudo)")

    if bad_lines:
        print(f"Warning: skipped {bad_lines} unreadable line(s).")
    return alerts


def summarize(alerts):
    """Count alerts by signature, source IP and severity."""
    by_signature = Counter()
    by_source = Counter()
    by_severity = Counter()

    for a in alerts:
        info = a.get("alert", {})
        by_signature[info.get("signature", "Unknown")] += 1
        by_source[a.get("src_ip", "Unknown")] += 1
        sev = info.get("severity", 0)
        by_severity[SEVERITY_NAMES.get(sev, f"Level {sev}")] += 1

    return by_signature, by_source, by_severity


def print_table(title, counter, headers):
    """Print a counter as a neat table (uses tabulate if installed)."""
    print(f"\n=== {title} ===")
    rows = counter.most_common()
    if tabulate:
        print(tabulate(rows, headers=headers, tablefmt="grid"))
    else:
        print(" | ".join(headers))
        for name, count in rows:
            print(f"{name} | {count}")


def save_csv(alerts, output_path):
    """Save every alert as one row in a CSV file."""
    fields = ["timestamp", "src_ip", "dest_ip", "proto", "signature", "severity"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(fields)
        for a in alerts:
            info = a.get("alert", {})
            writer.writerow([
                a.get("timestamp", ""),
                a.get("src_ip", ""),
                a.get("dest_ip", ""),
                a.get("proto", ""),
                info.get("signature", ""),
                info.get("severity", ""),
            ])
    print(f"\nCSV report saved to: {output_path}")


def save_chart(by_signature, chart_path):
    """Draw a horizontal bar chart of alerts per signature."""
    if plt is None:
        print("matplotlib not installed - skipping chart (pip install matplotlib).")
        return
    names = [n for n, _ in by_signature.most_common()]
    counts = [c for _, c in by_signature.most_common()]
    plt.figure(figsize=(9, 4))
    plt.barh(names, counts, color="#2a6fdb")
    plt.xlabel("Number of alerts")
    plt.title("Suricata Alerts by Signature")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(chart_path, dpi=150)
    plt.close()
    print(f"Chart saved to: {chart_path}")


def main():
    parser = argparse.ArgumentParser(description="Summarize Suricata eve.json alerts.")
    parser.add_argument("--file", default="/var/log/suricata/eve.json",
                        help="path to eve.json (default: /var/log/suricata/eve.json)")
    parser.add_argument("--output", default="alert_report.csv",
                        help="CSV file to write (default: alert_report.csv)")
    parser.add_argument("--chart", action="store_true",
                        help="also save a bar chart as alerts_chart.png")
    args = parser.parse_args()

    alerts = load_alerts(args.file)
    if not alerts:
        print("No alerts found in the file.")
        return

    by_signature, by_source, by_severity = summarize(alerts)

    print(f"\nTotal alerts: {len(alerts)}")
    print_table("Alerts by Signature", by_signature, ["Signature", "Count"])
    print_table("Alerts by Source IP", by_source, ["Source IP", "Count"])
    print_table("Alerts by Severity", by_severity, ["Severity", "Count"])

    save_csv(alerts, args.output)
    if args.chart:
        save_chart(by_signature, "alerts_chart.png")


if __name__ == "__main__":
    main()
