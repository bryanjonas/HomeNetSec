#!/usr/bin/env python3
"""
Simple command-line alert viewer for testing.

Usage:
    ./view_alerts.py --db /path/to/alerts.sqlite [--status active] [--limit 20]
"""

import argparse
import sqlite3
import json
import sys
from pathlib import Path


def format_alert(alert):
    """Format an alert for display."""
    lines = []
    lines.append(f"\n{'='*80}")
    lines.append(f"Alert ID: {alert['alert_id']}")
    lines.append(f"Kind: {alert['kind']}")
    lines.append(f"Severity: {alert['severity'].upper()}")
    lines.append(f"Status: {alert['status']}")

    if alert['src_ip']:
        lines.append(f"Source: {alert['src_name'] or alert['src_ip']}")
    if alert['dst_ip']:
        lines.append(f"Destination: {alert['dst_ip']}")
    if alert['dst_port']:
        lines.append(f"Port: {alert['dst_port']}")
    if alert['domain']:
        lines.append(f"Domain: {alert['domain']}")

    lines.append(f"First seen: {alert['first_seen']}")
    lines.append(f"Last seen: {alert['last_seen']}")
    lines.append(f"Occurrences: {alert['occurrence_count']}")

    if alert['evidence_json']:
        try:
            evidence = json.loads(alert['evidence_json'])
            lines.append(f"\nEvidence:")
            for key, value in evidence.items():
                if key not in ['detection_type']:
                    lines.append(f"  {key}: {value}")
        except:
            pass

    if alert['user_verdict']:
        lines.append(f"\nUser verdict: {alert['user_verdict']}")
    if alert['user_comment']:
        lines.append(f"Comment: {alert['user_comment']}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description='View alerts from alerts.sqlite')
    parser.add_argument('--db', required=True, help='Path to alerts.sqlite')
    parser.add_argument('--status', help='Filter by status (new, active, investigating, resolved, dismissed)')
    parser.add_argument('--severity', help='Filter by severity (info, low, med, high, critical)')
    parser.add_argument('--kind', help='Filter by alert kind')
    parser.add_argument('--limit', type=int, default=20, help='Max alerts to show')
    parser.add_argument('--offset', type=int, default=0, help='Pagination offset')
    parser.add_argument('--stats', action='store_true', help='Show statistics only')

    args = parser.parse_args()

    if not Path(args.db).exists():
        print(f"Error: Database not found: {args.db}", file=sys.stderr)
        return 1

    db = sqlite3.connect(args.db)
    db.row_factory = sqlite3.Row

    # Show statistics
    if args.stats:
        # Count by status
        print("\n=== Alert Statistics ===\n")
        print("By Status:")
        for row in db.execute("SELECT status, COUNT(*) as count FROM alerts GROUP BY status ORDER BY count DESC"):
            print(f"  {row['status']:20s}: {row['count']}")

        print("\nBy Severity:")
        for row in db.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity ORDER BY count DESC"):
            print(f"  {row['severity']:20s}: {row['count']}")

        print("\nBy Kind:")
        for row in db.execute("SELECT kind, COUNT(*) as count FROM alerts GROUP BY kind ORDER BY count DESC LIMIT 10"):
            print(f"  {row['kind']:30s}: {row['count']}")

        print(f"\nTotal alerts: {db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]}")
        print(f"Active alerts: {db.execute('SELECT COUNT(*) FROM alerts WHERE dismissed = 0').fetchone()[0]}")

        return 0

    # Build query
    query = "SELECT * FROM alerts"
    params = []

    conditions = []
    if args.status:
        if args.status == 'active':
            conditions.append("dismissed = 0 AND status NOT IN ('resolved', 'dismissed')")
        else:
            conditions.append("status = ?")
            params.append(args.status)
    if args.severity:
        conditions.append("severity = ?")
        params.append(args.severity)
    if args.kind:
        conditions.append("kind = ?")
        params.append(args.kind)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += """ ORDER BY
        CASE severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'med' THEN 3
            WHEN 'low' THEN 4
            ELSE 5
        END,
        last_seen DESC
    """

    if args.limit:
        query += f" LIMIT {args.limit}"
    if args.offset:
        query += f" OFFSET {args.offset}"

    # Execute and display
    alerts = db.execute(query, params).fetchall()

    if not alerts:
        print("No alerts found matching criteria")
        return 0

    print(f"\n=== Showing {len(alerts)} alerts ===")

    for alert in alerts:
        print(format_alert(dict(alert)))

    print(f"\n{'='*80}\n")
    print(f"Total shown: {len(alerts)}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
