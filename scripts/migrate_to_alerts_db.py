#!/usr/bin/env python3
"""
Migrate historical candidates.json and digest.json files to alerts.sqlite database.

This script reads historical day-scoped JSON files and populates the alerts.sqlite
database, preserving alert history and enabling the new persistent alert model.

Usage:
    ./scripts/migrate_to_alerts_db.py --workdir /path/to/output [--days 30]

Exit codes:
    0 - Success
    1 - Migration failed
"""

import argparse
import sqlite3
import json
import sys
import hashlib
from pathlib import Path
from datetime import datetime, timedelta


def generate_alert_id(kind, src_ip, dst_ip, dst_port, domain, day):
    """
    Generate stable alert ID for deduplication.

    Alert ID is based on:
    - kind (e.g., rita_beacon, new_external_destination)
    - src_ip
    - dst_ip (if applicable)
    - dst_port (if applicable)
    - domain (if applicable)
    - day (to allow same alert on different days to be separate)

    This ensures recurring alerts are identified correctly.
    """
    # Create a stable identifier
    components = [
        kind,
        src_ip or "",
        dst_ip or "",
        str(dst_port) if dst_port else "",
        domain or "",
        day  # Include day so alerts on different days are separate
    ]

    identifier = "|".join(components)
    return hashlib.sha256(identifier.encode()).hexdigest()[:32]


def parse_digest_item(item, day):
    """Parse a digest item and extract fields for alerts table."""

    # Extract core fields
    alert_id = item.get('id', generate_alert_id(
        item.get('kind', 'unknown'),
        item.get('evidence', {}).get('src_ip'),
        item.get('evidence', {}).get('dst_ip'),
        item.get('evidence', {}).get('dst_port'),
        item.get('evidence', {}).get('domain'),
        day
    ))

    kind = item.get('kind', 'unknown')
    severity = item.get('severity', 'med')
    verdict = item.get('verdict', 'needs_review')
    confidence = item.get('confidence', 0.5)

    # Extract evidence fields
    evidence = item.get('evidence', {})
    src_ip = evidence.get('src_ip')
    src_name = evidence.get('src_name')
    dst_ip = evidence.get('dst_ip')
    dst_port = evidence.get('dst_port')
    domain = evidence.get('domain')

    # Set timestamps (use day as best approximation)
    first_seen = f"{day}T12:00:00Z"  # Midday as estimate
    last_seen = first_seen

    # User feedback
    user_verdict = item.get('user_verdict')
    user_comment = item.get('user_comment')
    dismissed = 1 if item.get('dismissed', False) else 0
    dismissed_at = item.get('dismissed_at')
    dismiss_ttl_days = item.get('dismiss_ttl_days')

    # JSON blobs
    evidence_json = json.dumps(evidence)
    recommendation_json = json.dumps(item.get('recommendation', {}))

    return {
        'alert_id': alert_id,
        'kind': kind,
        'severity': severity,
        'status': 'resolved' if dismissed else 'new',  # Historical alerts are either dismissed or unresolved
        'verdict': verdict,
        'confidence': confidence,
        'src_ip': src_ip,
        'src_name': src_name,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'domain': domain,
        'first_seen': first_seen,
        'last_seen': last_seen,
        'occurrence_count': 1,
        'user_verdict': user_verdict,
        'user_comment': user_comment,
        'dismissed': dismissed,
        'dismissed_at': dismissed_at,
        'dismiss_ttl_days': dismiss_ttl_days,
        'evidence_json': evidence_json,
        'recommendation_json': recommendation_json
    }


def migrate_digest_file(digest_path, db_conn, day):
    """Migrate a single digest.json file to the database."""

    print(f"  Processing {digest_path.name}...")

    try:
        with open(digest_path, 'r') as f:
            digest = json.load(f)
    except Exception as e:
        print(f"    ⚠ Failed to load {digest_path}: {e}")
        return 0

    items = digest.get('items', [])
    migrated_count = 0

    cursor = db_conn.cursor()

    for item in items:
        try:
            alert = parse_digest_item(item, day)

            # Insert alert (ignore if already exists due to previous migration)
            cursor.execute("""
                INSERT OR IGNORE INTO alerts (
                    alert_id, kind, severity, status, verdict, confidence,
                    src_ip, src_name, dst_ip, dst_port, domain,
                    first_seen, last_seen, occurrence_count,
                    user_verdict, user_comment, dismissed, dismissed_at, dismiss_ttl_days,
                    evidence_json, recommendation_json
                ) VALUES (
                    :alert_id, :kind, :severity, :status, :verdict, :confidence,
                    :src_ip, :src_name, :dst_ip, :dst_port, :domain,
                    :first_seen, :last_seen, :occurrence_count,
                    :user_verdict, :user_comment, :dismissed, :dismissed_at, :dismiss_ttl_days,
                    :evidence_json, :recommendation_json
                )
            """, alert)

            if cursor.rowcount > 0:
                migrated_count += 1
        except Exception as e:
            print(f"    ⚠ Failed to migrate item: {e}")
            continue

    db_conn.commit()
    print(f"    ✓ Migrated {migrated_count} alerts")
    return migrated_count


def migrate_feedback_file(feedback_path, db_conn):
    """Migrate feedback.json to update alerts with user verdicts."""

    print(f"  Processing feedback.json...")

    if not feedback_path.exists():
        print("    No feedback.json found, skipping")
        return 0

    try:
        with open(feedback_path, 'r') as f:
            feedback = json.load(f)
    except Exception as e:
        print(f"    ⚠ Failed to load feedback.json: {e}")
        return 0

    updated_count = 0
    cursor = db_conn.cursor()

    for alert_id, feedback_data in feedback.items():
        try:
            user_verdict = feedback_data.get('verdict')
            user_comment = feedback_data.get('comment')
            dismissed = 1 if feedback_data.get('dismissed', False) else 0
            dismissed_at = feedback_data.get('dismissed_at')
            dismiss_ttl_days = feedback_data.get('suppress_ttl_days')

            cursor.execute("""
                UPDATE alerts
                SET user_verdict = ?,
                    user_comment = ?,
                    dismissed = ?,
                    dismissed_at = ?,
                    dismiss_ttl_days = ?,
                    status = CASE WHEN ? = 1 THEN 'dismissed' ELSE status END
                WHERE alert_id = ?
            """, (user_verdict, user_comment, dismissed, dismissed_at, dismiss_ttl_days, dismissed, alert_id))

            if cursor.rowcount > 0:
                updated_count += 1
        except Exception as e:
            print(f"    ⚠ Failed to apply feedback for {alert_id}: {e}")
            continue

    db_conn.commit()
    print(f"    ✓ Applied feedback to {updated_count} alerts")
    return updated_count


def main():
    parser = argparse.ArgumentParser(
        description='Migrate historical digest files to alerts.sqlite database'
    )
    parser.add_argument(
        '--workdir',
        required=True,
        help='Path to HOMENETSEC_WORKDIR (output directory)'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=30,
        help='Number of days of history to migrate (default: 30)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be migrated without actually doing it'
    )

    args = parser.parse_args()

    workdir = Path(args.workdir)
    if not workdir.exists():
        print(f"Error: WORKDIR does not exist: {workdir}", file=sys.stderr)
        return 1

    state_dir = workdir / 'state'
    alerts_db = state_dir / 'alerts.sqlite'

    if not alerts_db.exists():
        print(f"Error: alerts.sqlite does not exist: {alerts_db}", file=sys.stderr)
        print("Run init_databases.py first to create the schema", file=sys.stderr)
        return 1

    print(f"Migrating digest files from: {state_dir}")
    print(f"Target database: {alerts_db}")
    print(f"Looking back: {args.days} days")
    print()

    if args.dry_run:
        print("DRY RUN MODE - No data will be written")
        print()

    # Find digest files
    digest_files = sorted(state_dir.glob('*.digest.json'))

    if not digest_files:
        print("No digest files found in state directory")
        return 0

    print(f"Found {len(digest_files)} digest files")
    print()

    # Filter to recent files based on --days
    cutoff_date = datetime.now() - timedelta(days=args.days)
    recent_digests = []

    for digest_file in digest_files:
        # Extract date from filename (YYYY-MM-DD.digest.json)
        try:
            date_str = digest_file.stem.replace('.digest', '')
            file_date = datetime.strptime(date_str, '%Y-%m-%d')
            if file_date >= cutoff_date:
                recent_digests.append((date_str, digest_file))
        except ValueError:
            print(f"  ⚠ Skipping file with unexpected name: {digest_file.name}")
            continue

    print(f"Processing {len(recent_digests)} recent digest files (within {args.days} days)")
    print()

    if args.dry_run:
        for day, digest_file in recent_digests:
            print(f"  Would process: {digest_file.name} ({day})")
        return 0

    # Connect to database
    db_conn = sqlite3.connect(str(alerts_db))

    total_migrated = 0

    # Migrate each digest file
    for day, digest_file in recent_digests:
        count = migrate_digest_file(digest_file, db_conn, day)
        total_migrated += count

    # Migrate feedback
    feedback_file = state_dir / 'feedback.json'
    feedback_count = migrate_feedback_file(feedback_file, db_conn)

    db_conn.close()

    print()
    print("=" * 50)
    print(f"Migration complete!")
    print(f"Total alerts migrated: {total_migrated}")
    print(f"Feedback entries applied: {feedback_count}")
    print("=" * 50)

    return 0


if __name__ == '__main__':
    sys.exit(main())
