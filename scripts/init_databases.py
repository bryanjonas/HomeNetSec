#!/usr/bin/env python3
"""
Initialize alerts.sqlite and devices.sqlite databases with schemas.

This script creates the database schemas for persistent alert tracking
and device inventory management in the optimized HomeNetSec architecture.

Usage:
    ./scripts/init_databases.py --workdir /path/to/output

Exit codes:
    0 - Success
    1 - Database initialization failed
"""

import argparse
import sqlite3
import sys
from pathlib import Path


def ensure_column(cursor, table_name, column_name, definition):
    """Add a column when upgrading an existing schema in place."""
    columns = {
        row[1]
        for row in cursor.execute(f"PRAGMA table_info({table_name})").fetchall()
    }
    if column_name not in columns:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def init_alerts_database(db_path):
    """Initialize alerts.sqlite with schema."""
    print(f"Initializing alerts database: {db_path}")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Enable foreign keys
    cursor.execute("PRAGMA foreign_keys = ON")

    # Create alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new',
            verdict TEXT,
            confidence REAL,
            triage_verdict TEXT,
            triage_summary TEXT,
            triage_reasoning_json TEXT,
            triage_confidence REAL,
            triage_source TEXT,
            triage_updated_at TEXT,

            src_ip TEXT,
            src_name TEXT,
            dst_ip TEXT,
            dst_port INTEGER,
            domain TEXT,

            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            occurrence_count INTEGER DEFAULT 1,

            investigated_at TEXT,
            investigated_by TEXT,
            resolved_at TEXT,
            resolution_note TEXT,

            user_verdict TEXT,
            user_comment TEXT,
            dismissed BOOLEAN DEFAULT 0,
            dismissed_at TEXT,
            dismiss_ttl_days INTEGER,

            evidence_json TEXT,
            recommendation_json TEXT,

            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # Create indexes for alerts
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_dst_ip ON alerts(dst_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_first_seen ON alerts(first_seen)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status_first_seen ON alerts(status, first_seen DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_kind ON alerts(kind)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_dismissed ON alerts(dismissed)")
    ensure_column(cursor, "alerts", "investigated_by", "TEXT")
    ensure_column(cursor, "alerts", "resolved_at", "TEXT")
    ensure_column(cursor, "alerts", "resolution_note", "TEXT")
    ensure_column(cursor, "alerts", "user_verdict", "TEXT")
    ensure_column(cursor, "alerts", "user_comment", "TEXT")
    ensure_column(cursor, "alerts", "dismissed", "BOOLEAN DEFAULT 0")
    ensure_column(cursor, "alerts", "dismissed_at", "TEXT")
    ensure_column(cursor, "alerts", "dismiss_ttl_days", "INTEGER")
    ensure_column(cursor, "alerts", "evidence_json", "TEXT")
    ensure_column(cursor, "alerts", "recommendation_json", "TEXT")
    ensure_column(cursor, "alerts", "updated_at", "TEXT")
    ensure_column(cursor, "alerts", "triage_verdict", "TEXT")
    ensure_column(cursor, "alerts", "triage_summary", "TEXT")
    ensure_column(cursor, "alerts", "triage_reasoning_json", "TEXT")
    ensure_column(cursor, "alerts", "triage_confidence", "REAL")
    ensure_column(cursor, "alerts", "triage_source", "TEXT")
    ensure_column(cursor, "alerts", "triage_updated_at", "TEXT")

    # Create alert_occurrences table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_occurrences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            analysis_run_id TEXT,
            pcap_source TEXT,
            evidence_delta_json TEXT,
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
        )
    """)
    ensure_column(cursor, "alert_occurrences", "pcap_source", "TEXT")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_occurrences_alert_id ON alert_occurrences(alert_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_occurrences_occurred_at ON alert_occurrences(occurred_at)")

    # Create alert_state_changes table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_state_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            from_status TEXT,
            to_status TEXT,
            changed_by TEXT,
            changed_at TEXT NOT NULL DEFAULT (datetime('now')),
            reason TEXT,
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_state_changes_alert_id ON alert_state_changes(alert_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_state_changes_changed_at ON alert_state_changes(changed_at)")

    # Create alert_triage_history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_triage_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            triage_verdict TEXT,
            triage_summary TEXT,
            triage_reasoning_json TEXT,
            triage_confidence REAL,
            triage_source TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_triage_history_alert_id ON alert_triage_history(alert_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_triage_history_created_at ON alert_triage_history(created_at)")

    conn.commit()
    conn.close()

    print(f"✓ Alerts database initialized successfully")


def init_devices_database(db_path):
    """Initialize devices.sqlite with schema."""
    print(f"Initializing devices database: {db_path}")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create devices table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            friendly_name TEXT,
            device_type TEXT,
            manufacturer TEXT,

            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,

            total_connections INTEGER DEFAULT 0,
            total_upload_bytes INTEGER DEFAULT 0,
            total_download_bytes INTEGER DEFAULT 0,
            unique_destinations_count INTEGER DEFAULT 0,

            typical_active_hours TEXT,
            typical_protocols TEXT,
            typical_services TEXT,

            is_known BOOLEAN DEFAULT 0,
            is_trusted BOOLEAN DEFAULT 0,
            is_monitored BOOLEAN DEFAULT 1,

            notes TEXT,
            tags TEXT,

            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_is_known ON devices(is_known)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_is_monitored ON devices(is_monitored)")
    ensure_column(cursor, "devices", "device_type", "TEXT")
    ensure_column(cursor, "devices", "typical_active_hours", "TEXT")
    ensure_column(cursor, "devices", "typical_protocols", "TEXT")
    ensure_column(cursor, "devices", "typical_services", "TEXT")
    ensure_column(cursor, "devices", "is_trusted", "BOOLEAN DEFAULT 0")

    # Create unknown_devices view
    cursor.execute("""
        CREATE VIEW IF NOT EXISTS unknown_devices AS
        SELECT * FROM devices
        WHERE is_known = 0
          AND last_seen >= datetime('now', '-7 days')
    """)

    # Create device_activity table (optional for future use)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            hour_bucket TEXT NOT NULL,

            connection_count INTEGER DEFAULT 0,
            upload_bytes INTEGER DEFAULT 0,
            download_bytes INTEGER DEFAULT 0,
            unique_destinations INTEGER DEFAULT 0,
            protocol_distribution TEXT,

            FOREIGN KEY (ip) REFERENCES devices(ip)
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_activity_ip_hour ON device_activity(ip, hour_bucket)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_activity_hour ON device_activity(hour_bucket)")

    conn.commit()
    conn.close()

    print(f"✓ Devices database initialized successfully")


def main():
    parser = argparse.ArgumentParser(
        description='Initialize alerts and devices databases for HomeNetSec'
    )
    parser.add_argument(
        '--workdir',
        required=True,
        help='Path to HOMENETSEC_WORKDIR (output directory)'
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Recreate databases even if they exist (CAUTION: destroys existing data)'
    )

    args = parser.parse_args()

    workdir = Path(args.workdir)
    if not workdir.exists():
        print(f"Error: WORKDIR does not exist: {workdir}", file=sys.stderr)
        return 1

    state_dir = workdir / 'state'
    state_dir.mkdir(exist_ok=True)

    alerts_db = state_dir / 'alerts.sqlite'
    devices_db = state_dir / 'devices.sqlite'

    # Always run schema initialization so existing installs receive in-place
    # migrations via the ensure_column calls in the init helpers.
    if args.force and alerts_db.exists():
        print(f"Removing existing alerts database: {alerts_db}")
        alerts_db.unlink()
    elif alerts_db.exists():
        print(f"Alerts database already exists: {alerts_db}")
        print("Applying in-place schema checks and migrations")
    init_alerts_database(str(alerts_db))

    if args.force and devices_db.exists():
        print(f"Removing existing devices database: {devices_db}")
        devices_db.unlink()
    elif devices_db.exists():
        print(f"Devices database already exists: {devices_db}")
        print("Applying in-place schema checks and migrations")
    init_devices_database(str(devices_db))

    print("\n✓ Database initialization complete")
    print(f"  Alerts DB:  {alerts_db}")
    print(f"  Devices DB: {devices_db}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
