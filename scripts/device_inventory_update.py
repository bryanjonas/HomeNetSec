#!/usr/bin/env python3
"""Update device inventory database from Zeek logs.

Discovers and tracks network devices automatically by analyzing Zeek conn.log.
Creates entries in devices.sqlite for device tracking and unknown device detection.

Usage:
    ./device_inventory_update.py --day YYYY-MM-DD --zeek-flat-dir /path --db /path/to/devices.sqlite

Exit codes:
    0 - Success
    1 - Update failed
"""

import argparse
import ipaddress
import json
import sqlite3
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional

# Private IP regex
PRIVATE_RE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)")
DEFAULT_VISIBLE_DEVICE_CIDRS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
DEFAULT_HIDDEN_DEVICE_CIDRS = "127.0.0.0/8,169.254.0.0/16,172.17.0.0/16,172.18.0.0/16,172.19.0.0/16,172.30.0.0/16"


def is_private(ip: str) -> bool:
    """Check if IP is in private address space."""
    return bool(PRIVATE_RE.match(ip))


def parse_cidrs(raw_value: str) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse comma-separated CIDRs into network objects."""
    networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in (raw_value or "").split(","):
        cidr = item.strip()
        if not cidr:
            continue
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return networks


VISIBLE_DEVICE_CIDRS = parse_cidrs(
    os.getenv("HOMENETSEC_VISIBLE_DEVICE_CIDRS", DEFAULT_VISIBLE_DEVICE_CIDRS)
)
HIDDEN_DEVICE_CIDRS = parse_cidrs(
    os.getenv("HOMENETSEC_HIDDEN_DEVICE_CIDRS", DEFAULT_HIDDEN_DEVICE_CIDRS)
)


def should_show_device_ip(ip_value: str) -> bool:
    """Return True when this IP should be shown in unknown-device reporting."""
    try:
        ip_obj = ipaddress.ip_address((ip_value or "").strip())
    except ValueError:
        return False

    if not ip_obj.is_private:
        return False

    if VISIBLE_DEVICE_CIDRS and not any(ip_obj in network for network in VISIBLE_DEVICE_CIDRS):
        return False

    if any(ip_obj in network for network in HIDDEN_DEVICE_CIDRS):
        return False

    return True


def parse_zeek_tsv(path: str):
    """Parse Zeek TSV log file and yield rows."""
    sep = "\t"
    fields = []

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#separator"):
                if "\\x09" in line:
                    sep = "\t"
                continue
            if line.startswith("#fields"):
                parts = line.split()
                fields = parts[1:]
                continue
            if line.startswith("#"):
                continue
            if not fields:
                continue
            yield dict(zip(fields, line.split(sep)))


def get_adguard_clients(env_file: Optional[str] = None) -> Dict[str, str]:
    """
    Fetch known clients from AdGuard Home API.

    Returns: {ip: friendly_name}
    """
    known_clients = {}

    adguard_url = os.getenv("ADGUARD_URL", "").strip().strip('"\'')
    adguard_user = os.getenv("ADGUARD_USER", "").strip().strip('"\'')
    adguard_pass = os.getenv("ADGUARD_PASS", "").strip().strip('"\'')

    # Prefer process environment credentials (e.g. sourced .env in pipeline scripts).
    # Fall back to credentials file if env vars are missing/incomplete.
    if not all([adguard_url, adguard_user, adguard_pass]):
        if not env_file:
            env_file = os.path.expanduser("~/.config/homenetsec/adguard.env")

        if os.path.exists(env_file):
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("ADGUARD_URL="):
                            adguard_url = line.split("=", 1)[1].strip('"\'')
                        elif line.startswith("ADGUARD_USER="):
                            adguard_user = line.split("=", 1)[1].strip('"\'')
                        elif line.startswith("ADGUARD_PASS="):
                            adguard_pass = line.split("=", 1)[1].strip('"\'')
            except Exception:
                return known_clients

    if not all([adguard_url, adguard_user, adguard_pass]):
        return known_clients

    # Query AdGuard Home API
    try:
        import requests

        response = requests.get(
            f"{adguard_url}/control/clients",
            auth=(adguard_user, adguard_pass),
            timeout=5
        )

        if response.status_code == 200:
            data = response.json()
            clients = data.get("clients", [])
            for client in clients:
                # Get IPs from various fields
                ips = client.get("ids", [])
                name = client.get("name", "")

                for ip in ips:
                    # Clean up IP (remove CIDR notation if present)
                    clean_ip = ip.split("/")[0]
                    if is_private(clean_ip):
                        known_clients[clean_ip] = name

    except Exception as e:
        print(f"Warning: Could not fetch AdGuard clients: {e}", file=sys.stderr)

    return known_clients


def detect_manufacturer(ip: str) -> Optional[str]:
    """
    Attempt to detect device manufacturer from MAC address (if available).

    This is a placeholder - in a real implementation, you'd look up the MAC
    prefix in an OUI database. For now, returns None.
    """
    # TODO: Implement MAC->Manufacturer lookup using OUI database
    return None


def update_device_inventory(
    db_path: str,
    conn_log_path: str,
    day: str,
    adguard_env: Optional[str] = None
) -> int:
    """
    Update device inventory from Zeek logs.

    Returns: number of devices updated
    """
    if not os.path.exists(conn_log_path):
        print(f"Warning: conn.log not found: {conn_log_path}", file=sys.stderr)
        return 0

    # Parse conn.log to collect device statistics
    device_stats = defaultdict(lambda: {
        "connections": 0,
        "upload_bytes": 0,
        "download_bytes": 0,
        "destinations": set(),
        "protocols": Counter(),
        "first_ts": None,
        "last_ts": None
    })
    activity_buckets = defaultdict(lambda: {
        "connections": 0,
        "upload_bytes": 0,
        "download_bytes": 0,
        "destinations": set(),
        "protocols": Counter(),
    })

    def safe_int(value, default=0):
        """Safely convert to int, handling Zeek's '-' for missing values."""
        if not value or value == '-':
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    print(f"Parsing {conn_log_path}...")
    for row in parse_zeek_tsv(conn_log_path):
        src_ip = row.get("id.orig_h", "")
        dst_ip = row.get("id.resp_h", "")
        proto = row.get("proto", "")
        orig_bytes = safe_int(row.get("orig_bytes"))
        resp_bytes = safe_int(row.get("resp_bytes"))
        ts = row.get("ts", "")

        # Track internal sources (our devices)
        if is_private(src_ip):
            stats = device_stats[src_ip]
            stats["connections"] += 1
            stats["upload_bytes"] += orig_bytes
            stats["download_bytes"] += resp_bytes
            if proto:
                stats["protocols"][proto] += 1

            if not is_private(dst_ip):
                stats["destinations"].add(dst_ip)

            if ts:
                if not stats["first_ts"] or ts < stats["first_ts"]:
                    stats["first_ts"] = ts
                if not stats["last_ts"] or ts > stats["last_ts"]:
                    stats["last_ts"] = ts

                try:
                    hour_bucket = datetime.fromtimestamp(float(ts)).replace(
                        minute=0, second=0, microsecond=0
                    ).isoformat() + "Z"
                    bucket = activity_buckets[(src_ip, hour_bucket)]
                    bucket["connections"] += 1
                    bucket["upload_bytes"] += orig_bytes
                    bucket["download_bytes"] += resp_bytes
                    if proto:
                        bucket["protocols"][proto] += 1
                    if not is_private(dst_ip):
                        bucket["destinations"].add(dst_ip)
                except (ValueError, TypeError):
                    pass

    print(f"Found {len(device_stats)} active devices")

    # Get known clients from AdGuard Home
    print("Fetching known clients from AdGuard Home...")
    known_clients = get_adguard_clients(adguard_env)
    print(f"Found {len(known_clients)} known clients in AdGuard Home")

    # Update database
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    cursor = db.cursor()

    updated_count = 0

    for ip, stats in device_stats.items():
        # Check if device exists
        existing = cursor.execute("SELECT ip, first_seen FROM devices WHERE ip = ?", (ip,)).fetchone()

        # Determine if device is known
        is_known = 1 if ip in known_clients else 0
        friendly_name = known_clients.get(ip, None)
        manufacturer = detect_manufacturer(ip)
        total_proto_count = sum(stats["protocols"].values()) or 1
        typical_protocols = json.dumps({
            proto: round(count / total_proto_count, 3)
            for proto, count in stats["protocols"].most_common()
        })
        active_hours = sorted({
            datetime.fromtimestamp(float(ts)).hour
            for ts in [stats["first_ts"], stats["last_ts"]]
            if ts
        })
        typical_active_hours = json.dumps(active_hours)

        # Convert timestamp to ISO format
        first_seen = stats["first_ts"] or f"{day}T00:00:00Z"
        last_seen = stats["last_ts"] or f"{day}T23:59:59Z"

        # Convert epoch timestamps if needed
        try:
            first_seen_dt = datetime.fromtimestamp(float(first_seen))
            first_seen = first_seen_dt.isoformat() + "Z"
        except (ValueError, TypeError):
            pass

        try:
            last_seen_dt = datetime.fromtimestamp(float(last_seen))
            last_seen = last_seen_dt.isoformat() + "Z"
        except (ValueError, TypeError):
            pass

        if existing:
            # Update existing device
            # Preserve original first_seen
            original_first_seen = existing["first_seen"]

            cursor.execute("""
                UPDATE devices SET
                    friendly_name = COALESCE(?, friendly_name),
                    manufacturer = COALESCE(?, manufacturer),
                    last_seen = ?,
                    total_connections = total_connections + ?,
                    total_upload_bytes = total_upload_bytes + ?,
                    total_download_bytes = total_download_bytes + ?,
                    unique_destinations_count = ?,
                    typical_active_hours = COALESCE(?, typical_active_hours),
                    typical_protocols = COALESCE(?, typical_protocols),
                    is_known = ?,
                    updated_at = datetime('now')
                WHERE ip = ?
            """, (
                friendly_name,
                manufacturer,
                last_seen,
                stats["connections"],
                stats["upload_bytes"],
                stats["download_bytes"],
                len(stats["destinations"]),
                typical_active_hours,
                typical_protocols,
                is_known,
                ip
            ))
        else:
            # Insert new device
            cursor.execute("""
                INSERT INTO devices (
                    ip, friendly_name, manufacturer,
                    first_seen, last_seen,
                    total_connections, total_upload_bytes, total_download_bytes,
                    unique_destinations_count,
                    typical_active_hours, typical_protocols,
                    is_known, is_monitored
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """, (
                ip,
                friendly_name,
                manufacturer,
                first_seen,
                last_seen,
                stats["connections"],
                stats["upload_bytes"],
                stats["download_bytes"],
                len(stats["destinations"]),
                typical_active_hours,
                typical_protocols,
                is_known
            ))

        updated_count += 1

    for (ip, hour_bucket), stats in activity_buckets.items():
        protocol_distribution = json.dumps(dict(stats["protocols"]))
        existing_activity = cursor.execute("""
            SELECT id FROM device_activity
            WHERE ip = ? AND hour_bucket = ?
        """, (ip, hour_bucket)).fetchone()

        if existing_activity:
            cursor.execute("""
                UPDATE device_activity
                SET connection_count = connection_count + ?,
                    upload_bytes = upload_bytes + ?,
                    download_bytes = download_bytes + ?,
                    unique_destinations = ?,
                    protocol_distribution = ?
                WHERE id = ?
            """, (
                stats["connections"],
                stats["upload_bytes"],
                stats["download_bytes"],
                len(stats["destinations"]),
                protocol_distribution,
                existing_activity["id"],
            ))
        else:
            cursor.execute("""
                INSERT INTO device_activity (
                    ip, hour_bucket, connection_count, upload_bytes,
                    download_bytes, unique_destinations, protocol_distribution
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ip,
                hour_bucket,
                stats["connections"],
                stats["upload_bytes"],
                stats["download_bytes"],
                len(stats["destinations"]),
                protocol_distribution,
            ))

    db.commit()

    # Report unknown devices
    unknown_devices = cursor.execute("""
        SELECT ip, first_seen, last_seen, total_connections
        FROM devices
        WHERE is_known = 0
          AND last_seen >= datetime('now', '-7 days')
        ORDER BY last_seen DESC
    """).fetchall()

    visible_unknown_devices = [
        device for device in unknown_devices if should_show_device_ip(device["ip"])
    ]

    if visible_unknown_devices:
        print(f"\n⚠ Found {len(visible_unknown_devices)} unknown devices:")
        for device in visible_unknown_devices:
            print(f"  {device['ip']} - Last seen: {device['last_seen']} ({device['total_connections']} connections)")
    elif unknown_devices:
        print("\nℹ Unknown devices were detected only in hidden infrastructure ranges.")

    db.close()

    return updated_count


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Update device inventory from Zeek logs'
    )
    parser.add_argument(
        '--day',
        required=True,
        help='Day being analyzed (YYYY-MM-DD)'
    )
    parser.add_argument(
        '--zeek-flat-dir',
        help='Directory containing flattened Zeek logs'
    )
    parser.add_argument(
        '--zeek-dir',
        help='Directory containing flattened Zeek logs'
    )
    parser.add_argument(
        '--db',
        required=True,
        help='Path to devices.sqlite database'
    )
    parser.add_argument(
        '--adguard-env',
        help='Path to AdGuard Home credentials file (default: ~/.config/homenetsec/adguard.env)'
    )

    args = parser.parse_args()

    conn_log_path = None
    if args.zeek_dir:
        conn_log_path = os.path.join(args.zeek_dir, 'conn.log')
    elif args.zeek_flat_dir:
        conn_log_path = os.path.join(args.zeek_flat_dir, 'conn.log')

    if not conn_log_path:
        print("Error: either --zeek-dir or --zeek-flat-dir is required", file=sys.stderr)
        return 1

    if not os.path.exists(os.path.dirname(conn_log_path)):
        print(f"Error: Zeek directory does not exist: {os.path.dirname(conn_log_path)}", file=sys.stderr)
        return 1

    if not os.path.exists(args.db):
        print(f"Error: Database does not exist: {args.db}", file=sys.stderr)
        print("Run init_databases.py first to create the schema", file=sys.stderr)
        return 1

    updated_count = update_device_inventory(
        args.db,
        conn_log_path,
        args.day,
        args.adguard_env
    )

    print(f"\n✓ Device inventory updated: {updated_count} devices")

    return 0


if __name__ == '__main__':
    sys.exit(main())
