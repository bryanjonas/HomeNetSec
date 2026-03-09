#!/usr/bin/env python3
"""Detect continuous alerts from rolling baseline tables."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sqlite3
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

from alert_db import AlertDB
from detect_candidates import (
    create_alert_from_high_fanout,
    create_alert_from_new_destination,
    create_alert_from_new_domain,
    create_alert_from_new_tls_fp,
    create_alert_from_rita_beacon,
    create_alert_from_watch_tuple,
    is_allowlisted_domain,
    is_allowlisted_dst,
    load_allowlist,
    parse_rita_beacons,
    rdns,
)


def latest_bucket(conn: sqlite3.Connection) -> str | None:
    buckets = []
    for table_name in ("dest_counts_rolling", "dns_counts_rolling", "watch_counts_rolling", "tls_fp_rolling"):
        try:
            row = conn.execute(f"SELECT MAX(hour_bucket) FROM {table_name}").fetchone()
        except sqlite3.OperationalError:
            continue
        if row and row[0]:
            buckets.append(row[0])
    return max(buckets) if buckets else None


def iso_bucket_hours_ago(bucket: str, hours: int) -> str:
    parsed = dt.datetime.fromisoformat(bucket.replace("Z", "+00:00"))
    cutoff = parsed - dt.timedelta(hours=hours)
    return cutoff.isoformat().replace("+00:00", "Z")


def distinct_values(conn: sqlite3.Connection, table: str, column_sql: str, where_sql: str, params: tuple) -> set:
    rows = conn.execute(
        f"SELECT DISTINCT {column_sql} FROM {table} WHERE {where_sql}",
        params,
    ).fetchall()
    return {tuple(row) if len(row) > 1 else row[0] for row in rows}


def build_recent_domain_clients(conn: sqlite3.Connection, recent_cutoff: str, latest: str) -> dict[str, dict[str, object]]:
    """Return representative client IDs for domains observed in the recent window."""
    try:
        rows = conn.execute(
            """
            SELECT
                qname,
                client_ip,
                SUM(count) AS query_count
            FROM dns_counts_rolling
            WHERE hour_bucket >= ? AND hour_bucket <= ?
              AND COALESCE(client_ip, '') != ''
            GROUP BY qname, client_ip
            ORDER BY qname ASC, query_count DESC, client_ip ASC
            """,
            (recent_cutoff, latest),
        ).fetchall()
    except sqlite3.OperationalError:
        return {}

    by_domain: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        domain = str(row["qname"] or "").strip()
        client_ip = str(row["client_ip"] or "").strip()
        if not domain or not client_ip:
            continue
        by_domain.setdefault(domain, []).append(
            {
                "client_ip": client_ip,
                "query_count": int(row["query_count"] or 0),
            }
        )

    result: dict[str, dict[str, object]] = {}
    for domain, clients in by_domain.items():
        primary = clients[0]["client_ip"] if clients else None
        result[domain] = {
            "primary_client_ip": primary,
            "client_ids": [entry["client_ip"] for entry in clients[:5]],
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect alerts from rolling continuous baselines")
    parser.add_argument("--baseline-db", required=True, help="Path to rolling baselines sqlite")
    parser.add_argument("--alerts-db", required=True, help="Path to alerts sqlite")
    parser.add_argument("--devices-db", help="Optional devices sqlite path")
    parser.add_argument("--workdir", help="HomeNetSec workdir (used for RITA output defaults)")
    parser.add_argument("--allowlist", help="Allowlist JSON path")
    parser.add_argument("--lookback-hours", type=int, default=24 * 30, help="Historical baseline window")
    parser.add_argument("--recent-hours", type=int, default=2, help="Recent window to evaluate")
    parser.add_argument("--fanout-min-unique-dsts", type=int, default=50, help="High-fanout threshold")
    parser.add_argument("--rita-output", help="Optional RITA beacon output file")
    parser.add_argument("--rita-min-score", type=float, default=0.97, help="Minimum RITA beacon score")
    args = parser.parse_args()

    allow = load_allowlist(args.allowlist)
    baseline = sqlite3.connect(args.baseline_db)
    baseline.row_factory = sqlite3.Row

    try:
        latest = latest_bucket(baseline)
        if not latest:
            return 0

        recent_cutoff = iso_bucket_hours_ago(latest, args.recent_hours)
        historical_cutoff = iso_bucket_hours_ago(latest, args.lookback_hours)
        label = latest[:13]

        recent_dsts = distinct_values(
            baseline,
            "dest_counts_rolling",
            "dst_ip",
            "hour_bucket >= ? AND hour_bucket <= ?",
            (recent_cutoff, latest),
        )
        historical_dsts = distinct_values(
            baseline,
            "dest_counts_rolling",
            "dst_ip",
            "hour_bucket >= ? AND hour_bucket < ?",
            (historical_cutoff, recent_cutoff),
        )

        recent_domains = distinct_values(
            baseline,
            "dns_counts_rolling",
            "qname",
            "hour_bucket >= ? AND hour_bucket <= ?",
            (recent_cutoff, latest),
        )
        recent_domain_clients = build_recent_domain_clients(baseline, recent_cutoff, latest)
        historical_domains = distinct_values(
            baseline,
            "dns_counts_rolling",
            "qname",
            "hour_bucket >= ? AND hour_bucket < ?",
            (historical_cutoff, recent_cutoff),
        )

        recent_watch = distinct_values(
            baseline,
            "watch_counts_rolling",
            "src_ip, dst_ip, dst_port",
            "hour_bucket >= ? AND hour_bucket <= ?",
            (recent_cutoff, latest),
        )
        historical_watch = distinct_values(
            baseline,
            "watch_counts_rolling",
            "src_ip, dst_ip, dst_port",
            "hour_bucket >= ? AND hour_bucket < ?",
            (historical_cutoff, recent_cutoff),
        )

        try:
            recent_fps = distinct_values(
                baseline,
                "tls_fp_rolling",
                "src_ip, dst_ip, fp_type, fp_value",
                "hour_bucket >= ? AND hour_bucket <= ?",
                (recent_cutoff, latest),
            )
            historical_fps = distinct_values(
                baseline,
                "tls_fp_rolling",
                "src_ip, dst_ip, fp_type, fp_value",
                "hour_bucket >= ? AND hour_bucket < ?",
                (historical_cutoff, recent_cutoff),
            )
        except sqlite3.OperationalError:
            recent_fps = set()
            historical_fps = set()

        fanout_rows = baseline.execute(
            """
            SELECT src_ip, COUNT(DISTINCT dst_ip) AS unique_external_dsts, SUM(count) AS total_external_conns
            FROM dest_counts_rolling
            WHERE hour_bucket >= ? AND hour_bucket <= ?
            GROUP BY src_ip
            HAVING COUNT(DISTINCT dst_ip) >= ?
            ORDER BY unique_external_dsts DESC
            LIMIT 50
            """,
            (recent_cutoff, latest, max(args.fanout_min_unique_dsts, int(allow.get("fanout_min_unique_dsts", args.fanout_min_unique_dsts) or args.fanout_min_unique_dsts))),
        ).fetchall()

        rita_output = args.rita_output
        if not rita_output and args.workdir:
            rita_output = os.path.join(args.workdir, "rita-data", "beacons_latest.txt")
        beacons = parse_rita_beacons(rita_output, args.rita_min_score) if rita_output else []

        with AlertDB(args.alerts_db) as alerts:
            for dst_ip in sorted(recent_dsts - historical_dsts):
                name = rdns(dst_ip)
                if is_allowlisted_dst(dst_ip, name, allow):
                    continue
                create_alert_from_new_destination(alerts, dst_ip, name, label)

            for domain in sorted(recent_domains - historical_domains):
                if is_allowlisted_domain(domain, allow):
                    continue
                context = recent_domain_clients.get(domain) or {}
                create_alert_from_new_domain(
                    alerts,
                    domain,
                    label,
                    src_ip=context.get("primary_client_ip"),
                    client_ids=context.get("client_ids"),
                )

            for src_ip, dst_ip, dst_port in sorted(recent_watch - historical_watch):
                name = rdns(dst_ip)
                if is_allowlisted_dst(dst_ip, name, allow):
                    continue
                create_alert_from_watch_tuple(alerts, src_ip, dst_ip, str(dst_port), name, label)

            for src_ip, dst_ip, fp_type, fp_value in sorted(recent_fps - historical_fps):
                name = rdns(dst_ip)
                if is_allowlisted_dst(dst_ip, name, allow):
                    continue
                create_alert_from_new_tls_fp(alerts, src_ip, dst_ip, fp_type, fp_value, name, label)

            for row in fanout_rows:
                create_alert_from_high_fanout(
                    alerts,
                    row["src_ip"],
                    int(row["unique_external_dsts"]),
                    int(row["total_external_conns"]),
                    label,
                )

            for beacon in sorted(beacons, key=lambda item: item.get("score", 0), reverse=True)[:50]:
                name = rdns(beacon.get("dst_ip", "") or "")
                if beacon.get("dst_ip") and is_allowlisted_dst(beacon["dst_ip"], name, allow):
                    continue
                beacon = dict(beacon)
                beacon["dst_rdns"] = name
                create_alert_from_rita_beacon(alerts, beacon, label)
    finally:
        baseline.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
