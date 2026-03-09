#!/usr/bin/env python3
"""Update rolling HomeNetSec baselines from a single Zeek/Surricata artifact set.

This script maintains the continuous rolling-baseline tables.
It writes hourly aggregates and is designed to be idempotent per source_key.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Tuple

PRIVATE_RE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)")
WATCH_PORTS = {"22", "445", "8883", "8443"}


def is_private(ip: str) -> bool:
    return bool(PRIVATE_RE.match(ip))


def parse_zeek_tsv(path: str) -> Iterator[Dict[str, str]]:
    sep = "\t"
    fields: List[str] = []

    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
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


def hour_bucket_from_epoch(value: str) -> str | None:
    try:
        bucket = dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc).replace(
            minute=0,
            second=0,
            microsecond=0,
        )
        return bucket.isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
        return None


def hour_bucket_from_suricata_timestamp(value: str) -> str | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    bucket = parsed.astimezone(dt.timezone.utc).replace(minute=0, second=0, microsecond=0)
    return bucket.isoformat().replace("+00:00", "Z")


def load_watch_ports_local(workdir: str) -> set[str]:
    path = os.environ.get("HOMENETSEC_WATCH_PORTS_FILE") or os.path.join(workdir, "state", "watch_ports.local.txt")
    if not os.path.exists(path):
        return set()

    ports: set[str] = set()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^(\d{1,5})", line)
            if not match:
                continue
            port = match.group(1)
            try:
                if 0 < int(port) < 65536:
                    ports.add(port)
            except ValueError:
                continue
    return ports


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;

        CREATE TABLE IF NOT EXISTS meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS processed_artifacts (
          source_key TEXT PRIMARY KEY,
          processed_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS dest_counts_rolling (
          hour_bucket TEXT NOT NULL,
          src_ip TEXT NOT NULL,
          dst_ip TEXT NOT NULL,
          count INTEGER NOT NULL,
          bytes_sent INTEGER NOT NULL DEFAULT 0,
          bytes_received INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(hour_bucket, src_ip, dst_ip)
        );

        CREATE TABLE IF NOT EXISTS dns_counts_rolling (
          hour_bucket TEXT NOT NULL,
          client_ip TEXT NOT NULL,
          qname TEXT NOT NULL,
          rcode TEXT NOT NULL,
          count INTEGER NOT NULL,
          PRIMARY KEY(hour_bucket, client_ip, qname, rcode)
        );

        CREATE TABLE IF NOT EXISTS watch_counts_rolling (
          hour_bucket TEXT NOT NULL,
          src_ip TEXT NOT NULL,
          dst_ip TEXT NOT NULL,
          dst_port TEXT NOT NULL,
          count INTEGER NOT NULL,
          PRIMARY KEY(hour_bucket, src_ip, dst_ip, dst_port)
        );

        CREATE TABLE IF NOT EXISTS tls_fp_rolling (
          hour_bucket TEXT NOT NULL,
          src_ip TEXT NOT NULL,
          dst_ip TEXT NOT NULL,
          fp_type TEXT NOT NULL,
          fp_value TEXT NOT NULL,
          count INTEGER NOT NULL,
          PRIMARY KEY(hour_bucket, src_ip, dst_ip, fp_type, fp_value)
        );

        CREATE INDEX IF NOT EXISTS idx_dest_counts_rolling_hour ON dest_counts_rolling(hour_bucket);
        CREATE INDEX IF NOT EXISTS idx_dns_counts_rolling_hour ON dns_counts_rolling(hour_bucket);
        CREATE INDEX IF NOT EXISTS idx_watch_counts_rolling_hour ON watch_counts_rolling(hour_bucket);
        CREATE INDEX IF NOT EXISTS idx_tls_fp_rolling_hour ON tls_fp_rolling(hour_bucket);
        """
    )


def upsert_counter(
    conn: sqlite3.Connection,
    sql: str,
    rows: Iterable[Tuple],
) -> None:
    conn.executemany(sql, list(rows))


def cleanup_old_rows(conn: sqlite3.Connection, retention_hours: int) -> None:
    cutoff = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=retention_hours)
    ).replace(minute=0, second=0, microsecond=0).isoformat().replace("+00:00", "Z")

    for table_name in (
        "dest_counts_rolling",
        "dns_counts_rolling",
        "watch_counts_rolling",
        "tls_fp_rolling",
    ):
        conn.execute(f"DELETE FROM {table_name} WHERE hour_bucket < ?", (cutoff,))


def process_conn_log(
    conn_log: Path,
    watch_ports: set[str],
) -> tuple[
    Counter[Tuple[str, str, str]],
    Counter[Tuple[str, str, str, str]],
]:
    dest_counts: Counter[Tuple[str, str, str]] = Counter()
    watch_counts: Counter[Tuple[str, str, str, str]] = Counter()

    if not conn_log.exists():
        return dest_counts, watch_counts

    for row in parse_zeek_tsv(str(conn_log)):
        src = row.get("id.orig_h", "")
        dst = row.get("id.resp_h", "")
        port = row.get("id.resp_p", "")
        proto = row.get("proto", "")
        bucket = hour_bucket_from_epoch(row.get("ts", ""))
        if not bucket or not src or not dst:
            continue
        if not is_private(src) or is_private(dst):
            continue

        orig_bytes = row.get("orig_bytes") or "0"
        resp_bytes = row.get("resp_bytes") or "0"
        try:
            sent = int(orig_bytes if orig_bytes != "-" else 0)
        except ValueError:
            sent = 0
        try:
            received = int(resp_bytes if resp_bytes != "-" else 0)
        except ValueError:
            received = 0

        dest_counts[(bucket, src, dst)] += 1
        dest_counts[(bucket, src, dst, "sent")] += sent
        dest_counts[(bucket, src, dst, "received")] += received

        if proto == "tcp" and port in watch_ports:
            watch_counts[(bucket, src, dst, port)] += 1

    return dest_counts, watch_counts


def process_dns_log(dns_log: Path) -> Counter[Tuple[str, str, str, str]]:
    dns_counts: Counter[Tuple[str, str, str, str]] = Counter()
    if not dns_log.exists():
        return dns_counts

    for row in parse_zeek_tsv(str(dns_log)):
        client = row.get("id.orig_h", "")
        qname = (row.get("query") or "").lower().rstrip(".")
        rcode = row.get("rcode_name") or row.get("rcode") or ""
        bucket = hour_bucket_from_epoch(row.get("ts", ""))
        if not bucket or not client or not qname:
            continue
        dns_counts[(bucket, client, qname, rcode)] += 1

    return dns_counts


def process_eve(eve_path: Path) -> Counter[Tuple[str, str, str, str, str]]:
    fp_counts: Counter[Tuple[str, str, str, str, str]] = Counter()
    if not eve_path.exists():
        return fp_counts

    with open(eve_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "tls":
                continue
            src = event.get("src_ip")
            dst = event.get("dest_ip")
            bucket = hour_bucket_from_suricata_timestamp(event.get("timestamp", ""))
            if not bucket or not src or not dst:
                continue

            tls = event.get("tls") or {}
            for fp_type in ("ja4", "ja4s", "ja3", "ja3s"):
                value = tls.get(fp_type)
                if value:
                    fp_counts[(bucket, src, dst, fp_type, str(value))] += 1

    return fp_counts


def latest_seen_bucket(counters: List[Counter]) -> str | None:
    buckets = set()
    for counter in counters:
        for key in counter.keys():
            buckets.add(key[0])
    return max(buckets) if buckets else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Update rolling baselines from continuous artifacts")
    parser.add_argument("--zeek-dir", required=True, help="Directory containing Zeek logs for one merged PCAP")
    parser.add_argument("--db", required=True, help="Path to rolling baselines sqlite")
    parser.add_argument("--eve", help="Optional Suricata EVE path for the same merged PCAP")
    parser.add_argument("--source-key", help="Unique source key for idempotency; defaults to zeek-dir path")
    parser.add_argument("--retention-hours", type=int, default=24 * 30, help="Retention window for rolling rows")
    args = parser.parse_args()

    zeek_dir = Path(args.zeek_dir)
    source_key = args.source_key or str(zeek_dir.resolve())
    eve_path = Path(args.eve) if args.eve else None

    os.makedirs(os.path.dirname(args.db), exist_ok=True)
    db = sqlite3.connect(args.db)
    try:
        ensure_schema(db)

        if db.execute(
            "SELECT 1 FROM processed_artifacts WHERE source_key = ?",
            (source_key,),
        ).fetchone():
            return 0

        default_workdir = str(zeek_dir.parents[2]) if len(zeek_dir.parents) >= 3 else str(zeek_dir.parent)
        workdir = os.environ.get("HOMENETSEC_WORKDIR") or default_workdir
        watch_ports = WATCH_PORTS | load_watch_ports_local(workdir)

        dest_counts_raw, watch_counts = process_conn_log(zeek_dir / "conn.log", watch_ports)
        dns_counts = process_dns_log(zeek_dir / "dns.log")
        fp_counts = process_eve(eve_path) if eve_path else Counter()

        cleanup_old_rows(db, args.retention_hours)

        dest_rows = []
        for key, count in dest_counts_raw.items():
            if len(key) == 4:
                continue
            bucket, src, dst = key
            sent = dest_counts_raw.get((bucket, src, dst, "sent"), 0)
            received = dest_counts_raw.get((bucket, src, dst, "received"), 0)
            dest_rows.append((bucket, src, dst, count, sent, received))

        upsert_counter(
            db,
            """
            INSERT INTO dest_counts_rolling(hour_bucket, src_ip, dst_ip, count, bytes_sent, bytes_received)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(hour_bucket, src_ip, dst_ip) DO UPDATE SET
              count = count + excluded.count,
              bytes_sent = bytes_sent + excluded.bytes_sent,
              bytes_received = bytes_received + excluded.bytes_received
            """,
            dest_rows,
        )
        upsert_counter(
            db,
            """
            INSERT INTO dns_counts_rolling(hour_bucket, client_ip, qname, rcode, count)
            VALUES (?,?,?,?,?)
            ON CONFLICT(hour_bucket, client_ip, qname, rcode) DO UPDATE SET
              count = count + excluded.count
            """,
            ((bucket, client, qname, rcode, count) for (bucket, client, qname, rcode), count in dns_counts.items()),
        )
        upsert_counter(
            db,
            """
            INSERT INTO watch_counts_rolling(hour_bucket, src_ip, dst_ip, dst_port, count)
            VALUES (?,?,?,?,?)
            ON CONFLICT(hour_bucket, src_ip, dst_ip, dst_port) DO UPDATE SET
              count = count + excluded.count
            """,
            ((bucket, src, dst, port, count) for (bucket, src, dst, port), count in watch_counts.items()),
        )
        upsert_counter(
            db,
            """
            INSERT INTO tls_fp_rolling(hour_bucket, src_ip, dst_ip, fp_type, fp_value, count)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(hour_bucket, src_ip, dst_ip, fp_type, fp_value) DO UPDATE SET
              count = count + excluded.count
            """,
            ((bucket, src, dst, fp_type, fp_value, count) for (bucket, src, dst, fp_type, fp_value), count in fp_counts.items()),
        )

        latest_bucket = latest_seen_bucket([dest_counts_raw, dns_counts, fp_counts, watch_counts])
        db.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('continuous_latest_bucket', ?)",
            (latest_bucket or "",),
        )
        db.execute(
            "INSERT OR REPLACE INTO processed_artifacts(source_key, processed_at) VALUES (?, datetime('now'))",
            (source_key,),
        )
        db.commit()
    finally:
        db.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
