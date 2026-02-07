#!/usr/bin/env python3
"""Update HomeNetSec baseline SQLite DB from today's Zeek logs.

Inputs (all paths are host paths):
- --day YYYY-MM-DD
- --zeek-flat-dir: directory containing flattened Zeek logs for the day (conn.log, dns.log, ssl.log, ...)
- --db: sqlite path to write/update

We store daily aggregates that enable:
- new/rare destination detection
- spikes vs recent baseline
- high-fanout internal hosts
- DNS novelty/NXDOMAIN rates
- watch-port tuple tracking

This is designed to be deterministic, cheap, and to keep LLM inputs small.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import sqlite3
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Tuple

PRIVATE_RE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)")

WATCH_PORTS = {"22", "445", "8883", "8443"}


def is_private(ip: str) -> bool:
    return bool(PRIVATE_RE.match(ip))


def parse_zeek_tsv(path: str) -> Tuple[List[str], Iterable[List[str]]]:
    """Yield rows for Zeek TSV (ASCII) logs, skipping comments.

    Returns (fields, rows_iterable)
    """
    sep = "\t"
    fields: List[str] = []

    def rows():
        nonlocal sep, fields
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
                yield line.split(sep)

    return fields, rows()


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;

        CREATE TABLE IF NOT EXISTS meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS day_dest_counts (
          day TEXT NOT NULL,
          src_ip TEXT NOT NULL,
          dst_ip TEXT NOT NULL,
          count INTEGER NOT NULL,
          PRIMARY KEY(day, src_ip, dst_ip)
        );

        CREATE TABLE IF NOT EXISTS day_dest_unique (
          day TEXT NOT NULL,
          src_ip TEXT NOT NULL,
          dst_ip TEXT NOT NULL,
          PRIMARY KEY(day, src_ip, dst_ip)
        );

        CREATE TABLE IF NOT EXISTS day_watch_counts (
          day TEXT NOT NULL,
          src_ip TEXT NOT NULL,
          dst_ip TEXT NOT NULL,
          dst_port TEXT NOT NULL,
          count INTEGER NOT NULL,
          PRIMARY KEY(day, src_ip, dst_ip, dst_port)
        );

        CREATE TABLE IF NOT EXISTS day_dns_counts (
          day TEXT NOT NULL,
          client_ip TEXT NOT NULL,
          qname TEXT NOT NULL,
          rcode TEXT NOT NULL,
          count INTEGER NOT NULL,
          PRIMARY KEY(day, client_ip, qname, rcode)
        );

        CREATE TABLE IF NOT EXISTS day_fanout (
          day TEXT NOT NULL,
          src_ip TEXT NOT NULL,
          unique_external_dsts INTEGER NOT NULL,
          total_external_conns INTEGER NOT NULL,
          PRIMARY KEY(day, src_ip)
        );

        CREATE INDEX IF NOT EXISTS idx_day_dest_counts_day ON day_dest_counts(day);
        CREATE INDEX IF NOT EXISTS idx_day_dns_counts_day ON day_dns_counts(day);
        CREATE INDEX IF NOT EXISTS idx_day_watch_counts_day ON day_watch_counts(day);
        """
    )


def upsert_many(conn: sqlite3.Connection, sql: str, rows: Iterable[Tuple]) -> None:
    conn.executemany(sql, list(rows))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--day", required=True)
    ap.add_argument("--zeek-flat-dir", required=True)
    ap.add_argument("--db", required=True)
    args = ap.parse_args()

    day = args.day
    zeek_flat = args.zeek_flat_dir
    db_path = args.db

    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn_log = os.path.join(zeek_flat, "conn.log")
    dns_log = os.path.join(zeek_flat, "dns.log")

    dest_counts: Counter[Tuple[str, str]] = Counter()  # (src, dst)
    watch_counts: Counter[Tuple[str, str, str]] = Counter()  # (src, dst, port)
    fanout_dsts: Dict[str, set] = defaultdict(set)
    fanout_total: Counter[str] = Counter()

    if os.path.exists(conn_log):
        fields, rows = parse_zeek_tsv(conn_log)
        idx = {name: i for i, name in enumerate(fields)}

        def get(cols, name, default=""):
            i = idx.get(name)
            if i is None or i >= len(cols):
                return default
            v = cols[i]
            return "" if v in ("-", "(empty)") else v

        for cols in rows:
            src = get(cols, "id.orig_h")
            dst = get(cols, "id.resp_h")
            port = get(cols, "id.resp_p")
            proto = get(cols, "proto")

            if not src or not dst:
                continue
            # Only count private -> external
            if not is_private(src) or is_private(dst):
                continue

            dest_counts[(src, dst)] += 1
            fanout_total[src] += 1
            fanout_dsts[src].add(dst)

            if proto == "tcp" and port in WATCH_PORTS:
                watch_counts[(src, dst, port)] += 1

    dns_counts: Counter[Tuple[str, str, str]] = Counter()  # (client, qname, rcode)
    if os.path.exists(dns_log):
        fields, rows = parse_zeek_tsv(dns_log)
        idx = {name: i for i, name in enumerate(fields)}

        def get(cols, name, default=""):
            i = idx.get(name)
            if i is None or i >= len(cols):
                return default
            v = cols[i]
            return "" if v in ("-", "(empty)") else v

        for cols in rows:
            client = get(cols, "id.orig_h")
            qname = get(cols, "query")
            rcode = get(cols, "rcode_name") or get(cols, "rcode")

            if not client or not qname:
                continue
            dns_counts[(client, qname.lower().rstrip("."), rcode or "")] += 1

    db = sqlite3.connect(db_path)
    try:
        ensure_schema(db)
        db.execute("DELETE FROM day_dest_counts WHERE day=?", (day,))
        db.execute("DELETE FROM day_dest_unique WHERE day=?", (day,))
        db.execute("DELETE FROM day_watch_counts WHERE day=?", (day,))
        db.execute("DELETE FROM day_dns_counts WHERE day=?", (day,))
        db.execute("DELETE FROM day_fanout WHERE day=?", (day,))

        upsert_many(
            db,
            "INSERT OR REPLACE INTO day_dest_counts(day, src_ip, dst_ip, count) VALUES (?,?,?,?)",
            ((day, src, dst, c) for (src, dst), c in dest_counts.items()),
        )
        upsert_many(
            db,
            "INSERT OR REPLACE INTO day_dest_unique(day, src_ip, dst_ip) VALUES (?,?,?)",
            ((day, src, dst) for (src, dst) in dest_counts.keys()),
        )
        upsert_many(
            db,
            "INSERT OR REPLACE INTO day_watch_counts(day, src_ip, dst_ip, dst_port, count) VALUES (?,?,?,?,?)",
            ((day, src, dst, port, c) for (src, dst, port), c in watch_counts.items()),
        )
        upsert_many(
            db,
            "INSERT OR REPLACE INTO day_dns_counts(day, client_ip, qname, rcode, count) VALUES (?,?,?,?,?)",
            ((day, client, qname, rcode, c) for (client, qname, rcode), c in dns_counts.items()),
        )
        upsert_many(
            db,
            "INSERT OR REPLACE INTO day_fanout(day, src_ip, unique_external_dsts, total_external_conns) VALUES (?,?,?,?)",
            ((day, src, len(dsts), fanout_total[src]) for src, dsts in fanout_dsts.items()),
        )

        db.commit()
    finally:
        db.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
