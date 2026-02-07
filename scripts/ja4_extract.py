#!/usr/bin/env python3
"""Extract TLS fingerprints from Suricata eve.json and store daily aggregates.

Suricata eve.json TLS events may include fields like:
- tls.ja3 / tls.ja3s
- tls.ja4 / tls.ja4s (depending on Suricata version)
- src_ip, dest_ip
- sni

We store counts per (day, src_ip, dst_ip, fp_type, fp_value).
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from collections import Counter
from typing import Dict, Iterable, Tuple


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS day_tls_fp_counts (
          day TEXT NOT NULL,
          src_ip TEXT NOT NULL,
          dst_ip TEXT NOT NULL,
          fp_type TEXT NOT NULL,
          fp_value TEXT NOT NULL,
          count INTEGER NOT NULL,
          PRIMARY KEY(day, src_ip, dst_ip, fp_type, fp_value)
        );

        CREATE TABLE IF NOT EXISTS day_tls_sni_counts (
          day TEXT NOT NULL,
          src_ip TEXT NOT NULL,
          dst_ip TEXT NOT NULL,
          sni TEXT NOT NULL,
          count INTEGER NOT NULL,
          PRIMARY KEY(day, src_ip, dst_ip, sni)
        );

        CREATE INDEX IF NOT EXISTS idx_day_tls_fp_counts_day ON day_tls_fp_counts(day);
        CREATE INDEX IF NOT EXISTS idx_day_tls_sni_counts_day ON day_tls_sni_counts(day);
        """
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--day", required=True)
    ap.add_argument("--eve", required=True, help="Path to suricata eve.json")
    ap.add_argument("--db", required=True, help="Path to baselines sqlite")
    args = ap.parse_args()

    day = args.day
    eve_path = args.eve

    fp_counts: Counter[Tuple[str, str, str, str]] = Counter()  # (src,dst,type,val)
    sni_counts: Counter[Tuple[str, str, str]] = Counter()  # (src,dst,sni)

    if not os.path.exists(eve_path):
        return 0

    with open(eve_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue

            if ev.get("event_type") != "tls":
                continue
            src = ev.get("src_ip")
            dst = ev.get("dest_ip")
            tls = ev.get("tls") or {}
            if not src or not dst:
                continue

            # Collect whatever fingerprint fields exist
            for fp_type in ("ja4", "ja4s", "ja3", "ja3s"):
                v = tls.get(fp_type)
                if v:
                    fp_counts[(src, dst, fp_type, str(v))] += 1

            sni = tls.get("sni")
            if sni:
                sni_counts[(src, dst, str(sni).lower().rstrip("."))] += 1

    os.makedirs(os.path.dirname(args.db), exist_ok=True)
    db = sqlite3.connect(args.db)
    try:
        ensure_schema(db)
        db.execute("DELETE FROM day_tls_fp_counts WHERE day=?", (day,))
        db.execute("DELETE FROM day_tls_sni_counts WHERE day=?", (day,))

        db.executemany(
            "INSERT OR REPLACE INTO day_tls_fp_counts(day, src_ip, dst_ip, fp_type, fp_value, count) VALUES (?,?,?,?,?,?)",
            [(day, src, dst, t, v, c) for (src, dst, t, v), c in fp_counts.items()],
        )
        db.executemany(
            "INSERT OR REPLACE INTO day_tls_sni_counts(day, src_ip, dst_ip, sni, count) VALUES (?,?,?,?,?)",
            [(day, src, dst, sni, c) for (src, dst, sni), c in sni_counts.items()],
        )

        db.commit()
    finally:
        db.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
