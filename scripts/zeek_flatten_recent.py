#!/usr/bin/env python3
"""Flatten recent Zeek logs into a staging directory for continuous RITA imports."""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import os
from pathlib import Path

LOG_TYPES = ("conn.log", "dns.log", "http.log", "ssl.log", "weird.log", "notice.log")


def main() -> int:
    parser = argparse.ArgumentParser(description="Flatten recent Zeek logs for RITA")
    parser.add_argument("--zeek-logs-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--lookback-hours", type=int, default=2)
    args = parser.parse_args()

    zeek_root = Path(args.zeek_logs_dir)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=args.lookback_hours)
    recent_dirs = []
    for path in zeek_root.glob("**/*.zeek"):
        try:
            mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)
        except FileNotFoundError:
            continue
        if mtime >= cutoff:
            recent_dirs.append(path)

    for log_type in LOG_TYPES:
        out_path = output_dir / log_type
        with open(out_path, "w", encoding="utf-8") as out_handle:
            wrote_header = False
            for zeek_dir in sorted(recent_dirs):
                log_path = zeek_dir / log_type
                if not log_path.exists():
                    continue
                with open(log_path, "r", encoding="utf-8", errors="replace") as in_handle:
                    for line in in_handle:
                        if line.startswith("#"):
                            if not wrote_header:
                                out_handle.write(line)
                            continue
                        wrote_header = True
                        out_handle.write(line)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
