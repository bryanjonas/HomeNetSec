#!/usr/bin/env python3
"""Ingest RITA beacon output into alerts.sqlite."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

from alert_db import AlertDB
from detect_candidates import create_alert_from_rita_beacon, parse_rita_beacons, rdns


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert RITA beacon output into alerts")
    parser.add_argument("--rita-output", required=True)
    parser.add_argument("--alerts-db", required=True)
    parser.add_argument("--label", default="continuous")
    parser.add_argument("--min-score", type=float, default=0.97)
    args = parser.parse_args()

    beacons = parse_rita_beacons(args.rita_output, args.min_score)
    if not beacons:
        return 0

    with AlertDB(args.alerts_db) as db:
        for beacon in beacons:
            enriched = dict(beacon)
            enriched["dst_rdns"] = rdns(beacon.get("dst_ip", "") or "")
            create_alert_from_rita_beacon(db, enriched, args.label)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
