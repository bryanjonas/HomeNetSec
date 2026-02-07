#!/usr/bin/env python3
"""Detect anomaly candidates using the baseline DB + today's artifacts.

Outputs a small JSON document intended for LLM triage or direct alerting.

Signals implemented (v1):
- new external destinations (vs lookback days)
- new DNS domains (vs lookback days)
- watch-port tuple novelty
- high-fanout internal hosts (unique external dsts)
- RITA beacons above score threshold (if summary file exists)
- new TLS fingerprints (JA4/JA3) vs lookback

Quality gates:
- allowlist by dst IP, rdns suffix, domain suffix

This script is deterministic and should run fast.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import subprocess
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple


def rdns(ip: str) -> str:
    try:
        r = subprocess.run(["getent", "hosts", ip], capture_output=True, text=True, timeout=1)
        if r.returncode == 0 and r.stdout.strip():
            parts = r.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1]
    except Exception:
        pass
    return ""


def load_allowlist(path: Optional[str]) -> Dict[str, Any]:
    # Avoid yaml dependency; accept a simple JSON allowlist for now.
    if not path:
        return {}
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def is_allowlisted_dst(dst_ip: str, dst_rdns: str, allow: Dict[str, Any]) -> bool:
    ips = set(allow.get("dst_ips", []) or [])
    if dst_ip in ips:
        return True
    suffixes = allow.get("rdns_suffixes", []) or []
    for s in suffixes:
        if dst_rdns.endswith(s):
            return True
    return False


def is_allowlisted_domain(domain: str, allow: Dict[str, Any]) -> bool:
    doms = set(allow.get("domains", []) or [])
    if domain in doms:
        return True
    suffixes = allow.get("domain_suffixes", []) or []
    for s in suffixes:
        if domain.endswith(s):
            return True
    return False


def parse_rita_beacons(path: str, min_score: float) -> List[Dict[str, Any]]:
    # expects rita-summary file contains a CSV header line starting with "Score,Source IP,..."
    out: List[Dict[str, Any]] = []
    if not os.path.exists(path):
        return out
    in_beacons = False
    for line in open(path, "r", encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("Top beacons:"):
            in_beacons = True
            continue
        if line.startswith("Top long connections:"):
            break
        if not in_beacons:
            continue
        if line.startswith("Score,"):
            continue
        if line.startswith("("):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 4:
            continue
        try:
            score = float(parts[0])
        except Exception:
            continue
        if score < min_score:
            continue
        out.append({
            "score": score,
            "src_ip": parts[1],
            "dst_ip": parts[2],
            "connections": int(parts[3]) if parts[3].isdigit() else None,
            "top_interval": parts[-1] if parts else None,
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--day", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--lookback-days", type=int, default=30)
    ap.add_argument("--rita-min-score", type=float, default=0.97)
    ap.add_argument("--allowlist", default=None, help="Path to allowlist JSON")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    day = args.day
    workdir = args.workdir
    out_path = args.out
    lookback = max(1, args.lookback_days)

    allow = load_allowlist(args.allowlist)

    db = sqlite3.connect(args.db)
    db.row_factory = sqlite3.Row

    # compute lookback window days (strings)
    day_dt = dt.date.fromisoformat(day)
    days = [(day_dt - dt.timedelta(days=i)).isoformat() for i in range(1, lookback + 1)]

    # New destinations (any src)
    today_dsts = set(r[0] for r in db.execute("SELECT DISTINCT dst_ip FROM day_dest_counts WHERE day=?", (day,)))
    hist_dsts = set(r[0] for r in db.execute(
        "SELECT DISTINCT dst_ip FROM day_dest_counts WHERE day IN (%s)" % (" ,".join("?" * len(days))),
        days,
    )) if days else set()

    new_dsts = sorted(today_dsts - hist_dsts)

    # New domains
    today_domains = set(r[0] for r in db.execute("SELECT DISTINCT qname FROM day_dns_counts WHERE day=?", (day,)))
    hist_domains = set(r[0] for r in db.execute(
        "SELECT DISTINCT qname FROM day_dns_counts WHERE day IN (%s)" % (" ,".join("?" * len(days))),
        days,
    )) if days else set()
    new_domains = sorted(today_domains - hist_domains)

    # Watch tuple novelty
    today_watch = set(tuple(r) for r in db.execute("SELECT src_ip, dst_ip, dst_port FROM day_watch_counts WHERE day=?", (day,)))
    hist_watch = set(tuple(r) for r in db.execute(
        "SELECT DISTINCT src_ip, dst_ip, dst_port FROM day_watch_counts WHERE day IN (%s)" % (" ,".join("?" * len(days))),
        days,
    )) if days else set()
    new_watch = sorted(today_watch - hist_watch)

    # High fanout
    fanout_rows = list(db.execute(
        "SELECT src_ip, unique_external_dsts, total_external_conns FROM day_fanout WHERE day=? ORDER BY unique_external_dsts DESC LIMIT 20",
        (day,),
    ))

    # New TLS fingerprints (JA4/JA3)
    # Baseline DB may not have TLS tables yet (first runs or JA4 disabled); treat as empty.
    try:
        today_fps = set(tuple(r) for r in db.execute(
            "SELECT DISTINCT src_ip, dst_ip, fp_type, fp_value FROM day_tls_fp_counts WHERE day=?",
            (day,),
        ))
        hist_fps = set(tuple(r) for r in db.execute(
            "SELECT DISTINCT src_ip, dst_ip, fp_type, fp_value FROM day_tls_fp_counts WHERE day IN (%s)" % (" ,".join("?" * len(days))),
            days,
        )) if days else set()
        new_fps = sorted(today_fps - hist_fps)
    except sqlite3.OperationalError:
        new_fps = []

    # RITA beacons
    rita_summary = os.path.join(workdir, "rita-data", f"rita-summary-{day}.txt")
    rita_beacons = parse_rita_beacons(rita_summary, args.rita_min_score)

    # Apply allowlists
    new_dst_items = []
    for ip in new_dsts:
        name = rdns(ip)
        if is_allowlisted_dst(ip, name, allow):
            continue
        new_dst_items.append({"dst_ip": ip, "rdns": name})

    new_domain_items = [d for d in new_domains if not is_allowlisted_domain(d, allow)]

    new_watch_items = []
    for src, dst, port in new_watch:
        name = rdns(dst)
        if is_allowlisted_dst(dst, name, allow):
            continue
        new_watch_items.append({"src_ip": src, "dst_ip": dst, "dst_port": port, "rdns": name})

    new_fp_items = []
    for src, dst, fp_type, fp_value in new_fps:
        name = rdns(dst)
        if is_allowlisted_dst(dst, name, allow):
            continue
        new_fp_items.append({
            "src_ip": src,
            "dst_ip": dst,
            "dst_rdns": name,
            "fp_type": fp_type,
            "fp_value": fp_value,
        })

    # Filter RITA beacons by allowlist (dst)
    filtered_beacons = []
    for b in rita_beacons:
        name = rdns(b.get("dst_ip", "") or "")
        if b.get("dst_ip") and is_allowlisted_dst(b["dst_ip"], name, allow):
            continue
        b2 = dict(b)
        b2["dst_rdns"] = name
        filtered_beacons.append(b2)

    # Fanout gate: only keep above threshold if configured
    fanout_min = int(allow.get("fanout_min_unique_dsts", 50) or 50)
    fanout_items = [
        {
            "src_ip": r["src_ip"],
            "unique_external_dsts": int(r["unique_external_dsts"]),
            "total_external_conns": int(r["total_external_conns"]),
        }
        for r in fanout_rows
        if int(r["unique_external_dsts"]) >= fanout_min
    ]

    candidates: Dict[str, Any] = {
        "day": day,
        "lookback_days": lookback,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "signals": {
            "new_external_destinations": new_dst_items[:50],
            "new_domains": new_domain_items[:50],
            "new_watch_tuples": new_watch_items[:50],
            "high_fanout_hosts": fanout_items[:50],
            "rita_beacons": sorted(filtered_beacons, key=lambda x: x.get("score", 0), reverse=True)[:50],
            "new_tls_fingerprints": new_fp_items[:50],
        },
        "counts": {
            "new_external_destinations": len(new_dst_items),
            "new_domains": len(new_domain_items),
            "new_watch_tuples": len(new_watch_items),
            "high_fanout_hosts": len(fanout_items),
            "rita_beacons": len(filtered_beacons),
            "new_tls_fingerprints": len(new_fp_items),
        },
        "quality_gates": {
            "allowlist": args.allowlist or "",
            "fanout_min_unique_dsts": fanout_min,
            "rita_min_score": args.rita_min_score,
        },
    }

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(candidates, f, indent=2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
