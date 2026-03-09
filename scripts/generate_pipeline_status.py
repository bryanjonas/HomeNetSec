#!/usr/bin/env python3
"""Generate or update the continuous pipeline status document."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def count_nonempty_lines(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def latest_mtime_iso(path: Path) -> str | None:
    latest = None
    if path.is_file():
        latest = path.stat().st_mtime
    elif path.is_dir():
        for root, _dirs, files in os.walk(path):
            for filename in files:
                try:
                    mtime = (Path(root) / filename).stat().st_mtime
                except OSError:
                    continue
                latest = mtime if latest is None else max(latest, mtime)
    if latest is None:
        return None
    return isoformat(datetime.fromtimestamp(latest, tz=timezone.utc))


def directory_size_mb(path: Path) -> float:
    total = 0
    if not path.exists():
        return 0.0
    for root, _dirs, files in os.walk(path):
        for filename in files:
            try:
                total += (Path(root) / filename).stat().st_size
            except OSError:
                continue
    return round(total / (1024 * 1024), 2)


def epoch_to_iso(epoch: int | None) -> str | None:
    if not epoch:
        return None
    return isoformat(datetime.fromtimestamp(epoch, tz=timezone.utc))


def derive_coverage(workdir: Path) -> Dict[str, Any]:
    ingest_state = load_json(workdir / "state" / "ingest_state.json")
    pending = ingest_state.get("pending") or []
    cutoff = utc_now() - timedelta(hours=24)
    missing_intervals: List[str] = []

    recent_missing = 0
    for item in pending:
        epoch = int(item.get("epoch", 0) or 0)
        if epoch <= 0:
            continue
        ts = datetime.fromtimestamp(epoch, tz=timezone.utc)
        if ts >= cutoff:
            recent_missing += 1
            missing_intervals.append(isoformat(ts))

    coverage_percent = max(0.0, 100.0 - min(recent_missing * 5.0, 100.0))
    gap_free_since = epoch_to_iso(
        int(
            ingest_state.get("last_contiguous_epoch")
            or ingest_state.get("last_merged_epoch")
            or ingest_state.get("last_epoch")
            or 0
        )
    )

    return {
        "gap_free_since": gap_free_since,
        "coverage_percent_24h": round(coverage_percent, 1),
        "missing_intervals": missing_intervals[:25],
    }


def count_recent_merged_inputs(workdir: Path, hours: int = 24) -> int:
    """Count source PCAP inputs represented by merge manifests in the recent window."""
    pcap_root = workdir / "pcaps"
    if not pcap_root.exists():
        return 0

    cutoff_epoch = int((utc_now() - timedelta(hours=hours)).timestamp())
    total_inputs = 0

    for manifest_path in pcap_root.rglob("*.manifest.json"):
        payload = load_json(manifest_path)
        if not payload:
            continue

        merged_epoch = payload.get("merged_at_epoch")
        try:
            merged_epoch = int(merged_epoch or 0)
        except (TypeError, ValueError):
            merged_epoch = 0
        if merged_epoch < cutoff_epoch:
            continue

        inputs = payload.get("inputs")
        if isinstance(inputs, list) and inputs:
            total_inputs += len(inputs)
        else:
            # Some older/backfilled manifests may not include individual inputs.
            total_inputs += 1

    return total_inputs


def derive_rita(workdir: Path, existing: Dict[str, Any]) -> Dict[str, Any]:
    rita_dir = workdir / "rita-data"
    beacon_file = rita_dir / "beacons_latest.txt"
    last_import = latest_mtime_iso(beacon_file) or existing.get("last_import")
    if beacon_file.exists():
        record_count = count_nonempty_lines(beacon_file)
    else:
        record_count = int(existing.get("records_count") or 0)
    dataset_size_mb = existing.get("dataset_size_mb")
    if dataset_size_mb in (None, ""):
        dataset_size_mb = directory_size_mb(rita_dir)

    status = existing.get("status")
    if not status:
        status = "healthy" if last_import else "idle"
    message = existing.get("message")
    if not message:
        if status == "disabled":
            message = "RITA processing is disabled"
        elif status == "healthy":
            message = "RITA import and beacon extraction completed"
        elif status == "idle":
            message = "No recent RITA activity"
        elif status in {"error", "failed"}:
            message = "RITA processing reported failures"
        else:
            message = f"RITA status is {status}"

    return {
        "status": status,
        "message": message,
        "dataset_size_mb": dataset_size_mb,
        "last_import": last_import,
        "records_count": record_count or 0,
    }


def merge_section(existing: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(existing)
    for key, value in updates.items():
        if value is not None:
            merged[key] = value
    return merged


def derive_overall_status(doc: Dict[str, Any]) -> Dict[str, str]:
    overall = doc.get("overall") or {}
    if overall.get("status") in {"failed", "error", "running", "success"}:
        status = overall["status"]
    else:
        states = [doc.get("ingest", {}).get("status"), doc.get("analysis", {}).get("status"), doc.get("rita", {}).get("status")]
        if any(state in {"failed", "error"} for state in states):
            status = "error"
        elif any(state == "running" for state in states):
            status = "running"
        elif any(state in {"healthy", "idle", "completed", "success", "disabled"} for state in states if state):
            status = "healthy"
        else:
            status = "unknown"

    message = overall.get("message")
    if not message:
        if status == "error":
            message = "One or more pipeline sections are reporting failures"
        elif status == "running":
            message = "Pipeline activity in progress"
        elif status == "healthy":
            message = "Continuous pipeline healthy"
        else:
            message = "No pipeline status available"
    return {"status": status, "message": message}


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate or update pipeline_status.json")
    parser.add_argument("--workdir", required=True, help="HomeNetSec workdir/output path")
    parser.add_argument("--section", choices=["ingest", "analysis", "rita"], help="Section to update")
    parser.add_argument("--status", help="Section status")
    parser.add_argument("--message", help="Section message")
    parser.add_argument("--queue-depth", type=int, help="Queue depth for section")
    parser.add_argument("--next-expected-seconds", type=int, help="Seconds until next expected run")
    parser.add_argument("--pcaps-processed-24h", type=int, help="Recent PCAP count for ingest")
    parser.add_argument("--errors-24h", type=int, help="Recent error count")
    parser.add_argument("--avg-processing-time-sec", type=float, help="Rolling average analysis runtime")
    parser.add_argument("--last-duration-sec", type=float, help="Latest section runtime")
    parser.add_argument("--last-import", help="RITA last import timestamp")
    parser.add_argument("--dataset-size-mb", type=float, help="RITA dataset size")
    parser.add_argument("--records-count", type=int, help="RITA record count")
    parser.add_argument("--overall-status", help="Overall pipeline status")
    parser.add_argument("--overall-message", help="Overall pipeline message")
    args = parser.parse_args()

    workdir = Path(args.workdir)
    state_dir = workdir / "state"
    status_path = state_dir / "pipeline_status.json"
    queue_path = state_dir / "analysis_queue.txt"
    now = utc_now()

    doc = load_json(status_path)
    doc["updated_at"] = isoformat(now)

    queue_depth = args.queue_depth
    if queue_depth is None:
        queue_depth = count_nonempty_lines(queue_path)

    if args.section == "ingest":
        existing = doc.get("ingest") or {}
        pcaps_processed = args.pcaps_processed_24h
        if pcaps_processed is None:
            pcaps_processed = count_recent_merged_inputs(workdir, hours=24)
        if args.next_expected_seconds is None:
            existing.pop("next_expected", None)

        ingest_updates = {
            "status": args.status,
            "message": args.message,
            "last_run": isoformat(now),
            "pcaps_processed_24h": pcaps_processed,
            "queue_depth": queue_depth,
            "errors_24h": args.errors_24h if args.errors_24h is not None else existing.get("errors_24h", 0),
        }
        if args.next_expected_seconds is not None:
            ingest_updates["next_expected"] = isoformat(now + timedelta(seconds=args.next_expected_seconds))

        doc["ingest"] = merge_section(
            existing,
            ingest_updates,
        )

    if args.section == "analysis":
        existing = doc.get("analysis") or {}
        run_count = int(existing.get("run_count", 0) or 0)
        avg = existing.get("avg_processing_time_sec")
        if args.last_duration_sec is not None:
            previous_total = (float(avg or 0) * run_count) if run_count else 0.0
            run_count += 1
            avg = round((previous_total + float(args.last_duration_sec)) / run_count, 2)
        elif args.avg_processing_time_sec is not None:
            avg = args.avg_processing_time_sec
        doc["analysis"] = merge_section(
            existing,
            {
                "status": args.status,
                "message": args.message,
                "last_run": isoformat(now),
                "queue_depth": queue_depth,
                "avg_processing_time_sec": avg if avg is not None else 0.0,
                "errors_24h": args.errors_24h if args.errors_24h is not None else existing.get("errors_24h", 0),
                "run_count": run_count if run_count else existing.get("run_count", 0),
                "last_duration_sec": round(float(args.last_duration_sec), 2) if args.last_duration_sec is not None else existing.get("last_duration_sec"),
            },
        )

    if args.section == "rita":
        existing = doc.get("rita") or {}
        updated = merge_section(
            existing,
            {
                "status": args.status,
                "message": args.message,
                "last_import": args.last_import,
                "dataset_size_mb": args.dataset_size_mb,
                "records_count": args.records_count,
            },
        )
        doc["rita"] = derive_rita(workdir, updated)

    if args.overall_status or args.overall_message:
        doc["overall"] = merge_section(
            doc.get("overall") or {},
            {
                "status": args.overall_status,
                "message": args.overall_message,
                "last_run": isoformat(now),
            },
        )

    doc["coverage"] = derive_coverage(workdir)
    doc["rita"] = derive_rita(workdir, doc.get("rita") or {})
    doc.setdefault(
        "ingest",
        {
            "status": "unknown",
            "last_run": None,
            "pcaps_processed_24h": 0,
            "queue_depth": queue_depth,
            "errors_24h": 0,
            "message": "No ingest status available",
        },
    )
    doc.setdefault(
        "analysis",
        {
            "status": "unknown",
            "last_run": None,
            "queue_depth": queue_depth,
            "avg_processing_time_sec": 0.0,
            "errors_24h": 0,
            "message": "No analysis status available",
            "run_count": 0,
        },
    )

    overall = derive_overall_status(doc)
    doc["status"] = overall["status"]
    doc["message"] = overall["message"]
    doc["overall"] = merge_section(doc.get("overall") or {}, overall)

    save_json(status_path, doc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
