#!/usr/bin/env python3
"""Shared helpers for continuous HomeNetSec alert detection."""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any


def rdns(ip: str) -> str:
    """Return the best-effort reverse DNS name for an IP."""
    if not ip:
        return ""
    try:
        result = subprocess.run(
            ["getent", "hosts", ip],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
        )
    except Exception:
        return ""
    if result.returncode != 0 or not result.stdout.strip():
        return ""
    parts = result.stdout.strip().split()
    return parts[1] if len(parts) >= 2 else ""


def load_allowlist(path: str | None) -> dict[str, Any]:
    """Load a small JSON allowlist file."""
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def is_allowlisted_dst(dst_ip: str, dst_rdns: str, allow: dict[str, Any]) -> bool:
    """Return True when a destination IP or rDNS suffix is allowlisted."""
    if dst_ip and dst_ip in set(allow.get("dst_ips", []) or []):
        return True
    for suffix in allow.get("rdns_suffixes", []) or []:
        if dst_rdns and dst_rdns.endswith(suffix):
            return True
    return False


def is_allowlisted_domain(domain: str, allow: dict[str, Any]) -> bool:
    """Return True when a domain or suffix is allowlisted."""
    if domain and domain in set(allow.get("domains", []) or []):
        return True
    for suffix in allow.get("domain_suffixes", []) or []:
        if domain and domain.endswith(suffix):
            return True
    return False


def parse_rita_beacons(path: str, min_score: float) -> list[dict[str, Any]]:
    """Parse RITA beacon output into structured records."""
    if not os.path.exists(path):
        return []

    beacons: list[dict[str, Any]] = []
    in_table = False
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("Top beacons:"):
                in_table = True
                continue
            if not in_table:
                continue
            if line.startswith("Top ") and not line.startswith("Top beacons:"):
                break
            if line.startswith("Score,") or line.startswith("("):
                continue
            parts = [part.strip() for part in line.split(",")]
            if len(parts) < 4:
                continue
            try:
                score = float(parts[0])
            except ValueError:
                continue
            if score < min_score:
                continue
            beacons.append(
                {
                    "score": score,
                    "src_ip": parts[1],
                    "dst_ip": parts[2],
                    "connections": int(parts[3]) if parts[3].isdigit() else None,
                    "top_interval": parts[-1] if parts else None,
                }
            )
    return beacons


def create_alert_from_new_destination(alerts, dst_ip: str, dst_rdns: str, label: str) -> str:
    """Create or update a new external destination alert."""
    evidence = {
        "destination": dst_ip,
        "rdns": dst_rdns,
        "label": label,
        "detection_type": "new_external_destination",
    }
    recommendation = {
        "action": "review",
        "reason": f"New external destination {dst_ip} appeared in the rolling baseline.",
    }
    return alerts.create_or_update_alert(
        kind="new_external_dest",
        severity="med",
        dst_ip=dst_ip,
        verdict="needs_review",
        confidence=0.64,
        evidence=evidence,
        recommendation=recommendation,
        analysis_run_id=label,
    )


def create_alert_from_new_domain(
    alerts,
    domain: str,
    label: str,
    src_ip: str | None = None,
    client_ids: list[str] | None = None,
) -> str:
    """Create or update a new domain alert with representative client context."""
    normalized_client_ids = [str(value).strip() for value in (client_ids or []) if str(value).strip()]
    if src_ip and src_ip not in normalized_client_ids:
        normalized_client_ids.insert(0, src_ip)

    evidence = {
        "domain": domain,
        "label": label,
        "detection_type": "new_domain",
        "client_ids": normalized_client_ids,
        "representative_client_ip": src_ip,
    }
    reason_suffix = f" First observed from client {src_ip}." if src_ip else ""
    recommendation = {
        "action": "review",
        "reason": f"Domain {domain} is new in the rolling baseline.{reason_suffix}",
    }
    # Keep the alert ID stable per-domain even when representative client shifts.
    alert_id = alerts.generate_alert_id(kind="new_domain", domain=domain)
    return alerts.create_or_update_alert(
        kind="new_domain",
        severity="med",
        src_ip=src_ip,
        domain=domain,
        verdict="needs_review",
        confidence=0.61,
        evidence=evidence,
        recommendation=recommendation,
        alert_id=alert_id,
        analysis_run_id=label,
    )


def create_alert_from_watch_tuple(alerts, src_ip: str, dst_ip: str, dst_port: str, dst_rdns: str, label: str) -> str:
    """Create or update a watch-port novelty alert."""
    evidence = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": int(dst_port),
        "rdns": dst_rdns,
        "label": label,
        "detection_type": "new_watch_tuple",
    }
    recommendation = {
        "action": "investigate",
        "reason": f"New watch-port tuple {src_ip} -> {dst_ip}:{dst_port} appeared in the rolling baseline.",
    }
    return alerts.create_or_update_alert(
        kind="new_watch_tuple",
        severity="high" if str(dst_port) in {"22", "445"} else "med",
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=int(dst_port),
        verdict="needs_review",
        confidence=0.73,
        evidence=evidence,
        recommendation=recommendation,
        analysis_run_id=label,
    )


def create_alert_from_new_tls_fp(alerts, src_ip: str, dst_ip: str, fp_type: str, fp_value: str, dst_rdns: str, label: str) -> str:
    """Create or update a new TLS fingerprint alert."""
    evidence = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "fp_type": fp_type,
        "fp_value": fp_value,
        "rdns": dst_rdns,
        "label": label,
        "detection_type": "new_tls_fp",
    }
    recommendation = {
        "action": "review",
        "reason": f"New TLS fingerprint {fp_type}={fp_value} was observed for {src_ip} -> {dst_ip}.",
    }
    return alerts.create_or_update_alert(
        kind="new_tls_fp",
        severity="med",
        src_ip=src_ip,
        dst_ip=dst_ip,
        verdict="needs_review",
        confidence=0.68,
        evidence=evidence,
        recommendation=recommendation,
        analysis_run_id=label,
    )


def create_alert_from_high_fanout(alerts, src_ip: str, unique_external_dsts: int, total_external_conns: int, label: str) -> str:
    """Create or update a high-fanout alert."""
    evidence = {
        "src_ip": src_ip,
        "unique_external_dsts": unique_external_dsts,
        "total_external_conns": total_external_conns,
        "label": label,
        "detection_type": "high_fanout",
    }
    recommendation = {
        "action": "investigate",
        "reason": f"{src_ip} contacted {unique_external_dsts} unique external destinations recently.",
    }
    severity = "high" if unique_external_dsts >= 100 else "med"
    return alerts.create_or_update_alert(
        kind="high_fanout",
        severity=severity,
        src_ip=src_ip,
        verdict="needs_review",
        confidence=0.76 if severity == "high" else 0.67,
        evidence=evidence,
        recommendation=recommendation,
        analysis_run_id=label,
    )


def create_alert_from_rita_beacon(alerts, beacon: dict[str, Any], label: str) -> str:
    """Create or update a RITA beacon alert."""
    src_ip = beacon.get("src_ip")
    dst_ip = beacon.get("dst_ip")
    score = float(beacon.get("score") or 0.0)
    evidence = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "score": score,
        "connections": beacon.get("connections"),
        "top_interval": beacon.get("top_interval"),
        "dst_rdns": beacon.get("dst_rdns"),
        "label": label,
        "detection_type": "rita_beacon",
    }
    recommendation = {
        "action": "investigate",
        "reason": f"RITA identified a likely beacon from {src_ip} to {dst_ip} with score {score:.2f}.",
    }
    severity = "critical" if score >= 0.995 else "high"
    confidence = 0.92 if severity == "critical" else 0.84
    return alerts.create_or_update_alert(
        kind="rita_beacon",
        severity=severity,
        src_ip=src_ip,
        dst_ip=dst_ip,
        verdict="needs_review",
        confidence=confidence,
        evidence=evidence,
        recommendation=recommendation,
        analysis_run_id=label,
    )
