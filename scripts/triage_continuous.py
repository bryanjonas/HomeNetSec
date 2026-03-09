#!/usr/bin/env python3
"""Apply deterministic alert triage to the continuous alerts database."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

from alert_db import AlertDB

BENIGN_VERDICTS = {
    "allowlisted",
    "benign",
    "expected",
    "false_positive",
    "likely_benign",
    "resolved_benign",
}
MALICIOUS_VERDICTS = {
    "compromised",
    "confirmed_malicious",
    "likely_malicious",
    "malicious",
    "suspicious",
}
SEVERITY_SCORES = {
    "critical": 3,
    "high": 2,
    "med": 1,
    "low": 0,
    "info": 0,
}
ACTIVE_QUERY = """
    SELECT *
    FROM alerts
    WHERE dismissed = 0
      AND status NOT IN ('resolved', 'dismissed')
    ORDER BY
        CASE severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'med' THEN 3
            WHEN 'low' THEN 4
            ELSE 5
        END,
        last_seen DESC
"""
DEFAULT_ADGUARD_QUERYLOG_LIMIT = 500


def parse_json_field(value: Any, default: Any) -> Any:
    """Safely decode JSON columns."""
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def row_to_alert(row: sqlite3.Row) -> dict[str, Any]:
    """Convert an alert row to a dict with parsed JSON fields."""
    alert = dict(row)
    alert["evidence"] = parse_json_field(alert.get("evidence_json"), {})
    alert["recommendation"] = parse_json_field(alert.get("recommendation_json"), {})
    alert["triage_reasoning"] = parse_json_field(alert.get("triage_reasoning_json"), {})
    return alert


def load_adguard_credentials(env_file: str | None = None) -> tuple[str, str, str]:
    """Load AdGuard credentials from environment or optional env-file fallback."""
    adguard_url = os.getenv("ADGUARD_URL", "").strip().strip('"\'')
    adguard_user = os.getenv("ADGUARD_USER", "").strip().strip('"\'')
    adguard_pass = os.getenv("ADGUARD_PASS", "").strip().strip('"\'')

    if all((adguard_url, adguard_user, adguard_pass)):
        return adguard_url.rstrip("/"), adguard_user, adguard_pass

    if not env_file:
        env_file = os.path.expanduser("~/.config/homenetsec/adguard.env")

    if not os.path.exists(env_file):
        return "", "", ""

    try:
        with open(env_file, "r", encoding="utf-8") as handle:
            for line in handle:
                raw = line.strip()
                if raw.startswith("ADGUARD_URL="):
                    adguard_url = raw.split("=", 1)[1].strip().strip('"\'')
                elif raw.startswith("ADGUARD_USER="):
                    adguard_user = raw.split("=", 1)[1].strip().strip('"\'')
                elif raw.startswith("ADGUARD_PASS="):
                    adguard_pass = raw.split("=", 1)[1].strip().strip('"\'')
    except OSError:
        return "", "", ""

    if not all((adguard_url, adguard_user, adguard_pass)):
        return "", "", ""

    return adguard_url.rstrip("/"), adguard_user, adguard_pass


def fetch_adguard_querylog_index(
    adguard_env: str | None = None,
    query_limit: int = DEFAULT_ADGUARD_QUERYLOG_LIMIT,
) -> dict[str, list[dict[str, Any]]]:
    """Fetch recent AdGuard querylog and index by client IP."""
    adguard_url, adguard_user, adguard_pass = load_adguard_credentials(adguard_env)
    if not all((adguard_url, adguard_user, adguard_pass)):
        return {}

    safe_limit = max(1, min(int(query_limit), 5000))
    endpoint = f"{adguard_url}/control/querylog?{urllib.parse.urlencode({'limit': safe_limit})}"
    auth = base64.b64encode(f"{adguard_user}:{adguard_pass}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        endpoint,
        headers={
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError):
        return {}

    entries = payload.get("data")
    if not isinstance(entries, list):
        return {}

    by_client: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        client_ip = str(entry.get("client") or "").strip()
        question = entry.get("question") or {}
        domain = str(question.get("name") or "").strip().rstrip(".")
        if not client_ip or not domain:
            continue

        answers = []
        for answer in entry.get("answer") or []:
            if not isinstance(answer, dict):
                continue
            value = str(answer.get("value") or "").strip()
            if value:
                answers.append(value)

        client_info = entry.get("client_info") or {}
        client_name = str(client_info.get("name") or "").strip()

        by_client.setdefault(client_ip, []).append(
            {
                "domain": domain,
                "time": entry.get("time"),
                "status": entry.get("status"),
                "answers": answers,
                "client_name": client_name or None,
            }
        )

    return by_client


def lookup_adguard_context(
    alert: dict[str, Any],
    querylog_index: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """Find recent AdGuard domain evidence for this alert's source IP."""
    src_ip = alert.get("src_ip")
    if not src_ip:
        return {}

    entries = querylog_index.get(src_ip) or []
    if not entries:
        return {}

    dst_ip = str(alert.get("dst_ip") or "").strip()
    alert_domain = str(alert.get("domain") or "").strip().rstrip(".").lower()

    for entry in entries:
        answers = [str(value).strip() for value in entry.get("answers") or [] if value]
        if dst_ip and dst_ip in answers:
            return {
                "domain": entry.get("domain"),
                "time": entry.get("time"),
                "status": entry.get("status"),
                "matched_by": "answer_ip",
                "matched_dst_ip": dst_ip,
                "client_name": entry.get("client_name"),
            }

    if alert_domain:
        for entry in entries:
            domain = str(entry.get("domain") or "").strip().rstrip(".").lower()
            if domain == alert_domain:
                return {
                    "domain": entry.get("domain"),
                    "time": entry.get("time"),
                    "status": entry.get("status"),
                    "matched_by": "alert_domain",
                    "client_name": entry.get("client_name"),
                }

    latest = entries[0]
    return {
        "domain": latest.get("domain"),
        "time": latest.get("time"),
        "status": latest.get("status"),
        "matched_by": "recent_query",
        "client_name": latest.get("client_name"),
    }


def normalize_feedback(row: sqlite3.Row) -> str:
    """Map historical review outcomes into benign/malicious/review buckets."""
    verdict = str(row["user_verdict"] or "").strip().lower()
    triage = str(row["triage_verdict"] or "").strip().lower()

    if verdict in BENIGN_VERDICTS:
        return "benign"
    if verdict in MALICIOUS_VERDICTS:
        return "malicious"
    if row["dismissed"] or row["status"] == "dismissed":
        return "benign"
    if triage in BENIGN_VERDICTS:
        return "benign"
    if triage in MALICIOUS_VERDICTS:
        return "malicious"
    return "review"


def fetch_device_context(conn: sqlite3.Connection | None, src_ip: str | None) -> dict[str, Any]:
    """Load current device context for the alert source IP."""
    if conn is None or not src_ip:
        return {}
    try:
        row = conn.execute(
            """
            SELECT
                ip,
                friendly_name,
                device_type,
                manufacturer,
                is_known,
                is_trusted,
                is_monitored,
                total_connections,
                unique_destinations_count,
                typical_protocols,
                notes,
                tags
            FROM devices
            WHERE ip = ?
            """,
            (src_ip,),
        ).fetchone()
    except sqlite3.OperationalError:
        return {}
    return dict(row) if row else {}


def fetch_baseline_context(conn: sqlite3.Connection | None, alert: dict[str, Any]) -> dict[str, Any]:
    """Build recent rolling-baseline context for the alert pattern."""
    if conn is None:
        return {}

    context: dict[str, Any] = {}
    src_ip = alert.get("src_ip")
    dst_ip = alert.get("dst_ip")
    dst_port = alert.get("dst_port")
    domain = alert.get("domain")

    try:
        if src_ip:
            row = conn.execute(
                """
                SELECT
                    COUNT(DISTINCT dst_ip) AS unique_destinations,
                    SUM(count) AS total_connections,
                    COUNT(DISTINCT hour_bucket) AS active_hours
                FROM dest_counts_rolling
                WHERE src_ip = ?
                """,
                (src_ip,),
            ).fetchone()
            if row:
                context["source_recent_activity"] = {
                    "unique_destinations": int(row["unique_destinations"] or 0),
                    "total_connections": int(row["total_connections"] or 0),
                    "active_hours": int(row["active_hours"] or 0),
                }

        if src_ip and dst_ip:
            row = conn.execute(
                """
                SELECT
                    SUM(count) AS total_connections,
                    COUNT(DISTINCT hour_bucket) AS active_hours
                FROM dest_counts_rolling
                WHERE src_ip = ? AND dst_ip = ?
                """,
                (src_ip, dst_ip),
            ).fetchone()
            if row:
                context["destination_history"] = {
                    "total_connections": int(row["total_connections"] or 0),
                    "active_hours": int(row["active_hours"] or 0),
                }
    except sqlite3.OperationalError:
        pass

    if domain:
        try:
            row = conn.execute(
                """
                SELECT
                    SUM(count) AS total_queries,
                    COUNT(DISTINCT client_ip) AS distinct_clients,
                    COUNT(DISTINCT hour_bucket) AS active_hours
                FROM dns_counts_rolling
                WHERE qname = ?
                """,
                (domain,),
            ).fetchone()
            if row:
                context["domain_history"] = {
                    "total_queries": int(row["total_queries"] or 0),
                    "distinct_clients": int(row["distinct_clients"] or 0),
                    "active_hours": int(row["active_hours"] or 0),
                }
        except sqlite3.OperationalError:
            pass

    if src_ip and dst_ip and dst_port is not None:
        try:
            row = conn.execute(
                """
                SELECT
                    SUM(count) AS total_hits,
                    COUNT(DISTINCT hour_bucket) AS active_hours
                FROM watch_counts_rolling
                WHERE src_ip = ? AND dst_ip = ? AND dst_port = ?
                """,
                (src_ip, dst_ip, str(dst_port)),
            ).fetchone()
            if row:
                context["watch_tuple_history"] = {
                    "total_hits": int(row["total_hits"] or 0),
                    "active_hours": int(row["active_hours"] or 0),
                }
        except sqlite3.OperationalError:
            pass

    return context


def fetch_history(conn: sqlite3.Connection, alert: dict[str, Any]) -> dict[str, Any]:
    """Find prior reviewed alerts similar to the active alert."""
    match_terms: list[str] = []
    params: list[Any] = [alert["alert_id"], alert["kind"]]

    if alert.get("src_ip"):
        match_terms.append("src_ip = ?")
        params.append(alert["src_ip"])
    if alert.get("dst_ip"):
        match_terms.append("dst_ip = ?")
        params.append(alert["dst_ip"])
    if alert.get("domain"):
        match_terms.append("domain = ?")
        params.append(alert["domain"])
    if alert.get("dst_port") is not None:
        match_terms.append("dst_port = ?")
        params.append(alert["dst_port"])

    exact = conn.execute(
        """
        SELECT
            alert_id,
            kind,
            status,
            dismissed,
            user_verdict,
            user_comment,
            triage_verdict,
            first_seen,
            last_seen,
            src_ip,
            dst_ip,
            dst_port,
            domain
        FROM alerts
        WHERE alert_id != ?
          AND kind = ?
          AND COALESCE(src_ip, '') = COALESCE(?, '')
          AND COALESCE(dst_ip, '') = COALESCE(?, '')
          AND COALESCE(dst_port, '') = COALESCE(?, '')
          AND COALESCE(domain, '') = COALESCE(?, '')
        ORDER BY last_seen DESC
        LIMIT 10
        """,
        (
            alert["alert_id"],
            alert["kind"],
            alert.get("src_ip"),
            alert.get("dst_ip"),
            alert.get("dst_port"),
            alert.get("domain"),
        ),
    ).fetchall()

    related: list[sqlite3.Row] = []
    if match_terms:
        related = conn.execute(
            f"""
            SELECT
                alert_id,
                kind,
                status,
                dismissed,
                user_verdict,
                user_comment,
                triage_verdict,
                first_seen,
                last_seen,
                src_ip,
                dst_ip,
                dst_port,
                domain
            FROM alerts
            WHERE alert_id != ?
              AND kind = ?
              AND ({' OR '.join(match_terms)})
            ORDER BY last_seen DESC
            LIMIT 25
            """,
            params,
        ).fetchall()

    exact_counts = {"benign": 0, "malicious": 0, "review": 0}
    related_counts = {"benign": 0, "malicious": 0, "review": 0}
    examples: list[dict[str, Any]] = []

    seen_ids = set()
    for bucket, rows in (("exact", exact), ("related", related)):
        for row in rows:
            verdict = normalize_feedback(row)
            if bucket == "exact":
                exact_counts[verdict] += 1
            else:
                related_counts[verdict] += 1
            if row["alert_id"] in seen_ids or len(examples) >= 5:
                continue
            seen_ids.add(row["alert_id"])
            examples.append(
                {
                    "alert_id": row["alert_id"],
                    "match_type": bucket,
                    "classification": verdict,
                    "status": row["status"],
                    "user_verdict": row["user_verdict"],
                    "user_comment": row["user_comment"],
                    "last_seen": row["last_seen"],
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "domain": row["domain"],
                }
            )

    comparison_notes: list[str] = []
    if exact_counts["benign"]:
        comparison_notes.append(
            f"Matches {exact_counts['benign']} prior benign or dismissed alert(s) with the same signature."
        )
    if exact_counts["malicious"]:
        comparison_notes.append(
            f"Matches {exact_counts['malicious']} prior suspicious or malicious alert(s) with the same signature."
        )
    if related_counts["benign"]:
        comparison_notes.append(
            f"Resembles {related_counts['benign']} prior benign or dismissed alert(s) sharing this destination, source, or domain."
        )
    if related_counts["malicious"]:
        comparison_notes.append(
            f"Resembles {related_counts['malicious']} prior suspicious or malicious alert(s) sharing this destination, source, or domain."
        )
    if not comparison_notes:
        comparison_notes.append("No prior labeled alerts matched this pattern.")

    return {
        "exact_counts": exact_counts,
        "related_counts": related_counts,
        "comparison_notes": comparison_notes,
        "examples": examples,
    }


def resolve_source_name(alert: dict[str, Any], device_context: dict[str, Any]) -> str | None:
    """Pick the best display name for the alert source."""
    name = device_context.get("friendly_name") or alert.get("src_name")
    if not name:
        return None
    normalized = str(name).strip()
    return normalized or None


def describe_subject(alert: dict[str, Any], device_context: dict[str, Any]) -> str:
    """Return a short human-readable description for the alert source."""
    source_name = resolve_source_name(alert, device_context)
    src_ip = alert.get("src_ip")
    if source_name and src_ip:
        return f"{source_name} ({src_ip})"
    return source_name or src_ip or alert.get("domain") or "this activity"


def describe_destination(alert: dict[str, Any]) -> str:
    """Return a short destination label for summaries."""
    return alert.get("dst_ip") or alert.get("domain") or "the observed destination"


def build_triage(
    alert: dict[str, Any],
    device_context: dict[str, Any],
    baseline_context: dict[str, Any],
    history: dict[str, Any],
    adguard_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate deterministic triage output for a single alert."""
    adguard_context = adguard_context or {}
    evidence = alert.get("evidence") or {}
    score = SEVERITY_SCORES.get(str(alert.get("severity") or "").lower(), 0)
    signals: list[str] = []

    if score:
        signals.append(f"Severity contributed {score} risk point(s).")

    kind = str(alert.get("kind") or "")
    if kind == "rita_beacon":
        beacon_score = float(evidence.get("score") or 0.0)
        score += 2
        signals.append("RITA beacon detections carry elevated risk by default.")
        if beacon_score >= 0.99:
            score += 1
            signals.append(f"RITA score {beacon_score:.2f} is unusually strong.")
    elif kind == "high_fanout":
        unique_dsts = int(evidence.get("unique_external_dsts") or 0)
        score += 1
        signals.append("High-fanout behavior can indicate scanning or bulk callback activity.")
        if unique_dsts >= 100:
            score += 1
            signals.append(f"Observed fanout to {unique_dsts} external destinations.")
    elif kind in {"new_watch_tuple", "new_tls_fp"}:
        score += 1
        signals.append("Sensitive-port or TLS fingerprint novelty raised the review priority.")

    exact_counts = history["exact_counts"]
    related_counts = history["related_counts"]
    if exact_counts["malicious"]:
        score += 3
        signals.append("The exact pattern has prior suspicious or malicious outcomes.")
    elif related_counts["malicious"]:
        score += 2
        signals.append("Related alerts previously resolved as suspicious or malicious.")

    if exact_counts["benign"] >= 2:
        score -= 3
        signals.append("The exact pattern has multiple prior benign or dismissed outcomes.")
    elif exact_counts["benign"]:
        score -= 2
        signals.append("The exact pattern has a prior benign or dismissed outcome.")
    elif related_counts["benign"] >= 3:
        score -= 2
        signals.append("Similar activity was repeatedly dismissed or labeled benign.")
    elif related_counts["benign"]:
        score -= 1
        signals.append("There is at least one prior benign match for this pattern.")

    if device_context.get("is_trusted"):
        score -= 1
        signals.append("The source device is marked trusted.")
    elif device_context and not device_context.get("is_known"):
        score += 1
        signals.append("The source device is not yet identified in inventory.")

    destination_history = baseline_context.get("destination_history") or {}
    domain_history = baseline_context.get("domain_history") or {}
    if destination_history.get("total_connections", 0) >= 20:
        score -= 1
        signals.append("Rolling baseline shows sustained communication to this destination.")
    if domain_history.get("total_queries", 0) >= 20:
        score -= 1
        signals.append("Rolling baseline shows repeated DNS lookups for this domain.")
    if not destination_history and not domain_history and not exact_counts["benign"] and not related_counts["benign"]:
        score += 1
        signals.append("The pattern is new in the current rolling baseline and lacks benign precedent.")

    adguard_domain = str(adguard_context.get("domain") or "").strip()
    adguard_match = str(adguard_context.get("matched_by") or "")
    if adguard_domain:
        if adguard_match == "answer_ip":
            signals.append(
                f"AdGuard query log shows this client requested {adguard_domain}, resolving to the alert destination IP."
            )
        elif adguard_match == "alert_domain":
            signals.append(
                f"AdGuard query log confirms this client requested {adguard_domain}."
            )
        else:
            signals.append(
                f"Most recent AdGuard DNS query from this client was for {adguard_domain}."
            )

    if score <= -2:
        verdict = "likely_benign"
    elif score >= 4:
        verdict = "likely_malicious"
    else:
        verdict = "needs_review"

    comparison_note = history["comparison_notes"][0] if history["comparison_notes"] else ""
    subject = describe_subject(alert, device_context)
    destination = describe_destination(alert)
    if adguard_domain and adguard_match in {"answer_ip", "alert_domain"}:
        if alert.get("dst_ip"):
            destination = f"{adguard_domain} ({alert.get('dst_ip')})"
        else:
            destination = adguard_domain

    if verdict == "likely_benign":
        summary = f"{subject} likely generated expected traffic toward {destination}. {comparison_note}"
    elif verdict == "likely_malicious":
        summary = f"{subject} shows high-risk behavior involving {destination}. {comparison_note}"
    else:
        summary = f"{subject} activity involving {destination} needs review. {comparison_note}"

    confidence = round(min(0.98, 0.45 + (0.08 * abs(score)) + (0.03 * len(history["examples"]))), 2)
    reasoning = {
        "signals": signals,
        "comparison_notes": history["comparison_notes"],
        "historical_matches": {
            "exact": exact_counts,
            "related": related_counts,
            "examples": history["examples"],
        },
        "adguard_context": adguard_context,
        "device_context": device_context,
        "baseline_context": baseline_context,
    }

    return {
        "triage_verdict": verdict,
        "triage_summary": summary.strip(),
        "triage_reasoning": reasoning,
        "triage_confidence": confidence,
        "triage_source": "deterministic",
    }


def connect_optional(db_path: str | None) -> sqlite3.Connection | None:
    """Open an optional sqlite connection if the path exists."""
    if not db_path:
        return None
    path = Path(db_path)
    if not path.exists():
        return None
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply deterministic triage to active HomeNetSec alerts")
    parser.add_argument("--alerts-db", required=True, help="Path to alerts sqlite")
    parser.add_argument("--devices-db", help="Optional path to devices sqlite")
    parser.add_argument("--baseline-db", help="Optional path to rolling baselines sqlite")
    parser.add_argument("--adguard-env", help="Optional path to AdGuard env file")
    parser.add_argument(
        "--adguard-querylog-limit",
        type=int,
        default=int(os.getenv("HOMENETSEC_ADGUARD_QUERYLOG_LIMIT", str(DEFAULT_ADGUARD_QUERYLOG_LIMIT))),
        help="Max AdGuard querylog records to inspect for domain enrichment",
    )
    parser.add_argument("--limit", type=int, default=250, help="Maximum number of active alerts to triage")
    args = parser.parse_args()

    alerts_conn = connect_optional(args.alerts_db)
    if alerts_conn is None:
        raise FileNotFoundError(f"alerts database not found: {args.alerts_db}")

    devices_conn = connect_optional(args.devices_db)
    baseline_conn = connect_optional(args.baseline_db)
    adguard_querylog = fetch_adguard_querylog_index(args.adguard_env, args.adguard_querylog_limit)

    try:
        rows = alerts_conn.execute(f"{ACTIVE_QUERY} LIMIT ?", (args.limit,)).fetchall()
        if not rows:
            return 0

        with AlertDB(args.alerts_db) as alert_db:
            for row in rows:
                alert = row_to_alert(row)
                device_context = fetch_device_context(devices_conn, alert.get("src_ip"))
                adguard_context = lookup_adguard_context(alert, adguard_querylog)
                source_name = resolve_source_name(alert, device_context)
                if not source_name and adguard_context.get("client_name"):
                    source_name = str(adguard_context["client_name"]).strip() or None
                if source_name and source_name != (alert.get("src_name") or "").strip():
                    alert_db.update_alert_source_name(alert["alert_id"], source_name)
                    alert["src_name"] = source_name
                baseline_context = fetch_baseline_context(baseline_conn, alert)
                history = fetch_history(alerts_conn, alert)
                triage = build_triage(alert, device_context, baseline_context, history, adguard_context)
                alert_db.update_triage(
                    alert["alert_id"],
                    triage["triage_verdict"],
                    triage["triage_summary"],
                    triage["triage_reasoning"],
                    triage["triage_confidence"],
                    triage["triage_source"],
                )
    finally:
        alerts_conn.close()
        if devices_conn is not None:
            devices_conn.close()
        if baseline_conn is not None:
            baseline_conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
