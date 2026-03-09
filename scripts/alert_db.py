"""
Alert Database Helper Library

Provides functions for creating, updating, and querying alerts in alerts.sqlite.
Used by detection scripts to write alerts to the persistent database.

Usage:
    from alert_db import AlertDB

    db = AlertDB('/path/to/alerts.sqlite')
    db.create_or_update_alert(
        kind='rita_beacon',
        severity='high',
        src_ip='192.168.1.100',
        evidence={'score': 0.98, ...},
        recommendation={'action': 'investigate', ...}
    )
"""

import sqlite3
import json
import hashlib
from typing import Dict, Optional, List, Any


def parse_json(value: Optional[str], default: Any) -> Any:
    """Safely parse a JSON field from sqlite."""
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


class AlertDB:
    """Alert database manager."""

    def __init__(self, db_path: str):
        """Initialize alert database connection."""
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row  # Enable dict-like access
        self.conn.execute("PRAGMA foreign_keys = ON")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def _get_existing_alert_row(self, alert_id: str) -> Optional[sqlite3.Row]:
        """Fetch the current alert row for state-aware updates."""
        return self.conn.execute(
            """
            SELECT
                alert_id,
                status,
                dismissed,
                dismissed_at,
                dismiss_ttl_days,
                triage_verdict,
                triage_summary,
                triage_reasoning_json,
                triage_confidence,
                triage_source,
                user_verdict,
                user_comment
            FROM alerts
            WHERE alert_id = ?
            """,
            (alert_id,),
        ).fetchone()

    def _dismissal_ttl_expired(self, row: sqlite3.Row) -> bool:
        """Return True when a dismissed alert should become active again."""
        if not row["dismissed"]:
            return False

        ttl_days = row["dismiss_ttl_days"]
        dismissed_at = row["dismissed_at"]
        if ttl_days is None or dismissed_at is None:
            return False

        expired = self.conn.execute(
            """
            SELECT datetime(?) <= datetime('now', printf('-%d days', ?))
            """,
            (dismissed_at, int(ttl_days)),
        ).fetchone()[0]
        return bool(expired)

    def _log_state_change(
        self,
        cursor: sqlite3.Cursor,
        alert_id: str,
        from_status: Optional[str],
        to_status: str,
        changed_by: str,
        reason: str = "",
    ) -> None:
        """Persist alert lifecycle transitions for auditability."""
        cursor.execute(
            """
            INSERT INTO alert_state_changes (alert_id, from_status, to_status, changed_by, reason)
            VALUES (?, ?, ?, ?, ?)
            """,
            (alert_id, from_status, to_status, changed_by, reason),
        )

    def _log_triage_result(
        self,
        cursor: sqlite3.Cursor,
        alert_id: str,
        triage_verdict: Optional[str],
        triage_summary: Optional[str],
        triage_reasoning_json: str,
        triage_confidence: Optional[float],
        triage_source: Optional[str],
    ) -> None:
        """Persist triage output history when the recommendation changes."""
        cursor.execute(
            """
            INSERT INTO alert_triage_history (
                alert_id,
                triage_verdict,
                triage_summary,
                triage_reasoning_json,
                triage_confidence,
                triage_source
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                triage_verdict,
                triage_summary,
                triage_reasoning_json,
                triage_confidence,
                triage_source,
            ),
        )

    def generate_alert_id(
        self,
        kind: str,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        domain: Optional[str] = None,
        extra: Optional[str] = None
    ) -> str:
        """
        Generate stable alert ID for deduplication.

        The alert ID is a hash of the key identifying fields,
        ensuring the same alert condition produces the same ID
        across analysis runs.
        """
        components = [
            kind,
            src_ip or "",
            dst_ip or "",
            str(dst_port) if dst_port else "",
            domain or "",
            extra or ""
        ]

        identifier = "|".join(components)
        return hashlib.sha256(identifier.encode()).hexdigest()[:32]

    def create_or_update_alert(
        self,
        kind: str,
        severity: str,
        src_ip: Optional[str] = None,
        src_name: Optional[str] = None,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        domain: Optional[str] = None,
        verdict: str = 'needs_review',
        confidence: float = 0.5,
        evidence: Optional[Dict] = None,
        recommendation: Optional[Dict] = None,
        alert_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None
    ) -> str:
        """
        Create a new alert or update an existing one.

        If an alert with the same ID already exists, update its:
        - last_seen timestamp
        - occurrence_count (+1)
        - evidence (latest)

        Returns: alert_id
        """
        evidence = evidence or {}
        recommendation = recommendation or {}
        normalized_src_name = src_name.strip() if isinstance(src_name, str) else src_name
        if normalized_src_name == "":
            normalized_src_name = None

        # Generate alert ID if not provided
        if not alert_id:
            alert_id = self.generate_alert_id(
                kind=kind,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                domain=domain
            )

        # Check if alert exists
        existing = self._get_existing_alert_row(alert_id)

        cursor = self.conn.cursor()

        if existing:
            from_status = existing["status"]

            if existing["dismissed"] and not self._dismissal_ttl_expired(existing):
                return alert_id

            status = from_status
            dismissed = int(existing["dismissed"])
            dismissed_at = existing["dismissed_at"]
            dismiss_ttl_days = existing["dismiss_ttl_days"]

            if existing["dismissed"] and self._dismissal_ttl_expired(existing):
                status = "new"
                dismissed = 0
                dismissed_at = None
                dismiss_ttl_days = None

            cursor.execute("""
                UPDATE alerts SET
                    last_seen = datetime('now'),
                    occurrence_count = occurrence_count + 1,
                    src_ip = COALESCE(src_ip, ?),
                    src_name = COALESCE(?, src_name),
                    status = ?,
                    dismissed = ?,
                    dismissed_at = ?,
                    dismiss_ttl_days = ?,
                    evidence_json = ?,
                    recommendation_json = ?,
                    updated_at = datetime('now')
                WHERE alert_id = ?
            """, (
                src_ip,
                normalized_src_name,
                status,
                dismissed,
                dismissed_at,
                dismiss_ttl_days,
                json.dumps(evidence),
                json.dumps(recommendation),
                alert_id,
            ))

            if existing["dismissed"] and self._dismissal_ttl_expired(existing):
                self._log_state_change(
                    cursor,
                    alert_id,
                    from_status,
                    status,
                    "system",
                    "Dismissal TTL expired during rediscovery",
                )

            # Log occurrence
            cursor.execute("""
                INSERT INTO alert_occurrences (alert_id, occurred_at, analysis_run_id, evidence_delta_json)
                VALUES (?, datetime('now'), ?, ?)
            """, (alert_id, analysis_run_id, json.dumps(evidence)))

        else:
            # New alert - create it
            cursor.execute("""
                INSERT INTO alerts (
                    alert_id, kind, severity, status, verdict, confidence,
                    src_ip, src_name, dst_ip, dst_port, domain,
                    first_seen, last_seen, occurrence_count,
                    evidence_json, recommendation_json
                ) VALUES (
                    ?, ?, ?, 'new', ?, ?,
                    ?, ?, ?, ?, ?,
                    datetime('now'), datetime('now'), 1,
                    ?, ?
                )
            """, (
                alert_id, kind, severity, verdict, confidence,
                src_ip, normalized_src_name, dst_ip, dst_port, domain,
                json.dumps(evidence), json.dumps(recommendation)
            ))

        self.conn.commit()
        return alert_id

    def update_alert_source_name(self, alert_id: str, src_name: Optional[str]) -> bool:
        """Update the alert source display name for title rendering."""
        normalized = src_name.strip() if isinstance(src_name, str) else src_name
        if normalized == "":
            normalized = None

        cursor = self.conn.cursor()
        cursor.execute(
            """
            UPDATE alerts
            SET src_name = ?,
                updated_at = datetime('now')
            WHERE alert_id = ?
            """,
            (normalized, alert_id),
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def get_active_alerts(self, limit: Optional[int] = None) -> List[Dict]:
        """Get all active (non-dismissed) alerts."""
        query = """
            SELECT * FROM alerts
            WHERE dismissed = 0
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

        if limit:
            query += f" LIMIT {limit}"

        rows = self.conn.execute(query).fetchall()
        return [dict(row) for row in rows]

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict]:
        """Get a specific alert by ID."""
        row = self.conn.execute(
            "SELECT * FROM alerts WHERE alert_id = ?",
            (alert_id,)
        ).fetchone()

        if row:
            alert = dict(row)
            # Parse JSON fields
            alert['evidence'] = parse_json(alert.get('evidence_json'), {})
            alert['recommendation'] = parse_json(alert.get('recommendation_json'), {})
            alert['triage_reasoning'] = parse_json(alert.get('triage_reasoning_json'), {})
            alert.pop('evidence_json', None)
            alert.pop('recommendation_json', None)
            alert.pop('triage_reasoning_json', None)
            return alert
        return None

    def get_alert_occurrences(self, alert_id: str, limit: int = 50) -> List[Dict]:
        """Get occurrence history for an alert."""
        rows = self.conn.execute("""
            SELECT * FROM alert_occurrences
            WHERE alert_id = ?
            ORDER BY occurred_at DESC
            LIMIT ?
        """, (alert_id, limit)).fetchall()

        return [dict(row) for row in rows]

    def dismiss_alert(
        self,
        alert_id: str,
        user_comment: Optional[str] = None,
        ttl_days: int = 30,
        user_verdict: Optional[str] = None
    ) -> bool:
        """
        Dismiss an alert with optional TTL-based suppression.

        Returns: True if alert was dismissed, False if not found
        """
        return self.save_review(
            alert_id,
            user_verdict=user_verdict,
            user_comment=user_comment,
            status="dismissed",
            ttl_days=ttl_days,
            reviewed_by="user",
        )

    def investigate_alert(
        self,
        alert_id: str,
        investigated_by: str = 'user',
        note: Optional[str] = None
    ) -> bool:
        """
        Mark an alert as under investigation.

        Returns: True if updated, False if not found
        """
        return self.save_review(
            alert_id,
            status="investigating",
            user_comment=note,
            reviewed_by=investigated_by,
        )

    def resolve_alert(
        self,
        alert_id: str,
        resolution_note: Optional[str] = None,
        verdict: Optional[str] = None
    ) -> bool:
        """
        Resolve an alert.

        Returns: True if resolved, False if not found
        """
        return self.save_review(
            alert_id,
            user_verdict=verdict,
            user_comment=resolution_note,
            status="resolved",
            reviewed_by="user",
        )

    def update_triage(
        self,
        alert_id: str,
        triage_verdict: Optional[str],
        triage_summary: Optional[str],
        triage_reasoning: Optional[Dict[str, Any]] = None,
        triage_confidence: Optional[float] = None,
        triage_source: str = "deterministic",
    ) -> bool:
        """Persist triage output onto the alert and log changed recommendations."""
        existing = self._get_existing_alert_row(alert_id)
        if not existing:
            return False

        reasoning = triage_reasoning or {}
        reasoning_json = json.dumps(reasoning, sort_keys=True)
        cursor = self.conn.cursor()

        cursor.execute(
            """
            UPDATE alerts SET
                triage_verdict = ?,
                triage_summary = ?,
                triage_reasoning_json = ?,
                triage_confidence = ?,
                triage_source = ?,
                triage_updated_at = datetime('now'),
                updated_at = datetime('now')
            WHERE alert_id = ?
            """,
            (
                triage_verdict,
                triage_summary,
                reasoning_json,
                triage_confidence,
                triage_source,
                alert_id,
            ),
        )

        changed = any(
            [
                existing["triage_verdict"] != triage_verdict,
                existing["triage_summary"] != triage_summary,
                (existing["triage_reasoning_json"] or "") != reasoning_json,
                existing["triage_confidence"] != triage_confidence,
                existing["triage_source"] != triage_source,
            ]
        )
        if changed:
            self._log_triage_result(
                cursor,
                alert_id,
                triage_verdict,
                triage_summary,
                reasoning_json,
                triage_confidence,
                triage_source,
            )

        self.conn.commit()
        return True

    def get_alert_triage_history(self, alert_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Return recent triage recommendations for a given alert."""
        rows = self.conn.execute(
            """
            SELECT *
            FROM alert_triage_history
            WHERE alert_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (alert_id, limit),
        ).fetchall()

        history = []
        for row in rows:
            record = dict(row)
            record["triage_reasoning"] = parse_json(record.get("triage_reasoning_json"), {})
            record.pop("triage_reasoning_json", None)
            history.append(record)
        return history

    def save_review(
        self,
        alert_id: str,
        user_verdict: Optional[str] = None,
        user_comment: Optional[str] = None,
        status: Optional[str] = None,
        ttl_days: Optional[int] = None,
        reviewed_by: str = "user",
    ) -> bool:
        """Save structured alert review feedback and optional lifecycle changes."""
        existing = self._get_existing_alert_row(alert_id)
        if not existing:
            return False

        from_status = existing["status"]
        target_status = status or from_status
        cursor = self.conn.cursor()
        dismiss_ttl_days = ttl_days if target_status == "dismissed" else None
        resolution_note = user_comment if target_status == "resolved" else None

        if target_status not in {"new", "investigating", "resolved", "dismissed"}:
            raise ValueError(f"Unsupported alert review status: {target_status}")

        if target_status == "new":
            cursor.execute(
                """
                UPDATE alerts SET
                    status = 'new',
                    dismissed = 0,
                    dismissed_at = NULL,
                    dismiss_ttl_days = NULL,
                    user_verdict = COALESCE(?, user_verdict),
                    user_comment = COALESCE(?, user_comment),
                    updated_at = datetime('now')
                WHERE alert_id = ?
                """,
                (user_verdict, user_comment, alert_id),
            )
        elif target_status == "investigating":
            cursor.execute(
                """
                UPDATE alerts SET
                    status = 'investigating',
                    dismissed = 0,
                    dismissed_at = NULL,
                    dismiss_ttl_days = NULL,
                    investigated_at = datetime('now'),
                    investigated_by = ?,
                    user_verdict = COALESCE(?, user_verdict),
                    user_comment = COALESCE(?, user_comment),
                    updated_at = datetime('now')
                WHERE alert_id = ?
                """,
                (reviewed_by, user_verdict, user_comment, alert_id),
            )
        elif target_status == "resolved":
            cursor.execute(
                """
                UPDATE alerts SET
                    status = 'resolved',
                    dismissed = 0,
                    dismissed_at = NULL,
                    dismiss_ttl_days = NULL,
                    resolved_at = datetime('now'),
                    resolution_note = ?,
                    user_verdict = COALESCE(?, user_verdict),
                    user_comment = COALESCE(?, user_comment),
                    updated_at = datetime('now')
                WHERE alert_id = ?
                """,
                (resolution_note, user_verdict, user_comment, alert_id),
            )
        else:
            cursor.execute(
                """
                UPDATE alerts SET
                    status = 'dismissed',
                    dismissed = 1,
                    dismissed_at = datetime('now'),
                    dismiss_ttl_days = ?,
                    user_verdict = COALESCE(?, user_verdict),
                    user_comment = COALESCE(?, user_comment),
                    updated_at = datetime('now')
                WHERE alert_id = ?
                """,
                (dismiss_ttl_days if dismiss_ttl_days is not None else 30, user_verdict, user_comment, alert_id),
            )

        if cursor.rowcount == 0:
            self.conn.rollback()
            return False

        if target_status != from_status:
            self._log_state_change(cursor, alert_id, from_status, target_status, reviewed_by, user_comment or "")

        self.conn.commit()
        return True

    def get_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        stats = {}

        # Count by status
        rows = self.conn.execute("""
            SELECT status, COUNT(*) as count
            FROM alerts
            GROUP BY status
        """).fetchall()
        stats['by_status'] = {row['status']: row['count'] for row in rows}

        # Count by severity
        rows = self.conn.execute("""
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE dismissed = 0
              AND status NOT IN ('resolved', 'dismissed')
            GROUP BY severity
        """).fetchall()
        stats['by_severity'] = {row['severity']: row['count'] for row in rows}

        # Total alerts
        stats['total'] = self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

        # Active alerts
        stats['active'] = self.conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE dismissed = 0 AND status NOT IN ('resolved', 'dismissed')"
        ).fetchone()[0]

        return stats
