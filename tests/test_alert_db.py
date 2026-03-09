import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from alert_db import AlertDB
from init_databases import init_alerts_database


class AlertDBTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.temp_dir.name)
        self.db_path = self.workdir / "alerts.sqlite"
        init_alerts_database(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_lifecycle_operations_fail_for_missing_alerts(self):
        with AlertDB(str(self.db_path)) as db:
            self.assertFalse(db.dismiss_alert("missing"))
            self.assertFalse(db.investigate_alert("missing"))
            self.assertFalse(db.resolve_alert("missing"))

    def test_state_changes_capture_real_previous_status(self):
        with AlertDB(str(self.db_path)) as db:
            alert_id = db.create_or_update_alert(
                kind="rita_beacon",
                severity="high",
                src_ip="192.168.1.10",
                dst_ip="93.184.216.34",
                evidence={"score": 0.98},
                recommendation={"action": "investigate"},
            )
            self.assertTrue(db.investigate_alert(alert_id, "analyst", "started review"))
            self.assertTrue(db.resolve_alert(alert_id, "closed", "benign"))

        conn = sqlite3.connect(self.db_path)
        changes = conn.execute(
            "SELECT from_status, to_status, changed_by FROM alert_state_changes ORDER BY id"
        ).fetchall()
        conn.close()

        self.assertEqual(changes[0], ("new", "investigating", "analyst"))
        self.assertEqual(changes[1][:2], ("investigating", "resolved"))

    def test_dismissed_alert_reactivates_after_ttl_expiry(self):
        with AlertDB(str(self.db_path)) as db:
            alert_id = db.create_or_update_alert(
                kind="new_external_dest",
                severity="med",
                src_ip="192.168.1.20",
                dst_ip="203.0.113.10",
                evidence={"destination": "203.0.113.10"},
                recommendation={"action": "review"},
            )
            self.assertTrue(db.dismiss_alert(alert_id, "expected traffic", ttl_days=0, user_verdict="expected"))

            same_alert_id = db.create_or_update_alert(
                kind="new_external_dest",
                severity="med",
                src_ip="192.168.1.20",
                dst_ip="203.0.113.10",
                evidence={"destination": "203.0.113.10"},
                recommendation={"action": "review"},
            )
            self.assertEqual(alert_id, same_alert_id)
            alert = db.get_alert_by_id(alert_id)

        self.assertEqual(alert["status"], "new")
        self.assertEqual(alert["dismissed"], 0)
        self.assertEqual(alert["occurrence_count"], 2)

        conn = sqlite3.connect(self.db_path)
        transition = conn.execute(
            """
            SELECT from_status, to_status
            FROM alert_state_changes
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        conn.close()
        self.assertEqual(transition, ("dismissed", "new"))

    def test_triage_updates_are_persisted_and_logged(self):
        with AlertDB(str(self.db_path)) as db:
            alert_id = db.create_or_update_alert(
                kind="new_domain",
                severity="med",
                domain="updates.example.test",
                evidence={"domain": "updates.example.test"},
                recommendation={"action": "review"},
            )

            self.assertTrue(
                db.update_triage(
                    alert_id,
                    triage_verdict="likely_benign",
                    triage_summary="Recurring expected background traffic.",
                    triage_reasoning={"comparison_notes": ["Matched prior dismissed activity."]},
                    triage_confidence=0.88,
                )
            )
            alert = db.get_alert_by_id(alert_id)
            history = db.get_alert_triage_history(alert_id)

        self.assertEqual(alert["triage_verdict"], "likely_benign")
        self.assertEqual(alert["triage_summary"], "Recurring expected background traffic.")
        self.assertEqual(alert["triage_reasoning"]["comparison_notes"][0], "Matched prior dismissed activity.")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["triage_verdict"], "likely_benign")

    def test_save_review_updates_feedback_without_dismissal(self):
        with AlertDB(str(self.db_path)) as db:
            alert_id = db.create_or_update_alert(
                kind="rita_beacon",
                severity="high",
                src_ip="192.168.1.33",
                dst_ip="198.51.100.20",
                evidence={"score": 0.98},
                recommendation={"action": "investigate"},
            )
            self.assertTrue(
                db.save_review(
                    alert_id,
                    user_verdict="likely_malicious",
                    user_comment="Beaconing cadence is unusual.",
                    status="investigating",
                    reviewed_by="analyst",
                )
            )
            alert = db.get_alert_by_id(alert_id)

        self.assertEqual(alert["status"], "investigating")
        self.assertEqual(alert["user_verdict"], "likely_malicious")
        self.assertEqual(alert["user_comment"], "Beaconing cadence is unusual.")
        self.assertEqual(alert["dismissed"], 0)

    def test_stats_active_counts_exclude_resolved_and_dismissed(self):
        with AlertDB(str(self.db_path)) as db:
            active_id = db.create_or_update_alert(
                kind="new_domain",
                severity="med",
                domain="active.example",
                evidence={"domain": "active.example"},
                recommendation={"action": "review"},
            )
            resolved_id = db.create_or_update_alert(
                kind="new_domain",
                severity="high",
                domain="resolved.example",
                evidence={"domain": "resolved.example"},
                recommendation={"action": "review"},
            )
            dismissed_id = db.create_or_update_alert(
                kind="new_domain",
                severity="low",
                domain="dismissed.example",
                evidence={"domain": "dismissed.example"},
                recommendation={"action": "review"},
            )

            self.assertTrue(db.resolve_alert(resolved_id, "resolved for test", "likely_benign"))
            self.assertTrue(db.dismiss_alert(dismissed_id, "dismissed for test", ttl_days=30, user_verdict="likely_benign"))

            stats = db.get_stats()

        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["active"], 1)
        self.assertEqual(stats["by_severity"].get("med"), 1)
        self.assertNotIn("high", stats["by_severity"])
        self.assertNotIn("low", stats["by_severity"])


if __name__ == "__main__":
    unittest.main()
