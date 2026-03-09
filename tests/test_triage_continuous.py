import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from alert_db import AlertDB
from baseline_update_continuous import ensure_schema
from init_databases import init_alerts_database, init_devices_database


class TriageContinuousTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.temp_dir.name)
        self.state_dir = self.workdir / "state"
        self.state_dir.mkdir(parents=True)
        self.alerts_db = self.state_dir / "alerts.sqlite"
        self.devices_db = self.state_dir / "devices.sqlite"
        self.baseline_db = self.state_dir / "baselines.sqlite"

        init_alerts_database(self.alerts_db)
        init_devices_database(self.devices_db)

        baseline_conn = sqlite3.connect(self.baseline_db)
        ensure_schema(baseline_conn)
        baseline_conn.execute(
            """
            INSERT INTO dest_counts_rolling(hour_bucket, src_ip, dst_ip, count, bytes_sent, bytes_received)
            VALUES ('2026-03-08T10:00:00Z', '192.168.1.50', '203.0.113.10', 40, 1000, 800)
            """
        )
        baseline_conn.commit()
        baseline_conn.close()

        device_conn = sqlite3.connect(self.devices_db)
        device_conn.execute(
            """
            INSERT INTO devices (
                ip, friendly_name, device_type, first_seen, last_seen,
                total_connections, unique_destinations_count, is_known, is_trusted, is_monitored
            ) VALUES (?, ?, ?, datetime('now'), datetime('now'), ?, ?, ?, ?, ?)
            """,
            ("192.168.1.50", "Kitchen Display", "iot", 120, 8, 1, 1, 1),
        )
        device_conn.commit()
        device_conn.close()

        with AlertDB(str(self.alerts_db)) as db:
            prior_id = db.create_or_update_alert(
                kind="new_external_dest",
                severity="med",
                src_ip="192.168.1.50",
                dst_ip="203.0.113.10",
                evidence={"destination": "203.0.113.10"},
                recommendation={"action": "review"},
            )
            db.dismiss_alert(prior_id, "Expected cloud sync", ttl_days=30, user_verdict="benign")

            self.alert_id = db.create_or_update_alert(
                kind="new_external_dest",
                severity="med",
                src_ip="192.168.1.50",
                dst_ip="203.0.113.10",
                alert_id="triage-fixture-alert",
                evidence={"destination": "203.0.113.10"},
                recommendation={"action": "review"},
            )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_triage_uses_prior_feedback_and_baseline_context(self):
        script = REPO_ROOT / "scripts" / "triage_continuous.py"
        subprocess.run(
            [
                sys.executable,
                str(script),
                "--alerts-db",
                str(self.alerts_db),
                "--devices-db",
                str(self.devices_db),
                "--baseline-db",
                str(self.baseline_db),
            ],
            check=True,
        )

        with AlertDB(str(self.alerts_db)) as db:
            alert = db.get_alert_by_id(self.alert_id)
            history = db.get_alert_triage_history(self.alert_id)

        self.assertEqual(alert["triage_verdict"], "likely_benign")
        self.assertIn("expected traffic", alert["triage_summary"].lower())
        self.assertTrue(alert["triage_reasoning"]["comparison_notes"])
        self.assertEqual(len(history), 1)


if __name__ == "__main__":
    unittest.main()
