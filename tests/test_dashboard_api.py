import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from time import time
from urllib.parse import parse_qs, urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from alert_db import AlertDB
from init_databases import init_alerts_database, init_devices_database


def load_dashboard_module(workdir: Path):
    try:
        import flask  # noqa: F401
        import flask_cors  # noqa: F401
    except ModuleNotFoundError:
        install_flask_stub()

    os.environ["HOMENETSEC_WORKDIR"] = str(workdir)
    os.environ["HOMENETSEC_STATE_DIR"] = str(workdir / "state")
    module_path = REPO_ROOT / "assets" / "dashboard-api" / "app.py"
    spec = importlib.util.spec_from_file_location("dashboard_api_test", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install_flask_stub():
    if "flask" in sys.modules and "flask_cors" in sys.modules:
        return

    flask_module = types.ModuleType("flask")
    flask_cors_module = types.ModuleType("flask_cors")

    class FakeRequest:
        def __init__(self):
            self.args = {}
            self._json = None

        def get_json(self):
            return self._json

    class FakeResponse:
        def __init__(self, payload, status_code=200):
            self.payload = payload
            self.status_code = status_code

        def get_json(self):
            return self.payload

    class FakeClient:
        def __init__(self, app):
            self.app = app

        def _match_route(self, method, path):
            for rule, methods, func in self.app._routes:
                if method not in methods:
                    continue
                params = {}
                rule_parts = [part for part in rule.strip("/").split("/") if part]
                path_parts = [part for part in path.strip("/").split("/") if part]
                if len(rule_parts) != len(path_parts):
                    continue
                matched = True
                for rule_part, path_part in zip(rule_parts, path_parts):
                    if rule_part.startswith("<") and rule_part.endswith(">"):
                        params[rule_part[1:-1]] = path_part
                    elif rule_part != path_part:
                        matched = False
                        break
                if matched:
                    return func, params
            raise AssertionError(f"No route for {method} {path}")

        def _request(self, method, url, json=None):
            parsed = urlparse(url)
            flask_module.request.args = {key: values[-1] for key, values in parse_qs(parsed.query).items()}
            flask_module.request._json = json
            func, params = self._match_route(method, parsed.path)
            result = func(**params)
            if isinstance(result, tuple):
                payload, status_code = result
            else:
                payload, status_code = result, 200
            return FakeResponse(payload, status_code)

        def get(self, url):
            return self._request("GET", url)

        def post(self, url, json=None):
            return self._request("POST", url, json=json)

    class FakeFlask:
        def __init__(self, _name):
            self._routes = []

        def route(self, rule, methods=None):
            def decorator(func):
                self._routes.append((rule, tuple(methods or ["GET"]), func))
                return func

            return decorator

        def test_client(self):
            return FakeClient(self)

        def run(self, *args, **kwargs):
            return None

    def jsonify(payload):
        return payload

    def cors_noop(_app):
        return None

    flask_module.Flask = FakeFlask
    flask_module.jsonify = jsonify
    flask_module.request = FakeRequest()
    flask_cors_module.CORS = cors_noop

    sys.modules["flask"] = flask_module
    sys.modules["flask_cors"] = flask_cors_module


class DashboardApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.temp_dir.name)
        self.state_dir = self.workdir / "state"
        self.state_dir.mkdir(parents=True)
        init_alerts_database(self.state_dir / "alerts.sqlite")
        init_devices_database(self.state_dir / "devices.sqlite")

        with AlertDB(str(self.state_dir / "alerts.sqlite")) as db:
            self.alert_id = db.create_or_update_alert(
                kind="rita_beacon",
                severity="high",
                src_ip="192.168.1.60",
                dst_ip="198.51.100.12",
                evidence={"score": 0.91},
                recommendation={"action": "investigate"},
            )
            db.update_triage(
                self.alert_id,
                triage_verdict="needs_review",
                triage_summary="New beacon candidate requires validation.",
                triage_reasoning={"comparison_notes": ["No prior labeled alerts matched this pattern."]},
                triage_confidence=0.72,
            )

        conn = sqlite3.connect(self.state_dir / "devices.sqlite")
        conn.execute(
            """
            INSERT INTO devices (
                ip, friendly_name, device_type, first_seen, last_seen,
                total_connections, unique_destinations_count, is_known, is_trusted, is_monitored
            ) VALUES (?, ?, ?, datetime('now'), datetime('now'), ?, ?, ?, ?, ?)
            """,
            ("192.168.1.80", "Lab Laptop", "laptop", 25, 4, 1, 1, 1),
        )
        conn.commit()
        conn.close()

        (self.state_dir / "analysis_queue.txt").write_text(
            "/tmp/merged-1.pcap\n/tmp/merged-2.pcap\n",
            encoding="utf-8",
        )
        pcap_dir = self.workdir / "pcaps"
        pcap_dir.mkdir()
        (pcap_dir / "merged-test.pcap.manifest.json").write_text(
            json.dumps(
                {
                    "merged_at_epoch": int(time()),
                    "inputs": [{"path": "a"}, {"path": "b"}, {"path": "c"}],
                }
            ),
            encoding="utf-8",
        )
        (self.state_dir / "ingest_state.json").write_text(
            json.dumps(
                {
                    "last_contiguous_epoch": 1709683200,
                    "pending": [{"epoch": int(time()), "path": "missing.pcap", "reason": "not_found"}],
                }
            ),
            encoding="utf-8",
        )
        rita_dir = self.workdir / "rita-data"
        rita_dir.mkdir()
        (rita_dir / "beacons_latest.txt").write_text("src dst score\n10 20 0.9\n", encoding="utf-8")

        subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "generate_pipeline_status.py"),
                "--workdir",
                str(self.workdir),
                "--section",
                "ingest",
                "--status",
                "idle",
                "--message",
                "Continuous ingest cycle complete",
                "--next-expected-seconds",
                "300",
            ],
            check=True,
        )
        subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "generate_pipeline_status.py"),
                "--workdir",
                str(self.workdir),
                "--section",
                "analysis",
                "--status",
                "idle",
                "--message",
                "Continuous analysis queue processed successfully",
                "--queue-depth",
                "2",
                "--last-duration-sec",
                "34",
            ],
            check=True,
        )

        self.module = load_dashboard_module(self.workdir)
        self.client = self.module.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_pipeline_status_endpoint_returns_normalized_schema(self):
        response = self.client.get("/api/pipeline-status")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()

        self.assertIn("ingest", payload)
        self.assertIn("analysis", payload)
        self.assertIn("rita", payload)
        self.assertNotIn("coverage", payload)
        self.assertNotIn("message", payload)
        self.assertNotIn("overall", payload)
        self.assertNotIn("next_expected", payload["ingest"])
        self.assertNotIn("queue_depth", payload["ingest"])
        self.assertEqual(payload["ingest"]["pcaps_processed_24h"], 3)
        self.assertIn("gap_free_since", payload["ingest"])
        self.assertNotIn("queue_depth", payload["analysis"])
        self.assertEqual(payload["analysis"]["avg_processing_time_sec"], 34.0)
        self.assertEqual(payload["rita"]["records_count"], 2)
        self.assertNotIn("message", payload["rita"])

    def test_alert_actions_and_network_health_work(self):
        missing = self.client.post("/api/alerts/missing/dismiss", json={})
        self.assertEqual(missing.status_code, 404)
        dismiss = self.client.post(f"/api/alerts/{self.alert_id}/dismiss", json={"comment": "test dismiss", "ttl_days": 30})
        self.assertEqual(dismiss.status_code, 200)

        health = self.client.get("/api/network-health")
        self.assertEqual(health.status_code, 200)
        payload = health.get_json()
        self.assertEqual(payload["devices"]["total"], 1)
        self.assertNotIn("pipeline", payload)

    def test_alert_review_endpoint_returns_triage_fields(self):
        alerts_response = self.client.get("/api/alerts?status=active")
        self.assertEqual(alerts_response.status_code, 200)
        alerts_payload = alerts_response.get_json()
        self.assertEqual(alerts_payload["alerts"][0]["triage_verdict"], "needs_review")
        self.assertIn("triage_reasoning", alerts_payload["alerts"][0])

        review = self.client.post(
            f"/api/alerts/{self.alert_id}/review",
            json={
                "status": "resolved",
                "user_verdict": "likely_malicious",
                "user_comment": "Confirmed after manual review",
                "reviewed_by": "api-test",
            },
        )
        self.assertEqual(review.status_code, 200)
        review_payload = review.get_json()
        self.assertEqual(review_payload["alert"]["status"], "resolved")
        self.assertEqual(review_payload["alert"]["user_verdict"], "likely_malicious")

        detail = self.client.get(f"/api/alerts/{self.alert_id}")
        self.assertEqual(detail.status_code, 200)
        detail_payload = detail.get_json()
        self.assertIn("triage_history", detail_payload)
        self.assertIn("occurrences", detail_payload)
        self.assertEqual(detail_payload["triage_summary"], "New beacon candidate requires validation.")


if __name__ == "__main__":
    unittest.main()
