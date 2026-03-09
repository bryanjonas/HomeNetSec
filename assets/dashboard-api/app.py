#!/usr/bin/env python3
"""
HomeNetSec Dashboard API

Flask REST API for the HomeNetSec dashboard.
Provides endpoints for alert management, device inventory, and pipeline status.

Usage:
    gunicorn -w 4 -b 0.0.0.0:5000 app:app
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
import json
import os
import sys
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta, timezone

# Add scripts directory to path for imports
REPO_ROOT = Path(__file__).parent.parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from alert_db import AlertDB

app = Flask(__name__)
CORS(app)  # Enable CORS for local development

# Configuration
WORKDIR = os.environ.get('HOMENETSEC_WORKDIR', '/mnt/5TB/HomeNetSec/output')
STATE_DIR = os.environ.get('HOMENETSEC_STATE_DIR') or os.path.join(WORKDIR, 'state')
ALERTS_DB_PATH = os.path.join(STATE_DIR, 'alerts.sqlite')
DEVICES_DB_PATH = os.path.join(STATE_DIR, 'devices.sqlite')
PIPELINE_STATUS_PATH = os.path.join(STATE_DIR, 'pipeline_status.json')
MIN_ALERT_CONFIDENCE_RAW = os.environ.get("HOMENETSEC_MIN_ALERT_CONFIDENCE", "0").strip()
SUPPORTED_ALERT_SEVERITIES = ("critical", "high", "med", "low", "info")
ALERT_SEVERITY_FILTER_RAW = os.environ.get(
    "HOMENETSEC_ALERT_SEVERITIES",
    ",".join(SUPPORTED_ALERT_SEVERITIES),
).strip()


def parse_min_confidence(raw_value: str) -> float:
    """Parse a minimum confidence threshold from environment text."""
    try:
        value = float(raw_value)
    except (TypeError, ValueError):
        return 0.0
    if value < 0:
        return 0.0
    if value > 1:
        return 1.0
    return value


MIN_ALERT_CONFIDENCE = parse_min_confidence(MIN_ALERT_CONFIDENCE_RAW)


def parse_alert_severity_filter(raw_value: str) -> tuple[str, ...]:
    """Parse and normalize alert severity allowlist from env text."""
    requested = []
    seen = set()
    for item in (raw_value or "").split(","):
        severity = item.strip().lower()
        if severity not in SUPPORTED_ALERT_SEVERITIES:
            continue
        if severity in seen:
            continue
        seen.add(severity)
        requested.append(severity)

    if requested:
        return tuple(requested)
    return SUPPORTED_ALERT_SEVERITIES


ALERT_SEVERITY_FILTER = parse_alert_severity_filter(ALERT_SEVERITY_FILTER_RAW)

DEFAULT_VISIBLE_DEVICE_CIDRS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
DEFAULT_HIDDEN_DEVICE_CIDRS = "127.0.0.0/8,169.254.0.0/16,172.17.0.0/16,172.18.0.0/16,172.19.0.0/16,172.30.0.0/16"


def parse_cidrs(raw_value):
    """Parse comma-separated CIDRs, ignoring invalid entries."""
    networks = []
    for item in (raw_value or "").split(","):
        cidr = item.strip()
        if not cidr:
            continue
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return networks


VISIBLE_DEVICE_CIDRS = parse_cidrs(
    os.environ.get("HOMENETSEC_VISIBLE_DEVICE_CIDRS", DEFAULT_VISIBLE_DEVICE_CIDRS)
)
HIDDEN_DEVICE_CIDRS = parse_cidrs(
    os.environ.get("HOMENETSEC_HIDDEN_DEVICE_CIDRS", DEFAULT_HIDDEN_DEVICE_CIDRS)
)


def parse_json_field(value, default):
    """Parse a JSON-encoded database field safely."""
    try:
        return json.loads(value or json.dumps(default))
    except (TypeError, json.JSONDecodeError):
        return default


def load_json(path: Path):
    """Load JSON from disk safely."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return {}


def get_db_connection(db_path):
    """Get database connection with row factory."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def should_show_device_ip(ip_value):
    """Return True when an IP should be shown in dashboard device lists."""
    try:
        ip_obj = ipaddress.ip_address((ip_value or "").strip())
    except ValueError:
        return False

    if not ip_obj.is_private:
        return False

    if VISIBLE_DEVICE_CIDRS and not any(ip_obj in network for network in VISIBLE_DEVICE_CIDRS):
        return False

    if any(ip_obj in network for network in HIDDEN_DEVICE_CIDRS):
        return False

    return True


def serialize_alert(alert_dict):
    """Normalize alert rows for API responses."""
    payload = dict(alert_dict)
    payload['evidence'] = parse_json_field(payload.get('evidence_json'), {})
    payload['recommendation'] = parse_json_field(payload.get('recommendation_json'), {})
    payload['triage_reasoning'] = parse_json_field(payload.get('triage_reasoning_json'), {})
    payload.pop('evidence_json', None)
    payload.pop('recommendation_json', None)
    payload.pop('triage_reasoning_json', None)
    return payload


def count_nonempty_lines(path: str) -> int:
    """Count non-empty lines in a text file."""
    if not os.path.exists(path):
        return 0
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def latest_mtime_iso(path: Path):
    """Return the newest mtime under a file or directory as an ISO string."""
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
    return datetime.fromtimestamp(latest, tz=timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def directory_size_mb(path: Path) -> float:
    """Return directory size in MB."""
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


def derive_gap_free_since():
    """Return the latest contiguous ingest timestamp as an ISO string."""
    ingest_state_path = Path(STATE_DIR) / 'ingest_state.json'
    ingest_state = {}
    if ingest_state_path.exists():
        try:
            ingest_state = json.loads(ingest_state_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            ingest_state = {}

    gap_epoch = int(
        ingest_state.get('last_contiguous_epoch')
        or ingest_state.get('last_merged_epoch')
        or ingest_state.get('last_epoch')
        or 0
    )
    if not gap_epoch:
        return None
    return datetime.fromtimestamp(gap_epoch, tz=timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def count_recent_merged_inputs(hours=24):
    """Count source PCAP inputs represented by recent merge manifests."""
    pcap_root = Path(WORKDIR) / 'pcaps'
    if not pcap_root.exists():
        return 0

    cutoff_epoch = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp())
    total_inputs = 0

    for manifest_path in pcap_root.rglob('*.manifest.json'):
        payload = load_json(manifest_path)
        if not payload:
            continue
        try:
            merged_epoch = int(payload.get('merged_at_epoch') or 0)
        except (TypeError, ValueError):
            merged_epoch = 0
        if merged_epoch < cutoff_epoch:
            continue

        inputs = payload.get('inputs')
        if isinstance(inputs, list) and inputs:
            total_inputs += len(inputs)
        else:
            total_inputs += 1

    return total_inputs


def derive_rita_status(existing=None):
    """Build RITA status from current state."""
    existing = existing or {}
    rita_dir = Path(WORKDIR) / 'rita-data'
    beacon_file = rita_dir / 'beacons_latest.txt'
    last_import = latest_mtime_iso(beacon_file) or existing.get('last_import')
    status = existing.get('status') or ('healthy' if last_import else 'idle')
    if beacon_file.exists():
        records_count = count_nonempty_lines(str(beacon_file))
    else:
        records_count = int(existing.get('records_count') or 0)

    return {
        'status': status,
        'dataset_size_mb': existing.get('dataset_size_mb', directory_size_mb(rita_dir)),
        'last_import': last_import,
        'records_count': records_count,
    }


def normalize_pipeline_status(payload):
    """Normalize pipeline status to the continuous dashboard schema."""
    payload = payload or {}

    ingest = payload.get('ingest') or {}
    analysis = payload.get('analysis') or {}
    coverage = payload.get('coverage') or {}
    pcaps_processed = ingest.get('pcaps_processed_24h')
    if pcaps_processed is None:
        pcaps_processed = count_recent_merged_inputs(hours=24)
    gap_free_since = ingest.get('gap_free_since') or coverage.get('gap_free_since') or derive_gap_free_since()

    normalized = {
        'updated_at': payload.get('updated_at') or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
        'status': payload.get('status') or payload.get('overall', {}).get('status') or 'unknown',
        'ingest': {
            'status': ingest.get('status', payload.get('status', 'unknown')),
            'last_run': ingest.get('last_run') or payload.get('last_run'),
            'gap_free_since': gap_free_since,
            'pcaps_processed_24h': pcaps_processed,
            'errors_24h': ingest.get('errors_24h', 0),
        },
        'analysis': {
            'status': analysis.get('status', payload.get('status', 'unknown')),
            'last_run': analysis.get('last_run') or payload.get('last_run'),
            'avg_processing_time_sec': analysis.get('avg_processing_time_sec', 0),
            'errors_24h': analysis.get('errors_24h', 0),
            'last_duration_sec': analysis.get('last_duration_sec'),
        },
        'rita': derive_rita_status(payload.get('rita') or {}),
    }

    return normalized


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'alerts_db_exists': os.path.exists(ALERTS_DB_PATH),
        'devices_db_exists': os.path.exists(DEVICES_DB_PATH),
    })


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """
    Get alerts with optional filtering.

    Query parameters:
    - status: Filter by status (new, resolved, dismissed)
    - severity: Filter by severity (info, low, med, high, critical)
    - kind: Filter by kind
    - limit: Max results (default: 100)
    - offset: Pagination offset (default: 0)
    """
    status = request.args.get('status')
    severity = request.args.get('severity')
    kind = request.args.get('kind')
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))

    try:
        # Build query
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if status == 'active':
            query += " AND dismissed = 0 AND status NOT IN ('resolved', 'dismissed')"
        elif status:
            query += " AND status = ?"
            params.append(status)
        if ALERT_SEVERITY_FILTER:
            placeholders = ",".join("?" for _ in ALERT_SEVERITY_FILTER)
            query += f" AND severity IN ({placeholders})"
            params.extend(ALERT_SEVERITY_FILTER)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if kind:
            query += " AND kind = ?"
            params.append(kind)
        if MIN_ALERT_CONFIDENCE > 0:
            query += " AND COALESCE(triage_confidence, confidence, 0) >= ?"
            params.append(MIN_ALERT_CONFIDENCE)

        # Add ordering
        query += """ ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'med' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            last_seen DESC
        """

        # Add pagination
        query += f" LIMIT {limit} OFFSET {offset}"

        # Execute
        conn = get_db_connection(ALERTS_DB_PATH)
        alerts = conn.execute(query, params).fetchall()
        conn.close()

        # Convert to dicts and parse JSON fields
        result = []
        for alert in alerts:
            result.append(serialize_alert(dict(alert)))

        counts = {}
        for alert in result:
            severity_name = alert.get('severity', 'unknown')
            counts[severity_name] = counts.get(severity_name, 0) + 1

        return jsonify({
            'alerts': result,
            'count': len(result),
            'counts': counts,
            'min_confidence_applied': MIN_ALERT_CONFIDENCE,
            'severity_filter_applied': list(ALERT_SEVERITY_FILTER),
            'limit': limit,
            'offset': offset
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>', methods=['GET'])
def get_alert(alert_id):
    """Get detailed alert information."""
    try:
        db = AlertDB(ALERTS_DB_PATH)
        alert = db.get_alert_by_id(alert_id)
        triage_history = db.get_alert_triage_history(alert_id)
        occurrences = db.get_alert_occurrences(alert_id, limit=20)
        db.close()

        if not alert:
            return jsonify({'error': 'Alert not found'}), 404

        alert['triage_history'] = triage_history
        alert['occurrences'] = occurrences
        return jsonify(serialize_alert(alert))

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>/dismiss', methods=['POST'])
def dismiss_alert(alert_id):
    """Dismiss an alert with optional TTL."""
    try:
        data = request.get_json() or {}
        comment = data.get('comment', '')
        ttl_days = int(data.get('ttl_days', 30))
        verdict = data.get('verdict', 'false_positive')

        db = AlertDB(ALERTS_DB_PATH)
        success = db.dismiss_alert(alert_id, comment, ttl_days, verdict)
        db.close()

        if not success:
            return jsonify({'error': 'Alert not found'}), 404

        return jsonify({
            'success': True,
            'alert_id': alert_id,
            'status': 'dismissed',
            'ttl_days': ttl_days
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Resolve an alert."""
    try:
        data = request.get_json() or {}
        note = data.get('note', '')
        verdict = data.get('verdict', 'resolved')

        db = AlertDB(ALERTS_DB_PATH)
        success = db.resolve_alert(alert_id, note, verdict)
        db.close()

        if not success:
            return jsonify({'error': 'Alert not found'}), 404

        return jsonify({
            'success': True,
            'alert_id': alert_id,
            'status': 'resolved'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>/review', methods=['POST'])
def review_alert(alert_id):
    """Save structured review feedback and optional status updates."""
    try:
        data = request.get_json() or {}
        status = data.get('status')
        if status == 'active':
            status = 'new'

        ttl_days = data.get('ttl_days')
        ttl_days = int(ttl_days) if ttl_days not in (None, '') else None

        db = AlertDB(ALERTS_DB_PATH)
        success = db.save_review(
            alert_id,
            user_verdict=data.get('user_verdict'),
            user_comment=data.get('user_comment'),
            status=status,
            ttl_days=ttl_days,
            reviewed_by=data.get('reviewed_by', 'dashboard'),
        )
        alert = db.get_alert_by_id(alert_id) if success else None
        db.close()

        if not success:
            return jsonify({'error': 'Alert not found'}), 404

        return jsonify({
            'success': True,
            'alert_id': alert_id,
            'alert': alert,
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/stats', methods=['GET'])
def get_alert_stats():
    """Get alert statistics."""
    try:
        db = AlertDB(ALERTS_DB_PATH)
        stats = db.get_stats()
        db.close()

        return jsonify(stats)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/devices', methods=['GET'])
def get_devices():
    """
    Get devices with optional filtering.

    Query parameters:
    - status: Filter by status (known, unknown)
    - limit: Max results (default: 100)
    """
    status = request.args.get('status')
    limit = int(request.args.get('limit', 100))

    try:
        conn = get_db_connection(DEVICES_DB_PATH)

        query = "SELECT * FROM devices WHERE 1=1"
        params = []

        if status == 'unknown':
            query += " AND is_known = 0 AND last_seen >= datetime('now', '-7 days')"
        elif status == 'known':
            query += " AND is_known = 1"

        query += " ORDER BY last_seen DESC"

        devices = conn.execute(query, params).fetchall()
        conn.close()

        result = [dict(device) for device in devices if should_show_device_ip(device["ip"])]
        result = result[:limit]

        return jsonify({
            'devices': result,
            'count': len(result)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/devices/<ip>', methods=['GET'])
def get_device(ip):
    """Get device details."""
    try:
        conn = get_db_connection(DEVICES_DB_PATH)
        device = conn.execute("SELECT * FROM devices WHERE ip = ?", (ip,)).fetchone()
        conn.close()

        if not device:
            return jsonify({'error': 'Device not found'}), 404

        return jsonify(dict(device))

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/devices/<ip>/identify', methods=['POST'])
def identify_device(ip):
    """Mark device as known and set friendly name."""
    try:
        data = request.get_json() or {}
        friendly_name = data.get('friendly_name', '')
        device_type = data.get('device_type', '')

        conn = get_db_connection(DEVICES_DB_PATH)
        conn.execute("""
            UPDATE devices
            SET friendly_name = ?,
                device_type = ?,
                is_known = 1,
                updated_at = datetime('now')
            WHERE ip = ?
        """, (friendly_name, device_type, ip))
        conn.commit()

        success = conn.total_changes > 0
        conn.close()

        if not success:
            return jsonify({'error': 'Device not found'}), 404

        return jsonify({
            'success': True,
            'ip': ip,
            'friendly_name': friendly_name
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/devices/<ip>/trust', methods=['POST'])
def trust_device(ip):
    """Mark a device as trusted."""
    try:
        conn = get_db_connection(DEVICES_DB_PATH)
        conn.execute("""
            UPDATE devices
            SET is_known = 1,
                is_trusted = 1,
                updated_at = datetime('now')
            WHERE ip = ?
        """, (ip,))
        conn.commit()
        success = conn.total_changes > 0
        conn.close()

        if not success:
            return jsonify({'error': 'Device not found'}), 404

        return jsonify({'success': True, 'ip': ip, 'is_trusted': True})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/devices/<ip>/monitor', methods=['POST'])
def set_device_monitoring(ip):
    """Toggle device monitoring."""
    try:
        data = request.get_json() or {}
        is_monitored = 1 if data.get('is_monitored', True) else 0

        conn = get_db_connection(DEVICES_DB_PATH)
        conn.execute("""
            UPDATE devices
            SET is_monitored = ?,
                updated_at = datetime('now')
            WHERE ip = ?
        """, (is_monitored, ip))
        conn.commit()
        success = conn.total_changes > 0
        conn.close()

        if not success:
            return jsonify({'error': 'Device not found'}), 404

        return jsonify({'success': True, 'ip': ip, 'is_monitored': bool(is_monitored)})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/pipeline-status', methods=['GET'])
def get_pipeline_status():
    """Get pipeline execution status."""
    try:
        if not os.path.exists(PIPELINE_STATUS_PATH):
            return jsonify(normalize_pipeline_status({}))

        with open(PIPELINE_STATUS_PATH, 'r') as f:
            status = json.load(f)

        return jsonify(normalize_pipeline_status(status))

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/timeline', methods=['GET'])
def get_timeline():
    """
    Get recent activity timeline.

    Query parameters:
    - hours: Hours to look back (default: 24)
    """
    hours = int(request.args.get('hours', 24))

    try:
        cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

        # Get recent alerts
        conn = get_db_connection(ALERTS_DB_PATH)
        recent_alerts = conn.execute("""
            SELECT alert_id, kind, severity, src_ip, dst_ip, created_at as timestamp, 'alert_created' as event_type
            FROM alerts
            WHERE created_at >= ?
            ORDER BY created_at DESC
            LIMIT 50
        """, (cutoff,)).fetchall()
        conn.close()

        # Get recent devices
        conn = get_db_connection(DEVICES_DB_PATH)
        recent_devices = conn.execute("""
            SELECT ip, friendly_name, first_seen as timestamp, 'device_discovered' as event_type
            FROM devices
            WHERE first_seen >= ?
            ORDER BY first_seen DESC
            LIMIT 20
        """, (cutoff,)).fetchall()
        conn.close()

        # Combine and sort
        timeline = []
        timeline.extend([dict(row) for row in recent_alerts])
        timeline.extend([dict(row) for row in recent_devices])
        timeline.sort(key=lambda x: x['timestamp'], reverse=True)

        return jsonify({
            'timeline': timeline[:50],
            'count': len(timeline[:50])
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/network-health', methods=['GET'])
def get_network_health():
    """Get network health summary."""
    try:
        # Get device counts
        conn = get_db_connection(DEVICES_DB_PATH)
        rows = conn.execute("SELECT ip, is_known FROM devices").fetchall()
        visible_rows = [row for row in rows if should_show_device_ip(row["ip"])]
        total_devices = len(visible_rows)
        known_devices = sum(1 for row in visible_rows if int(row["is_known"] or 0) == 1)
        unknown_devices = total_devices - known_devices
        conn.close()

        # Get alert counts
        db = AlertDB(ALERTS_DB_PATH)
        stats = db.get_stats()
        db.close()

        return jsonify({
            'devices': {
                'total': total_devices,
                'known': known_devices,
                'unknown': unknown_devices
            },
            'alerts': {
                'total': stats.get('total', 0),
                'active': stats.get('active', 0),
                'by_severity': stats.get('by_severity', {})
            },
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Development server
    app.run(host='0.0.0.0', port=5000, debug=True)
