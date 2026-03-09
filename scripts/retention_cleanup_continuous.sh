#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$ROOT_DIR/.env" ]] && set -a && source "$ROOT_DIR/.env" && set +a

if [[ -z "${HOMENETSEC_WORKDIR:-}" ]]; then
  echo "[homenetsec] ERROR: HOMENETSEC_WORKDIR not set. Please configure in .env file." >&2
  exit 2
fi

WORKDIR="$HOMENETSEC_WORKDIR"
if [[ "${WORKDIR##*/}" != "output" ]]; then
  WORKDIR="$WORKDIR/output"
fi

MERGED_PCAP_RETENTION_DAYS="${MERGED_PCAP_RETENTION_DAYS:-3}"
HOURLY_ARTIFACT_RETENTION_DAYS="${HOURLY_ARTIFACT_RETENTION_DAYS:-30}"
RESOLVED_ALERT_RETENTION_DAYS="${RESOLVED_ALERT_RETENTION_DAYS:-90}"
ALERTS_DB="$WORKDIR/state/alerts.sqlite"

find "$WORKDIR/pcaps" -type f -name 'merged-*.pcap' -mtime +"$MERGED_PCAP_RETENTION_DAYS" -delete
find "$WORKDIR/pcaps" -type f -name 'merged-*.pcap.manifest.json' -mtime +"$MERGED_PCAP_RETENTION_DAYS" -delete
find "$WORKDIR/zeek-logs" -type d -name '*.zeek' -mtime +"$HOURLY_ARTIFACT_RETENTION_DAYS" -exec rm -rf {} +
find "$WORKDIR/suricata" -type f -name 'eve-merged-*.json' -mtime +"$HOURLY_ARTIFACT_RETENTION_DAYS" -delete
find "$WORKDIR/suricata" -type f -name 'fast-merged-*.log' -mtime +"$HOURLY_ARTIFACT_RETENTION_DAYS" -delete

if [[ -f "$ALERTS_DB" ]]; then
  sqlite3 "$ALERTS_DB" \
    "DELETE FROM alerts WHERE status='resolved' AND resolved_at < datetime('now', '-${RESOLVED_ALERT_RETENTION_DAYS} days');"
fi
