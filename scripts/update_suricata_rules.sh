#!/usr/bin/env bash
set -euo pipefail

# Update Suricata Emerging Threats Open rules into the host-mounted rules dir.
# This avoids re-downloading rules every run, and makes offline Suricata runs consistent.

DAY=${1:-}

WORKDIR=${HOMENETSEC_WORKDIR:-"$(cd "$(dirname "$0")/.." && pwd)/output"}
RULESDIR="$WORKDIR/suricata-rules"

mkdir -p "$RULESDIR"

echo "[homenetsec] updating Suricata rules (ET Open) into: $RULESDIR"

# Use the suricata-offline image so we don't require suricata-update on the host.
# The compose file mounts $RULESDIR -> /var/lib/suricata/rules.
cd "$(dirname "$0")/.."

# Enable ET Open if not already enabled, then update.
# (suricata-update is idempotent; enable-source may fail if already enabled, so we ignore that.)
set +e
COMPOSE_PROJECT_PIPELINE="${HOMENETSEC_PIPELINE_COMPOSE_PROJECT:-homenetsec-pipeline}"

DOCKER_BUILDKIT=1 docker compose -p "$COMPOSE_PROJECT_PIPELINE" -f assets/docker-compose.yml --profile ja4 run --rm \
  --entrypoint /bin/sh suricata-offline -lc 'suricata-update list-sources >/dev/null 2>&1 || true; suricata-update enable-source et/open >/dev/null 2>&1 || true; suricata-update' 
rc=$?
set -e

if [[ $rc -ne 0 ]]; then
  echo "[homenetsec] ERROR: suricata-update failed (rc=$rc)" >&2
  exit $rc
fi

# Sanity check that the expected consolidated rules file exists.
if [[ ! -s "$RULESDIR/suricata.rules" ]]; then
  echo "[homenetsec] ERROR: expected rules file missing or empty: $RULESDIR/suricata.rules" >&2
  ls -la "$RULESDIR" >&2 || true
  exit 2
fi

echo "[homenetsec] rules updated: $RULESDIR/suricata.rules ($(wc -l < "$RULESDIR/suricata.rules") lines)"
