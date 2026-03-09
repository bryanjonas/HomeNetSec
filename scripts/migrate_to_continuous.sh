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

DRY_RUN="${1:-}"

log() {
  echo "[$(date -Iseconds)] [migrate_to_continuous] $*"
}

run_or_echo() {
  if [[ "$DRY_RUN" == "--dry-run" ]]; then
    printf '[dry-run] %q ' "$@"
    printf '\n'
  else
    "$@"
  fi
}

flatten_historical_merges() {
  local found=0
  while IFS= read -r -d '' merge_path; do
    found=1
    run_or_echo python3 "$ROOT_DIR/scripts/flatten_continuous_layout.py" --workdir "$WORKDIR" --pcap "$merge_path"
  done < <(find "$WORKDIR/pcaps" -mindepth 2 -type f -name 'merged-*.pcap' -print0)

  if [[ "$found" -eq 0 ]]; then
    log "No historical merged PCAPs found under day folders"
  fi
}

main() {
  log "Initializing continuous databases"
  run_or_echo python3 "$ROOT_DIR/scripts/init_databases.py" --workdir "$WORKDIR"

  log "Migrating historical alerts"
  run_or_echo python3 "$ROOT_DIR/scripts/migrate_to_alerts_db.py" --workdir "$WORKDIR" --days 3650

  log "Migrating historical device data"
  run_or_echo "$ROOT_DIR/scripts/migrate_devices.sh"

  log "Flattening historical merged artifacts"
  flatten_historical_merges

  log "Continuous migration complete"
}

main "$@"
