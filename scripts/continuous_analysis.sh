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

STATE_DIR="$WORKDIR/state"
QUEUE_FILE="$STATE_DIR/analysis_queue.txt"
BASELINE_DB="$STATE_DIR/baselines.sqlite"
ALERTS_DB="$STATE_DIR/alerts.sqlite"
DEVICES_DB="$STATE_DIR/devices.sqlite"
RITA_STAGING_DIR="${HOMENETSEC_RITA_STAGING_DIR:-$STATE_DIR/zeek-flat-staging}"
MODE="${1:---process-queue}"
RUN_RITA="${RUN_RITA:-0}"
COMPOSE_FILE="${HOMENETSEC_COMPOSE_FILE:-$ROOT_DIR/assets/docker-compose.yml}"
RITA_CFG_HOST="${HOMENETSEC_RITA_CONFIG:-$ROOT_DIR/assets/rita-config.yaml.example}"
COMPOSE_PROJECT_PIPELINE="${HOMENETSEC_PIPELINE_COMPOSE_PROJECT:-homenetsec-pipeline}"

mkdir -p "$STATE_DIR" "$WORKDIR/reports"

timestamp() { date -Iseconds; }
log_info() { echo "[$(timestamp)] [continuous_analysis] INFO: $*"; }
log_error() { echo "[$(timestamp)] [continuous_analysis] ERROR: $*" >&2; }

ensure_state_databases() {
  python3 "$ROOT_DIR/scripts/init_databases.py" --workdir "$WORKDIR" >/dev/null
}

compose() {
  HOMENETSEC_WORKDIR="$WORKDIR" HOMENETSEC_RITA_STAGING_DIR="$RITA_STAGING_DIR" docker compose -p "$COMPOSE_PROJECT_PIPELINE" -f "$COMPOSE_FILE" "$@"
}

update_pipeline_status() {
  local status="$1"
  local message="$2"
  local queue_depth="$3"
  local duration_sec="${4:-}"

  local args=(
    "$ROOT_DIR/scripts/generate_pipeline_status.py"
    --workdir "$WORKDIR"
    --section analysis
    --status "$status"
    --message "$message"
    --queue-depth "$queue_depth"
  )

  if [[ -n "$duration_sec" ]]; then
    args+=(--last-duration-sec "$duration_sec")
  fi

  python3 "${args[@]}" >/dev/null
}

dequeue_items() {
  touch "$QUEUE_FILE"
  exec 201>"$QUEUE_FILE.lock"
  flock -x 201

  mapfile -t queue_items < <(grep -ve '^[[:space:]]*$' "$QUEUE_FILE" || true)
  : >"$QUEUE_FILE"
  flock -u 201

  printf '%s\n' "${queue_items[@]}"
}

pcap_day() {
  local pcap_path="$1"
  local base
  base="$(basename "$pcap_path")"

  if [[ "$base" =~ (lan-)?([0-9]{4}-[0-9]{2}-[0-9]{2})_ ]]; then
    printf '%s\n' "${BASH_REMATCH[2]}"
    return 0
  fi

  if [[ "$base" =~ ([0-9]{4})-([0-9]{2})-([0-9]{2})T ]]; then
    printf '%s-%s-%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
    return 0
  fi

  if [[ "$base" =~ ([0-9]{4})([0-9]{2})([0-9]{2})T ]]; then
    printf '%s-%s-%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
    return 0
  fi

  return 1
}

pcap_zeek_dir() {
  local pcap_path="$1"
  local base day flat_path day_path
  base="$(basename "$pcap_path")"
  flat_path="$WORKDIR/zeek-logs/${base}.zeek"
  if [[ -d "$flat_path" ]]; then
    printf '%s\n' "$flat_path"
    return 0
  fi
  day="$(basename "$(dirname "$pcap_path")")"
  day_path="$WORKDIR/zeek-logs/$day/${base}.zeek"
  printf '%s\n' "$day_path"
}

pcap_eve_path() {
  local pcap_path="$1"
  local base day flat_path day_path
  base="$(basename "$pcap_path")"
  flat_path="$WORKDIR/suricata/eve-${base%.pcap}.json"
  if [[ -f "$flat_path" ]]; then
    printf '%s\n' "$flat_path"
    return 0
  fi
  day="$(basename "$(dirname "$pcap_path")")"
  day_path="$WORKDIR/suricata/$day/eve-${base%.pcap}.json"
  printf '%s\n' "$day_path"
}

run_rita_continuous() {
  if [[ "$RUN_RITA" != "1" ]]; then
    python3 "$ROOT_DIR/scripts/generate_pipeline_status.py" \
      --workdir "$WORKDIR" \
      --section rita \
      --status disabled \
      --message "RITA disabled (set RUN_RITA=1 to enable)" >/dev/null
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1; then
    log_error "Skipping continuous RITA: docker not available"
    python3 "$ROOT_DIR/scripts/generate_pipeline_status.py" \
      --workdir "$WORKDIR" \
      --section rita \
      --status degraded \
      --message "docker not available for RITA" >/dev/null
    return 0
  fi

  mkdir -p "$RITA_STAGING_DIR" 2>/dev/null || true
  if [[ ! -w "$RITA_STAGING_DIR" ]] && rmdir "$RITA_STAGING_DIR" 2>/dev/null; then
    mkdir -p "$RITA_STAGING_DIR" 2>/dev/null || true
  fi
  if [[ ! -w "$RITA_STAGING_DIR" ]]; then
    log_error "RITA staging directory is not writable: $RITA_STAGING_DIR"
    python3 "$ROOT_DIR/scripts/generate_pipeline_status.py" \
      --workdir "$WORKDIR" \
      --section rita \
      --status error \
      --message "RITA staging directory not writable: zeek-flat-staging" >/dev/null
    return 1
  fi

  if ! python3 "$ROOT_DIR/scripts/zeek_flatten_recent.py" \
    --zeek-logs-dir "$WORKDIR/zeek-logs" \
    --output "$RITA_STAGING_DIR" \
    --lookback-hours "${RITA_RECENT_LOOKBACK_HOURS:-2}"; then
    log_error "Failed to flatten recent Zeek logs for RITA"
    python3 "$ROOT_DIR/scripts/generate_pipeline_status.py" \
      --workdir "$WORKDIR" \
      --section rita \
      --status error \
      --message "Failed to prepare recent Zeek logs for RITA" >/dev/null
    return 1
  fi

  if [[ ! -s "$RITA_STAGING_DIR/conn.log" ]]; then
    log_info "Skipping continuous RITA: no recent Zeek conn.log data"
    python3 "$ROOT_DIR/scripts/generate_pipeline_status.py" \
      --workdir "$WORKDIR" \
      --section rita \
      --status idle \
      --message "No recent Zeek data for RITA" >/dev/null
    return 0
  fi

  mkdir -p "$WORKDIR/rita-data"
  compose --profile rita up -d mongo >/dev/null 2>&1 || {
    log_error "Unable to start Mongo for continuous RITA"
    python3 "$ROOT_DIR/scripts/generate_pipeline_status.py" \
      --workdir "$WORKDIR" \
      --section rita \
      --status error \
      --message "Unable to start Mongo for RITA" >/dev/null
    return 1
  }

  local ready=0
  local _i
  for _i in $(seq 1 30); do
    if docker exec rita-mongo mongo --quiet --eval 'db.adminCommand({ping:1}).ok' 2>/dev/null | grep -q '^1$'; then
      ready=1
      break
    fi
    if docker exec rita-mongo mongosh --quiet --eval 'db.adminCommand({ping:1}).ok' 2>/dev/null | grep -q '^1$'; then
      ready=1
      break
    fi
    sleep 2
  done

  if [[ "$ready" != "1" ]]; then
    log_error "Mongo did not become ready for continuous RITA"
    python3 "$ROOT_DIR/scripts/generate_pipeline_status.py" \
      --workdir "$WORKDIR" \
      --section rita \
      --status error \
      --message "Mongo did not become ready for RITA" >/dev/null
    return 1
  fi

  install -m 0644 "$RITA_CFG_HOST" "$WORKDIR/rita-data/rita-config.yaml"
  if ! compose --profile rita run --rm rita \
    --config /out/rita-config.yaml import /logs-flat-staging zeek_continuous; then
    log_error "Continuous RITA import failed"
    python3 "$ROOT_DIR/scripts/generate_pipeline_status.py" \
      --workdir "$WORKDIR" \
      --section rita \
      --status error \
      --message "Continuous RITA import failed" >/dev/null
    return 1
  fi

  if ! compose --profile rita run --rm rita \
    --config /out/rita-config.yaml show-beacons zeek_continuous >"$WORKDIR/rita-data/beacons_latest.txt"; then
    log_error "Continuous RITA beacon extraction failed"
    python3 "$ROOT_DIR/scripts/generate_pipeline_status.py" \
      --workdir "$WORKDIR" \
      --section rita \
      --status error \
      --message "Continuous RITA beacon extraction failed" >/dev/null
    return 1
  fi

  python3 "$ROOT_DIR/scripts/rita_to_alerts.py" \
    --rita-output "$WORKDIR/rita-data/beacons_latest.txt" \
    --alerts-db "$ALERTS_DB" \
    --label "$(date -u +%Y-%m-%dT%H:00:00Z)"

  python3 "$ROOT_DIR/scripts/generate_pipeline_status.py" \
    --workdir "$WORKDIR" \
    --section rita \
    --status healthy \
    --last-import "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
}

process_queue_once() {
  ensure_state_databases
  local started_at
  started_at=$(date +%s)
  local analysis_failed=0
  local queue_output
  queue_output="$(dequeue_items)"
  local queue_depth=0
  [[ -n "$queue_output" ]] && queue_depth=$(printf '%s\n' "$queue_output" | grep -cve '^[[:space:]]*$' || true)

  if [[ "$queue_depth" -eq 0 ]]; then
    if [[ "$RUN_RITA" != "1" ]]; then
      python3 "$ROOT_DIR/scripts/generate_pipeline_status.py" \
        --workdir "$WORKDIR" \
        --section rita \
        --status disabled \
        --message "RITA disabled (set RUN_RITA=1 to enable)" >/dev/null
    else
      python3 "$ROOT_DIR/scripts/generate_pipeline_status.py" \
        --workdir "$WORKDIR" \
        --section rita \
        --status idle \
        --message "No queued analysis work; RITA not run" >/dev/null
    fi
    update_pipeline_status "idle" "No queued analysis work" 0
    return 0
  fi

  update_pipeline_status "running" "Processing queued analysis work" "$queue_depth"
  log_info "Processing $queue_depth queued items"

  local item
  while IFS= read -r item; do
    [[ -z "$item" ]] && continue
    local day zeek_dir eve_path
    if ! day="$(pcap_day "$item")"; then
      log_error "Could not derive day from queued item: $item"
      continue
    fi
    zeek_dir="$(pcap_zeek_dir "$item")"
    eve_path="$(pcap_eve_path "$item")"

    if [[ ! -d "$zeek_dir" ]]; then
      log_error "Missing Zeek directory for queued item: $zeek_dir"
      analysis_failed=1
      continue
    fi

    if ! python3 "$ROOT_DIR/scripts/baseline_update_continuous.py" \
      --zeek-dir "$zeek_dir" \
      --db "$BASELINE_DB" \
      --eve "$eve_path" \
      --source-key "$item"; then
      log_error "Rolling baseline update failed for $item"
      analysis_failed=1
      continue
    fi

    if ! python3 "$ROOT_DIR/scripts/device_inventory_update.py" \
      --day "$day" \
      --zeek-dir "$zeek_dir" \
      --db "$DEVICES_DB"; then
      log_error "Device inventory update failed for $item"
      analysis_failed=1
    fi
  done <<<"$queue_output"

  local ALLOWLIST_PATH="${HOMENETSEC_ALLOWLIST:-}"
  if [[ -z "$ALLOWLIST_PATH" ]]; then
    if [[ -f "$STATE_DIR/allowlist.local.json" ]]; then
      ALLOWLIST_PATH="$STATE_DIR/allowlist.local.json"
    else
      ALLOWLIST_PATH="$ROOT_DIR/assets/allowlist.example.json"
    fi
  fi

  if ! python3 "$ROOT_DIR/scripts/detect_continuous.py" \
    --baseline-db "$BASELINE_DB" \
    --alerts-db "$ALERTS_DB" \
    --devices-db "$DEVICES_DB" \
    --workdir "$WORKDIR" \
    --allowlist "$ALLOWLIST_PATH" \
    --lookback-hours "${CONTINUOUS_LOOKBACK_HOURS:-720}" \
    --recent-hours "${CONTINUOUS_RECENT_HOURS:-2}"; then
    log_error "Continuous detection failed"
    analysis_failed=1
  fi

  if ! run_rita_continuous; then
    log_error "Continuous RITA processing failed"
    analysis_failed=1
  fi

  if ! python3 "$ROOT_DIR/scripts/triage_continuous.py" \
    --alerts-db "$ALERTS_DB" \
    --devices-db "$DEVICES_DB" \
    --baseline-db "$BASELINE_DB"; then
    log_error "Continuous triage failed"
    analysis_failed=1
  fi

  if ! (
    cd "$ROOT_DIR" && \
    HOMENETSEC_WORKDIR="$WORKDIR" \
    ./scripts/generate_dashboard.sh
  ); then
    log_error "Dashboard generation failed"
    analysis_failed=1
  fi

  (cd "$ROOT_DIR" && HOMENETSEC_WORKDIR="$WORKDIR" ./scripts/retention_cleanup_continuous.sh) || true

  local ended_at duration_sec
  ended_at=$(date +%s)
  duration_sec=$((ended_at - started_at))

  if [[ "$analysis_failed" -eq 1 ]]; then
    update_pipeline_status "error" "Continuous analysis completed with failures" 0 "$duration_sec"
    return 1
  fi

  update_pipeline_status "idle" "Continuous analysis queue processed successfully" 0 "$duration_sec"
  return 0
}

case "$MODE" in
  --process-queue|--once|once)
    process_queue_once
    ;;
  *)
    log_error "Unsupported mode: $MODE (expected --process-queue)"
    exit 2
    ;;
esac
