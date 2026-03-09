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
MODE="${1:---once}"
INGEST_EXPECT_NEXT_RUN_SECONDS="${INGEST_EXPECT_NEXT_RUN_SECONDS:-}"

mkdir -p "$STATE_DIR"

timestamp() { date -Iseconds; }
log_info() { echo "[$(timestamp)] [continuous_ingest] INFO: $*"; }
log_warn() { echo "[$(timestamp)] [continuous_ingest] WARN: $*" >&2; }
log_error() { echo "[$(timestamp)] [continuous_ingest] ERROR: $*" >&2; }

snapshot_merge_paths() {
  python3 - "$WORKDIR/pcaps" <<'PY'
import glob
import json
import os
import sys

root = sys.argv[1]
paths = set()
for manifest in glob.glob(os.path.join(root, "**", "*.manifest.json"), recursive=True):
    try:
        with open(manifest, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        continue
    merge_path = data.get("merge_path")
    if merge_path:
        paths.add(os.path.realpath(merge_path))

for path in sorted(paths):
    print(path)
PY
}

enqueue_new_merges() {
  local before_snapshot="$1"
  local after_snapshot="$2"
  local new_paths

  new_paths=$(comm -13 "$before_snapshot" "$after_snapshot" || true)
  if [[ -z "$new_paths" ]]; then
    return 0
  fi

  exec 200>"$QUEUE_FILE.lock"
  flock -x 200
  touch "$QUEUE_FILE"

  while IFS= read -r merge_path; do
    [[ -z "$merge_path" ]] && continue
    if ! grep -Fxq "$merge_path" "$QUEUE_FILE"; then
      printf '%s\n' "$merge_path" >>"$QUEUE_FILE"
      log_info "Queued merged PCAP for analysis: $merge_path"
    fi
  done <<<"$new_paths"

  flock -u 200
}

flatten_new_merges() {
  local before_snapshot="$1"
  local after_snapshot="$2"
  local flattened_snapshot
  local new_paths
  flattened_snapshot="$(mktemp)"

  # Flatten only newly discovered merges to avoid reprocessing historical artifacts.
  new_paths=$(comm -13 "$before_snapshot" "$after_snapshot" || true)
  while IFS= read -r merge_path; do
    [[ -z "$merge_path" ]] && continue
    if ! python3 "$ROOT_DIR/scripts/flatten_continuous_layout.py" --workdir "$WORKDIR" --pcap "$merge_path" >/dev/null; then
      log_warn "Flatten failed for merged PCAP (continuing): $merge_path"
    fi
  done <<<"$new_paths"

  snapshot_merge_paths >"$flattened_snapshot"
  cat "$flattened_snapshot"
  rm -f "$flattened_snapshot"
}

update_pipeline_status() {
  local status="$1"
  local message="$2"
  local args=(
    "$ROOT_DIR/scripts/generate_pipeline_status.py"
    --workdir "$WORKDIR"
    --section ingest
    --status "$status"
    --message "$message"
  )

  if [[ -n "$INGEST_EXPECT_NEXT_RUN_SECONDS" ]]; then
    args+=(--next-expected-seconds "$INGEST_EXPECT_NEXT_RUN_SECONDS")
  fi

  python3 "${args[@]}" >/dev/null
}

run_once() {
  local before_snapshot after_snapshot flat_snapshot
  before_snapshot="$(mktemp)"
  after_snapshot="$(mktemp)"
  flat_snapshot="$(mktemp)"
  trap 'rm -f "$before_snapshot" "$after_snapshot" "$flat_snapshot"' RETURN

  snapshot_merge_paths >"$before_snapshot"
  update_pipeline_status "running" "Ingest cycle in progress"

  if ! (cd "$ROOT_DIR" && ./scripts/pcap_ingest_merge_process.sh); then
    update_pipeline_status "error" "Ingest cycle failed"
    log_error "Underlying ingest pipeline failed"
    return 1
  fi

  snapshot_merge_paths >"$after_snapshot"
  flatten_new_merges "$before_snapshot" "$after_snapshot" >"$flat_snapshot"
  enqueue_new_merges "$before_snapshot" "$flat_snapshot"
  update_pipeline_status "idle" "Ingest cycle complete"
}

case "$MODE" in
  --process-once|--once|once)
    run_once
    ;;
  *)
    log_error "Unsupported mode: $MODE (expected --once)"
    exit 2
    ;;
esac
