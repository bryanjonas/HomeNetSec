#!/usr/bin/env bash
set -Eeuo pipefail

timestamp() { date '+%Y-%m-%dT%H:%M:%S%z'; }
log_info() { echo "[$(timestamp)] [homenetsec] INFO: $*"; }
log_warn() { echo "[$(timestamp)] [homenetsec] WARN: $*" >&2; }
log_error() { echo "[$(timestamp)] [homenetsec] ERROR: $*" >&2; }

on_error() {
  local rc="$1"
  local line="$2"
  local cmd="$3"
  log_error "unexpected failure (exit=$rc line=$line cmd=$cmd)"
  exit "$rc"
}

trap 'on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

# Self-check: fail fast if this script has a syntax error (prevents wasted PCAP pulls).
if ! bash -n "$0"; then
  log_error "pcap_ingest_merge_process.sh failed bash syntax check"
  exit 2
fi

# Hourly ingest:
# - Download all new PCAPs since last successful ingest
# - Merge the downloaded set into a single PCAP
# - Run Suricata + Zeek on the merged PCAP
#
# This is intended to keep analysis incremental without paying per-PCAP container startup cost.

BACKFILL_INDEX_ONLY=0
if [[ "${1:-}" == "--backfill-index-only" ]]; then
  BACKFILL_INDEX_ONLY=1
fi

TZ="America/New_York"; export TZ

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source .env if present (for HOMENETSEC_WORKDIR, etc.)
[[ -f "$ROOT_DIR/.env" ]] && set -a && source "$ROOT_DIR/.env" && set +a

# WORKDIR is REQUIRED - must be set in .env
if [[ -z "${HOMENETSEC_WORKDIR:-}" ]]; then
  log_error "HOMENETSEC_WORKDIR not set. Please configure in .env file."
  exit 2
fi
WORKDIR="$HOMENETSEC_WORKDIR"
if [[ "${WORKDIR##*/}" != "output" ]]; then
  WORKDIR="$WORKDIR/output"
fi
STATE_DIR="$WORKDIR/state"
mkdir -p "$STATE_DIR"

STATE_JSON="$STATE_DIR/ingest_state.json"
SOURCE_PCAP_DELETE_DELAY_HOURS="${SOURCE_PCAP_DELETE_DELAY_HOURS:-48}"
RECENT_MERGE_INDEX_BACKFILL_HOURS="${RECENT_MERGE_INDEX_BACKFILL_HOURS:-36}"

# Retention (PCAPs are storage-heavy; Zeek/Suricata artifacts are small and needed for RITA's 7-day rolling window)
MERGED_PCAP_RETENTION_DAYS="${MERGED_PCAP_RETENTION_DAYS:-3}"
HOURLY_ARTIFACT_RETENTION_DAYS="${HOURLY_ARTIFACT_RETENTION_DAYS:-30}"


# PCAP source directory (local) - REQUIRED
# Must be set in .env or as environment variable
if [[ -z "${PCAP_SOURCE_DIR:-}" ]]; then
  log_error "PCAP_SOURCE_DIR not set. Please configure in .env file."
  exit 2
fi

# Partial protections
SAFETY_LAG_SECONDS="${SAFETY_LAG_SECONDS:-120}"  # don't consider anything newer than now-lag

require() {
  command -v "$1" >/dev/null 2>&1 || { log_error "missing dependency: $1"; exit 127; }
}

require python3
if (( BACKFILL_INDEX_ONLY == 0 )); then
  require docker
  require mergecap
  require capinfos
  require tshark
fi

COMPOSE_PROJECT_PIPELINE="${HOMENETSEC_PIPELINE_COMPOSE_PROJECT:-homenetsec-pipeline}"

compose() {
  HOMENETSEC_WORKDIR="$WORKDIR" docker compose -p "$COMPOSE_PROJECT_PIPELINE" -f "$ROOT_DIR/assets/docker-compose.yml" "$@"
}

write_merge_manifest() {
  local manifest_path="$1"
  local merge_path="$2"
  local merged_at_epoch="$3"
  local delete_delay_hours="$4"
  local py
  shift 4

  py=$(cat <<'PY'
import datetime as dt
import json
import os
import re
import sys
import time

if hasattr(time, "tzset"):
    time.tzset()

manifest_path = os.environ["MANIFEST_PATH"]
merge_path = os.path.realpath(os.environ["MERGE_PATH"])
merged_at_epoch = int(os.environ["MERGED_AT_EPOCH"])
delete_delay_hours = int(os.environ["DELETE_DELAY_HOURS"])
paths = [p for p in sys.stdin.buffer.read().decode("utf-8").split("\0") if p]

inputs = []
for raw_path in paths:
    real_path = os.path.realpath(raw_path)
    st = os.stat(real_path)
    bn = os.path.basename(real_path)
    epoch = 0
    m = re.match(r"^lan-(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})\.pcap", bn)
    if m:
        day = dt.date.fromisoformat(m.group(1))
        ts = dt.datetime(day.year, day.month, day.day, int(m.group(2)), int(m.group(3)), int(m.group(4)))
        epoch = int(ts.timestamp())
    inputs.append({
        "path": real_path,
        "basename": bn,
        "size": int(st.st_size),
        "mtime_ns": int(st.st_mtime_ns),
        "epoch": int(epoch),
    })

doc = {
    "merge_path": merge_path,
    "merge_basename": os.path.basename(merge_path),
    "merged_at_epoch": merged_at_epoch,
    "merged_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(merged_at_epoch)),
    "delete_after_epoch": merged_at_epoch + (delete_delay_hours * 3600),
    "delete_after": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(merged_at_epoch + (delete_delay_hours * 3600))),
    "inputs": inputs,
}

tmp_path = manifest_path + ".partial"
with open(tmp_path, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2)
os.replace(tmp_path, manifest_path)
PY
)

  printf '%s\0' "$@" | \
    MANIFEST_PATH="$manifest_path" \
    MERGE_PATH="$merge_path" \
    MERGED_AT_EPOCH="$merged_at_epoch" \
    DELETE_DELAY_HOURS="$delete_delay_hours" \
    python3 -c "$py"
}

filter_previously_merged_candidates() {
  local py
  py=$(cat <<'PY'
import glob
import json
import os
import sys

root = os.environ["MERGE_MANIFEST_ROOT"]
merged_keys = set()

def add_key(path, size, mtime_ns):
    merged_keys.add(f"{os.path.realpath(path)}\t{int(size)}\t{int(mtime_ns)}")

for manifest_path in glob.glob(os.path.join(root, "**", "*.manifest.json"), recursive=True):
    try:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        continue
    for item in data.get("inputs", []) or []:
        path = (item.get("path") or "").strip()
        size = item.get("size")
        mtime_ns = item.get("mtime_ns")
        if path and size is not None and mtime_ns is not None:
            add_key(path, size, mtime_ns)

for manifest_path in glob.glob(os.path.join(root, "**", "*.manifest"), recursive=True):
    try:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            for raw in fh:
                path = raw.strip()
                if not path:
                    continue
                try:
                    st = os.stat(path)
                except FileNotFoundError:
                    continue
                add_key(path, st.st_size, st.st_mtime_ns)
    except Exception:
        continue

for raw in sys.stdin:
    raw = raw.rstrip("\n")
    if not raw:
        continue
    ep, path = raw.split("\t", 1)
    status = "keep"
    try:
        st = os.stat(path)
    except FileNotFoundError:
        pass
    else:
        key = f"{os.path.realpath(path)}\t{int(st.st_size)}\t{int(st.st_mtime_ns)}"
        if key in merged_keys:
            status = "already_merged"
    print(f"{ep}\t{path}\t{status}")
PY
)
  MERGE_MANIFEST_ROOT="$WORKDIR/pcaps" python3 -c "$py"
}

cleanup_delayed_source_pcaps() {
  local cleanup_report
  cleanup_report=$(
    MERGE_MANIFEST_ROOT="$WORKDIR/pcaps" \
    DELETE_DELAY_HOURS="$SOURCE_PCAP_DELETE_DELAY_HOURS" \
    python3 - <<'PY'
import glob
import json
import os
import sys
import time

root = os.environ["MERGE_MANIFEST_ROOT"]
delay_hours = int(os.environ["DELETE_DELAY_HOURS"])
now = int(time.time())
seen = set()

for manifest_path in glob.glob(os.path.join(root, "**", "*.manifest.json"), recursive=True):
    try:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        print(f"WARN\tmanifest unreadable\t{manifest_path}")
        continue

    merged_at_epoch = int(data.get("merged_at_epoch", 0) or 0)
    delete_after_epoch = int(data.get("delete_after_epoch", merged_at_epoch + (delay_hours * 3600)) or 0)
    if delete_after_epoch <= 0 or now < delete_after_epoch:
        continue

    for item in data.get("inputs", []) or []:
        path = (item.get("path") or "").strip()
        if not path:
            continue
        size = item.get("size")
        mtime_ns = item.get("mtime_ns")
        key = (path, size, mtime_ns)
        if key in seen:
            continue
        seen.add(key)

        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue

        if size is not None and int(st.st_size) != int(size):
            print(f"WARN\tmodified size changed\t{path}")
            continue
        if mtime_ns is not None and int(st.st_mtime_ns) != int(mtime_ns):
            print(f"WARN\tmodified mtime changed\t{path}")
            continue

        try:
            os.remove(path)
        except Exception as exc:
            print(f"WARN\tdelete failed ({exc})\t{path}")
            continue

        print(f"INFO\tdeleted delayed merged source\t{path}")
PY
  )

  [[ -z "$cleanup_report" ]] && return 0

  while IFS=$'\t' read -r level action path; do
    [[ -z "$level" ]] && continue
    if [[ "$level" == "WARN" ]]; then
      log_warn "delayed delete: $action: $path"
    else
      log_info "delayed delete: $action: $path"
    fi
  done <<< "$cleanup_report"
}

backfill_recent_merge_manifests() {
  local backfill_report
  backfill_report=$(
    MERGE_MANIFEST_ROOT="$WORKDIR/pcaps" \
    SOURCE_PCAP_DIR="$PCAP_SOURCE_DIR" \
    BACKFILL_HOURS="$RECENT_MERGE_INDEX_BACKFILL_HOURS" \
    DELETE_DELAY_HOURS="$SOURCE_PCAP_DELETE_DELAY_HOURS" \
    python3 - <<'PY'
import datetime as dt
import glob
import json
import os
import re
import time

if hasattr(time, "tzset"):
    time.tzset()

merge_root = os.environ["MERGE_MANIFEST_ROOT"]
source_root = os.environ["SOURCE_PCAP_DIR"]
backfill_hours = int(os.environ["BACKFILL_HOURS"])
delete_delay_hours = int(os.environ["DELETE_DELAY_HOURS"])
now = int(time.time())
window_start = now - (backfill_hours * 3600)

source_entries = []
for path in glob.glob(os.path.join(source_root, "lan-*.pcap*")):
    bn = os.path.basename(path)
    m = re.match(r"^lan-(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})\.pcap", bn)
    if not m:
        continue
    day = dt.date.fromisoformat(m.group(1))
    ts = dt.datetime(day.year, day.month, day.day, int(m.group(2)), int(m.group(3)), int(m.group(4)))
    source_entries.append((int(ts.timestamp()), os.path.realpath(path), bn))

source_entries.sort()

merge_paths = sorted(glob.glob(os.path.join(merge_root, "**", "merged-*.pcap"), recursive=True))
for merge_path in merge_paths:
    manifest_path = merge_path + ".manifest.json"
    if os.path.exists(manifest_path):
        continue

    try:
        merge_stat = os.stat(merge_path)
    except FileNotFoundError:
        continue

    merged_at_epoch = int(merge_stat.st_mtime)
    if merged_at_epoch < window_start:
        continue

    bn = os.path.basename(merge_path)
    m = re.match(r"^merged-(lan-\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})(?:\.pcap)?-to-(lan-\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})(?:\.pcap)?\.pcap$", bn)
    if not m:
        print(f"WARN\tunrecognized merge filename\t{merge_path}")
        continue

    def to_epoch(label: str) -> int:
        mm = re.match(r"^lan-(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})$", label)
        if not mm:
            return 0
        day = dt.date.fromisoformat(mm.group(1))
        ts = dt.datetime(day.year, day.month, day.day, int(mm.group(2)), int(mm.group(3)), int(mm.group(4)))
        return int(ts.timestamp())

    start_epoch = to_epoch(m.group(1))
    end_epoch = to_epoch(m.group(2))
    if start_epoch <= 0 or end_epoch <= 0 or end_epoch < start_epoch:
        print(f"WARN\tcould not infer merge bounds\t{merge_path}")
        continue

    inputs = []
    for epoch, path, src_bn in source_entries:
        if epoch < start_epoch or epoch > end_epoch:
            continue
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue
        inputs.append({
            "path": path,
            "basename": src_bn,
            "size": int(st.st_size),
            "mtime_ns": int(st.st_mtime_ns),
            "epoch": int(epoch),
        })

    if not inputs:
        print(f"WARN\tno source pcaps available for recent merge backfill\t{merge_path}")
        continue

    doc = {
        "merge_path": os.path.realpath(merge_path),
        "merge_basename": bn,
        "merged_at_epoch": merged_at_epoch,
        "merged_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(merged_at_epoch)),
        "delete_after_epoch": merged_at_epoch + (delete_delay_hours * 3600),
        "delete_after": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(merged_at_epoch + (delete_delay_hours * 3600))),
        "inputs": inputs,
        "backfilled": True,
    }

    tmp_path = manifest_path + ".partial"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    os.replace(tmp_path, manifest_path)
    print(f"INFO\tbackfilled merge manifest\t{manifest_path}")
PY
  )

  [[ -z "$backfill_report" ]] && return 0

  while IFS=$'\t' read -r level action path; do
    [[ -z "$level" ]] && continue
    if [[ "$level" == "WARN" ]]; then
      log_warn "recent merge index: $action: $path"
    else
      log_info "recent merge index: $action: $path"
    fi
  done <<< "$backfill_report"
}

if (( BACKFILL_INDEX_ONLY == 1 )); then
  backfill_recent_merge_manifests
  log_info "recent merge index backfill complete (hours=$RECENT_MERGE_INDEX_BACKFILL_HOURS)"
  exit 0
fi

now_epoch=$(date +%s)
cutoff_epoch=$(( now_epoch - SAFETY_LAG_SECONDS ))

epoch_from_basename() {
  # Extract epoch from lan-YYYY-MM-DD_HH-MM-SS.pcap...
  # IMPORTANT: honor TZ env (America/New_York) so timestamps match the filename convention.
  local bn="$1"
  python3 -c 'import re,sys,datetime,time
if hasattr(time, "tzset"):
  time.tzset()
bn=sys.argv[1]
m=re.match(r"^lan-(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})\.pcap", bn)
if not m:
  print(0); sys.exit(0)
d=datetime.date.fromisoformat(m.group(1))
dt=datetime.datetime(d.year,d.month,d.day,int(m.group(2)),int(m.group(3)),int(m.group(4)))
print(int(dt.timestamp()))' "$bn"
}

# State model (gap-safe catch-up)
# - last_contiguous_epoch: last epoch for which we have processed all eligible segments up to that point
# - high_watermark_epoch: highest eligible epoch we've seen (or attempted) so far
# - pending: list of segments we still need to copy/validate (may be older than 1h)
last_contig_epoch=0
high_epoch=0
pending_json='[]'
last_merged_epoch=0
merge_name=""
merge_day=""
merge_path=""
merge_manifest_path=""
merge_performed=0

if [[ -f "$STATE_JSON" ]]; then
  export STATE_JSON_PATH="$STATE_JSON"
  read -r last_contig_epoch high_epoch pending_json last_merged_epoch < <(python3 - <<'PY'
import json, os
p = os.environ.get('STATE_JSON_PATH','')
try:
  j = json.load(open(p,'r',encoding='utf-8')) if p else {}
except Exception:
  j = {}
# Back-compat: older state used last_epoch
last_epoch = int(j.get('last_epoch', 0) or 0)
last_merged = int(j.get('last_merged_epoch', last_epoch) or 0)
last_contig = int(j.get('last_contiguous_epoch', last_merged if last_merged > 0 else last_epoch) or 0)
high = int(j.get('high_watermark_epoch', last_epoch) or 0)
pending = j.get('pending', []) or []
print(f"{last_contig} {high} {json.dumps(pending)} {last_merged}")
PY
)
fi

if (( last_contig_epoch <= 0 )); then
  # First run: backfill from the oldest available source pcap (if present).
  oldest_epoch=0
  while IFS= read -r -d '' p; do
    bn=$(basename "$p")
    ep=$(epoch_from_basename "$bn")
    if (( ep > 0 )) && { (( oldest_epoch == 0 )) || (( ep < oldest_epoch )); }; then
      oldest_epoch=$ep
    fi
  done < <(find "$PCAP_SOURCE_DIR" -maxdepth 1 -type f -name "lan-*.pcap*" -print0 2>/dev/null)

  if (( oldest_epoch > 0 )); then
    last_contig_epoch=$(( oldest_epoch - 1 ))
    log_info "bootstrap: first run using oldest source pcap epoch=$oldest_epoch"
  else
    # No source pcaps yet; keep a small default lookback.
    last_contig_epoch=$(( now_epoch - 3600 ))
  fi
fi
if (( high_epoch <= 0 )); then
  high_epoch=$last_contig_epoch
fi
if (( last_merged_epoch <= 0 )); then
  last_merged_epoch=$last_contig_epoch
fi

# Build the list of days to query on OPNsense.
# Unlike the old implementation (2-day bridge), we include ALL days between last_contig and today,
# plus any days implied by pending epochs, so multi-day downtime catch-up works.
start_day=$(date -d "@$last_contig_epoch" +%F)
end_day=$(date -d "@$now_epoch" +%F)

export START_DAY="$start_day" END_DAY="$end_day" PENDING_JSON_RAW="$pending_json"

days_list=$(python3 - <<'PY'
import datetime as dt, json, os
sd = dt.date.fromisoformat(os.environ['START_DAY'])
ed = dt.date.fromisoformat(os.environ['END_DAY'])

pending = []
try:
  pending = json.loads(os.environ.get('PENDING_JSON_RAW','[]') or '[]')
except Exception:
  pending = []

extra_days = set()
for it in pending:
  try:
    ep = int(it.get('epoch', 0) or 0)
    if ep > 0:
      extra_days.add(dt.datetime.fromtimestamp(ep).date().isoformat())
  except Exception:
    pass

days = []
d = sd
while d <= ed:
  days.append(d.isoformat())
  d += dt.timedelta(days=1)

# Add pending days (if any), then dedupe + sort
for x in sorted(extra_days):
  days.append(x)

print("\n".join(sorted(set(days))))
PY
)
mapfile -t days <<< "$days_list"


# 1) Build source file list (from local PCAP_SOURCE_DIR across all relevant days)
all_files=""
for day in "${days[@]}"; do
  [[ -z "$day" ]] && continue
  # List all matching files for this day pattern
  while IFS= read -r -d '' filepath; do
    all_files+="$filepath"$'\n'
  done < <(find "$PCAP_SOURCE_DIR" -maxdepth 1 -type f -name "lan-${day}_*.pcap*" -print0 2>/dev/null | sort -z)
done

if [[ -z "$all_files" ]]; then
  log_info "No source pcaps found in $PCAP_SOURCE_DIR (days=${days[0]:-?}..${days[-1]:-?})."
  exit 0
fi

# 2) Filter source file list into candidates:
# - eligible fresh files: (last_contig_epoch, cutoff_epoch]
# - plus any pending epochs <= cutoff_epoch (even if older)
export LAST_CONTIG_EPOCH="$last_contig_epoch" CUTOFF_EPOCH="$cutoff_epoch" HIGH_EPOCH="$high_epoch" PENDING_JSON="$pending_json"

# Note: on very large lists, the producer side of a pipe can receive SIGPIPE depending on
# how bash captures command substitution output. Treat rc=141 as non-fatal here.
# IMPORTANT: do NOT use `python3 -` with a heredoc when piping data; stdin would be consumed by the script.
set +o pipefail
py_candidates=$(cat <<'PY'
import os, re, sys, json, datetime, time
# Ensure TZ env is honored for naive datetime.timestamp()
if hasattr(time, 'tzset'):
  time.tzset()

last_contig = int(os.environ['LAST_CONTIG_EPOCH'])
cutoff = int(os.environ['CUTOFF_EPOCH'])
high_prev = int(os.environ.get('HIGH_EPOCH', '0') or 0)

pending = []
try:
  pending = json.loads(os.environ.get('PENDING_JSON','[]') or '[]')
except Exception:
  pending = []

pending_epochs = set()
for it in pending:
  try:
    ep = int(it.get('epoch',0) or 0)
    path = (it.get('path') or '').strip()
    if ep>0 and path:
      pending_epochs.add(ep)
  except Exception:
    pass

def to_epoch(path: str):
  bn=path.strip().split('/')[-1]
  m=re.match(r'^lan-(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})\.pcap', bn)
  if not m:
    return None
  day, hh, mm, ss = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
  d=datetime.date.fromisoformat(day)
  dt=datetime.datetime(d.year,d.month,d.day,hh,mm,ss)
  return int(dt.timestamp())

# Track all paths per epoch (multiple .pcap00x can share the same timestamp)
seen = []
max_seen_eligible = high_prev
for line in sys.stdin:
  p=line.strip()
  if not p:
    continue
  ep = to_epoch(p)
  if ep is None:
    continue
  seen.append((ep,p))
  if last_contig < ep <= cutoff and ep > max_seen_eligible:
    max_seen_eligible = ep

out = []
for ep, p in seen:
  if ep in pending_epochs and ep <= cutoff:
    out.append((ep, p, 1))
  elif last_contig < ep <= cutoff:
    out.append((ep, p, 0))

out.sort()
for ep, p, is_pending in out:
  print(f"{ep}\t{p}\t{is_pending}\t{max_seen_eligible}")
PY
)

candidates_tsv=$(printf '%s' "$all_files" | python3 -c "$py_candidates")
set -o pipefail

if [[ -z "$candidates_tsv" ]]; then
  log_info "No eligible pcaps (last_contig_epoch=$last_contig_epoch cutoff=$cutoff_epoch)."
  exit 0
fi

# Parse candidates TSV
candidate_epochs=()
candidate_paths=()
max_seen_eligible=0
while IFS=$'\t' read -r ep path _is_pending max_seen; do
  [[ -z "$ep" || -z "$path" ]] && continue
  candidate_epochs+=("$ep")
  candidate_paths+=("$path")
  max_seen_eligible="$max_seen"
done <<< "$candidates_tsv"

high_seen_epoch=${max_seen_eligible:-$high_epoch}

backfill_recent_merge_manifests

# Use all eligible candidates (fresh + pending), sorted by epoch.
use_idxs=()
for i in "${!candidate_paths[@]}"; do
  use_idxs+=("$i")
done

# Dedup idx list while preserving order
uniq_use_idxs=()
seen_idx=" "
for idx in "${use_idxs[@]}"; do
  if [[ "$seen_idx" != *" $idx "* ]]; then
    uniq_use_idxs+=("$idx")
    seen_idx+="$idx "
  fi
done
use_idxs=("${uniq_use_idxs[@]}")

if (( ${#use_idxs[@]} == 0 )); then
  log_info "No eligible candidates to process."
  exit 0
fi

already_merged_epochs=()
merge_candidate_epochs=()
merge_candidate_paths=()
filter_input=""
for idx in "${use_idxs[@]}"; do
  filter_input+="${candidate_epochs[$idx]}"$'\t'"${candidate_paths[$idx]}"$'\n'
done

while IFS=$'\t' read -r ep path status; do
  [[ -z "$ep" || -z "$path" ]] && continue
  if [[ "$status" == "already_merged" ]]; then
    already_merged_epochs+=("$ep")
  else
    merge_candidate_epochs+=("$ep")
    merge_candidate_paths+=("$path")
  fi
done < <(printf '%s' "$filter_input" | filter_previously_merged_candidates)

if (( ${#already_merged_epochs[@]} > 0 )); then
  log_info "skipping ${#already_merged_epochs[@]} source pcaps already represented by destination merge manifests"
fi

log_info "candidate summary: selected=${#use_idxs[@]} mergeable=${#merge_candidate_paths[@]} already_merged=${#already_merged_epochs[@]} last_contig_epoch=$last_contig_epoch cutoff_epoch=$cutoff_epoch high_epoch=$high_epoch"

# 2) Copy source files to workdir and track local paths for merge
# Strategy:
# - Copy source files to a .partial file
# - Validate by rewriting via tshark to the final path
# - Skip/quarantine any pcap that fails validation; continue with the rest
local_paths=()
ok_epochs=()

# pending_next will be computed from previous pending + any failures this run.
pending_next_json='[]'

add_pending() {
  local ep="$1"; local path="$2"; local err="$3"
  pending_next_json=$(python3 - <<PY
import json, time
prev = []
try:
  prev = json.loads('''$pending_next_json''') if '''$pending_next_json'''.strip() else []
except Exception:
  prev = []
base = []
try:
  base = json.loads('''$pending_json''') if '''$pending_json'''.strip() else []
except Exception:
  base = []

items = {}
for it in (base + prev):
  try:
    e = int(it.get('epoch',0) or 0)
    if e>0:
      items[e] = it
  except Exception:
    pass

ep = int($ep)
cur = items.get(ep, {})
cur['epoch'] = ep
cur['path'] = '$path'
cur['tries'] = int(cur.get('tries',0) or 0) + 1
cur['last_error'] = '$err'
cur['updated_at'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
items[ep] = cur

out = [items[k] for k in sorted(items.keys())]
print(json.dumps(out))
PY
)
}

# Iterate selected candidate indices
# NOTE: use source PCAPs directly (no per-file copies in WORKDIR).
for idx in "${!merge_candidate_paths[@]}"; do
  source_file="${merge_candidate_paths[$idx]}"
  ep="${merge_candidate_epochs[$idx]}"

  # Skip if source file doesn't exist (may have been processed in earlier run)
  if [[ ! -f "$source_file" ]]; then
    log_warn "skip(not found): $source_file"
    add_pending "$ep" "$source_file" "not_found"
    continue
  fi

  # Validate source file in-place (no duplicate copy); capinfos exits non-zero on invalid PCAPs.
  if capinfos -c "$source_file" >/dev/null 2>&1; then
    local_paths+=("$source_file")
    ok_epochs+=("$ep")
  else
    log_warn "invalid pcap (skipping): $source_file"
    add_pending "$ep" "$source_file" "invalid_pcap"
    continue
  fi

done

if (( ${#local_paths[@]} == 0 && ${#already_merged_epochs[@]} == 0 )); then
  log_warn "No validated pcaps to merge (after validation filters)."
  exit 0
fi

if (( ${#local_paths[@]} > 0 )); then
  # 3) Merge into a single pcap under the corresponding day directory (end day)
  merge_day=$(date -d "@${cutoff_epoch}" +%F)
  merge_dir="$WORKDIR/pcaps/$merge_day"
  mkdir -p "$merge_dir"

  first_bn=$(basename "${local_paths[0]}")
  last_bn=$(basename "${local_paths[-1]}")

  # Use a deterministic-ish name (safe for re-runs)
  merge_name="merged-${first_bn%.*}-to-${last_bn%.*}.pcap"
  merge_path="$merge_dir/$merge_name"
  merge_manifest_path="${merge_path}.manifest.json"
  merge_tmp="${merge_path}.partial"

  log_info "mergecap -> $merge_path (${#local_paths[@]} pcaps)"

  # Merge with one retry (helps with transient IO hiccups)
  MERGE_RETRIES="${MERGE_RETRIES:-1}"
  merge_attempt=0
  while :; do
    merge_attempt=$((merge_attempt + 1))
    rm -f -- "$merge_tmp" 2>/dev/null || true

    if mergecap -w "$merge_tmp" "${local_paths[@]}"; then
      :
    else
      if (( merge_attempt <= MERGE_RETRIES )); then
        log_warn "mergecap failed (attempt ${merge_attempt}); retrying"
        sleep 1
        continue
      fi
      log_error "mergecap failed after ${merge_attempt} attempt(s)"
      exit 1
    fi

    # Verify merge (packet counts): merged packet count should equal the sum of inputs.
    # This is fast and catches truncated/failed merges.
    if [[ "${VERIFY_MERGE:-1}" == "1" ]]; then
      log_info "verify_merge: start (attempt ${merge_attempt})"
      # Use capinfos -M for machine-readable exact counts (avoids "k" suffix rounding).
      in_pkts=$(capinfos -M -c "${local_paths[@]}" 2>/dev/null | awk '/Number of packets/ {v=$NF; gsub(/[^0-9]/,"",v); sum += (v+0)} END {printf("%d", sum+0)}')
      out_pkts=$(capinfos -M -c "$merge_tmp" 2>/dev/null | awk '/Number of packets/ {v=$NF; gsub(/[^0-9]/,"",v); print v; exit}')
      if [[ -z "${out_pkts:-}" ]]; then
        if (( merge_attempt <= MERGE_RETRIES )); then
          log_warn "verify_merge could not read merged pcap (attempt ${merge_attempt}); retrying"
          sleep 1
          continue
        fi
        log_error "verify_merge failed to read merged pcap via capinfos"
        exit 1
      fi
      if (( in_pkts != out_pkts )); then
        if (( merge_attempt <= MERGE_RETRIES )); then
          log_warn "verify_merge mismatch (attempt ${merge_attempt}): inputs=$in_pkts merged=$out_pkts; retrying"
          sleep 1
          continue
        fi
        log_error "verify_merge packet mismatch: inputs=$in_pkts merged=$out_pkts"
        log_error "refusing to queue source pcaps for delayed deletion"
        exit 1
      fi
      log_info "verify_merge: ok (packets=$out_pkts)"
    fi

    mv -f -- "$merge_tmp" "$merge_path"
    merged_at_epoch=$(date +%s)
    write_merge_manifest "$merge_manifest_path" "$merge_path" "$merged_at_epoch" "$SOURCE_PCAP_DELETE_DELAY_HOURS" "${local_paths[@]}"
    merge_performed=1
    log_info "queued ${#local_paths[@]} source pcaps for delayed deletion after ${SOURCE_PCAP_DELETE_DELAY_HOURS} hour(s)"
    break
  done
else
  log_info "No new source pcaps needed merging; eligible candidates were already represented in destination merge files."
fi

# 4) Run Suricata + Zeek on the merged pcap
if (( merge_performed == 1 )); then
  # Suricata writes to output/suricata/$merge_day/eve.json (overwrites each run)
  merged_in_container="/pcaps/$merge_day/$merge_name"

  eve_name="eve-${merge_name%.pcap}.json"

  log_info "suricata(docker) -> $merge_name (eve=$eve_name)"
  if compose --profile ja4 run --rm -e DAY="$merge_day" -e PCAP="$merged_in_container" -e EVE_NAME="$eve_name" suricata-offline; then
    :
  else
    rc=$?
    log_warn "suricata failed for merged pcap (exit=$rc); continuing"
  fi

  log_info "zeek(docker) -> $merge_name"
  if compose --profile zeek run --rm -e PCAP="$merged_in_container" zeek-offline; then
    :
  else
    rc=$?
    log_warn "zeek failed for merged pcap (exit=$rc); continuing"
  fi
fi

# 5) Update state (gap-safe)
# - last_contiguous_epoch advances only when we've validated all eligible segments up to that epoch
# - high_watermark_epoch tracks the highest eligible epoch observed
# - pending tracks missing/failed segments to retry on future runs
export LAST_CONTIG_EPOCH="$last_contig_epoch" HIGH_EPOCH="$high_epoch" HIGH_SEEN_EPOCH="$high_seen_epoch"
processed_epochs=("${ok_epochs[@]}")
if (( ${#already_merged_epochs[@]} > 0 )); then
  processed_epochs+=("${already_merged_epochs[@]}")
fi
export OK_EPOCHS_JSON="$(python3 - <<PY
import json
print(json.dumps([int(x) for x in "${processed_epochs[*]}".split() if x.strip()]))
PY
)"
export CANDIDATE_MAP_JSON="$(python3 - <<PY
import json
# Build epoch->path map from bash arrays
# We accept that later duplicates overwrite (shouldn't happen).
epochs="${candidate_epochs[*]}".split()
paths="${candidate_paths[*]}".split()
out={}
for e,p in zip(epochs,paths):
  try:
    out[int(e)]=p
  except Exception:
    pass
print(json.dumps(out))
PY
)"

read -r new_contig new_high pending_final_json < <(python3 - <<'PY'
import json, os, time

last_contig = int(os.environ['LAST_CONTIG_EPOCH'])
high_prev = int(os.environ.get('HIGH_EPOCH','0') or 0)
high_seen = int(os.environ.get('HIGH_SEEN_EPOCH','0') or 0)

ok = set(json.loads(os.environ.get('OK_EPOCHS_JSON','[]') or '[]'))
mp = json.loads(os.environ.get('CANDIDATE_MAP_JSON','{}') or '{}')
# mp keys are strings if reloaded; normalize
mp2 = {}
for k,v in mp.items():
  try:
    mp2[int(k)] = v
  except Exception:
    pass
mp = mp2

# pending_next_json was built in bash and includes prev+new failures
pending = []
try:
  pending = json.loads('''$pending_next_json''') if '''$pending_next_json'''.strip() else []
except Exception:
  pending = []

# Eligible epochs are all candidate epochs above the current contiguous watermark.
eligible_epochs = sorted([e for e in mp.keys() if e > last_contig])

# Any eligible epoch not ok should remain pending
pending_by_epoch = {int(it.get('epoch',0) or 0): it for it in pending if int(it.get('epoch',0) or 0) > 0}
for e in eligible_epochs:
  if e not in ok:
    it = pending_by_epoch.get(e, {})
    it['epoch'] = e
    it['path'] = mp.get(e, it.get('path',''))
    it['tries'] = int(it.get('tries',0) or 0)
    it.setdefault('last_error', 'missing_or_failed')
    it['updated_at'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    pending_by_epoch[e] = it

# Advance contiguous watermark
new_contig = last_contig
for e in eligible_epochs:
  if e in ok:
    new_contig = e
  else:
    break

# Drop pending entries <= new_contig
pending_out = [pending_by_epoch[e] for e in sorted(pending_by_epoch.keys()) if e > new_contig]

new_high = max(high_prev, high_seen, new_contig)

print(f"{new_contig} {new_high} {json.dumps(pending_out)}")
PY
)

python3 - <<PY
import json, time
p="$STATE_JSON"
existing = {}
try:
  existing = json.load(open(p, 'r', encoding='utf-8'))
except Exception:
  existing = {}
processed_epochs = [int(x) for x in "${processed_epochs[*]}".split() if x.strip()]
last_merged_epoch = max(processed_epochs) if processed_epochs else int(existing.get("last_merged_epoch", $last_merged_epoch) or $last_merged_epoch)
merge_name = """$merge_name"""
merge_day = """$merge_day"""
j={
  # Back-compat key
  "last_epoch": int($new_contig),
  "last_contiguous_epoch": int($new_contig),
  "high_watermark_epoch": int($new_high),
  "last_merged_epoch": int(last_merged_epoch),
  "last_merged_pcap": merge_name or existing.get("last_merged_pcap", ""),
  "pending": $pending_final_json,
  "updated_at": time.strftime('%Y-%m-%dT%H:%M:%S%z'),
  "last_merge": merge_name or existing.get("last_merge", ""),
  "merge_day": merge_day or existing.get("merge_day", ""),
  "validated_count": int(${#local_paths[@]}),
}
json.dump(j, open(p,'w',encoding='utf-8'), indent=2)
print(p)
PY

log_info "ingest pipeline complete (contiguous_epoch=$new_contig high_watermark=$new_high pending=$(python3 - <<PY
import json
print(len(json.loads('''$pending_final_json''') if '''$pending_final_json'''.strip() else '[]'))
PY
))"

# 6) Retention cleanup
cleanup_delayed_source_pcaps

# - merged PCAPs: configurable (default 3 days to conserve disk)
# - Zeek logs + Suricata EVE outputs: configurable (default 30 days for RITA's 7-day rolling window + baseline analysis)
if [[ "${RUN_RETENTION_CLEANUP:-1}" == "1" ]]; then
  log_info "retention: merged pcaps older than ${MERGED_PCAP_RETENTION_DAYS} days"
  find "$WORKDIR/pcaps" -type f -name 'merged-*.pcap' -mtime +"$MERGED_PCAP_RETENTION_DAYS" -print0 | xargs -0 -r rm -f
  find "$WORKDIR/pcaps" -type f -name 'merged-*.pcap.manifest.json' -mtime +"$MERGED_PCAP_RETENTION_DAYS" -print0 | xargs -0 -r rm -f

  log_info "retention: ingest zeek/suricata artifacts older than ${HOURLY_ARTIFACT_RETENTION_DAYS} days"
  # Zeek per-merge output dirs end with .zeek
  find "$WORKDIR/zeek-logs" -type d -name '*.zeek' -mtime +"$HOURLY_ARTIFACT_RETENTION_DAYS" -print0 | xargs -0 -r rm -rf
  # Suricata per-merge eve files
  find "$WORKDIR/suricata" -type f -name 'eve-merged-*.json' -mtime +"$HOURLY_ARTIFACT_RETENTION_DAYS" -print0 | xargs -0 -r rm -f
fi

# 7) Update dashboard pages (best-effort)
if ( cd "$ROOT_DIR" && HOMENETSEC_WORKDIR="$WORKDIR" ./scripts/generate_dashboard.sh ); then
  :
else
  rc=$?
  log_warn "dashboard generation failed (exit=$rc)"
fi
