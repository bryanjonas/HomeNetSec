#!/usr/bin/env bash
set -euo pipefail

# Hourly ingest:
# - Download all new PCAPs since last successful ingest
# - Skip the newest N remote files to avoid partial copies
# - Merge the downloaded set into a single PCAP
# - Run Suricata + Zeek on the merged PCAP
#
# This is intended to keep analysis incremental without paying per-PCAP container startup cost.

TZ="America/New_York"; export TZ

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${HOMENETSEC_WORKDIR:-$ROOT_DIR/output}"
STATE_DIR="$WORKDIR/state"
mkdir -p "$STATE_DIR"

STATE_JSON="$STATE_DIR/hourly_ingest_state.json"

# Retention
MERGED_PCAP_RETENTION_DAYS="${MERGED_PCAP_RETENTION_DAYS:-7}"
HOURLY_ARTIFACT_RETENTION_DAYS="${HOURLY_ARTIFACT_RETENTION_DAYS:-30}"


# OPNsense pull settings
OPNSENSE_HOST="${OPNSENSE_HOST:-192.168.1.X}"
OPNSENSE_USER="${OPNSENSE_USER:-openclaw}"
OPNSENSE_KEY="${OPNSENSE_KEY:-$HOME/.ssh/openclaw-opnsense}"
OPNSENSE_PCAP_DIR="${OPNSENSE_PCAP_DIR:-/var/log/pcaps}"

# Partial protections
PULL_SKIP_NEWEST_N="${PULL_SKIP_NEWEST_N:-1}"
SAFETY_LAG_SECONDS="${SAFETY_LAG_SECONDS:-120}"  # don't consider anything newer than now-lag
REMOTE_STABILITY_SECONDS="${REMOTE_STABILITY_SECONDS:-15}"  # file size+mtime must be stable across this interval

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "[homenetsec] ERROR: missing dependency: $1" >&2; exit 127; }
}

require docker
require python3
require mergecap
require capinfos
require tshark

compose() {
  HOMENETSEC_WORKDIR="$WORKDIR" docker compose -f "$ROOT_DIR/assets/docker-compose.yml" "$@"
}

now_epoch=$(date +%s)
cutoff_epoch=$(( now_epoch - SAFETY_LAG_SECONDS ))

last_epoch=0
if [[ -f "$STATE_JSON" ]]; then
  last_epoch=$(python3 - <<PY
import json
p="$STATE_JSON"
try:
  j=json.load(open(p,'r',encoding='utf-8'))
  print(int(j.get('last_epoch',0) or 0))
except Exception:
  print(0)
PY
)
fi

if (( last_epoch <= 0 )); then
  # First run: only pull last hour window (so we don't backfill an entire day).
  last_epoch=$(( now_epoch - 3600 ))
fi

start_day=$(date -d "@$last_epoch" +%F)
# IMPORTANT: include "today" in the listing window even if cutoff_epoch is still yesterday.
# We still filter candidates by cutoff_epoch later; this just ensures day-rollover doesn't stall ingest.
end_day=$(date -d "@$now_epoch" +%F)

# day list (handle midnight boundary)
# Keep it simple: we only need to bridge at most into "today" for midnight rollover.
days="$start_day"$'\n'
if [[ "$end_day" != "$start_day" ]]; then
  days+="$end_day"$'\n'
fi

ssh_base=(ssh -i "$OPNSENSE_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=8)
scp_base=(scp -i "$OPNSENSE_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=20)

remote_stat() {
  # Prints: "<size> <mtime>" for a remote path, or empty on failure.
  local remote_path="$1"
  ${ssh_base[@]} "$OPNSENSE_USER@$OPNSENSE_HOST" "stat -f '%z %m' '$remote_path'" 2>/dev/null || true
}

remote_is_stable() {
  # Checks remote file size+mtime stability across REMOTE_STABILITY_SECONDS.
  # Returns 0 if stable, 1 if changing/unstat-able.
  local remote_path="$1"
  local a b
  a=$(remote_stat "$remote_path")
  [[ -z "$a" ]] && return 1
  sleep "$REMOTE_STABILITY_SECONDS"
  b=$(remote_stat "$remote_path")
  [[ -z "$b" ]] && return 1
  [[ "$a" == "$b" ]]
}

epoch_from_basename() {
  # Extract epoch from lan-YYYY-MM-DD_HH-MM-SS.pcap...
  local bn="$1"
  python3 -c 'import re,sys,datetime
bn=sys.argv[1]
m=re.match(r"^lan-(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})\.pcap", bn)
if not m:
  print(0); sys.exit(0)
d=datetime.date.fromisoformat(m.group(1))
dt=datetime.datetime(d.year,d.month,d.day,int(m.group(2)),int(m.group(3)),int(m.group(4)))
print(int(dt.timestamp()))' "$bn"
}

# 1) Build remote list
all_files=""
for day in "$start_day" "$end_day"; do
  [[ -z "$day" ]] && continue
  # avoid duplicate listing if start_day == end_day
  if [[ "$day" == "$start_day" && "$start_day" == "$end_day" ]]; then
    :
  elif [[ "$day" == "$end_day" && "$start_day" == "$end_day" ]]; then
    continue
  fi

  if ! part=$(${ssh_base[@]} "$OPNSENSE_USER@$OPNSENSE_HOST" \
      "ls -1 $OPNSENSE_PCAP_DIR/lan-${day}_*.pcap* 2>/dev/null | sort"); then
    echo "[homenetsec] ERROR: SSH list failed for day=$day ($OPNSENSE_USER@$OPNSENSE_HOST:$OPNSENSE_PCAP_DIR)" >&2
    exit 1
  fi
  [[ -n "$part" ]] && all_files+="$part"$'\n'
done

if [[ -z "$all_files" ]]; then
  echo "[homenetsec] No remote pcaps found (days=$start_day..$end_day)."
  exit 0
fi

export LAST_EPOCH="$last_epoch" CUTOFF_EPOCH="$cutoff_epoch"

filtered=$(printf '%s' "$all_files" | python3 -c 'import os, re, sys, datetime
last=int(os.environ["LAST_EPOCH"])
cutoff=int(os.environ["CUTOFF_EPOCH"])

def to_epoch(path: str):
  bn=path.strip().split("/")[-1]
  m=re.match(r"^lan-(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})\.pcap", bn)
  if not m:
    return None
  day, hh, mm, ss = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
  d=datetime.date.fromisoformat(day)
  dt=datetime.datetime(d.year,d.month,d.day,hh,mm,ss)
  return int(dt.timestamp())

out=[]
for line in sys.stdin:
  p=line.strip()
  if not p:
    continue
  ep=to_epoch(p)
  if ep is None:
    continue
  if last < ep <= cutoff:
    out.append((ep,p))

out.sort()
for _,p in out:
  print(p)
')

if [[ -z "$filtered" ]]; then
  echo "[homenetsec] No new pcaps since last_epoch=$last_epoch (cutoff=$cutoff_epoch)."
  exit 0
fi

mapfile -t new_files <<< "$filtered"

# Skip newest N from this candidate set too (extra partial protection)
if (( ${#new_files[@]} <= PULL_SKIP_NEWEST_N )); then
  echo "[homenetsec] Found ${#new_files[@]} new pcaps; skipping because PULL_SKIP_NEWEST_N=$PULL_SKIP_NEWEST_N"
  exit 0
fi

upto=$(( ${#new_files[@]} - PULL_SKIP_NEWEST_N ))

# 2) Download missing and track local paths for merge
# Strategy:
# - Only copy remote files that appear stable (size+mtime unchanged across REMOTE_STABILITY_SECONDS)
# - Copy to a .partial file
# - Validate by rewriting via tshark to the final path
# - Skip/quarantine any pcap that fails validation; continue with the rest
local_paths=()
max_epoch=0

for (( i=0; i<upto; i++ )); do
  remote="${new_files[$i]}"
  base=$(basename "$remote")
  day=$(echo "$base" | cut -d_ -f1 | sed 's/^lan-//')
  out_dir="$WORKDIR/pcaps/$day"
  mkdir -p "$out_dir"
  out_path="$out_dir/$base"

  # If we already have a validated local copy, include it.
  if [[ -f "$out_path" ]]; then
    local_paths+=("$out_path")
    ep=$(epoch_from_basename "$base")
    (( ep > max_epoch )) && max_epoch=$ep
    continue
  fi

  # Remote stability check to avoid copying actively-written segments.
  if ! remote_is_stable "$remote"; then
    echo "[homenetsec] skip(unstable): $remote"
    continue
  fi

  tmp_path="$out_path.partial"
  rm -f -- "$tmp_path" 2>/dev/null || true

  echo "[homenetsec] pulling $remote"
  ${scp_base[@]} "$OPNSENSE_USER@$OPNSENSE_HOST:$remote" "$tmp_path" >/dev/null || {
    echo "[homenetsec] WARN: scp failed for $remote" >&2
    rm -f -- "$tmp_path" 2>/dev/null || true
    continue
  }

  # Validate/normalize by rewriting via tshark.
  # If tshark can read and write, the file is parseable end-to-end.
  if tshark -r "$tmp_path" -w "$out_path" >/dev/null 2>&1; then
    rm -f -- "$tmp_path" 2>/dev/null || true
    local_paths+=("$out_path")
    ep=$(epoch_from_basename "$base")
    (( ep > max_epoch )) && max_epoch=$ep
  else
    bad_path="$out_path.bad.$(date +%s)"
    mv -f -- "$tmp_path" "$bad_path" 2>/dev/null || true
    rm -f -- "$out_path" 2>/dev/null || true
    echo "[homenetsec] WARN: invalid pcap (quarantined): $bad_path" >&2
    continue
  fi

done

if (( ${#local_paths[@]} == 0 )); then
  echo "[homenetsec] No validated pcaps to merge (after stability+validation filters)."
  exit 0
fi

# 3) Merge into a single pcap under the corresponding day directory (end day)
merge_day=$(date -d "@${cutoff_epoch}" +%F)
merge_dir="$WORKDIR/pcaps/$merge_day"
mkdir -p "$merge_dir"

first_bn=$(basename "${local_paths[0]}")
last_bn=$(basename "${local_paths[-1]}")

# Use a deterministic-ish name (safe for re-runs)
merge_name="merged-${first_bn%.*}-to-${last_bn%.*}.pcap"
merge_path="$merge_dir/$merge_name"

echo "[homenetsec] mergecap -> $merge_path (${#local_paths[@]} pcaps)"

# Merge with one retry (helps with transient IO hiccups)
MERGE_RETRIES="${MERGE_RETRIES:-1}"
merge_attempt=0
while :; do
  merge_attempt=$((merge_attempt + 1))
  rm -f -- "$merge_path" 2>/dev/null || true

  if mergecap -w "$merge_path" "${local_paths[@]}"; then
    :
  else
    if (( merge_attempt <= MERGE_RETRIES )); then
      echo "[homenetsec] WARN: mergecap failed (attempt ${merge_attempt}); retrying" >&2
      sleep 1
      continue
    fi
    echo "[homenetsec] ERROR: mergecap failed after ${merge_attempt} attempt(s)" >&2
    exit 1
  fi

  # Verify merge (packet counts): merged packet count should equal the sum of inputs.
  # This is fast and catches truncated/failed merges.
  if [[ "${VERIFY_MERGE:-1}" == "1" ]]; then
    echo "[homenetsec] verify_merge: start (attempt ${merge_attempt})"
    # Use capinfos -M for machine-readable exact counts (avoids "k" suffix rounding).
    in_pkts=$(capinfos -M -c "${local_paths[@]}" 2>/dev/null | awk '/Number of packets/ {v=$NF; gsub(/[^0-9]/,"",v); sum += (v+0)} END {printf("%d", sum+0)}')
    out_pkts=$(capinfos -M -c "$merge_path" 2>/dev/null | awk '/Number of packets/ {v=$NF; gsub(/[^0-9]/,"",v); print v; exit}')
    if [[ -z "${out_pkts:-}" ]]; then
      if (( merge_attempt <= MERGE_RETRIES )); then
        echo "[homenetsec] WARN: verify_merge could not read merged pcap (attempt ${merge_attempt}); retrying" >&2
        sleep 1
        continue
      fi
      echo "[homenetsec] ERROR: verify_merge failed to read merged pcap via capinfos" >&2
      exit 1
    fi
    if (( in_pkts != out_pkts )); then
      if (( merge_attempt <= MERGE_RETRIES )); then
        echo "[homenetsec] WARN: verify_merge mismatch (attempt ${merge_attempt}): inputs=$in_pkts merged=$out_pkts; retrying" >&2
        sleep 1
        continue
      fi
      echo "[homenetsec] ERROR: verify_merge packet mismatch: inputs=$in_pkts merged=$out_pkts" >&2
      echo "[homenetsec]        refusing to delete source pcaps" >&2
      exit 1
    fi
    echo "[homenetsec] verify_merge: ok (packets=$out_pkts)"
  fi

  break
done

# Optionally delete the source PCAPs that were merged (safe only after verify_merge).
if [[ "${DELETE_MERGED_INPUTS:-1}" == "1" ]]; then
  echo "[homenetsec] delete_inputs: removing ${#local_paths[@]} source pcap(s) after successful merge"
  rm -f -- "${local_paths[@]}"
fi

# 4) Run Suricata + Zeek on the merged pcap
# Suricata writes to output/suricata/$merge_day/eve.json (overwrites each run)
merged_in_container="/pcaps/$merge_day/$merge_name"

eve_name="eve-${merge_name%.pcap}.json"

echo "[homenetsec] suricata(docker) -> $merge_name (eve=$eve_name)"
compose --profile ja4 run --rm -e DAY="$merge_day" -e PCAP="$merged_in_container" -e EVE_NAME="$eve_name" suricata-offline || \
  echo "[homenetsec] WARN: suricata failed for merged pcap; continuing"

echo "[homenetsec] zeek(docker) -> $merge_name"
compose --profile zeek run --rm -e PCAP="$merged_in_container" zeek-offline || \
  echo "[homenetsec] WARN: zeek failed for merged pcap; continuing"

# 5) Update state: advance last_epoch to the newest validated file timestamp we actually processed
new_last="$max_epoch"

python3 - <<PY
import json, time
p="$STATE_JSON"
j={
  "last_epoch": int($new_last),
  "updated_at": time.strftime('%Y-%m-%dT%H:%M:%S%z'),
  "last_merge": "$merge_name",
  "merge_day": "$merge_day",
  "validated_count": int(${#local_paths[@]}),
}
json.dump(j, open(p,'w',encoding='utf-8'), indent=2)
print(p)
PY

echo "[homenetsec] hourly ingest complete (processed up to epoch=$new_last)"

# 6) Retention cleanup
# - merged PCAPs: 7 days
# - Zeek logs + Suricata EVE outputs from hourly merged runs: 30 days
if [[ "${RUN_RETENTION_CLEANUP:-1}" == "1" ]]; then
  echo "[homenetsec] retention: merged pcaps older than ${MERGED_PCAP_RETENTION_DAYS} days"
  find "$WORKDIR/pcaps" -type f -name 'merged-*.pcap' -mtime +"$MERGED_PCAP_RETENTION_DAYS" -print0 | xargs -0 -r rm -f

  echo "[homenetsec] retention: hourly zeek/suricata artifacts older than ${HOURLY_ARTIFACT_RETENTION_DAYS} days"
  # Zeek per-merge output dirs end with .zeek
  find "$WORKDIR/zeek-logs" -type d -name '*.zeek' -mtime +"$HOURLY_ARTIFACT_RETENTION_DAYS" -print0 | xargs -0 -r rm -rf
  # Suricata per-merge eve files
  find "$WORKDIR/suricata" -type f -name 'eve-merged-*.json' -mtime +"$HOURLY_ARTIFACT_RETENTION_DAYS" -print0 | xargs -0 -r rm -f
fi

# 7) Update dashboard pages (best-effort)
( cd "$ROOT_DIR" && HOMENETSEC_WORKDIR="$WORKDIR" ./scripts/generate_dashboard.sh ) || \
  echo "[homenetsec] WARN: dashboard generation failed"

