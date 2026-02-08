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

# OPNsense pull settings
OPNSENSE_HOST="${OPNSENSE_HOST:-192.168.1.X}"
OPNSENSE_USER="${OPNSENSE_USER:-openclaw}"
OPNSENSE_KEY="${OPNSENSE_KEY:-$HOME/.ssh/openclaw-opnsense}"
OPNSENSE_PCAP_DIR="${OPNSENSE_PCAP_DIR:-/var/log/pcaps}"

# Partial protections
PULL_SKIP_NEWEST_N="${PULL_SKIP_NEWEST_N:-1}"
SAFETY_LAG_SECONDS="${SAFETY_LAG_SECONDS:-120}"  # don't consider anything newer than now-lag

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "[homenetsec] ERROR: missing dependency: $1" >&2; exit 127; }
}

require docker
require python3
require mergecap

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
end_day=$(date -d "@$cutoff_epoch" +%F)

# day list (handle midnight boundary)
days=$(python3 - <<PY
import datetime
sd=datetime.date.fromisoformat("$start_day")
ed=datetime.date.fromisoformat("$end_day")
d=sd
out=[]
while d<=ed:
  out.append(d.isoformat())
  d += datetime.timedelta(days=1)
print("\n".join(out))
PY
)

ssh_base=(ssh -i "$OPNSENSE_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=8)
scp_base=(scp -i "$OPNSENSE_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=20)

# 1) Build remote list
all_files=""
while IFS= read -r day; do
  [[ -z "$day" ]] && continue
  if ! part=$(${ssh_base[@]} "$OPNSENSE_USER@$OPNSENSE_HOST" \
      "ls -1 $OPNSENSE_PCAP_DIR/lan-${day}_*.pcap* 2>/dev/null | sort"); then
    echo "[homenetsec] ERROR: SSH list failed for day=$day ($OPNSENSE_USER@$OPNSENSE_HOST:$OPNSENSE_PCAP_DIR)" >&2
    exit 1
  fi
  [[ -n "$part" ]] && all_files+="$part"$'\n'
done <<< "$days"

if [[ -z "$all_files" ]]; then
  echo "[homenetsec] No remote pcaps found (days=$start_day..$end_day)."
  exit 0
fi

export LAST_EPOCH="$last_epoch" CUTOFF_EPOCH="$cutoff_epoch"

filtered=$(printf '%s' "$all_files" | python3 - <<'PY'
import os, re, sys, datetime
last=int(os.environ['LAST_EPOCH'])
cutoff=int(os.environ['CUTOFF_EPOCH'])

def to_epoch(path: str):
  bn=path.strip().split('/')[-1]
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
  # strictly greater than last_epoch to avoid reprocessing
  if last < ep <= cutoff:
    out.append((ep,p))

out.sort()
for _,p in out:
  print(p)
PY
)

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
local_paths=()
for (( i=0; i<upto; i++ )); do
  remote="${new_files[$i]}"
  base=$(basename "$remote")
  day=$(echo "$base" | cut -d_ -f1 | sed 's/^lan-//')
  out_dir="$WORKDIR/pcaps/$day"
  mkdir -p "$out_dir"
  out_path="$out_dir/$base"
  if [[ ! -f "$out_path" ]]; then
    echo "[homenetsec] pulling $remote"
    ${scp_base[@]} "$OPNSENSE_USER@$OPNSENSE_HOST:$remote" "$out_path" >/dev/null
  fi
  local_paths+=("$out_path")
done

if (( ${#local_paths[@]} == 0 )); then
  echo "[homenetsec] Nothing downloaded (all new files already present locally)."
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
mergecap -w "$merge_path" "${local_paths[@]}"

# Verify merge (packet counts): merged packet count should equal the sum of inputs.
# This is fast and catches truncated/failed merges.
if [[ "${VERIFY_MERGE:-1}" == "1" ]]; then
  echo "[homenetsec] verify_merge: start"
  in_pkts=$(capinfos -c "${local_paths[@]}" 2>/dev/null | awk '/Number of packets/ {sum += $NF} END {printf("%d", sum+0)}')
  out_pkts=$(capinfos -c "$merge_path" 2>/dev/null | awk '/Number of packets/ {print $NF; exit}')
  if [[ -z "${out_pkts:-}" ]]; then
    echo "[homenetsec] ERROR: verify_merge failed to read merged pcap via capinfos" >&2
    exit 1
  fi
  if (( in_pkts != out_pkts )); then
    echo "[homenetsec] ERROR: verify_merge packet mismatch: inputs=$in_pkts merged=$out_pkts" >&2
    echo "[homenetsec]        refusing to delete source pcaps" >&2
    exit 1
  fi
  echo "[homenetsec] verify_merge: ok (packets=$out_pkts)"
fi

# Optionally delete the source PCAPs that were merged (safe only after verify_merge).
if [[ "${DELETE_MERGED_INPUTS:-1}" == "1" ]]; then
  echo "[homenetsec] delete_inputs: removing ${#local_paths[@]} source pcap(s) after successful merge"
  rm -f -- "${local_paths[@]}"
fi

# 4) Run Suricata + Zeek on the merged pcap
# Suricata writes to output/suricata/$merge_day/eve.json (overwrites each run)
merged_in_container="/pcaps/$merge_day/$merge_name"

echo "[homenetsec] suricata(docker) -> $merge_name"
compose --profile ja4 run --rm -e DAY="$merge_day" -e PCAP="$merged_in_container" suricata-offline || \
  echo "[homenetsec] WARN: suricata failed for merged pcap; continuing"

echo "[homenetsec] zeek(docker) -> $merge_name"
compose --profile zeek run --rm -e PCAP="$merged_in_container" zeek-offline || \
  echo "[homenetsec] WARN: zeek failed for merged pcap; continuing"

# 5) Update state: advance last_epoch to the newest processed file timestamp
new_last=$(python3 - <<PY
import re, datetime
bn="$last_bn"
m=re.match(r"^lan-(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})\.pcap", bn)
if not m:
  print($cutoff_epoch)
else:
  d=datetime.date.fromisoformat(m.group(1))
  dt=datetime.datetime(d.year,d.month,d.day,int(m.group(2)),int(m.group(3)),int(m.group(4)))
  print(int(dt.timestamp()))
PY
)

python3 - <<PY
import json, time
p="$STATE_JSON"
j={
  "last_epoch": int($new_last),
  "updated_at": time.strftime('%Y-%m-%dT%H:%M:%S%z'),
  "last_merge": "$merge_name",
  "merge_day": "$merge_day",
  "downloaded_count": int(${#local_paths[@]}),
}
json.dump(j, open(p,'w',encoding='utf-8'), indent=2)
print(p)
PY

echo "[homenetsec] hourly ingest complete (processed up to epoch=$new_last)"
