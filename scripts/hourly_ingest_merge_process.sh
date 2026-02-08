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

# State model (gap-safe catch-up)
# - last_contiguous_epoch: last epoch for which we have processed all eligible segments up to that point
# - high_watermark_epoch: highest eligible epoch we've seen (or attempted) so far
# - pending: list of segments we still need to copy/validate (may be older than 1h)
last_contig_epoch=0
high_epoch=0
pending_json='[]'

if [[ -f "$STATE_JSON" ]]; then
  read -r last_contig_epoch high_epoch pending_json < <(python3 - <<'PY'
import json
p = "$STATE_JSON"
try:
  j = json.load(open(p,'r',encoding='utf-8'))
except Exception:
  j = {}
# Back-compat: older state used last_epoch
last_epoch = int(j.get('last_epoch', 0) or 0)
last_contig = int(j.get('last_contiguous_epoch', last_epoch) or 0)
high = int(j.get('high_watermark_epoch', last_epoch) or 0)
pending = j.get('pending', []) or []
print(f"{last_contig} {high} {json.dumps(pending)}")
PY
)
fi

if (( last_contig_epoch <= 0 )); then
  # First run: only pull last hour window (so we don't backfill an entire day).
  last_contig_epoch=$(( now_epoch - 3600 ))
fi
if (( high_epoch <= 0 )); then
  high_epoch=$last_contig_epoch
fi

# Build the list of days to query on OPNsense.
# Unlike the old implementation (2-day bridge), we include ALL days between last_contig and today,
# plus any days implied by pending epochs, so multi-day downtime catch-up works.
start_day=$(date -d "@$last_contig_epoch" +%F)
end_day=$(date -d "@$now_epoch" +%F)

days_list=$(python3 - <<'PY'
import datetime as dt, json
sd = dt.date.fromisoformat("$start_day")
ed = dt.date.fromisoformat("$end_day")
pending = []
try:
  pending = json.loads("""$pending_json""")
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
  if x not in days:
    days.append(x)

print("\n".join(sorted(set(days))))
PY
)
mapfile -t days <<< "$days_list"

# NOTE: OPNsense often runs a non-interactive SSH account for PCAP pulls.
# To support that, we use SFTP (no remote shell commands).
sftp_base=(sftp -i "$OPNSENSE_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=12)

sftp_ls() {
  # Lists remote paths (supports globs) one-per-line.
  # Returns 0 even if no matches; returns nonzero on auth/network errors.
  local remote_glob="$1"
  local out
  if ! out=$(printf 'ls -1 %s\n' "$remote_glob" | ${sftp_base[@]} "$OPNSENSE_USER@$OPNSENSE_HOST" 2>/dev/null); then
    return 1
  fi
  # Filter out sftp prompts/noise; keep only absolute paths.
  printf '%s\n' "$out" | sed -n 's/^sftp> //p; /^\//p' | sed '/^$/d'
}

sftp_ls_long_one() {
  # Best-effort long listing for a single remote file.
  # We just compare the resulting line text for stability.
  local remote_path="$1"
  local out
  if ! out=$(printf 'ls -l %s\n' "$remote_path" | ${sftp_base[@]} "$OPNSENSE_USER@$OPNSENSE_HOST" 2>/dev/null); then
    return 1
  fi
  # Return the first line that looks like a permission string.
  printf '%s\n' "$out" | sed -n '/^-[rwx-]/p' | head -n 1
}

remote_is_stable() {
  # Checks remote file stability across REMOTE_STABILITY_SECONDS.
  # Because we can't run remote stat(1), we compare the `sftp ls -l` output line.
  local remote_path="$1"
  local a b
  a=$(sftp_ls_long_one "$remote_path" || true)
  [[ -z "$a" ]] && return 1
  sleep "$REMOTE_STABILITY_SECONDS"
  b=$(sftp_ls_long_one "$remote_path" || true)
  [[ -z "$b" ]] && return 1
  [[ "$a" == "$b" ]]
}

sftp_get() {
  local remote_path="$1"
  local local_path="$2"
  printf 'get %s %s\n' "$remote_path" "$local_path" | ${sftp_base[@]} "$OPNSENSE_USER@$OPNSENSE_HOST" >/dev/null
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

# 1) Build remote list (across all relevant days)
all_files=""
for day in "${days[@]}"; do
  [[ -z "$day" ]] && continue
  if ! part=$(sftp_ls "$OPNSENSE_PCAP_DIR/lan-${day}_*.pcap*" | sort); then
    echo "[homenetsec] ERROR: SFTP list failed for day=$day ($OPNSENSE_USER@$OPNSENSE_HOST:$OPNSENSE_PCAP_DIR)" >&2
    exit 1
  fi
  [[ -n "$part" ]] && all_files+="$part"$'\n'
done

if [[ -z "$all_files" ]]; then
  echo "[homenetsec] No remote pcaps found (days=${days[0]:-?}..${days[-1]:-?})."
  exit 0
fi

# 2) Filter remote list into candidates:
# - eligible fresh files: (last_contig_epoch, cutoff_epoch]
# - plus any pending epochs <= cutoff_epoch (even if older)
# - apply PULL_SKIP_NEWEST_N only to the newest N of the FRESH set (not pending)
export LAST_CONTIG_EPOCH="$last_contig_epoch" CUTOFF_EPOCH="$cutoff_epoch" HIGH_EPOCH="$high_epoch" PENDING_JSON="$pending_json"

candidates_tsv=$(printf '%s' "$all_files" | python3 - <<'PY'
import os, re, sys, json, datetime

last_contig = int(os.environ['LAST_CONTIG_EPOCH'])
cutoff = int(os.environ['CUTOFF_EPOCH'])
high_prev = int(os.environ.get('HIGH_EPOCH', '0') or 0)

pending = []
try:
  pending = json.loads(os.environ.get('PENDING_JSON','[]') or '[]')
except Exception:
  pending = []

pending_epochs = set()
pending_by_epoch = {}
for it in pending:
  try:
    ep = int(it.get('epoch',0) or 0)
    path = (it.get('path') or '').strip()
    if ep>0 and path:
      pending_epochs.add(ep)
      pending_by_epoch[ep] = path
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

seen = {}
max_seen_eligible = high_prev
for line in sys.stdin:
  p=line.strip()
  if not p:
    continue
  ep = to_epoch(p)
  if ep is None:
    continue
  seen[ep] = p
  if last_contig < ep <= cutoff and ep > max_seen_eligible:
    max_seen_eligible = ep

# Build candidate list with a pending flag
out = []
for ep, p in seen.items():
  if ep in pending_epochs and ep <= cutoff:
    out.append((ep, p, 1))
  elif last_contig < ep <= cutoff:
    out.append((ep, p, 0))

out.sort()
for ep, p, is_pending in out:
  print(f"{ep}\t{p}\t{is_pending}\t{max_seen_eligible}")
PY
)

if [[ -z "$candidates_tsv" ]]; then
  echo "[homenetsec] No eligible pcaps (last_contig_epoch=$last_contig_epoch cutoff=$cutoff_epoch)."
  exit 0
fi

# Parse candidates TSV
candidate_epochs=()
candidate_paths=()
candidate_pending=()
max_seen_eligible=0
while IFS=$'\t' read -r ep path is_pending max_seen; do
  [[ -z "$ep" || -z "$path" ]] && continue
  candidate_epochs+=("$ep")
  candidate_paths+=("$path")
  candidate_pending+=("$is_pending")
  max_seen_eligible="$max_seen"
done <<< "$candidates_tsv"

high_seen_epoch=${max_seen_eligible:-$high_epoch}

# Apply skip-newest only to FRESH candidates (pending=0)
fresh_idxs=()
for i in "${!candidate_paths[@]}"; do
  if [[ "${candidate_pending[$i]}" == "0" ]]; then
    fresh_idxs+=("$i")
  fi
done

skipped_epochs=()
use_idxs=()
if (( ${#fresh_idxs[@]} > PULL_SKIP_NEWEST_N )); then
  # skip last N fresh idxs (already sorted by epoch)
  keep_count=$(( ${#fresh_idxs[@]} - PULL_SKIP_NEWEST_N ))
  for ((j=0; j<keep_count; j++)); do
    use_idxs+=("${fresh_idxs[$j]}")
  done
  for ((j=keep_count; j<${#fresh_idxs[@]}; j++)); do
    idx="${fresh_idxs[$j]}"
    skipped_epochs+=("${candidate_epochs[$idx]}")
  done
else
  # if we don't have enough fresh files, we don't process fresh this run
  for idx in "${fresh_idxs[@]}"; do
    skipped_epochs+=("${candidate_epochs[$idx]}")
  done
fi

# Always include pending candidates (even if few fresh)
for i in "${!candidate_paths[@]}"; do
  if [[ "${candidate_pending[$i]}" == "1" ]]; then
    use_idxs+=("$i")
  fi
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
  echo "[homenetsec] No candidates to process after skip-newest (pending=0, fresh<=skip)."
  exit 0
fi

# 2) Download missing and track local paths for merge
# Strategy:
# - Only copy remote files that appear stable (size+mtime unchanged across REMOTE_STABILITY_SECONDS)
# - Copy to a .partial file
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

# Iterate selected candidate indices (pending + fresh-minus-skip)
for idx in "${use_idxs[@]}"; do
  remote="${candidate_paths[$idx]}"
  base=$(basename "$remote")
  ep="${candidate_epochs[$idx]}"
  day=$(echo "$base" | cut -d_ -f1 | sed 's/^lan-//')
  out_dir="$WORKDIR/pcaps/$day"
  mkdir -p "$out_dir"
  out_path="$out_dir/$base"

  # If we already have a validated local copy, include it.
  if [[ -f "$out_path" ]]; then
    local_paths+=("$out_path")
    ok_epochs+=("$ep")
    continue
  fi

  if ! remote_is_stable "$remote"; then
    echo "[homenetsec] skip(unstable): $remote"
    add_pending "$ep" "$remote" "unstable"
    continue
  fi

  tmp_path="$out_path.partial"
  rm -f -- "$tmp_path" 2>/dev/null || true

  echo "[homenetsec] pulling $remote"
  if ! sftp_get "$remote" "$tmp_path"; then
    echo "[homenetsec] WARN: sftp get failed for $remote" >&2
    rm -f -- "$tmp_path" 2>/dev/null || true
    add_pending "$ep" "$remote" "sftp_get_failed"
    continue
  fi

  if tshark -r "$tmp_path" -w "$out_path" >/dev/null 2>&1; then
    rm -f -- "$tmp_path" 2>/dev/null || true
    local_paths+=("$out_path")
    ok_epochs+=("$ep")
  else
    bad_path="$out_path.bad.$(date +%s)"
    mv -f -- "$tmp_path" "$bad_path" 2>/dev/null || true
    rm -f -- "$out_path" 2>/dev/null || true
    echo "[homenetsec] WARN: invalid pcap (quarantined): $bad_path" >&2
    add_pending "$ep" "$remote" "invalid_pcap"
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

# 5) Update state (gap-safe)
# - last_contiguous_epoch advances only when we've validated all eligible segments up to that epoch
# - high_watermark_epoch tracks the highest eligible epoch observed
# - pending tracks missing/failed segments to retry on future runs
export LAST_CONTIG_EPOCH="$last_contig_epoch" HIGH_EPOCH="$high_epoch" HIGH_SEEN_EPOCH="$high_seen_epoch"
export SKIPPED_EPOCHS_JSON="$(python3 - <<PY
import json
print(json.dumps([int(x) for x in "${skipped_epochs[*]}".split() if x.strip()]))
PY
)"
export OK_EPOCHS_JSON="$(python3 - <<PY
import json
print(json.dumps([int(x) for x in "${ok_epochs[*]}".split() if x.strip()]))
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

skipped = set(json.loads(os.environ.get('SKIPPED_EPOCHS_JSON','[]') or '[]'))
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

# Eligible epochs are all candidate epochs excluding skipped-newest epochs
eligible_epochs = sorted([e for e in mp.keys() if e not in skipped and e > last_contig])

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
j={
  # Back-compat key
  "last_epoch": int($new_contig),
  "last_contiguous_epoch": int($new_contig),
  "high_watermark_epoch": int($new_high),
  "pending": $pending_final_json,
  "updated_at": time.strftime('%Y-%m-%dT%H:%M:%S%z'),
  "last_merge": "$merge_name",
  "merge_day": "$merge_day",
  "validated_count": int(${#local_paths[@]}),
}
json.dump(j, open(p,'w',encoding='utf-8'), indent=2)
print(p)
PY

echo "[homenetsec] hourly ingest complete (contiguous_epoch=$new_contig high_watermark=$new_high pending=$(python3 - <<PY
import json
print(len(json.loads('''$pending_final_json''') if '''$pending_final_json'''.strip() else '[]'))
PY
))"

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

