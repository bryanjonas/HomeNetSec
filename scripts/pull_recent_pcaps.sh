#!/usr/bin/env bash
set -euo pipefail

# Pull the most recent N hours worth of PCAPs from OPNsense into the local workdir.
#
# This is designed for frequent scheduled pulls (e.g., every 4 hours) without
# needing to download a whole day's worth of traffic.

TZ="America/New_York"; export TZ

HOURS="${1:-4}"

if ! [[ "$HOURS" =~ ^[0-9]+$ ]] || (( HOURS <= 0 )); then
  echo "[homenetsec] ERROR: HOURS must be a positive integer (got: $HOURS)" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${HOMENETSEC_WORKDIR:-$ROOT_DIR/output}"

STATE_DIR="$WORKDIR/state"
mkdir -p "$STATE_DIR"

# OPNsense pull settings
OPNSENSE_HOST="${OPNSENSE_HOST:-192.168.1.X}"
OPNSENSE_USER="${OPNSENSE_USER:-openclaw}"
OPNSENSE_KEY="${OPNSENSE_KEY:-$HOME/.ssh/openclaw-opnsense}"
OPNSENSE_PCAP_DIR="${OPNSENSE_PCAP_DIR:-/var/log/pcaps}"

# Avoid copying a PCAP file while tcpdump/daemon is still writing it.
# For frequent pulls, skipping just the newest 1 is usually sufficient.
SKIP_NEWEST_N="${PULL_SKIP_NEWEST_N:-1}"

ssh_base=(ssh -i "$OPNSENSE_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=8)
scp_base=(scp -i "$OPNSENSE_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=12)

now_epoch=$(date +%s)
start_epoch=$(date -d "$HOURS hours ago" +%s)

start_day=$(date -d "@$start_epoch" +%F)
end_day=$(date -d "@$now_epoch" +%F)

# Build the list of candidate remote files across the affected day(s)
# (handles the midnight boundary when HOURS crosses into the previous day).
remote_list=$(python3 - <<PY
import datetime
sd=datetime.date.fromisoformat("$start_day")
ed=datetime.date.fromisoformat("$end_day")
out=[]
d=sd
while d<=ed:
  out.append(d.isoformat())
  d += datetime.timedelta(days=1)
print("\n".join(out))
PY
)

all_files=""
while IFS= read -r day; do
  [[ -z "$day" ]] && continue
  # Use remote shell expansion for the day prefix.
  # If it fails (SSH/auth/perms), fail fast.
  if ! part=$(${ssh_base[@]} "$OPNSENSE_USER@$OPNSENSE_HOST" \
      "ls -1 $OPNSENSE_PCAP_DIR/lan-${day}_*.pcap* 2>/dev/null | sort" ); then
    echo "[homenetsec] ERROR: SSH list failed for day=$day ($OPNSENSE_USER@$OPNSENSE_HOST:$OPNSENSE_PCAP_DIR)" >&2
    exit 1
  fi
  if [[ -n "$part" ]]; then
    all_files+="$part"$'\n'
  fi
done <<< "$remote_list"

# Filter down to just the files whose embedded timestamp lies in [start, now].
export START_EPOCH="$start_epoch" END_EPOCH="$now_epoch"
filtered=$(printf '%s' "$all_files" | python3 - <<'PY'
import os, re, sys, datetime
start=int(os.environ['START_EPOCH'])
end=int(os.environ['END_EPOCH'])

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
  if start <= ep <= end:
    out.append((ep,p))

out.sort()
for _,p in out:
  print(p)
PY
)

if [[ -z "$filtered" ]]; then
  echo "[homenetsec] No pcaps found in last ${HOURS}h window (${start_day}..${end_day})."
  exit 0
fi

# Skip newest N from the filtered set to avoid partial copies.
mapfile -t files <<< "$filtered"
if (( ${#files[@]} <= SKIP_NEWEST_N )); then
  echo "[homenetsec] Found ${#files[@]} matching pcaps; skipping pull because SKIP_NEWEST_N=$SKIP_NEWEST_N"
  exit 0
fi

upto=$(( ${#files[@]} - SKIP_NEWEST_N ))

for (( i=0; i<upto; i++ )); do
  remote="${files[$i]}"
  [[ -z "$remote" ]] && continue
  base=$(basename "$remote")

  # Infer day folder from filename.
  day=$(echo "$base" | cut -d_ -f1 | sed 's/^lan-//')
  out_dir="$WORKDIR/pcaps/$day"
  mkdir -p "$out_dir"

  if [[ ! -f "$out_dir/$base" ]]; then
    echo "[homenetsec] pulling $remote"
    ${scp_base[@]} "$OPNSENSE_USER@$OPNSENSE_HOST:$remote" "$out_dir/$base" >/dev/null
  fi
done

echo "[homenetsec] pull_recent_pcaps complete (last ${HOURS}h; skipped newest ${SKIP_NEWEST_N})"
