#!/usr/bin/env bash
set -euo pipefail

# HomeNetSec daily pipeline (dockerized)
# - Pull PCAPs from OPNsense via SSH
# - Run Zeek offline in Docker per PCAP
# - Flatten Zeek logs for RITA
# - Run RITA (docker) backed by MongoDB (docker)
# - Summarize Zeek (top-5) + RITA (top-5) + AdGuardHome (top-5)
# - Write report to: $HOMENETSEC_WORKDIR/reports/YYYY-MM-DD.txt

TZ="America/New_York"; export TZ

DAY="${1:-$(date +%F)}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${HOMENETSEC_WORKDIR:-$ROOT_DIR/output}"
COMPOSE_FILE="${HOMENETSEC_COMPOSE_FILE:-$ROOT_DIR/assets/docker-compose.yml}"
RITA_CFG_HOST="${HOMENETSEC_RITA_CONFIG:-$ROOT_DIR/assets/rita-config.yaml.example}"

PCAP_DIR="$WORKDIR/pcaps/$DAY"
ZEEK_ROOT="$WORKDIR/zeek-logs/$DAY"
ZEEK_FLAT_ROOT="$WORKDIR/zeek-flat/$DAY"
RITA_DATA_DIR="$WORKDIR/rita-data"
REPORT_DIR="$WORKDIR/reports"
STATE_DIR="$WORKDIR/state"
BASELINE_DB="$STATE_DIR/baselines.sqlite"
CANDIDATES_PATH="$STATE_DIR/${DAY}.candidates.json"
REPORT_PATH="$REPORT_DIR/$DAY.txt"

# OPNsense pull settings
OPNSENSE_HOST="${OPNSENSE_HOST:-192.168.1.X}"
OPNSENSE_USER="${OPNSENSE_USER:-openclaw}"
OPNSENSE_KEY="${OPNSENSE_KEY:-$HOME/.ssh/openclaw-opnsense}"
OPNSENSE_PCAP_DIR="${OPNSENSE_PCAP_DIR:-/var/log/pcaps}"

# Controls
RUN_RITA="${RUN_RITA:-1}"
PCAP_RETENTION_DAYS="${PCAP_RETENTION_DAYS:-7}"
ZEEK_LOG_RETENTION_DAYS="${ZEEK_LOG_RETENTION_DAYS:-30}"

mkdir -p "$PCAP_DIR" "$ZEEK_ROOT" "$ZEEK_FLAT_ROOT" "$RITA_DATA_DIR" "$REPORT_DIR" "$STATE_DIR"

require_docker() {
  command -v docker >/dev/null 2>&1 || { echo "[homenetsec] ERROR: docker CLI not found"; return 127; }
  docker info >/dev/null 2>&1 || { echo "[homenetsec] ERROR: docker daemon not reachable"; return 1; }
}

compose() {
  HOMENETSEC_WORKDIR="$WORKDIR" docker compose -f "$COMPOSE_FILE" "$@"
}

pull_pcaps() {
  if [[ "${SKIP_PCAP_PULL:-0}" == "1" ]]; then
    echo "[homenetsec] SKIP_PCAP_PULL=1 (skipping PCAP pull step)"
    return 0
  fi

  local list
  local -a ssh_base scp_base
  ssh_base=(ssh -i "$OPNSENSE_KEY" -o BatchMode=yes -o ConnectTimeout=8)
  scp_base=(scp -i "$OPNSENSE_KEY" -o BatchMode=yes -o ConnectTimeout=8)

  list=$(${ssh_base[@]} "$OPNSENSE_USER@$OPNSENSE_HOST" \
    "ls -1 $OPNSENSE_PCAP_DIR/lan-${DAY}_*.pcap* 2>/dev/null" || true)

  if [[ -z "$list" ]]; then
    echo "[homenetsec] No pcaps found on OPNsense for $DAY (or SSH blocked)."
    return 0
  fi

  while IFS= read -r remote; do
    [[ -z "$remote" ]] && continue
    local base
    base=$(basename "$remote")
    if [[ ! -f "$PCAP_DIR/$base" ]]; then
      echo "[homenetsec] pulling $remote"
      ${scp_base[@]} "$OPNSENSE_USER@$OPNSENSE_HOST:$remote" "$PCAP_DIR/$base" >/dev/null
    fi
  done <<< "$list"
}

run_zeek_docker() {
  if [[ "${SKIP_ZEEK:-0}" == "1" ]]; then
    echo "[homenetsec] SKIP_ZEEK=1 (skipping Zeek processing)"
    return 0
  fi

  shopt -s nullglob
  local pcaps=("$PCAP_DIR"/lan-${DAY}_*.pcap*)
  if (( ${#pcaps[@]} == 0 )); then
    echo "[homenetsec] No local pcaps to process for $DAY at $PCAP_DIR"
    return 0
  fi

  for pcap in "${pcaps[@]}"; do
    local bn out
    bn=$(basename "$pcap")
    out="$ZEEK_ROOT/${bn}.zeek"
    if [[ -s "$out/conn.log" ]]; then
      continue
    fi
    if [[ -f "$out/.failed" ]]; then
      continue
    fi
    mkdir -p "$out"

    echo "[homenetsec] zeek(docker) -> $bn"
    if compose --profile zeek run --rm -e PCAP="/pcaps/$DAY/$bn" zeek-offline; then
      :
    else
      echo "[homenetsec] WARN: zeek failed for $bn (marking $out/.failed and continuing)"
      echo "zeek failed for $bn at $(date -Is)" > "$out/.failed" || true
      continue
    fi
  done
}

flatten_zeek_logs_for_rita() {
  if [[ "${SKIP_FLATTEN:-0}" == "1" ]]; then
    echo "[homenetsec] SKIP_FLATTEN=1 (skipping Zeek flatten step)"
    return 0
  fi

  mkdir -p "$ZEEK_FLAT_ROOT"

  python3 - "$ZEEK_ROOT" "$ZEEK_FLAT_ROOT" <<'PY'
import glob, os, sys
src_root, out_root = sys.argv[1], sys.argv[2]
log_types = ['conn.log','dns.log','http.log','ssl.log','weird.log','notice.log']
os.makedirs(out_root, exist_ok=True)
for lt in log_types:
  inputs = glob.glob(os.path.join(src_root, '*.zeek', lt))
  if not inputs:
    continue
  out_path = os.path.join(out_root, lt)
  wrote_header = False
  with open(out_path, 'w', encoding='utf-8') as out:
    for p in sorted(inputs):
      try:
        with open(p, 'r', encoding='utf-8', errors='replace') as f:
          for line in f:
            if line.startswith('#'):
              if not wrote_header:
                out.write(line)
              continue
            wrote_header = True
            out.write(line)
      except FileNotFoundError:
        continue
PY
}

ensure_mongo_ready() {
  local timeout_s="${1:-60}"
  compose --profile rita up -d mongo

  local start end
  start=$(date +%s)
  end=$((start + timeout_s))

  while (( $(date +%s) < end )); do
    if docker exec rita-mongo mongo --quiet --eval 'db.adminCommand({ping:1}).ok' 2>/dev/null | grep -q '^1$'; then
      return 0
    fi
    if docker exec rita-mongo mongosh --quiet --eval 'db.adminCommand({ping:1}).ok' 2>/dev/null | grep -q '^1$'; then
      return 0
    fi
    sleep 2
  done

  echo "[homenetsec] ERROR: mongo did not become ready within ${timeout_s}s"
  docker logs --tail=80 rita-mongo 2>/dev/null || true
  return 1
}

run_rita_docker() {
  if [[ "$RUN_RITA" != "1" ]]; then
    echo "[homenetsec] RITA disabled (RUN_RITA=$RUN_RITA)"
    return 0
  fi

  flatten_zeek_logs_for_rita

  echo "[homenetsec] starting mongo (for rita)"
  if ! ensure_mongo_ready 60; then
    echo "[homenetsec] WARN: skipping RITA because mongo is not healthy"
    echo "RITA: skipped (mongo not healthy / crash-looping)" > "$RITA_DATA_DIR/rita-summary-${DAY}.txt"
    return 0
  fi

  local chunk
  chunk=$(python3 - "$DAY" <<'PY'
import datetime, sys
s=sys.argv[1]
d=datetime.date.fromisoformat(s)
print(d.toordinal() % 7)
PY
)

  local cfg="/out/rita-config.yaml"

  # Copy the host config into the workdir so it's available via bind mount
  install -m 0644 "$RITA_CFG_HOST" "$RITA_DATA_DIR/rita-config.yaml"

  echo "[homenetsec] rita(docker) rolling import for $DAY (dataset=zeek_rolling chunk=$chunk)"
  compose --profile rita run --rm rita --config "$cfg" import --rolling --numchunks 7 --chunk "$chunk" --delete "/logs-flat/$DAY" zeek_rolling

  local out="$RITA_DATA_DIR/rita-summary-${DAY}.txt"
  {
    echo "RITA summary (rolling window: 7 days; dataset=zeek_rolling; chunk=$chunk)";
    echo;
    echo "Top beacons:";
    compose --profile rita run --rm rita --config "$cfg" show-beacons zeek_rolling 2>/dev/null | head -n 5 || echo "(no beacons / unsupported)";
    echo;
    echo "Top long connections:";
    compose --profile rita run --rm rita --config "$cfg" show-long-connections zeek_rolling 2>/dev/null | head -n 5 || echo "(no long connections / unsupported)";
  } > "$out"
}

summarize_zeek_basic() {
  shopt -s nullglob
  local conns=("$ZEEK_ROOT"/*.zeek/conn.log)
  if (( ${#conns[@]} == 0 )); then
    echo "(no Zeek conn.log files found for $DAY)"
    return 0
  fi

  python3 - "$ZEEK_ROOT" <<'PY'
import glob, os, sys, subprocess

zeek_root = sys.argv[1]
paths = glob.glob(os.path.join(zeek_root, '*.zeek', 'conn.log'))

def is_private(ip: str) -> bool:
    return (
        ip.startswith('10.') or
        ip.startswith('192.168.') or
        (ip.startswith('172.') and len(ip.split('.')) >= 2 and ip.split('.')[1].isdigit() and 16 <= int(ip.split('.')[1]) <= 31)
    )

cache = {}

def rdns(ip: str) -> str:
    if ip in cache:
        return cache[ip]
    name = ''
    try:
        r = subprocess.run(['getent', 'hosts', ip], capture_output=True, text=True, timeout=1)
        if r.returncode == 0 and r.stdout.strip():
            parts = r.stdout.strip().split()
            if len(parts) >= 2:
                name = parts[1]
    except Exception:
        name = ''
    cache[ip] = name
    return name

src_to_ext = {}
dst_ext = {}
watch = {}

for p in paths:
    with open(p, 'r', encoding='utf-8', errors='replace') as f:
        sep = '\t'
        idx = {}
        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue
            if line.startswith('#separator'):
                if '\\x09' in line:
                    sep = '\t'
                continue
            if line.startswith('#fields'):
                parts = line.split()
                fields = parts[1:]
                idx = {name:i for i,name in enumerate(fields)}
                continue
            if line.startswith('#'):
                continue
            if not idx:
                continue
            cols = line.split(sep)
            def get(name, default=''):
                i = idx.get(name)
                if i is None or i >= len(cols):
                    return default
                v = cols[i]
                return '' if v in ('-', '(empty)') else v

            src = get('id.orig_h')
            dst = get('id.resp_h')
            proto = get('proto')
            port = get('id.resp_p')
            if not src or not dst:
                continue
            if (not is_private(dst)) and is_private(src):
                src_to_ext[src] = src_to_ext.get(src, 0) + 1
                dst_ext[dst] = dst_ext.get(dst, 0) + 1
                if proto == 'tcp' and port in ('8883','8443','22','445'):
                    key = f"{src} -> {dst}:{port}"
                    watch[key] = watch.get(key, 0) + 1

print('Zeek: suspicious-traffic signals (offline PCAP)')
print()
print('Top internal sources -> external (by conn count):')
for ip, n in sorted(src_to_ext.items(), key=lambda kv: kv[1], reverse=True)[:5]:
    print(f"{n}\t{ip}")
print()
print('Top external destinations (dst IP by conn count):')
for ip, n in sorted(dst_ext.items(), key=lambda kv: kv[1], reverse=True)[:5]:
    host = rdns(ip)
    extra = f" ({host})" if host else ""
    print(f"{n}\t{ip}{extra}")
print()
print('Watch ports (8883, 8443, 22, 445) to external (top tuples):')
for k, n in sorted(watch.items(), key=lambda kv: kv[1], reverse=True)[:5]:
    try:
        dst = k.split('->',1)[1].strip().rsplit(':',1)[0].strip()
    except Exception:
        dst = ''
    host = rdns(dst) if dst else ''
    extra = f" ({host})" if host else ""
    print(f"{n}\t{k}{extra}")
PY
}

summarize_rita() {
  local p="$RITA_DATA_DIR/rita-summary-${DAY}.txt"
  if [[ -f "$p" ]]; then
    sed -n '1,120p' "$p"
  else
    echo "RITA: (no summary file found at $p)"
  fi
}

summarize_adguard() {
  local env_path="${ADGUARD_ENV:-$HOME/.openclaw/credentials/adguard.env}"
  if [[ ! -f "$env_path" ]]; then
    echo "AdGuard: missing credentials env ($env_path)"
    return 0
  fi

  set -a
  # shellcheck disable=SC1090
  source "$env_path"
  set +a

  python3 - <<'PY'
import json, os, sys
from urllib.request import Request, urlopen

url = os.environ.get('ADGUARD_URL','').rstrip('/')
user = os.environ.get('ADGUARD_USER','')
pw   = os.environ.get('ADGUARD_PASS','')

if not url or not user or not pw:
    print('AdGuard: missing ADGUARD_URL/USER/PASS')
    sys.exit(0)

# Login to get a cookie
login_url = f"{url}/control/login"
login_body = json.dumps({"name": user, "password": pw}).encode('utf-8')
req = Request(login_url, data=login_body, method='POST', headers={'Content-Type':'application/json'})

try:
    resp = urlopen(req, timeout=20)
    cookies = resp.headers.get_all('Set-Cookie') or []
    resp.read()
except Exception as e:
    print(f"AdGuard: login failed: {e}")
    sys.exit(0)

cookie_hdr = '; '.join([c.split(';',1)[0] for c in cookies if c])

# Fetch stats
stats_url = f"{url}/control/stats"
req2 = Request(stats_url, method='GET', headers={'Cookie': cookie_hdr} if cookie_hdr else {})
try:
    stats_raw = urlopen(req2, timeout=20).read().decode('utf-8', errors='replace')
    stats = json.loads(stats_raw)
except Exception as e:
    print(f"AdGuard: stats fetch/parse failed: {e}")
    sys.exit(0)

def top_from_list(key, n):
    out=[]
    for obj in (stats.get(key) or []):
        if isinstance(obj, dict):
            out.extend(list(obj.items()))
    out.sort(key=lambda kv: kv[1], reverse=True)
    return out[:n]

print('AdGuard (stats window):')
print('\nTop clients by DNS volume:')
for c,n in top_from_list('top_clients', 5):
    print(f"  {n}\t{c}")

print('\nTop blocked domains (context):')
for d,n in top_from_list('top_blocked_domains', 5):
    print(f"  {n}\t{d}")
PY
}

cleanup_old_pcaps() {
  echo "[homenetsec] cleanup: pcaps older than ${PCAP_RETENTION_DAYS} days"
  find "$WORKDIR/pcaps" -type f -mtime +"$PCAP_RETENTION_DAYS" -print0 | xargs -0 -r rm -f
}

cleanup_old_zeek_logs() {
  echo "[homenetsec] cleanup: zeek logs older than ${ZEEK_LOG_RETENTION_DAYS} days"
  find "$WORKDIR/zeek-logs" -mindepth 1 -maxdepth 1 -type d -mtime +"$ZEEK_LOG_RETENTION_DAYS" -print0 | xargs -0 -r rm -rf
}

main() {
  require_docker

  pull_pcaps
  run_zeek_docker
  run_rita_docker

  # Update baseline DB and build anomaly candidates (deterministic, small output)
  python3 "$ROOT_DIR/scripts/baseline_update.py" \
    --day "$DAY" \
    --zeek-flat-dir "$ZEEK_FLAT_ROOT" \
    --db "$BASELINE_DB" || true

  python3 "$ROOT_DIR/scripts/detect_candidates.py" \
    --day "$DAY" \
    --db "$BASELINE_DB" \
    --workdir "$WORKDIR" \
    --allowlist "${HOMENETSEC_ALLOWLIST:-$ROOT_DIR/assets/allowlist.example.json}" \
    --out "$CANDIDATES_PATH" || true

  {
    echo "Network security daily report ($DAY)"
    echo "Generated: $(date)"
    echo
    summarize_zeek_basic
    echo
    summarize_rita
    echo
    summarize_adguard
    echo
    echo "Anomaly candidates (baseline-driven):"
    if [[ -f "$CANDIDATES_PATH" ]]; then
      python3 - <<PY
import json
p="$CANDIDATES_PATH"
j=json.load(open(p,'r',encoding='utf-8'))
print(f"  new_external_destinations: {j['counts']['new_external_destinations']}")
print(f"  new_domains: {j['counts']['new_domains']}")
print(f"  new_watch_tuples: {j['counts']['new_watch_tuples']}")
print(f"  high_fanout_hosts: {j['counts']['high_fanout_hosts']}")
print(f"  rita_beacons(>=threshold): {j['counts']['rita_beacons']}")
PY
    else
      echo "  (no candidates file)"
    fi
  } > "$REPORT_PATH"

  cleanup_old_pcaps
  cleanup_old_zeek_logs

  echo "$REPORT_PATH"
}

main
