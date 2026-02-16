#!/usr/bin/env bash
set -euo pipefail

# Manage the HomeNetSec *reporting* allowlist (suppresses/ignores candidates).
# This does NOT change firewall behavior.
#
# Usage:
#   ./scripts/allowlist_manage.sh init
#   ./scripts/allowlist_manage.sh add-domain example.com
#   ./scripts/allowlist_manage.sh add-domain-suffix .vendor.com
#   ./scripts/allowlist_manage.sh add-dst-ip 1.2.3.4
#   ./scripts/allowlist_manage.sh add-rdns-suffix .compute.amazonaws.com
#
# By default, writes to $HOMENETSEC_WORKDIR/state/allowlist.local.json.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source .env if present (for HOMENETSEC_WORKDIR, etc.)
[[ -f "$ROOT_DIR/.env" ]] && set -a && source "$ROOT_DIR/.env" && set +a

WORKDIR="${HOMENETSEC_WORKDIR:-$ROOT_DIR/output}"
STATE_DIR="$WORKDIR/state"
mkdir -p "$STATE_DIR"

ALLOWLIST_PATH="${HOMENETSEC_ALLOWLIST_PATH:-$STATE_DIR/allowlist.local.json}"
EXAMPLE="$ROOT_DIR/assets/allowlist.example.json"

cmd="${1:-}"
arg="${2:-}"

python_edit() {
  python3 - "$ALLOWLIST_PATH" "$1" "$2" <<'PY'
import json, os, sys
path, key, value = sys.argv[1], sys.argv[2], sys.argv[3]

j = {}
if os.path.exists(path):
  j = json.load(open(path,'r',encoding='utf-8'))

arr = list(j.get(key, []) or [])
if value not in arr:
  arr.append(value)
  arr = sorted(arr)
  j[key] = arr

with open(path,'w',encoding='utf-8') as f:
  json.dump(j,f,indent=2,sort_keys=True)
  f.write('\n')

print(path)
PY
}

case "$cmd" in
  init)
    if [[ -f "$ALLOWLIST_PATH" ]]; then
      echo "exists: $ALLOWLIST_PATH"
      exit 0
    fi
    cp "$EXAMPLE" "$ALLOWLIST_PATH"
    echo "initialized: $ALLOWLIST_PATH"
    ;;
  add-domain)
    [[ -n "$arg" ]] || { echo "missing domain" >&2; exit 2; }
    python_edit domains "$arg" >/dev/null
    echo "added domain: $arg"
    ;;
  add-domain-suffix)
    [[ -n "$arg" ]] || { echo "missing suffix" >&2; exit 2; }
    python_edit domain_suffixes "$arg" >/dev/null
    echo "added domain suffix: $arg"
    ;;
  add-dst-ip)
    [[ -n "$arg" ]] || { echo "missing ip" >&2; exit 2; }
    python_edit dst_ips "$arg" >/dev/null
    echo "added dst ip: $arg"
    ;;
  add-rdns-suffix)
    [[ -n "$arg" ]] || { echo "missing suffix" >&2; exit 2; }
    python_edit rdns_suffixes "$arg" >/dev/null
    echo "added rDNS suffix: $arg"
    ;;
  *)
    echo "Usage: $0 {init|add-domain|add-domain-suffix|add-dst-ip|add-rdns-suffix} <value>" >&2
    exit 2
    ;;
esac
