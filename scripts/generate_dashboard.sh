#!/usr/bin/env bash
set -euo pipefail

# Generate the HomeNetSec dashboard site under $HOMENETSEC_WORKDIR/www.
# Legacy static digest mode has been removed; this script always publishes
# the live API-backed dashboard assets.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source .env if present (for HOMENETSEC_WORKDIR, etc.)
[[ -f "$ROOT_DIR/.env" ]] && set -a && source "$ROOT_DIR/.env" && set +a

if [[ -z "${HOMENETSEC_WORKDIR:-}" ]]; then
  echo "[homenetsec] ERROR: HOMENETSEC_WORKDIR not set. Please configure in .env file." >&2
  exit 2
fi

WORKDIR="$HOMENETSEC_WORKDIR"
if [[ "${WORKDIR##*/}" != "output" ]]; then
  WORKDIR="$WORKDIR/output"
fi

WWW_DIR="$WORKDIR/www"
STATIC_SRC="$ROOT_DIR/assets/dashboard-static"
STATIC_DIR="$WWW_DIR/static"
DASHBOARD_MODE="${HOMENETSEC_DASHBOARD_MODE:-live}"

if [[ "$DASHBOARD_MODE" != "live" ]]; then
  echo "[homenetsec] WARN: HOMENETSEC_DASHBOARD_MODE=$DASHBOARD_MODE is unsupported; forcing live mode." >&2
fi

mkdir -p "$STATIC_DIR"
cp "$STATIC_SRC/index.html" "$WWW_DIR/index.html"
cp "$STATIC_SRC/dashboard.js" "$STATIC_DIR/dashboard.js"
cp "$STATIC_SRC/dashboard.css" "$STATIC_DIR/dashboard.css"

python3 - "$WORKDIR/state/pipeline_status.json" "$WWW_DIR/build.json" <<'PY'
import json
import os
import sys
import time

status_path, out_path = sys.argv[1:3]
payload = {
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "mode": "live",
}

if os.path.exists(status_path):
    try:
        with open(status_path, "r", encoding="utf-8") as fh:
            payload["pipeline_status"] = json.load(fh)
    except Exception:
        payload["pipeline_status"] = {"status": "unreadable"}

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
