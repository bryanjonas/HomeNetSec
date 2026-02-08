#!/usr/bin/env bash
set -euo pipefail

# OpenClaw-oriented wrapper: run HomeNetSec pipeline and send a condensed report via Telegram.
# NOTE: This script is environment-specific (expects OpenClaw config paths). Keep secrets out of git.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${HOMENETSEC_WORKDIR:-$ROOT_DIR/output}"
PIPELINE="$ROOT_DIR/scripts/run_daily.sh"

CONFIG_JSON="${OPENCLAW_CONFIG_JSON:-$HOME/.openclaw/openclaw.json}"
CHAT_ID="${OPENCLAW_TELEGRAM_CHAT_ID:-<TELEGRAM_CHAT_ID>}"
LOG_PATH="${HOMENETSEC_LOG_PATH:-$WORKDIR/cron.log}"
LOCK_PATH="${HOMENETSEC_LOCK_PATH:-$WORKDIR/run_and_send_daily.lock}"

mkdir -p "$(dirname "$LOG_PATH")" "$WORKDIR/reports"
exec >>"$LOG_PATH" 2>&1

ts() { date -Is; }
RUN_ID="$(TZ=America/New_York date +%F)T$(TZ=America/New_York date +%H%M%S)-$$"
export RUN_ID

echo "[$(ts)] [homenetsec] START run_id=$RUN_ID"

# Prevent overlaps.
if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK_PATH"
  if ! flock -n 9; then
    echo "[$(ts)] [homenetsec] SKIP: lock held ($LOCK_PATH)"
    exit 0
  fi
fi

TODAY_ET="$(TZ=America/New_York date +%F)"
REPORT_PATH="$WORKDIR/reports/${TODAY_ET}.txt"

# Hourly-style ingest/catch-up before daily run (download new pcaps since last ingest,
# merge them, run Suricata+Zeek on the merged pcap). This keeps the local cache warm and
# reduces per-PCAP container churn.
if [[ "${RUN_HOURLY_INGEST_BEFORE_DAILY:-1}" == "1" ]]; then
  echo "[$(ts)] [homenetsec] hourly_ingest: start"
  ( cd "$ROOT_DIR" && \
    HOMENETSEC_WORKDIR="$WORKDIR" \
    PULL_SKIP_NEWEST_N="${PULL_SKIP_NEWEST_N:-1}" \
    SAFETY_LAG_SECONDS="${SAFETY_LAG_SECONDS:-120}" \
    ./scripts/hourly_ingest_merge_process.sh ) || \
    echo "[$(ts)] [homenetsec] WARN: hourly_ingest failed; continuing with daily pipeline"
  echo "[$(ts)] [homenetsec] hourly_ingest: end"
fi

# Generate report
# At 8pm we do NOT re-run Zeek/Suricata over a whole day. Those are handled incrementally
# by the hourly ingest (merged PCAP) job. Here we run the reporting layer: RITA + baselines +
# candidates + report.
HOMENETSEC_WORKDIR="$WORKDIR" \
  SKIP_PCAP_PULL=1 \
  SKIP_ZEEK=1 \
  RUN_JA4=0 \
  "$PIPELINE" "$TODAY_ET" >/dev/null

if [[ ! -f "$REPORT_PATH" ]]; then
  echo "[$(ts)] [homenetsec] Report missing: $REPORT_PATH"
  exit 2
fi

# Condense and send to Telegram via Telegram Bot API token from OpenClaw config.
python3 - "$CONFIG_JSON" "$CHAT_ID" "$REPORT_PATH" <<'PY'
import json, sys, urllib.parse, urllib.request

config_path, chat_id, report_path = sys.argv[1], sys.argv[2], sys.argv[3]

with open(config_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)

token = cfg["channels"]["telegram"]["botToken"]

with open(report_path, 'r', encoding='utf-8', errors='replace') as f:
    lines = [ln.rstrip('\n') for ln in f]

# keep it short
MAX_LINES = 60
text = "\n".join(lines[:MAX_LINES])

url = f"https://api.telegram.org/bot{token}/sendMessage"
body = urllib.parse.urlencode({
    "chat_id": chat_id,
    "text": text,
    "disable_web_page_preview": "true",
}).encode("utf-8")

req = urllib.request.Request(url, data=body, method="POST")
with urllib.request.urlopen(req, timeout=30) as resp:
    resp.read()
PY

echo "[$(ts)] [homenetsec] END run_id=$RUN_ID"
