#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${HOMENETSEC_WORKDIR:-$ROOT_DIR/output}"

TS() { date -Is; }
ET_DATE() { TZ=America/New_York date +%F; }

TODAY_ET="${1:-$(ET_DATE)}"

WWW_DIR="$WORKDIR/www"
DAILY_DIR="$WWW_DIR/daily"
STATE_JSON="$WORKDIR/state/hourly_ingest_state.json"
REPORT_TXT="$WORKDIR/reports/${TODAY_ET}.txt"

mkdir -p "$DAILY_DIR"

# Build a minimal machine-readable status blob.
python3 - "$STATE_JSON" "$TODAY_ET" "$REPORT_TXT" "$WWW_DIR/status.json" <<'PY'
import json, os, sys, time

state_path, today_et, report_txt, out_path = sys.argv[1:5]

def load_json(p):
    try:
        with open(p, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return None

state = load_json(state_path) or {}

report_exists = os.path.exists(report_txt)
report_mtime = int(os.path.getmtime(report_txt)) if report_exists else None

payload = {
    "generated_at": time.strftime('%Y-%m-%dT%H:%M:%S%z'),
    "today_et": today_et,
    "hourly_state": state,
    "daily_report": {
        "path": os.path.basename(report_txt),
        "exists": report_exists,
        "mtime": report_mtime,
    },
}

os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, 'w', encoding='utf-8') as f:
    json.dump(payload, f, indent=2, sort_keys=True)
    f.write("\n")
PY

# Build index.html (current status)
python3 - "$WWW_DIR/status.json" "$WWW_DIR/index.html" <<'PY'
import html, json, sys

status_path, out_path = sys.argv[1], sys.argv[2]
with open(status_path, 'r', encoding='utf-8') as f:
    st = json.load(f)

hourly = st.get('hourly_state') or {}
last_epoch = hourly.get('last_ingested_epoch')

body = []
body.append('<!doctype html>')
body.append('<html><head><meta charset="utf-8">')
body.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
body.append('<title>HomeNetSec Dashboard</title>')
body.append('<style>body{font-family:system-ui,Arial,sans-serif;max-width:960px;margin:24px auto;padding:0 16px} code,pre{background:#f6f8fa;padding:2px 4px;border-radius:4px} .card{border:1px solid #ddd;border-radius:8px;padding:16px;margin:16px 0} .muted{color:#555} a{color:#0b5fff;text-decoration:none} a:hover{text-decoration:underline}</style>')
body.append('</head><body>')
body.append('<h1>HomeNetSec</h1>')
body.append(f"<div class='muted'>Generated: {html.escape(st.get('generated_at',''))}</div>")

body.append('<div class="card">')
body.append('<h2>Hourly ingest</h2>')
if last_epoch:
    body.append(f"<div>last_ingested_epoch: <code>{html.escape(str(last_epoch))}</code></div>")
else:
    body.append('<div class="muted">No hourly state found yet.</div>')
body.append('<details style="margin-top:10px"><summary>raw state</summary>')
body.append('<pre>' + html.escape(json.dumps(hourly, indent=2, sort_keys=True)) + '</pre>')
body.append('</details>')
body.append('</div>')

body.append('<div class="card">')
body.append('<h2>Daily reports</h2>')
body.append('<ul>')
body.append('<li><a href="/daily/">Browse daily</a></li>')
body.append('</ul>')
body.append('</div>')

body.append('</body></html>')

with open(out_path, 'w', encoding='utf-8') as f:
    f.write('\n'.join(body) + '\n')
PY

# If the daily report exists, render it to a dated HTML page.
if [[ -f "$REPORT_TXT" ]]; then
  python3 - "$REPORT_TXT" "$DAILY_DIR/${TODAY_ET}.html" "$TODAY_ET" <<'PY'
import html, sys

report_path, out_path, day = sys.argv[1:4]
with open(report_path, 'r', encoding='utf-8', errors='replace') as f:
    txt = f.read()

page = f"""<!doctype html>
<html><head><meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>HomeNetSec Daily Report — {html.escape(day)}</title>
<style>body{{font-family:system-ui,Arial,sans-serif;max-width:960px;margin:24px auto;padding:0 16px}} pre{{background:#0b1020;color:#e8eefc;padding:16px;border-radius:8px;overflow:auto;white-space:pre-wrap}} a{{color:#0b5fff;text-decoration:none}} a:hover{{text-decoration:underline}} .muted{{color:#555}}</style>
</head><body>
<h1>HomeNetSec — Daily Report</h1>
<div class=\"muted\">{html.escape(day)}</div>
<p><a href=\"/\">← Dashboard</a></p>
<pre>{html.escape(txt)}</pre>
</body></html>
"""
with open(out_path, 'w', encoding='utf-8') as f:
    f.write(page)
PY
fi

# Generate daily index (simple link list)
python3 - "$DAILY_DIR" "$DAILY_DIR/index.html" <<'PY'
import os, sys, html

dir_path, out_path = sys.argv[1:3]
files = [f for f in os.listdir(dir_path) if f.endswith('.html') and f != 'index.html']
files.sort(reverse=True)

body = []
body.append('<!doctype html>')
body.append('<html><head><meta charset="utf-8">')
body.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
body.append('<title>HomeNetSec Daily Reports</title>')
body.append('<style>body{font-family:system-ui,Arial,sans-serif;max-width:960px;margin:24px auto;padding:0 16px} a{color:#0b5fff;text-decoration:none} a:hover{text-decoration:underline}</style>')
body.append('</head><body>')
body.append('<h1>Daily Reports</h1>')
body.append('<p><a href="/">← Dashboard</a></p>')
body.append('<ul>')
for f in files:
    body.append(f'<li><a href="{html.escape(f)}">{html.escape(f.replace(".html",""))}</a></li>')
body.append('</ul>')
body.append('</body></html>')

with open(out_path, 'w', encoding='utf-8') as out:
    out.write('\n'.join(body) + '\n')
PY

echo "[$(TS)] [homenetsec] dashboard updated under: $WWW_DIR"