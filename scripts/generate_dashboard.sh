#!/usr/bin/env bash
set -euo pipefail

# Generate the HomeNetSec dashboard site under $HOMENETSEC_WORKDIR/www.
#
# Design goal:
# - Single page UX: the root page (/) is always "today" and gets updated at 8pm with the latest digest.
# - Digest alerts are sourced from $WORKDIR/state/YYYY-MM-DD.digest.json (LLM triage output).
#   If that file is missing, we fall back to $WORKDIR/state/YYYY-MM-DD.candidates.json.
# - User feedback is currently stored in the browser (localStorage) and can be exported.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${HOMENETSEC_WORKDIR:-$ROOT_DIR/output}"

TS() { date -Is; }
ET_DATE() { TZ=America/New_York date +%F; }

TODAY_ET="${1:-$(ET_DATE)}"

WWW_DIR="$WORKDIR/www"
STATE_JSON="$WORKDIR/state/hourly_ingest_state.json"
REPORT_TXT="$WORKDIR/reports/${TODAY_ET}.txt"
DIGEST_JSON="$WORKDIR/state/${TODAY_ET}.digest.json"
CANDIDATES_JSON="$WORKDIR/state/${TODAY_ET}.candidates.json"

mkdir -p "$WWW_DIR"

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

# Build the single-page dashboard at / (index.html).
python3 - "$WWW_DIR/status.json" "$REPORT_TXT" "$DIGEST_JSON" "$CANDIDATES_JSON" "$WWW_DIR/index.html" <<'PY'
import html, json, os, sys, hashlib

status_path, report_path, digest_path, candidates_path, out_path = sys.argv[1:6]

st = json.load(open(status_path, 'r', encoding='utf-8'))
hourly = st.get('hourly_state') or {}
day = st.get('today_et') or ''

# hourly state key drift compatibility
last_epoch = hourly.get('last_epoch')
if last_epoch is None:
    last_epoch = hourly.get('last_ingested_epoch')

report_txt = ''
if os.path.exists(report_path):
    report_txt = open(report_path, 'r', encoding='utf-8', errors='replace').read()

digest = None
if os.path.exists(digest_path):
    try:
        digest = json.load(open(digest_path, 'r', encoding='utf-8'))
    except Exception:
        digest = None

candidates = None
if os.path.exists(candidates_path):
    try:
        candidates = json.load(open(candidates_path, 'r', encoding='utf-8'))
    except Exception:
        candidates = None

# Build "alerts".
# Prefer LLM triage digest if present; otherwise fall back to baseline candidates.
alerts = []
if digest and isinstance(digest.get('items'), list):
    for it in digest.get('items'):
        if not isinstance(it, dict):
            continue
        alerts.append({
            'kind': 'digest_item',
            'title': it.get('title') or '(untitled)',
            'data': it,
            'id': it.get('id') or None,
        })
else:
    if candidates:
        for item in candidates.get('new_external_destinations', []) or []:
            alerts.append({'kind': 'new_external_destination', 'title': f"New external destination: {item.get('dst_ip','?')}", 'data': item})
        for d in candidates.get('new_domains', []) or []:
            alerts.append({'kind': 'new_domain', 'title': f"New domain: {d}", 'data': {'domain': d}})
        for item in candidates.get('new_watch_tuples', []) or []:
            alerts.append({'kind': 'new_watch_tuple', 'title': f"New watch tuple: {item.get('src_ip','?')} → {item.get('dst_ip','?')}:{item.get('dst_port','?')}", 'data': item})
        for b in candidates.get('rita_beacons', []) or []:
            alerts.append({'kind': 'rita_beacon', 'title': f"RITA beacon candidate: {b.get('src_ip','?')} → {b.get('dst_ip','?')}", 'data': b})

# Stable-ish id for feedback storage.
for a in alerts:
    if not a.get('id'):
        h = hashlib.sha256((a['kind'] + '|' + json.dumps(a['data'], sort_keys=True)).encode('utf-8')).hexdigest()[:16]
        a['id'] = f"{day}-{h}"

style = """
body{font-family:system-ui,Arial,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px}
a{color:#0b5fff;text-decoration:none} a:hover{text-decoration:underline}
.card{border:1px solid #ddd;border-radius:10px;padding:16px;margin:16px 0}
.muted{color:#555}
pre{background:#0b1020;color:#e8eefc;padding:14px;border-radius:10px;overflow:auto;white-space:pre-wrap}
.small{font-size:12px}
.row{display:flex;gap:12px;flex-wrap:wrap}
.pill{display:inline-block;border:1px solid #ccc;border-radius:999px;padding:2px 8px;font-size:12px;color:#333;background:#fafafa}
textarea{width:100%;min-height:72px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
select,button,input{font-size:14px}
button{padding:6px 10px}
hr{border:none;border-top:1px solid #eee;margin:16px 0}
"""

js = """
const DAY = document.body.dataset.day;
const STORE_KEY = `homenetsec-feedback:${DAY}`;
function loadStore(){ try { return JSON.parse(localStorage.getItem(STORE_KEY) || '{}'); } catch(e){ return {}; } }
function saveStore(obj){ localStorage.setItem(STORE_KEY, JSON.stringify(obj)); }
function onSave(alertId){
  const store = loadStore();
  const note = document.querySelector(`#note-${alertId}`).value;
  const verdict = document.querySelector(`#verdict-${alertId}`).value;
  const action = document.querySelector(`#action-${alertId}`).value;
  const actionValue = document.querySelector(`#actionval-${alertId}`).value;
  store[alertId] = { updated_at: new Date().toISOString(), verdict, note, action, action_value: actionValue };
  saveStore(store);
  document.querySelector(`#status-${alertId}`).textContent = 'saved locally';
}
function hydrate(){
  const store = loadStore();
  for (const [alertId, v] of Object.entries(store)){
    const noteEl = document.querySelector(`#note-${alertId}`);
    if (!noteEl) continue;
    document.querySelector(`#note-${alertId}`).value = v.note || '';
    document.querySelector(`#verdict-${alertId}`).value = v.verdict || 'unsure';
    document.querySelector(`#action-${alertId}`).value = v.action || '';
    document.querySelector(`#actionval-${alertId}`).value = v.action_value || '';
    document.querySelector(`#status-${alertId}`).textContent = 'saved locally';
  }
}
function exportFeedback(){
  const store = loadStore();
  const blob = new Blob([JSON.stringify({day: DAY, feedback: store}, null, 2)], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `homenetsec-feedback-${DAY}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
window.addEventListener('DOMContentLoaded', hydrate);
window.exportFeedback = exportFeedback;
window.onSave = onSave;
"""

body = []
body.append('<!doctype html>')
body.append('<html><head><meta charset="utf-8">')
body.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
body.append('<title>HomeNetSec Dashboard</title>')
body.append(f'<style>{style}</style>')
body.append('</head>')
body.append(f'<body data-day="{html.escape(day)}">')
body.append('<h1>HomeNetSec</h1>')
body.append(f"<div class='muted'>Generated: {html.escape(st.get('generated_at',''))} · Day (ET): <code>{html.escape(day)}</code></div>")

body.append('<div class="card">')
body.append('<h2>Hourly ingest</h2>')
if last_epoch:
    body.append(f"<div>last_epoch: <code>{html.escape(str(last_epoch))}</code></div>")
else:
    body.append('<div class="muted">No hourly state found yet.</div>')
body.append('<details style="margin-top:10px"><summary>raw state</summary>')
body.append('<pre>' + html.escape(json.dumps(hourly, indent=2, sort_keys=True)) + '</pre>')
body.append('</details>')
body.append('</div>')

body.append('<div class="card">')
body.append("<h2>Today\'s digest alerts (for review)</h2>")
body.append('<div class="muted">Feedback is stored in your browser (localStorage) for now; use “Export feedback” to share/apply.</div>')
body.append('<p><button onclick="exportFeedback()">Export feedback JSON</button></p>')

if not alerts:
    body.append('<div class="muted">No candidates found yet. This will populate after the 8pm daily run writes <code>output/state/YYYY-MM-DD.candidates.json</code>.</div>')
else:
    for a in alerts:
        aid = html.escape(a['id'])
        body.append('<hr>')
        body.append(f'<div class="row"><div class="pill">{html.escape(a["kind"])}</div><div class="small muted">id: <code>{aid}</code></div></div>')
        body.append(f'<h3 style="margin:10px 0">{html.escape(a["title"])}</h3>')
        body.append('<details><summary>evidence (raw)</summary>')
        body.append('<pre>' + html.escape(json.dumps(a['data'], indent=2, sort_keys=True)) + '</pre>')
        body.append('</details>')

        body.append('<div class="row" style="align-items:center;margin-top:10px">')
        body.append(f'<label>Verdict: <select id="verdict-{aid}"><option value="unsure">unsure</option><option value="benign">likely benign</option><option value="review">needs review</option><option value="suspicious">suspicious</option></select></label>')
        body.append(f'<span class="muted small" id="status-{aid}"></span>')
        body.append('</div>')

        body.append(f'<div style="margin-top:10px"><label>Comment / context:<br><textarea id="note-{aid}" placeholder="e.g. Doorbell doing NTP lookups (pool.ntp.org)."></textarea></label></div>')

        body.append('<div class="row" style="margin-top:10px">')
        body.append(f'<label>Suggest suppress (allowlist) action: <select id="action-{aid}">'
                    '<option value="">(none)</option>'
                    '<option value="domain">domain</option>'
                    '<option value="domain_suffix">domain suffix</option>'
                    '<option value="dst_ip">destination IP</option>'
                    '<option value="rdns_suffix">rDNS suffix</option>'
                    '</select></label>')
        body.append(f'<label>Value: <input id="actionval-{aid}" size="32" placeholder="e.g. pool.ntp.org or .ntp.org"/></label>')
        body.append(f'<button onclick="onSave(\'{aid}\')">Save</button>')
        body.append('</div>')

body.append('</div>')

body.append('<div class="card">')
body.append('<h2>Raw daily roll-up (if present)</h2>')
if report_txt.strip():
    body.append('<pre>' + html.escape(report_txt) + '</pre>')
else:
    body.append('<div class="muted">No daily report text found yet.</div>')
body.append('</div>')

body.append(f'<script>{js}</script>')
body.append('</body></html>')

with open(out_path, 'w', encoding='utf-8') as f:
    f.write('\n'.join(body) + '\n')
PY

echo "[$(TS)] [homenetsec] dashboard updated under: $WWW_DIR"