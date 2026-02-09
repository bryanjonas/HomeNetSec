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

# DOM-safe ids: do not use the logical alert id directly in CSS selectors/element ids,
# because some ids can include characters (e.g. '|') that break querySelector.
for a in alerts:
    a['dom_id'] = hashlib.sha256((a['id']).encode('utf-8')).hexdigest()[:16]

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

function loadLocal(){ try { return JSON.parse(localStorage.getItem(STORE_KEY) || '{}'); } catch(e){ return {}; } }
function saveLocal(obj){ localStorage.setItem(STORE_KEY, JSON.stringify(obj)); }

async function apiGet(){
  try {
    const r = await fetch(`/api/feedback?day=${encodeURIComponent(DAY)}`, { cache: 'no-store' });
    if (!r.ok) return null;
    const j = await r.json();
    return j.feedback || {};
  } catch(e){
    return null;
  }
}

async function apiPutOne(alertId, rec){
  try {
    const r = await fetch('/api/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ day: DAY, alert_id: alertId, ...rec })
    });
    return r.ok;
  } catch(e){
    return false;
  }
}

function setStatus(domId, msg){
  const el = document.querySelector(`#status-${domId}`);
  if (el) el.textContent = msg;
}

function logicalIdFromDom(domId){
  const card = document.querySelector(`#card-${domId}`);
  return card ? (card.dataset.alertId || '') : '';
}

async function onSave(domId){
  const alertId = logicalIdFromDom(domId) || domId;

  const note = document.querySelector(`#note-${domId}`).value;
  const verdict = document.querySelector(`#verdict-${domId}`).value;
  const action = document.querySelector(`#action-${domId}`).value;
  const actionValue = document.querySelector(`#actionval-${domId}`).value;

  const dismissed = document.querySelector(`#dismiss-${domId}`).checked;
  const rec = { updated_at: new Date().toISOString(), verdict, note, dismissed };

  // Always save locally as a fallback (keyed by logical alert id).
  const store = loadLocal();
  store[alertId] = rec;
  saveLocal(store);

  // Best-effort server save.
  setStatus(domId, 'saving…');
  const ok = await apiPutOne(alertId, rec);
  setStatus(domId, ok ? 'saved' : 'saved locally (server unavailable)');

  // Hide on dismiss.
  if (dismissed) {
    const card = document.querySelector(`#card-${domId}`);
    if (card) card.style.display = 'none';
  }
}

async function hydrate(){
  const server = await apiGet();
  const local = loadLocal();

  // Prefer server state when available; else local.
  const store = (server !== null) ? server : local;

  for (const [alertId, v] of Object.entries(store)){
    // Find the card that matches this logical id.
    const card = document.querySelector(`[data-alert-id="${CSS.escape(alertId)}"]`);
    if (!card) continue;
    const domId = (card.id || '').replace(/^card-/, '');
    if (!domId) continue;

    const noteEl = document.querySelector(`#note-${domId}`);
    if (!noteEl) continue;
    document.querySelector(`#note-${domId}`).value = v.note || '';
    document.querySelector(`#verdict-${domId}`).value = v.verdict || 'unsure';
    document.querySelector(`#dismiss-${domId}`).checked = !!v.dismissed;
    document.querySelector(`#note-${domId}`).value = v.note || '';
    document.querySelector(`#verdict-${domId}`).value = v.verdict || 'unsure';

    if (v.dismissed) {
      card.style.display = 'none';
    }

    setStatus(domId, (server !== null) ? 'loaded' : 'loaded from local');
  }
}

window.addEventListener('DOMContentLoaded', hydrate);
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
body.append('<div class="muted">Add comments and optionally dismiss alerts once you\'ve reviewed them. (Feedback is saved server-side.)</div>')

if not alerts:
    body.append('<div class="muted">No candidates found yet. This will populate after the 8pm daily run writes <code>output/state/YYYY-MM-DD.candidates.json</code>.</div>')
else:
    for a in alerts:
        alert_id = a['id']
        dom_id = a.get('dom_id') or hashlib.sha256(alert_id.encode('utf-8')).hexdigest()[:16]

        aid = html.escape(alert_id)
        did = html.escape(dom_id)

        body.append('<hr>')
        body.append(f'<div id="card-{did}" data-alert-id="{aid}">')
        # Render kind + small badges
        badges = []
        try:
            ev = a.get('data') or {}
            evidence = ev.get('evidence') or {}
            notes = evidence.get('notes') or []
            if any(isinstance(x, str) and x.startswith('novelty=') for x in notes):
                badges.append('new-for-device')
            if any(isinstance(x, str) and x.startswith('ja4_') for x in notes) or any(isinstance(x, str) and x.startswith('ja4') for x in notes):
                badges.append('ja4')
            if evidence.get('domain'):
                badges.append('dns')
        except Exception:
            badges = badges

        base_kind = a.get('data', {}).get('kind') if isinstance(a.get('data'), dict) else None
        kind_label = base_kind or a["kind"]

        pills = [f'<div class="pill">{html.escape(str(kind_label))}</div>']
        for b in badges[:4]:
            pills.append(f'<div class="pill">{html.escape(b)}</div>')

        body.append(f'<div class="row">{"".join(pills)}<div class="small muted">id: <code>{aid}</code></div></div>')
        body.append(f'<h3 style="margin:10px 0">{html.escape(a["title"])}</h3>')
        body.append('<details><summary>evidence (raw)</summary>')
        body.append('<pre>' + html.escape(json.dumps(a['data'], indent=2, sort_keys=True)) + '</pre>')
        body.append('</details>')

        body.append('<div class="row" style="align-items:center;margin-top:10px">')
        body.append(f'<label>Verdict: <select id="verdict-{did}"><option value="unsure">unsure</option><option value="benign">likely benign</option><option value="review">needs review</option><option value="suspicious">suspicious</option></select></label>')
        body.append(f'<span class="muted small" id="status-{did}"></span>')
        body.append('</div>')

        body.append(f'<div style="margin-top:10px"><label>Comment / context:<br><textarea id="note-{did}" placeholder="e.g. Doorbell doing NTP lookups (pool.ntp.org)."></textarea></label></div>')

        body.append('<div class="row" style="align-items:center;margin-top:10px">')
        body.append(f'<label><input type="checkbox" id="dismiss-{did}"/> Dismiss (hide this alert)</label>')
        body.append(f'<button onclick="onSave(\'{did}\')">Save</button>')
        body.append('</div>')
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

# Compatibility: old links pointed at /daily/YYYY-MM-DD.html. Keep those working.
mkdir -p "$WWW_DIR/daily"
cat >"$WWW_DIR/daily/index.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0; url=/">
<link rel="canonical" href="/">
<title>HomeNetSec</title>
<p>Redirecting to <a href="/">/</a>…</p>
HTML
cat >"$WWW_DIR/daily/${TODAY_ET}.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0; url=/">
<link rel="canonical" href="/">
<title>HomeNetSec</title>
<p>Redirecting to <a href="/">/</a>…</p>
HTML

echo "[$(TS)] [homenetsec] dashboard updated under: $WWW_DIR"