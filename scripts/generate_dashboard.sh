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

# Source AdGuard credentials for unknown device detection
if [[ -f "$HOME/.openclaw/credentials/adguard.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$HOME/.openclaw/credentials/adguard.env"
  set +a
fi

TS() { date -Is; }
ET_DATE() { TZ=America/New_York date +%F; }

TODAY_ET="${1:-$(ET_DATE)}"

WWW_DIR="$WORKDIR/www"
STATE_JSON="$WORKDIR/state/hourly_ingest_state.json"
REPORT_TXT="$WORKDIR/reports/${TODAY_ET}.txt"
REPORTS_DIR="$WORKDIR/reports"
DIGEST_JSON="$WORKDIR/state/${TODAY_ET}.digest.json"
CANDIDATES_JSON="$WORKDIR/state/${TODAY_ET}.candidates.json"

mkdir -p "$WWW_DIR"

# Build a minimal machine-readable status blob.
python3 - "$STATE_JSON" "$TODAY_ET" "$REPORT_TXT" "$WORKDIR/state/alerts_queue.json" "$WWW_DIR/status.json" <<'PY'
import json, os, sys, time

state_path, today_et, report_txt, queue_path, out_path = sys.argv[1:6]

def load_json(p):
    try:
        with open(p, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return None

state = load_json(state_path) or {}

report_exists = os.path.exists(report_txt)
report_mtime = int(os.path.getmtime(report_txt)) if report_exists else None

# Count currently-active alerts (best-effort) so the status card can show queue size.
queue_count = None
try:
    q = load_json(queue_path) or {}
    items = q.get("items") if isinstance(q, dict) else None
    if isinstance(items, dict):
        queue_count = len(items)
except Exception:
    queue_count = None

payload = {
    "generated_at": time.strftime('%Y-%m-%dT%H:%M:%S%z'),
    "today_et": today_et,
    "hourly_state": state,
    "active_alerts": {"count": queue_count},
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
python3 - "$WWW_DIR/status.json" "$REPORTS_DIR" "$DIGEST_JSON" "$CANDIDATES_JSON" "$WORKDIR/state/feedback.json" "$WORKDIR/state/alerts_queue.json" "$WWW_DIR/index.html" <<'PY'
import html, json, os, sys, hashlib, time, re
from urllib.request import Request, urlopen

status_path, reports_dir, digest_path, candidates_path, feedback_path, queue_path, out_path = sys.argv[1:8]

st = json.load(open(status_path, 'r', encoding='utf-8'))
hourly = st.get('hourly_state') or {}
day = st.get('today_et') or ''

# Load persisted feedback.
# We use it for:
# - filtering dismissed alerts out of the rendered HTML
# - drafting comment text using prior notes/verdicts
feedback_for_day = {}
feedback_days = {}
try:
    fb = json.load(open(feedback_path, 'r', encoding='utf-8'))
    if isinstance(fb, dict):
        feedback_days = fb.get('days') if isinstance(fb.get('days'), dict) else {}
        feedback_for_day = (feedback_days.get(day) or {}) if isinstance(feedback_days, dict) else {}
except FileNotFoundError:
    feedback_for_day = {}
    feedback_days = {}
except Exception:
    feedback_for_day = {}
    feedback_days = {}

def is_dismissed(alert_id: str) -> bool:
    try:
        rec = feedback_for_day.get(alert_id) or {}
        return bool(rec.get('dismissed'))
    except Exception:
        return False

def latest_feedback(alert_id: str):
    """Return (day, rec) for latest record for this alert across all days."""
    best_day, best_rec, best_ts = None, None, None
    for d, mp in (feedback_days or {}).items():
        if not isinstance(mp, dict):
            continue
        rec = mp.get(alert_id)
        if not isinstance(rec, dict):
            continue
        ts = rec.get('updated_at') or ''
        # timestamps are comparable enough lexicographically in this project (ISO-like)
        if best_ts is None or str(ts) > str(best_ts):
            best_ts = ts
            best_day = d
            best_rec = rec
    return best_day, best_rec

# hourly state key drift compatibility
last_epoch = hourly.get('last_epoch')
if last_epoch is None:
    last_epoch = hourly.get('last_ingested_epoch')

def adguard_client_map() -> dict:
    """Best-effort {client_id/ip: friendly name} from AdGuard Home."""
    url = (os.environ.get('ADGUARD_URL') or '').rstrip('/')
    user = os.environ.get('ADGUARD_USER') or ''
    pw = os.environ.get('ADGUARD_PASS') or ''
    if not (url and user and pw):
        return {}

    try:
        login_url = f"{url}/control/login"
        body = json.dumps({"name": user, "password": pw}).encode('utf-8')
        resp = urlopen(Request(login_url, data=body, method='POST', headers={'Content-Type': 'application/json'}), timeout=20)
        cookies = resp.headers.get_all('Set-Cookie') or []
        resp.read()
        cookie = '; '.join([c.split(';', 1)[0] for c in cookies if c])
        raw = urlopen(Request(f"{url}/control/clients", headers={'Cookie': cookie}), timeout=20).read()
        payload = json.loads(raw.decode('utf-8', errors='replace'))

        out = {}
        for it in (payload.get('clients') or []):
            if not isinstance(it, dict):
                continue
            name = (it.get('name') or '').strip()
            if not name:
                continue
            for cid in (it.get('ids') or []):
                if cid:
                    out[str(cid)] = name
        return out
    except Exception:
        return {}


def replace_ips_with_names(text: str, cmap: dict) -> str:
    if not text or not cmap:
        return text

    ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def repl(m):
        ip = m.group(0)
        nm = cmap.get(ip)
        if not nm:
            return ip
        # Avoid double-wrapping if already formatted.
        # If the immediate following characters already include "(" and the IP, leave as-is.
        return f"{nm} ({ip})"

    return ip_re.sub(repl, text)


# Rolling 24h roll-up: concatenate report files modified in the last 24 hours.
report_txt = ''
try:
    cmap = adguard_client_map()

    now = time.time()
    paths = []
    if os.path.isdir(reports_dir):
        for fn in os.listdir(reports_dir):
            if not fn.endswith('.txt'):
                continue
            p = os.path.join(reports_dir, fn)
            try:
                st2 = os.stat(p)
            except Exception:
                continue
            if (now - st2.st_mtime) <= 24*3600:
                paths.append((st2.st_mtime, p))

    # newest first
    paths.sort(key=lambda x: x[0], reverse=True)

    chunks = []
    for mtime, p in paths:
        label = os.path.basename(p)
        ts = time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(mtime))
        txt = open(p, 'r', encoding='utf-8', errors='replace').read().strip()
        if not txt:
            continue
        txt2 = replace_ips_with_names(txt, cmap)
        chunks.append(f"===== {label} (mtime {ts}) =====\n{txt2}\n")

    report_txt = "\n".join(chunks).strip()
except Exception:
    report_txt = ''

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

# Build today's alerts from digest/candidates.
# These are used to update a persistent "active alerts" queue.
alerts_today = []
if digest and isinstance(digest.get('items'), list):
    for it in digest.get('items'):
        if not isinstance(it, dict):
            continue
        alert_id = it.get('id') or None
        if not alert_id:
            continue
        alerts_today.append({
            'title': it.get('title') or '(untitled)',
            'data': it,
            'id': str(alert_id),
        })
else:
    # Fallback mode (legacy candidates) is kept for resilience; ids will be day-scoped.
    if candidates:
        for item in candidates.get('new_external_destinations', []) or []:
            h = hashlib.sha256(('new_external_destination|' + json.dumps(item, sort_keys=True)).encode('utf-8')).hexdigest()[:16]
            alerts_today.append({'title': f"New external destination: {item.get('dst_ip','?')}", 'data': item, 'id': f"{day}-new_external_destination-{h}"})
        for d in candidates.get('new_domains', []) or []:
            h = hashlib.sha256(('new_domain|' + str(d)).encode('utf-8')).hexdigest()[:16]
            alerts_today.append({'title': f"New domain: {d}", 'data': {'domain': d}, 'id': f"{day}-new_domain-{h}"})
        for item in candidates.get('new_watch_tuples', []) or []:
            h = hashlib.sha256(('new_watch_tuple|' + json.dumps(item, sort_keys=True)).encode('utf-8')).hexdigest()[:16]
            alerts_today.append({'title': f"New watch tuple: {item.get('src_ip','?')} → {item.get('dst_ip','?')}:{item.get('dst_port','?')}", 'data': item, 'id': f"{day}-new_watch_tuple-{h}"})
        for b in candidates.get('rita_beacons', []) or []:
            h = hashlib.sha256(('rita_beacon|' + json.dumps(b, sort_keys=True)).encode('utf-8')).hexdigest()[:16]
            alerts_today.append({'title': f"RITA beacon candidate: {b.get('src_ip','?')} → {b.get('dst_ip','?')}", 'data': b, 'id': f"{day}-rita_beacon-{h}"})

# Persistent queue: alerts remain until explicitly dismissed (regardless of date).
queue = {"items": {}}
try:
    if os.path.exists(queue_path):
        queue = json.load(open(queue_path, 'r', encoding='utf-8'))
        if not isinstance(queue, dict):
            queue = {"items": {}}
except Exception:
    queue = {"items": {}}

queue.setdefault('items', {})
if not isinstance(queue['items'], dict):
    queue['items'] = {}

# Build a fast lookup of dismissed ids (any day): if latest feedback has dismissed=true, remove from queue.
# We treat the verdict drop-down as the user's final verdict; dismiss is the only thing that removes from dashboard.
dismissed_any = set()
try:
    for d, mp in (feedback_days or {}).items():
        if not isinstance(mp, dict):
            continue
        for aid, rec in mp.items():
            if isinstance(rec, dict) and bool(rec.get('dismissed')):
                dismissed_any.add(str(aid))
except Exception:
    dismissed_any = set()

# Update queue with today's alerts.
for a in alerts_today:
    aid = a['id']
    if aid in dismissed_any:
        continue
    cur = queue['items'].get(aid) or {}
    if not isinstance(cur, dict):
        cur = {}
    cur.setdefault('first_seen_day', day)
    cur['last_seen_day'] = day
    cur['title'] = a.get('title')
    cur['data'] = a.get('data')
    queue['items'][aid] = cur

# Prune dismissed.
for aid in list(queue['items'].keys()):
    if str(aid) in dismissed_any:
        queue['items'].pop(aid, None)

# De-dup: Suricata P1–P2 summary vs per-signature items.
# If we have any per-signature Suricata items for the day, hide the summary card
# so it doesn't appear as a separate alert.
try:
    has_sig = any(str(aid).startswith('suricata_sig|') and str(aid).endswith('|' + str(day)) for aid in queue['items'].keys())
    if has_sig:
        queue['items'].pop(f"suricata_alerts_p12|{day}", None)
except Exception:
    pass

# Write updated queue.
os.makedirs(os.path.dirname(queue_path), exist_ok=True)
with open(queue_path, 'w', encoding='utf-8') as f:
    json.dump(queue, f, indent=2, sort_keys=True)
    f.write('\n')

# Alerts to render = all active items in queue.
alerts = []
for aid, rec in queue['items'].items():
    if not isinstance(rec, dict):
        continue
    data = rec.get('data') if isinstance(rec.get('data'), dict) else {}
    alerts.append({
        'kind': 'queued_alert',
        'title': rec.get('title') or '(untitled)',
        'data': data,
        'id': str(aid),
        'first_seen_day': rec.get('first_seen_day') or '',
        'last_seen_day': rec.get('last_seen_day') or '',
    })

# Stable ordering: most recently seen first.
alerts.sort(key=lambda a: (a.get('last_seen_day') or '', a.get('first_seen_day') or '', a.get('id') or ''), reverse=True)

# DOM-safe ids.
for a in alerts:
    a['dom_id'] = hashlib.sha256((a['id']).encode('utf-8')).hexdigest()[:16]

style = """
:root {
  --bg: #f8fafc;
  --card-bg: #ffffff;
  --border: #e2e8f0;
  --text: #1e293b;
  --text-muted: #64748b;
  --accent: #3b82f6;
  --success: #10b981;
  --success-bg: #ecfdf5;
  --warning: #f59e0b;
  --warning-bg: #fffbeb;
  --danger: #ef4444;
  --danger-bg: #fef2f2;
  --code-bg: #f1f5f9;
  --pre-bg: #0f172a;
  --pre-text: #e2e8f0;
  --shadow: 0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.06);
}
*, *::before, *::after { box-sizing: border-box; }
body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  background: var(--bg);
  color: var(--text);
  margin: 0;
  padding: 0;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}
.container { max-width: 960px; margin: 0 auto; padding: 24px 20px 48px; }
header {
  background: linear-gradient(135deg, #1e3a5f 0%, #2d4a6f 100%);
  color: #fff;
  padding: 32px 20px;
  margin-bottom: 24px;
}
header .inner { max-width: 960px; margin: 0 auto; }
header h1 { margin: 0 0 4px; font-size: 28px; font-weight: 700; letter-spacing: -0.5px; }
header .subtitle { color: #94a3b8; font-size: 14px; margin: 0; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.card {
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px 24px;
  margin-bottom: 20px;
  box-shadow: var(--shadow);
}
.card h2 {
  margin: 0 0 16px;
  font-size: 18px;
  font-weight: 600;
  color: var(--text);
  display: flex;
  align-items: center;
  gap: 10px;
}
.card h2 .icon { font-size: 20px; }
.metrics { display: flex; flex-wrap: wrap; gap: 10px; margin: 12px 0; }
.metric {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: var(--code-bg);
  border-radius: 6px;
  padding: 6px 12px;
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
}
.metric.success { background: var(--success-bg); color: #047857; }
.metric.warning { background: var(--warning-bg); color: #b45309; }
.metric.danger { background: var(--danger-bg); color: #b91c1c; }
.metric .label { color: var(--text-muted); font-weight: 400; }
.muted { color: var(--text-muted); font-size: 14px; }
.small { font-size: 13px; }
code {
  background: var(--code-bg);
  padding: 2px 6px;
  border-radius: 4px;
  font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 13px;
}
pre {
  background: var(--pre-bg);
  color: var(--pre-text);
  padding: 16px;
  border-radius: 8px;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 12px;
  line-height: 1.5;
  margin: 12px 0;
}
details {
  margin: 12px 0;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg);
}
details summary {
  padding: 10px 14px;
  cursor: pointer;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-muted);
  list-style: none;
}
details summary::-webkit-details-marker { display: none; }
details summary::before { content: '▸ '; color: var(--text-muted); }
details[open] summary::before { content: '▾ '; }
details > pre { margin: 0; border-radius: 0 0 8px 8px; }
hr { border: none; border-top: 1px solid var(--border); margin: 20px 0; }
.row { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
.pill {
  display: inline-block;
  background: var(--code-bg);
  border-radius: 6px;
  padding: 4px 10px;
  font-size: 12px;
  font-weight: 500;
  color: var(--text);
}
.pill.danger { background: var(--danger-bg); color: #b91c1c; }
.pill.warning { background: var(--warning-bg); color: #b45309; }
.pill.success { background: var(--success-bg); color: #047857; }
.alert-item {
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-left: 4px solid var(--warning);
  border-radius: 8px;
  padding: 16px 20px;
  margin: 16px 0;
}
.alert-item h3 {
  margin: 0 0 12px;
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
}
.alert-item.dismissed { opacity: 0.5; }
textarea {
  width: 100%;
  min-height: 80px;
  font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 13px;
  padding: 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg);
  color: var(--text);
  resize: vertical;
}
textarea:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
select, button, input[type="checkbox"] { font-size: 14px; }
select {
  padding: 8px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--card-bg);
  color: var(--text);
}
button {
  padding: 8px 16px;
  background: var(--accent);
  color: #fff;
  border: none;
  border-radius: 6px;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.15s;
}
button:hover { background: #2563eb; }
input[type="checkbox"] {
  width: 16px;
  height: 16px;
  margin-right: 6px;
  accent-color: var(--accent);
}
label { display: inline-flex; align-items: center; font-size: 14px; }
.empty-state {
  text-align: center;
  padding: 32px;
  color: var(--text-muted);
}
.empty-state .icon { font-size: 40px; margin-bottom: 12px; opacity: 0.5; }
footer {
  text-align: center;
  padding: 24px;
  color: var(--text-muted);
  font-size: 12px;
}
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

  // Merge: always include local fallback entries, but let server override when it has a record.
  // This prevents "saved locally" dismissals from reappearing when the API later becomes available.
  const store = (server !== null) ? ({...local, ...server}) : local;

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
body.append('<html lang="en"><head><meta charset="utf-8">')
body.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
body.append('<title>HomeNetSec Dashboard</title>')
body.append('<link rel="preconnect" href="https://fonts.googleapis.com">')
body.append('<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>')
body.append('<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">')
body.append(f'<style>{style}</style>')
body.append('</head>')
body.append(f'<body data-day="{html.escape(day)}">')
body.append('<header><div class="inner">')
body.append('<h1>🔒 HomeNetSec</h1>')
body.append(f"<p class='subtitle'>Network Security Monitor · Generated {html.escape(st.get('generated_at',''))}</p>")
body.append('</div></header>')
body.append('<div class="container">')

body.append('<div class="card">')
body.append('<h2><span class="icon">📊</span> Pipeline Status</h2>')

pending_count = len(hourly.get('pending') or []) if isinstance(hourly.get('pending'), list) else 0
hwm = hourly.get('high_watermark_epoch') or ''

body.append('<div class="metrics">')
if last_epoch:
    body.append(f"<div class='metric'><span class='label'>Last Epoch</span> {html.escape(str(last_epoch))}</div>")
if hwm:
    body.append(f"<div class='metric'><span class='label'>High Watermark</span> {html.escape(str(hwm))}</div>")
pending_class = 'warning' if pending_count > 0 else 'success'
body.append(f"<div class='metric {pending_class}'><span class='label'>Pending</span> {pending_count}</div>")
body.append('</div>')

if not last_epoch and not hwm:
    body.append('<div class="muted">No hourly state found yet. The pipeline will populate this after the first ingest run.</div>')

body.append('<details><summary>View raw pipeline state</summary>')
body.append('<pre>' + html.escape(json.dumps(hourly, indent=2, sort_keys=True)) + '</pre>')
body.append('</details>')
body.append('</div>')

body.append('<div class="card">')
alert_class = 'danger' if len(alerts) > 0 else 'success'
body.append(f'<h2><span class="icon">🚨</span> Active Alerts <span class="metric {alert_class}" style="margin-left:auto">{len(alerts)}</span></h2>')

if not alerts:
    body.append('<div class="empty-state"><div class="icon">✅</div><p>No active alerts. New alerts appear when the pipeline generates a digest and remain until dismissed.</p></div>')
else:
    for a in alerts:
        alert_id = a['id']
        dom_id = a.get('dom_id') or hashlib.sha256(alert_id.encode('utf-8')).hexdigest()[:16]

        aid = html.escape(alert_id)
        did = html.escape(dom_id)

        body.append(f'<div class="alert-item" id="card-{did}" data-alert-id="{aid}">')
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

        body.append(f'<h3>{html.escape(a["title"])}</h3>')

        pills = [f'<span class="pill">{html.escape(str(kind_label))}</span>']
        for b in badges[:4]:
            pills.append(f'<span class="pill">{html.escape(b)}</span>')

        meta_bits = []
        if a.get('first_seen_day'):
            meta_bits.append(f"first: {html.escape(str(a.get('first_seen_day')))}")
        if a.get('last_seen_day'):
            meta_bits.append(f"last: {html.escape(str(a.get('last_seen_day')))}")
        body.append(f'<div class="row" style="margin-bottom:12px">{"".join(pills)}<span class="small muted">{" · ".join(meta_bits)}</span></div>')

        # Plain-language evidence summary (above the raw evidence dropdown)
        ev = a.get('data') if isinstance(a.get('data'), dict) else {}
        evidence = (ev.get('evidence') or {}) if isinstance(ev, dict) else {}
        src_ip = evidence.get('src_ip') or ''
        src_name = evidence.get('src_name') or ''
        dst_ip = evidence.get('dst_ip') or ''
        dst_port = evidence.get('dst_port') or 0
        domain = evidence.get('domain') or ''
        rdns = evidence.get('rdns') or ''
        notes = evidence.get('notes') or []
        novelty = next((n for n in notes if isinstance(n, str) and n.startswith('novelty=')), '')
        ja4 = next((n for n in notes if isinstance(n, str) and n.startswith('ja4_') or (isinstance(n,str) and n.startswith('ja4'))), '')

        ev_lines = []
        if src_ip or dst_ip:
            left = f"{src_name} ({src_ip})" if src_name and src_ip else (src_ip or src_name)
            right = dst_ip
            if domain:
                right += f" via DNS {domain}"
            elif rdns:
                right += f" (rDNS {rdns})"
            ev_lines.append(f"Traffic observed: {left} → {right}.".strip())
        if novelty:
            ev_lines.append(f"Novelty: {novelty.replace('novelty=','')}." )
        if ja4:
            ev_lines.append(f"TLS fingerprint: {ja4}." )

        # Suricata summary cards store evidence as notes without src/dst.
        if not ev_lines and isinstance(ev.get('evidence'), dict):
            pass
        if not ev_lines and isinstance(ev.get('evidence'), dict) and isinstance(ev.get('evidence',{}).get('notes'), list):
            # fallback for summary cards
            ev_lines.append("Evidence: derived from Suricata/Zeek artifacts; see raw evidence for details.")

        if ev_lines:
            body.append('<div class="muted" style="margin:8px 0;padding:10px;background:var(--bg);border-radius:6px">' + html.escape(' '.join(ev_lines)) + '</div>')

        body.append('<details><summary>View raw evidence</summary>')
        body.append('<pre>' + html.escape(json.dumps(a['data'], indent=2, sort_keys=True)) + '</pre>')
        body.append('</details>')

        # Verdict drop-down is treated as the user's final verdict.
        # Prefer latest saved feedback verdict (any day), else fall back to digest suggestion.
        vv = 'unsure'
        try:
            _prev_day, _prev = latest_feedback(alert_id)
            prev_verdict = (_prev or {}).get('verdict') if isinstance(_prev, dict) else ''
            if str(prev_verdict).lower() in ('benign', 'likely benign', 'likely_benign'):
                vv = 'benign'
            elif str(prev_verdict).lower() in ('review', 'needs review', 'needs_review'):
                vv = 'review'
            elif str(prev_verdict).lower() in ('suspicious', 'malicious'):
                vv = 'suspicious'
        except Exception:
            vv = 'unsure'

        if vv == 'unsure':
            digest_verdict = ''
            try:
                digest_verdict = (a.get('data') or {}).get('verdict') if isinstance(a.get('data'), dict) else ''
            except Exception:
                digest_verdict = ''
            if str(digest_verdict).lower() in ('likely_benign', 'benign'):
                vv = 'benign'
            elif str(digest_verdict).lower() in ('needs_review', 'review'):
                vv = 'review'
            elif str(digest_verdict).lower() in ('suspicious', 'malicious'):
                vv = 'suspicious'

        def opt(val, label):
            sel = ' selected' if vv == val else ''
            return f'<option value="{val}"{sel}>{html.escape(label)}</option>'

        body.append('<div class="row" style="margin-top:12px">')
        body.append(
            f'<label>Verdict: <select id="verdict-{did}">'
            + opt('unsure','unsure')
            + opt('benign','likely benign')
            + opt('review','needs review')
            + opt('suspicious','suspicious')
            + '</select></label>'
        )
        body.append(f'<span class="muted small" id="status-{did}"></span>')
        body.append('</div>')

        # Draft comment text (only used if user hasn't saved a note yet today).
        # Requirements:
        # - no "test" filler
        # - drafted text should explain the observation
        # - permissible to write "Unable to draft comments."
        draft_note = ""

        def _is_useless_note(s: str) -> bool:
            s2 = (s or '').strip().lower()
            return (not s2) or s2 in ('test', 'testing', 'tbd', 'todo', 'n/a') or len(s2) < 6

        try:
            todays = feedback_for_day.get(alert_id) if isinstance(feedback_for_day, dict) else None
            if not (isinstance(todays, dict) and (todays.get('note') or '').strip()):
                # 1) Primary explanation based on evidence
                expl = []
                kind_label = (a.get('data') or {}).get('kind') if isinstance(a.get('data'), dict) else a.get('kind')
                left = f"{src_name} ({src_ip})" if src_name and src_ip else (src_ip or src_name)
                right = dst_ip or ''
                if dst_port:
                    right += f":{dst_port}"
                if domain:
                    right += f" (DNS: {domain})"
                elif rdns:
                    right += f" (rDNS: {rdns})"

                if left or right:
                    expl.append(f"Observation: {left} → {right}.".strip())

                if kind_label == 'rita_beacon':
                    # pull a couple useful notes
                    bpc = next((n for n in (notes or []) if isinstance(n, str) and 'bytes_per_conn' in n), '')
                    interval = ''
                    try:
                        interval = str((a.get('data') or {}).get('why_flagged') or '')
                    except Exception:
                        interval = ''
                    extra = []
                    if novelty:
                        extra.append("new for this device")
                    if bpc:
                        extra.append(bpc)
                    if interval:
                        extra.append(interval)
                    if extra:
                        expl.append("Why flagged: " + "; ".join(extra) + ".")

                # quick benign-ish heuristics
                if domain and domain.endswith('.pool.ntp.org'):
                    expl.append("Most likely NTP pool traffic (routine time sync).")
                if dst_ip and str(dst_ip).startswith('162.159.'):
                    expl.append("Destination is in Cloudflare space; could still be normal (NTP/CDN), but confirm expected.")

                # 2) Incorporate useful context from dismissed similar alerts (any day)
                try:
                    sim_notes = []
                    kind_prefix = ''
                    if isinstance(a.get('data'), dict) and (a.get('data') or {}).get('kind'):
                        kind_prefix = str((a.get('data') or {}).get('kind'))
                    if not kind_prefix:
                        kind_prefix = str(alert_id).split('|', 1)[0]

                    for _d, mp in (feedback_days or {}).items():
                        if not isinstance(mp, dict):
                            continue
                        for _aid, _rec in mp.items():
                            if len(sim_notes) >= 2:
                                break
                            if not isinstance(_rec, dict) or not bool(_rec.get('dismissed')):
                                continue
                            note = str(_rec.get('note') or '').strip()
                            if _is_useless_note(note):
                                continue

                            _aid_s = str(_aid)
                            if not _aid_s.startswith(kind_prefix + '|') and _aid_s.split('|', 1)[0] != kind_prefix:
                                continue

                            same_src = src_ip and (f"|{src_ip}|" in _aid_s)
                            same_dst = dst_ip and (_aid_s.endswith(f"|{dst_ip}") or f"|{dst_ip}" in _aid_s)
                            ntpish = (domain and domain.endswith('.pool.ntp.org')) and ('ntp' in note.lower())
                            if same_src or same_dst or ntpish:
                                sim_notes.append(note)
                        if len(sim_notes) >= 2:
                            break

                    if sim_notes:
                        expl.append("Related prior dismissals (context): " + " | ".join(sim_notes))
                except Exception:
                    pass

                draft_note = "\n".join([x for x in expl if x and not _is_useless_note(x)])

                if not draft_note.strip():
                    draft_note = "Unable to draft comments."
        except Exception:
            draft_note = "Unable to draft comments."

        body.append(f'<div style="margin-top:12px"><label style="display:block;margin-bottom:6px;font-weight:500">Comment / context:</label><textarea id="note-{did}" placeholder="Add notes about this alert...">{html.escape(draft_note)}</textarea></div>')

        body.append('<div class="row" style="margin-top:14px">')
        body.append(f'<label><input type="checkbox" id="dismiss-{did}"/> Dismiss</label>')
        body.append(f'<button onclick="onSave(\'{did}\')">💾 Save</button>')
        body.append('</div>')
        body.append('</div>')

body.append('</div>')

# ============================================================================
# Unknown Network Devices Panel
# Finds devices in Zeek conn.log that aren't in AdGuard known clients
# ============================================================================
body.append('<div class="card">')

def fetch_adguard_known_ips():
    """Fetch known device IPs from AdGuard Home."""
    url = os.environ.get('ADGUARD_URL', '').rstrip('/')
    user = os.environ.get('ADGUARD_USER', '')
    pw = os.environ.get('ADGUARD_PASS', '')
    if not (url and user and pw):
        return {}, {}
    
    try:
        import base64
        auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
        
        # Login
        login_body = json.dumps({"name": user, "password": pw}).encode('utf-8')
        login_req = Request(f"{url}/control/login", data=login_body, method='POST')
        login_req.add_header('Content-Type', 'application/json')
        login_resp = urlopen(login_req, timeout=15)
        cookies = login_resp.headers.get_all('Set-Cookie') or []
        login_resp.read()
        cookie = '; '.join([c.split(';', 1)[0] for c in cookies if c])
        
        # Get clients
        clients_req = Request(f"{url}/control/clients")
        clients_req.add_header('Cookie', cookie)
        raw = urlopen(clients_req, timeout=15).read()
        data = json.loads(raw.decode('utf-8', errors='replace'))
        
        ip_to_name = {}  # IP -> name
        mac_to_name = {}  # MAC -> name
        
        # Configured clients
        for c in (data.get('clients') or []):
            if not isinstance(c, dict):
                continue
            name = c.get('name', '')
            for cid in (c.get('ids') or []):
                cid_s = str(cid).strip().lower()
                if ':' in cid_s and len(cid_s) == 17:  # MAC
                    mac_to_name[cid_s] = name
                elif re.match(r'^\d+\.\d+\.\d+\.\d+$', cid_s):  # IPv4
                    ip_to_name[cid_s] = name
        
        # Auto-discovered clients (runtime)
        for c in (data.get('auto_clients') or []):
            if not isinstance(c, dict):
                continue
            ip = c.get('ip', '')
            name = c.get('name') or ip
            if ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                if ip not in ip_to_name:
                    ip_to_name[ip] = name
        
        return ip_to_name, mac_to_name
    except Exception as e:
        print(f"[homenetsec] WARN: could not fetch AdGuard clients: {e}")
        return {}, {}

def get_zeek_conn_ips(workdir, day):
    """Extract unique internal source IPs from Zeek conn.log."""
    conn_log = os.path.join(workdir, 'zeek-flat', day, 'conn.log')
    internal_ips = set()
    ip_bytes = {}  # IP -> total bytes
    
    if not os.path.exists(conn_log):
        return internal_ips, ip_bytes
    
    try:
        with open(conn_log, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                parts = line.strip().split('\t')
                if len(parts) < 10:
                    continue
                src_ip = parts[2]  # id.orig_h
                # Only internal IPs
                if src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.'):
                    internal_ips.add(src_ip)
                    # Track bytes
                    try:
                        orig_bytes = int(parts[9]) if parts[9] not in ('-', '(empty)') else 0
                        resp_bytes = int(parts[10]) if parts[10] not in ('-', '(empty)') else 0
                        ip_bytes[src_ip] = ip_bytes.get(src_ip, 0) + orig_bytes + resp_bytes
                    except (ValueError, IndexError):
                        pass
    except Exception as e:
        print(f"[homenetsec] WARN: could not parse conn.log: {e}")
    
    return internal_ips, ip_bytes

# Get data
workdir_base = os.environ.get('HOMENETSEC_WORKDIR', '')
if not workdir_base:
    workdir_base = os.path.dirname(os.path.dirname(status_path))

adguard_ips, adguard_macs = fetch_adguard_known_ips()
zeek_ips, ip_bytes = get_zeek_conn_ips(workdir_base, day)

# Find unknown IPs (in Zeek but not in AdGuard)
# Exclude gateway/router IPs (typically .1)
known_infra = {'192.168.1.1', '192.168.30.1', '192.168.40.1', '10.0.0.1'}
unknown_ips = []
for ip in zeek_ips:
    if ip in known_infra:
        continue
    if ip not in adguard_ips:
        unknown_ips.append({
            'ip': ip,
            'bytes': ip_bytes.get(ip, 0)
        })

# Sort by bytes (most traffic first)
unknown_ips.sort(key=lambda x: x['bytes'], reverse=True)

unknown_class = 'danger' if unknown_ips else 'success'
body.append(f'<h2><span class="icon">👤</span> Unknown Network Devices <span class="metric {unknown_class}" style="margin-left:auto">{len(unknown_ips)}</span></h2>')

body.append('<div class="metrics">')
body.append(f"<div class='metric'><span class='label'>Devices in Zeek</span> {len(zeek_ips)}</div>")
body.append(f"<div class='metric'><span class='label'>Known in AdGuard</span> {len(adguard_ips)}</div>")
body.append(f"<div class='metric {unknown_class}'><span class='label'>Unknown</span> {len(unknown_ips)}</div>")
body.append('</div>')
body.append("<p class='muted small'>Unknown = seen in PCAP traffic but not in AdGuard clients list</p>")

if not adguard_ips:
    body.append('<div class="empty-state"><div class="icon">⚠️</div><p>Could not fetch AdGuard clients.<br>Set ADGUARD_URL, ADGUARD_USER, ADGUARD_PASS in environment.</p></div>')
elif not unknown_ips:
    body.append('<div class="empty-state"><div class="icon">✅</div><p>All devices in network traffic are known to AdGuard.</p></div>')
else:
    body.append('<table class="data-table" style="width:100%">')
    body.append('<thead><tr><th>IP Address</th><th>Traffic</th><th>Status</th></tr></thead>')
    body.append('<tbody>')
    for ud in unknown_ips[:50]:  # Limit to 50
        ip = ud['ip']
        bytes_val = ud['bytes']
        if bytes_val > 1000000:
            traffic = f"{bytes_val/1000000:.1f} MB"
        elif bytes_val > 1000:
            traffic = f"{bytes_val/1000:.1f} KB"
        else:
            traffic = f"{bytes_val} B"
        
        body.append(f'<tr>')
        body.append(f'<td><code>{html.escape(ip)}</code></td>')
        body.append(f'<td>{html.escape(traffic)}</td>')
        body.append(f'<td><span class="pill">unknown</span></td>')
        body.append(f'</tr>')
    body.append('</tbody>')
    body.append('</table>')
    if len(unknown_ips) > 50:
        body.append(f"<p class='muted small'>Showing top 50 of {len(unknown_ips)} unknown devices</p>")

body.append('</div>')

body.append('<div class="card">')
body.append('<h2><span class="icon">📋</span> Raw Roll-up (Last 24 Hours)</h2>')
if report_txt.strip():
    body.append('<pre>' + html.escape(report_txt) + '</pre>')
else:
    body.append('<div class="empty-state"><div class="icon">📋</div><p>No report data found in the last 24 hours.</p></div>')
body.append('</div>')

body.append('</div>')  # close .container
body.append('<footer>HomeNetSec · Network Security Monitor</footer>')
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