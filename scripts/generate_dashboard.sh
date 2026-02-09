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
python3 - "$WWW_DIR/status.json" "$REPORT_TXT" "$DIGEST_JSON" "$CANDIDATES_JSON" "$WORKDIR/state/feedback.json" "$WORKDIR/state/alerts_queue.json" "$WWW_DIR/index.html" <<'PY'
import html, json, os, sys, hashlib

status_path, report_path, digest_path, candidates_path, feedback_path, queue_path, out_path = sys.argv[1:8]

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
body.append("<h2>Active alerts</h2>")

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

        meta_bits = [f"id: <code>{aid}</code>"]
        if a.get('first_seen_day'):
            meta_bits.append(f"first_seen: <code>{html.escape(str(a.get('first_seen_day')))}</code>")
        if a.get('last_seen_day'):
            meta_bits.append(f"last_seen: <code>{html.escape(str(a.get('last_seen_day')))}</code>")
        body.append(f'<div class="row">{"".join(pills)}<div class="small muted">{" · ".join(meta_bits)}</div></div>')
        body.append(f'<h3 style="margin:10px 0">{html.escape(a["title"])}</h3>')

        # Plain-language evidence summary (above the raw evidence dropdown)
        ev = a.get('data') if isinstance(a.get('data'), dict) else {}
        evidence = (ev.get('evidence') or {}) if isinstance(ev, dict) else {}
        src_ip = evidence.get('src_ip') or ''
        src_name = evidence.get('src_name') or ''
        dst_ip = evidence.get('dst_ip') or ''
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
            body.append('<div class="muted" style="margin-top:6px">' + html.escape(' '.join(ev_lines)) + '</div>')

        body.append('<details><summary>evidence (raw)</summary>')
        body.append('<pre>' + html.escape(json.dumps(a['data'], indent=2, sort_keys=True)) + '</pre>')
        body.append('</details>')

        body.append('<div class="row" style="align-items:center;margin-top:10px">')
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
        draft_note = ""
        try:
            todays = feedback_for_day.get(alert_id) if isinstance(feedback_for_day, dict) else None
            if not (isinstance(todays, dict) and (todays.get('note') or '').strip()):
                prev_day, prev = latest_feedback(alert_id)
                if isinstance(prev, dict) and (prev.get('note') or '').strip():
                    draft_note += f"Prev note ({prev_day}): {prev.get('note').strip()}\n"

                # Factor in comments from dismissed alerts of similar nature (any day).
                try:
                    sim = []
                    kind_prefix = ''
                    if isinstance(a.get('data'), dict) and (a.get('data') or {}).get('kind'):
                        kind_prefix = str((a.get('data') or {}).get('kind'))
                    if not kind_prefix:
                        # fall back to id prefix like rita_beacon|...
                        kind_prefix = str(alert_id).split('|', 1)[0]

                    for _d, mp in (feedback_days or {}).items():
                        if not isinstance(mp, dict):
                            continue
                        for _aid, _rec in mp.items():
                            if len(sim) >= 2:
                                break
                            if not isinstance(_rec, dict):
                                continue
                            if not bool(_rec.get('dismissed')):
                                continue
                            note = str(_rec.get('note') or '').strip()
                            if not note:
                                continue
                            _aid_s = str(_aid)
                            if not _aid_s.startswith(kind_prefix + '|') and _aid_s.split('|', 1)[0] != kind_prefix:
                                continue

                            # Similarity heuristics
                            same_src = src_ip and (f"|{src_ip}|" in _aid_s)
                            same_dst = dst_ip and (_aid_s.endswith(f"|{dst_ip}") or f"|{dst_ip}" in _aid_s)
                            ntpish = (domain and domain.endswith('.pool.ntp.org')) and ('ntp' in note.lower())

                            if same_src or same_dst or ntpish:
                                sim.append(note)
                        if len(sim) >= 2:
                            break

                    if sim:
                        draft_note += "Similar dismissed notes:\n" + "\n".join([f"- {x}" for x in sim]) + "\n"
                except Exception:
                    pass

                # Heuristics based on evidence
                if domain and domain.endswith('.pool.ntp.org'):
                    draft_note += "Looks like NTP pool traffic. Likely benign.\n"
                if dst_ip and str(dst_ip).startswith('162.159.'):
                    draft_note += "Destination is Cloudflare (162.159.x.x). Could be NTP/DoH/CDN; confirm expected for this device.\n"
                if novelty:
                    draft_note += "Marking as new-for-device; if expected, dismiss.\n"
                if ja4:
                    draft_note += "JA4 present; if unexpected for this device, worth deeper review.\n"
        except Exception:
            pass

        body.append(f'<div style="margin-top:10px"><label>Comment / context:<br><textarea id="note-{did}" placeholder="(drafted when possible)">{html.escape(draft_note)}</textarea></label></div>')

        body.append('<div class="row" style="align-items:center;margin-top:10px">')
        body.append(f'<label><input type="checkbox" id="dismiss-{did}"/> Dismiss (hide this alert)</label>')
        body.append(f'<button onclick="onSave(\'{did}\')">Save</button>')
        body.append('</div>')
        body.append('</div>')

body.append('</div>')

body.append('<div class="card">')
body.append('<h2>Raw daily roll-up</h2>')
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