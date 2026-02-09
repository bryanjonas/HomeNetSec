# HomeNetSec — System Operation (LLM-oriented)

This document explains **how the whole HomeNetSec system operates**, end-to-end, in terms that are friendly to an LLM (or a human reviewing the design).

The intent is not to repeat every line of code, but to capture:
- the major components
- what data flows between them
- what state is persisted
- what safety/robustness rules govern behavior
- where to look in the repo for each stage

---

## 1) Inputs and external dependencies

### 1.1 PCAP source (network telemetry)
- Source host: **OPNsense** (separate host)
- Remote directory: `${OPNSENSE_PCAP_DIR:-/var/log/pcaps}`
- File naming convention:
  - `lan-YYYY-MM-DD_HH-MM-SS.pcap000`
  - `lan-YYYY-MM-DD_HH-MM-SS.pcap001` (size-based rollover)

**Important constraint:** the SSH account used for pulling PCAPs may be locked down (no interactive shell).

Therefore, HomeNetSec uses **SFTP** (not `ssh <cmd>`), so it can operate with a non-shell account.

### 1.2 DNS telemetry (resolver context)
- DNS telemetry is pulled from **AdGuard Home** via its HTTP API.
- Evidence enrichment should also attempt to map `src_ip` → **client name** using the DNS server’s client list (when available), so digests read like “Kitchen-iPad (RFC1918_IP)” instead of just an IP.
- Credentials are not in the repo; they live in a local env file (default documented in README):
  - `~/.openclaw/credentials/adguard.env`

### 1.3 Containerized tools
HomeNetSec uses Docker to run the analysis tools in a controlled, repeatable way:
- Zeek (offline): `blacktop/zeek`
- Suricata (offline): `jasonish/suricata`
- RITA + Mongo: `quay.io/activecm/rita` and `mongo:4.2`

See: `assets/docker-compose.yml`

---

## 2) Local filesystem layout (workdir)

All runtime data lives under:

- `${HOMENETSEC_WORKDIR:-./output}`

Subdirectories (typical):
- `pcaps/YYYY-MM-DD/` — pulled segments + merged PCAPs
- `zeek-logs/YYYY-MM-DD/` — Zeek per-PCAP or per-merge logs
- `zeek-flat/YYYY-MM-DD/` — flattened Zeek logs for RITA
- `suricata/YYYY-MM-DD/` — Suricata EVE outputs (per merged PCAP)
- `rita-data/` — RITA output artifacts
- `reports/YYYY-MM-DD.txt` — daily roll-up text
- `state/` — small durable state (SQLite + JSON)
- `www/` — dashboard site (static HTML/JSON)

Repo policy: runtime outputs are not committed.

---

## 3) Scheduling model (pipelines can run separately)

HomeNetSec is intentionally split so the **download/processing pipeline** can be scheduled separately from the **analysis pipeline**.

### 3.1 Download + processing pipeline (PCAP ingest → merge → Suricata + Zeek)
Entry point:
- `scripts/hourly_ingest_merge_process.sh`

Goal:
- incrementally ingest new PCAP segments, merge them into a single PCAP batch, and run Suricata+Zeek on the merged batch.

Typical cadence:
- hourly (top of hour)

### 3.2 Analysis + dashboard pipeline (RITA/reporting → triage digest → dashboard)
Entry points:
- `scripts/run_daily.sh` (reporting layer)
- `scripts/triage_digest.py` (deterministic digest enrichment + suppression)
- `scripts/generate_dashboard.sh` (static dashboard generation)

Goal:
- update baselines/candidates, run RITA over flattened Zeek logs, enrich into a deterministic triage digest, and refresh the dashboard.

Typical cadence:
- 2×/day (e.g., morning/evening), or hourly if you want near-real-time dashboard updates

Important property:
- This pipeline does *not* need to pull PCAPs and does *not* rerun Zeek/Suricata; it consumes outputs produced by the download/processing pipeline.

### 3.3 Optional delivery wrapper (Telegram)
Entry point:
- `scripts/run_and_send_openclaw.sh`

Goal:
- run analysis steps and optionally send a Telegram message with a dashboard link.

Delivery is intentionally separable: you can run analysis hourly and choose when/if to send messages.

---

## 4) Hourly ingest details (gap-safe SFTP pull)

### 4.1 Partial protections
The hourly job must avoid copying files that are still being written.
It applies multiple “partial protections”:

- `SAFETY_LAG_SECONDS` (default 120s): ignore files newer than `now - lag`.
- `PULL_SKIP_NEWEST_N` (default 1): after time filtering, skip the newest N eligible files.
- Remote stability check: compare `sftp ls -l` output twice across `REMOTE_STABILITY_SECONDS`.

### 4.2 Gap-safe state model (Option 2)
State file:
- `$HOMENETSEC_WORKDIR/state/hourly_ingest_state.json`

Key fields:
- `last_contiguous_epoch`: safe watermark (only advances when all eligible epochs up to it are validated)
- `high_watermark_epoch`: highest eligible epoch observed
- `pending`: retry set of segments that were missing/unstable/failed validation

Why this exists:
- Without it, the system could “skip over” a missing/failed older segment if newer segments validate, creating a silent analysis gap.

### 4.3 Selection logic summary
Each run:
1) Lists remote segments for all relevant days via **SFTP**.
2) Parses an epoch from each filename.
3) Builds candidates:
   - fresh eligible: `last_contiguous_epoch < epoch <= cutoff_epoch`
   - pending retry: any `pending.epoch <= cutoff_epoch`
4) Applies `PULL_SKIP_NEWEST_N` to the newest N of the **fresh** set only.
5) Processes all pending candidates + remaining fresh candidates.

### 4.4 Local validation
Downloads are staged as `*.partial` and then rewritten via:
- `tshark -r partial -w final`

If tshark fails:
- quarantine as `*.bad.<timestamp>`
- keep in `pending`

### 4.5 Merge + verify + delete inputs
Validated segments are merged:
- `mergecap -w merged.pcap <segments...>`

Merge verification:
- packet counts must match (merged == sum(inputs)) using `capinfos -M -c`
- can retry merge+verify (`MERGE_RETRIES`)

After verified merge:
- optionally deletes source segments (`DELETE_MERGED_INPUTS=1`)

### 4.6 Hourly processing
For the merged PCAP:
- Suricata offline writes:
  - EVE JSON (TLS enabled; may include alert events depending on config)
  - `fast.log` / `suricata.log` (signature/decoder alerts)
- Zeek offline writes logs

---

## 5) Reporting layer (schedule independently from ingest)

Entry points:
- `scripts/run_daily.sh`
- (optional wrapper) `scripts/run_and_send_openclaw.sh`

The reporting layer:
1) runs `run_daily.sh` in report-only mode:
   - `SKIP_PCAP_PULL=1 SKIP_ZEEK=1 RUN_JA4=0`
2) updates baseline DB and anomaly candidates
3) writes daily report text: `output/reports/YYYY-MM-DD.txt`

This layer can run hourly or 2×/day. It assumes Zeek logs have already been produced by the download/processing pipeline.

Candidate detection:
- `scripts/detect_candidates.py` (baseline-driven)
- output: `output/state/YYYY-MM-DD.candidates.json`

Allowlist behavior:
- allowlist suppresses candidates (reporting-only; never firewall)
- allowlist should be user-managed outside the repo (typically `output/state/allowlist.local.json`)

---

## 6) Dashboard / web UI

Dashboard is served as static files under:
- `output/www/`

Generator:
- `scripts/generate_dashboard.sh`

The root page (`/`) is a single-page dashboard showing:
- hourly ingest status
- **active alerts queue** (alerts remain until dismissed; not day-scoped)
- per-alert feedback (verdict + comment + dismiss)
- raw daily roll-up text

Feedback persistence:
- feedback is persisted server-side via the dashboard API into:
  - `output/state/feedback.json` (not committed)
- the dashboard hydrates saved verdict/comment/dismiss state on refresh.

Alert queue:
- active alert queue is stored in:
  - `output/state/alerts_queue.json` (not committed)
- it is updated whenever the dashboard is regenerated.

---

## 7) Delivery (Telegram)

Daily wrapper sends:
- a dashboard link (base URL `/`)
- plus a short excerpt of the text report

Script:
- `scripts/run_and_send_openclaw.sh`

---

## 8) Security & privacy rules

- Do not commit secrets (tokens, chat IDs, credentials, private IPs that identify a specific install).
- Do not commit runtime artifacts: PCAPs, logs, reports, DB files.
- No automated firewall changes.
- “Allowlist” means suppress/report-ignore; any new allowlist decisions should be surfaced in the daily output.

---

## 9) Where to look (repo map)

- Hourly ingest (SFTP pull + gap-safe state): `scripts/hourly_ingest_merge_process.sh`
- Daily reporting orchestration: `scripts/run_and_send_openclaw.sh`
- Report generation + candidates: `scripts/run_daily.sh`, `scripts/detect_candidates.py`, `scripts/baseline_update.py`
- Docker tool stack: `assets/docker-compose.yml`
- Dashboard generator: `scripts/generate_dashboard.sh`
- Allowlist management helper: `scripts/allowlist_manage.sh`
