---
name: home-netsec
description: Run and maintain the HomeNetSec network security pipeline. The PCAP processing pipeline (gap-safe selection → merge+verify → manifest tracking → delayed source deletion → Suricata+Zeek) can be scheduled separately from the analysis pipeline (RITA/reporting → triage digest → dashboard). Optional Telegram delivery via OpenClaw wrapper. Use for packaging, running, troubleshooting, or refactoring the HomeNetSec workflow.
---

# HomeNetSec

This skill bundles the HomeNetSec ingest + analysis pipeline.

## What this skill contains

- `scripts/` — deterministic executables (pipeline runner + helpers)
- `references/` — notes / schemas / troubleshooting guides
- `assets/` — templates (docker-compose, report templates)

## Entry points

- `scripts/pcap_ingest_merge_process.sh` — PCAP ingest/processing (select new pcaps since last ingest, skip already-merged inputs, merge+verify, write manifests, delayed delete, run Suricata+Zeek)
- `scripts/run_analysis_pipeline.sh` — analysis/reporting pipeline (RITA + baselines/candidates + report; can be run in report-only mode)
- `scripts/run_and_send_openclaw.sh` — OpenClaw wrapper (optionally run ingest + analysis, then send Telegram)

## Notes

- Keep secrets out of the repo/skill. Use environment variables or external credential files.
- Keep data (PCAPs, Zeek logs, RITA DB, reports) in a configurable work directory and exclude it from git.
- The pipeline normalizes `HOMENETSEC_WORKDIR` to an `output/` suffix; set it to the parent (e.g., `/mnt/5TB/openclaw/data/HomeNetSec`) and the scripts will write under `/output`.
- The dashboard drafts a Comment/Context block with: why the alert was flagged, a likely explanation (or "Not available"), and synthesized prior dismissal context.
