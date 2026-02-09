---
name: home-netsec
description: Run and maintain the HomeNetSec network security pipeline. The PCAP download/processing pipeline (SFTP pull → merge+verify+delete inputs → Suricata+Zeek) can be scheduled separately from the analysis pipeline (RITA/reporting → triage digest → dashboard). Optional Telegram delivery via OpenClaw wrapper. Use for packaging, running, troubleshooting, or refactoring the HomeNetSec workflow.
---

# HomeNetSec

This skill bundles the HomeNetSec daily pipeline.

## What this skill contains

- `scripts/` — deterministic executables (pipeline runner + helpers)
- `references/` — notes / schemas / troubleshooting guides
- `assets/` — templates (docker-compose, report templates)

## Entry points

- `scripts/hourly_ingest_merge_process.sh` — hourly ingest+processing (download new pcaps since last ingest, merge+verify, delete inputs, run Suricata+Zeek)
- `scripts/run_daily.sh` — report generator (RITA + baselines/candidates + report; can be run in report-only mode)
- `scripts/run_and_send_openclaw.sh` — OpenClaw wrapper (optionally run ingest + analysis, then send Telegram)

## Notes

- Keep secrets out of the repo/skill. Use environment variables or external credential files.
- Keep data (PCAPs, Zeek logs, RITA DB, reports) in a configurable work directory and exclude it from git.
