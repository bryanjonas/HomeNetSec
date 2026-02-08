---
name: home-netsec
description: Run and maintain the HomeNetSec network security pipeline: hourly PCAP ingest (OPNsense SSH pull), merge+verify+delete inputs, Suricata+Zeek on merged PCAPs, plus daily 8pm reporting (RITA + baselines/candidates + AdGuardHome DNS stats) with Telegram delivery. Use for packaging, running, troubleshooting, or refactoring the HomeNetSec workflow.
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
- `scripts/run_and_send_openclaw.sh` — 8pm wrapper (run hourly ingest once, then run `run_daily.sh` report-only and send Telegram)

## Notes

- Keep secrets out of the repo/skill. Use environment variables or external credential files.
- Keep data (PCAPs, Zeek logs, RITA DB, reports) in a configurable work directory and exclude it from git.
