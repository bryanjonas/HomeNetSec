---
name: home-netsec
description: Run and maintain a home network security daily pipeline (OPNsense PCAP pull, Zeek offline analysis, Zeek log flattening, RITA analysis with MongoDB, AdGuardHome DNS stats) and produce a concise report suitable for sending via OpenClaw messaging. Use for packaging, running, troubleshooting, or refactoring the HomeNetSec workflow.
---

# HomeNetSec

This skill bundles the HomeNetSec daily pipeline.

## What this skill contains

- `scripts/` — deterministic executables (pipeline runner + helpers)
- `references/` — notes / schemas / troubleshooting guides
- `assets/` — templates (docker-compose, report templates)

## Entry points

- `scripts/run_daily.sh` (to be added): run the full pipeline for a given day.

## Notes

- Keep secrets out of the repo/skill. Use environment variables or external credential files.
- Keep data (PCAPs, Zeek logs, RITA DB, reports) in a configurable work directory and exclude it from git.
