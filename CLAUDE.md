# CLAUDE.md - HomeNetSec AI Assistant Guide

This repository now targets a continuous pipeline. Legacy day-scoped planning and status docs, plus the old daily analysis wrapper, have been removed.

## Project Overview

HomeNetSec is a local network-security pipeline built around:

- gap-safe PCAP ingest
- continuous Zeek and Suricata processing
- rolling baseline and alert generation
- persistent SQLite-backed alerts and devices
- a live dashboard served from `www/`

The missing piece is alert triage enrichment. That work is tracked in [TRIAGE_INTEGRATION_PLAN.md](/home/bareclaw/HomeNetSec/TRIAGE_INTEGRATION_PLAN.md).

## Active Entry Points

- `scripts/continuous_ingest.sh`
  - groups source PCAPs into time windows
  - writes merged PCAPs and manifests
  - runs Zeek and Suricata
  - appends work to the analysis queue
- `scripts/continuous_analysis.sh`
  - consumes the analysis queue
  - updates rolling baselines
  - runs continuous detection
  - updates devices, RITA outputs, pipeline status, and dashboard assets
- `scripts/run_ingest_and_analysis.sh`
  - convenience wrapper that runs ingest, analysis, and dashboard refresh
- `scripts/generate_dashboard.sh`
  - generates live dashboard assets under `www/`

## Supporting Components

- `scripts/pcap_ingest_merge_process.sh`
  - ingest primitive used by the continuous wrapper
- `scripts/baseline_update_continuous.py`
  - rolling baseline maintenance
- `scripts/detect_continuous.py`
  - writes alerts into `alerts.sqlite`
- `scripts/alert_db.py`
  - alert lifecycle storage and audit history
- `scripts/device_inventory_update.py`
  - device inventory and trust/monitor state
- `scripts/generate_pipeline_status.py`
  - normalized pipeline health snapshot
- `assets/dashboard-api/app.py`
  - live Flask API for alerts, devices, and pipeline status
- `assets/dashboard-static/`
  - live dashboard frontend

## Runtime Layout

The configured workdir is expected to contain:

- `pcaps/`
- `zeek-logs/`
- `suricata/`
- `rita-data/`
- `state/`
- `reports/`
- `www/`

Important state files:

- `state/analysis_queue.txt`
- `state/pipeline_status.json`
- `state/alerts.sqlite`
- `state/devices.sqlite`
- `state/baselines.sqlite`

## Current Constraints

- The live dashboard is backed by the alert and device databases, not a day-scoped digest.
- The old LLM-style triage explanation workflow is not currently restored.
- New triage work should target the continuous database-backed path, not rebuild the removed day-based pipeline.

## Common Operations

Initialize or migrate state:

```bash
python3 scripts/init_databases.py
```

Run ingest once:

```bash
./scripts/continuous_ingest.sh --once
```

Process the queue once:

```bash
./scripts/continuous_analysis.sh --process-queue
```

Run the wrapper:

```bash
./scripts/run_ingest_and_analysis.sh
```

Refresh the dashboard:

```bash
./scripts/generate_dashboard.sh
```

## Editing Guidance

- Prefer changes in the continuous scripts over reintroducing legacy day-based flows.
- Preserve the SQLite-backed alert lifecycle and audit trail.
- If adding triage, store it on alerts and expose it through the live API.
- Keep docs aligned with the active pipeline so the repo does not drift back into split-brain documentation.
