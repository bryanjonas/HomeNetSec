# HomeNetSec LLM Notes

This repository no longer uses the old day-scoped LLM and digest flow.

The active system is:

- `scripts/continuous_ingest.sh`
- `scripts/continuous_analysis.sh`
- `scripts/run_ingest_and_analysis.sh`
- `assets/dashboard-api/app.py`
- `assets/dashboard-static/`

The missing triage functionality is tracked in [TRIAGE_INTEGRATION_PLAN.md](/home/bareclaw/HomeNetSec/TRIAGE_INTEGRATION_PLAN.md).

Current expectations for future LLM-assisted work:

- triage should run against `alerts.sqlite`, `devices.sqlite`, and `baselines.sqlite`
- prior dismissed and labeled alerts should be used as comparison context
- results should be stored on alerts, not in day-scoped JSON files
- the live dashboard should show explanation, suggested verdict, confidence, and operator feedback

Use [README.md](/home/bareclaw/HomeNetSec/README.md) plus [TRIAGE_INTEGRATION_PLAN.md](/home/bareclaw/HomeNetSec/TRIAGE_INTEGRATION_PLAN.md) as the current source of truth.
