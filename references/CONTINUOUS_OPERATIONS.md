# Continuous Operations Guide

This guide covers deployment, monitoring, testing, and performance validation for the continuous HomeNetSec path.

## Scheduled Operation

### Cron

Recommended when you want simple recovery semantics and transparent logs.

```bash
*/5 * * * * cd /home/bareclaw/HomeNetSec && ./scripts/continuous_ingest.sh --once >> /var/log/homenetsec-continuous.log 2>&1
*/5 * * * * cd /home/bareclaw/HomeNetSec && ./scripts/continuous_analysis.sh --process-queue >> /var/log/homenetsec-continuous.log 2>&1
```

### systemd timers

Example one-shot unit files:

`/etc/systemd/system/homenetsec-ingest.service`

```ini
[Unit]
Description=HomeNetSec Continuous Ingest
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/home/bareclaw/HomeNetSec
ExecStart=/home/bareclaw/HomeNetSec/scripts/continuous_ingest.sh --once

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/homenetsec-analysis.service`

```ini
[Unit]
Description=HomeNetSec Continuous Analysis
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/home/bareclaw/HomeNetSec
ExecStart=/home/bareclaw/HomeNetSec/scripts/continuous_analysis.sh --process-queue

[Install]
WantedBy=multi-user.target
```

## Dashboard Deployment

```bash
cd /home/bareclaw/HomeNetSec
docker compose --env-file .env -f assets/dashboard-compose.yml up -d
```

## Test and Verification

Run the local automated tests:

```bash
cd /home/bareclaw/HomeNetSec
python3 -m unittest discover -s tests -v
```

Run lightweight syntax checks:

```bash
python3 -m compileall scripts assets/dashboard-api tests
bash -n scripts/continuous_ingest.sh
bash -n scripts/continuous_analysis.sh
bash -n scripts/run_ingest_and_analysis.sh
```

## Performance Validation Checklist

Use this checklist after enabling the continuous path in a real environment.

1. Verify queue stability.
   - `wc -l "$HOMENETSEC_WORKDIR/output/state/analysis_queue.txt"`
   - Queue depth should return to zero between ingest cycles under normal load.

2. Verify ingest coverage.
   - `cat "$HOMENETSEC_WORKDIR/output/state/pipeline_status.json"`
   - `coverage.coverage_percent_24h` should stay near `100.0`.
   - `coverage.missing_intervals` should remain empty or short-lived.

3. Verify analysis latency.
   - `analysis.avg_processing_time_sec` should stay below your ingest interval.
   - If ingest runs every 5 minutes, keep average analysis well under 300 seconds.

4. Verify storage growth.
   - `du -sh "$HOMENETSEC_WORKDIR/output/pcaps" "$HOMENETSEC_WORKDIR/output/zeek-logs" "$HOMENETSEC_WORKDIR/output/suricata" "$HOMENETSEC_WORKDIR/output/rita-data"`
   - Confirm retention cleanup is holding steady over several days.

5. Verify alert health.
   - `./scripts/view_alerts.py --db "$HOMENETSEC_WORKDIR/output/state/alerts.sqlite" --stats`
   - Check active counts, severities, and recurrence volume against expected network behavior.

## Operational Expectations

- `pipeline_status.json` is the source of truth for dashboard health.
- `alerts.sqlite` and `devices.sqlite` are expected to persist across runs.
- `continuous_ingest.sh` and `continuous_analysis.sh` are safe to invoke repeatedly.
