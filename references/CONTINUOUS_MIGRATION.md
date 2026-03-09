# Continuous Migration Guide

This guide moves an existing day-scoped HomeNetSec deployment onto the continuous layout.

## Preconditions

- `.env` is configured with `HOMENETSEC_WORKDIR`
- existing historical outputs still exist under the current workdir
- the repo is updated to the continuous implementation

## Dry Run

Review the migration plan without changing files:

```bash
cd /home/bareclaw/HomeNetSec
./scripts/migrate_to_continuous.sh --dry-run
```

## Migration Steps

1. Stop scheduled day-based jobs.
2. Run the migration entrypoint:

```bash
cd /home/bareclaw/HomeNetSec
./scripts/migrate_to_continuous.sh
```

3. Verify resulting state:

```bash
./scripts/view_alerts.py --db "$HOMENETSEC_WORKDIR/output/state/alerts.sqlite" --stats
find "$HOMENETSEC_WORKDIR/output/pcaps" -maxdepth 1 -name 'merged-*.pcap'
find "$HOMENETSEC_WORKDIR/output/zeek-logs" -maxdepth 1 -type d -name 'merged-*.zeek'
find "$HOMENETSEC_WORKDIR/output/suricata" -maxdepth 1 -name 'eve-merged-*.json'
```

4. Start the continuous path:

```bash
./scripts/continuous_ingest.sh --once
./scripts/continuous_analysis.sh --process-queue
```

5. Deploy or refresh the dashboard:

```bash
docker compose --env-file .env -f assets/dashboard-compose.yml up -d
```

## Rollback

Rollback is operational rather than destructive:

1. Stop continuous ingest and analysis jobs.
2. Resume the prior day-based scheduler.
3. Keep the migrated SQLite databases for comparison.
4. If needed, regenerate historical dashboard/report outputs from the old day-based pipeline.

## Notes

- The migration reuses the existing alert and device migration scripts.
- Historical merged PCAP, Zeek, and Suricata artifacts are flattened into the active continuous layout.
- The migration does not delete historical reports.
