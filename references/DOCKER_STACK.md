# Netsec Docker Deployment (Zeek offline + optional RITA)

This replaces native Zeek with a dockerized, offline workflow.

## Directory mounts (host)

All paths are relative to `/home/openclaw/.openclaw/workspace/HomeNetSec/`:

- `pcaps/` — merged PCAP staging area plus `.manifest.json` sidecars
- `zeek-logs/` — Zeek output (conn.log, dns.log, ssl.log, etc.)
- `rita-data/` — optional RITA working dir
- `reports/` — daily text reports (sent to Telegram)

## Current ingest model

HomeNetSec now expects source PCAPs to exist in a local `PCAP_SOURCE_DIR` outside the docker stack.
The ingest script:

- selects eligible source PCAPs using a safety lag
- skips source PCAPs already represented by destination merge manifests
- merges the remaining batch into `output/pcaps/YYYY-MM-DD/merged-*.pcap`
- writes `merged-*.pcap.manifest.json` beside each merged PCAP
- deletes source PCAPs from `PCAP_SOURCE_DIR` after the configured delay (`SOURCE_PCAP_DELETE_DELAY_HOURS`, default 48)

Primary entry point:

```bash
cd /home/openclaw/.openclaw/workspace/HomeNetSec
./scripts/pcap_ingest_merge_process.sh
```

## Bring up Mongo (only when running RITA)

```bash
cd /home/openclaw/.openclaw/workspace/HomeNetSec/assets
docker compose --profile rita up -d mongo
```

## Run Zeek on a PCAP (one-shot)

```bash
cd /home/openclaw/.openclaw/workspace/HomeNetSec/assets
docker compose --profile zeek run --rm zeek-offline /pcaps/2026-02-05/lan-2026-02-05_2000.pcap
```

Output ends up in:
- `../zeek-logs/2026-02-05/lan-2026-02-05_2000.pcap.zeek/`

## Run RITA on Zeek logs for a day (one-shot)

```bash
cd /home/openclaw/.openclaw/workspace/HomeNetSec/assets
docker compose --profile rita run --rm rita-batch 2026-02-05
```

## Retention

Defaults in the current system:

- merged PCAPs under `output/pcaps/`: 3 days
- merged source PCAPs in `PCAP_SOURCE_DIR`: 48 hours after successful merge
- Suricata/Zeek artifacts: 30 days

If you want to keep **7 days of merged PCAPs**, raise `MERGED_PCAP_RETENTION_DAYS=7`.

Example host cleanup (safe/recoverable if you use `trash-put`):

```bash
find /home/openclaw/.openclaw/workspace/HomeNetSec/output/pcaps -type f -mtime +7 -print0 | xargs -0 -r trash-put
```

If you use the example above, include both merged PCAPs and their sidecar manifests.

## OPNsense capture service changes

None required for this dockerization.

The system still just needs the same PCAP files you already rotate into your source PCAP directory.
