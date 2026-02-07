# Netsec Docker Deployment (Zeek offline + optional RITA)

This replaces native Zeek with a dockerized, offline workflow.

## Directory mounts (host)

All paths are relative to `/home/bryan/.openclaw/workspace/netsec/`:

- `pcaps/` — PCAP staging area (pulled from OPNsense)
- `zeek-logs/` — Zeek output (conn.log, dns.log, ssl.log, etc.)
- `rita-data/` — optional RITA working dir
- `reports/` — daily text reports (sent to Telegram)

## Bring up Mongo (only when running RITA)

```bash
cd /home/bryan/.openclaw/workspace/netsec/docker
docker compose --profile rita up -d mongo
```

## Run Zeek on a PCAP (one-shot)

```bash
cd /home/bryan/.openclaw/workspace/netsec/docker
docker compose --profile zeek run --rm zeek-offline /pcaps/2026-02-05/lan-2026-02-05_2000.pcap
```

Output ends up in:
- `../zeek-logs/2026-02-05/lan-2026-02-05_2000.pcap.zeek/`

## Run RITA on Zeek logs for a day (one-shot)

```bash
cd /home/bryan/.openclaw/workspace/netsec/docker
docker compose --profile rita run --rm rita-batch 2026-02-05
```

## Retention

You said: keep **7 days of PCAPs**.

Suggested host cleanup (safe/recoverable if you use `trash-put`):

```bash
find /home/bryan/.openclaw/workspace/netsec/pcaps -type f -mtime +7 -print0 | xargs -0 -r trash-put
```

## OPNsense capture service changes

None required for this dockerization.

The pipeline still just needs the same PCAP files you already rotate into `/var/log/pcaps`.
