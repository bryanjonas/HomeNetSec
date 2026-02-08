# HomeNetSec PCAP ingest: gap-safe watermark model (LLM-oriented)

This document explains how the **hourly ingest** chooses which PCAP segments to copy from OPNsense, and how it avoids “skipping over” missing/failed segments.

Primary script:
- `scripts/hourly_ingest_merge_process.sh`

## Background

OPNsense rotates PCAP segment files that look like:

- `lan-YYYY-MM-DD_HH-MM-SS.pcap000`
- `lan-YYYY-MM-DD_HH-MM-SS.pcap001`

HomeNetSec pulls these segments to a local workdir, validates them, merges them into a single PCAP for the ingest batch, and runs Suricata+Zeek on the merged PCAP.

Because segment files can be **actively written**, truncated, or briefly inaccessible, ingest must:
- avoid copying partial files
- be able to **catch up** after downtime
- avoid “advancing the watermark” past a missing segment (a silent gap)

## Key idea: two watermarks + a pending retry set

HomeNetSec tracks progress in a small JSON state file:

`$HOMENETSEC_WORKDIR/state/hourly_ingest_state.json`

Important fields:

- `last_contiguous_epoch`
  - The last timestamp (derived from filename) for which we have processed **all eligible segments up to that point**.
  - This is the “safe” watermark.

- `high_watermark_epoch`
  - The highest eligible timestamp we’ve observed on the source side.
  - This can move ahead even if there is a gap.

- `pending` (list)
  - A retry list for segments we still need to copy/validate.
  - Each entry includes at least:
    - `epoch` (parsed from filename)
    - `path` (remote path)
    - optional metadata like `tries`, `last_error`, `updated_at`

This enables **gap-safe catch-up**:
- if a segment fails validation, it is remembered and retried
- the contiguous watermark only advances when there are no missing eligible segments

## How candidate files are selected each run

Each hourly run computes a **cutoff time**:

- `cutoff_epoch = now - SAFETY_LAG_SECONDS`

This prevents pulling very recent segments.

The script then:

1) Lists remote segments (via SFTP) for all days between:
   - `date(last_contiguous_epoch)` and `date(now)`
   - plus any additional days implied by `pending` entries

2) Parses an epoch from each filename’s embedded timestamp.

3) Builds a candidate set:

- **Fresh eligible segments**: `last_contiguous_epoch < epoch <= cutoff_epoch`
- **Pending segments**: any `pending.epoch <= cutoff_epoch` that still exist remotely

4) Applies `PULL_SKIP_NEWEST_N` **only to the newest N of the fresh set**.

Why:
- skipping newest N is a partial-file protection
- pending items are typically older and should not be skipped

## Download/validation logic

For each selected segment:

1) **Remote stability check** (no remote shell required):
   - run `sftp ls -l <file>` twice
   - wait `REMOTE_STABILITY_SECONDS`
   - if the line changes, treat as unstable → add/keep in `pending`

2) Download to `*.partial` via SFTP `get`.

3) Validate by rewriting the PCAP locally:
   - `tshark -r partial -w final`

If validation fails:
- quarantine as `*.bad.<timestamp>`
- add/keep in `pending`

If validation succeeds:
- the segment is considered “ok” for this run.

## How the contiguous watermark advances

After processing:

- Let `eligible_epochs` be all candidate epochs (fresh+pending) excluding the skipped-newest epochs.
- Let `ok_epochs` be epochs that are present locally as validated files (either already existed or validated this run).

Then:

- Start at `last_contiguous_epoch`.
- Walk `eligible_epochs` in ascending order.
- Advance the contiguous watermark while each next epoch is present in `ok_epochs`.
- Stop at the first missing epoch.

All missing eligible epochs remain in `pending`.

This ensures the system does **not** permanently skip older uncopied segments, even if newer segments succeed.

## Notes for LLM triage/ops

- A healthy ingest typically has a small `pending` list (often 0).
- Persistent `pending` entries indicate:
  - a segment is repeatedly being written/truncated
  - permissions/transport issues
  - the capture process producing malformed PCAPs

- The design intentionally avoids remote shell commands, so it works with locked-down SSH accounts.
