#!/usr/bin/env python3
"""Flatten active continuous artifacts out of day-based folders.

This keeps the legacy ingest pipeline intact while moving the active
continuous-analysis path onto flat storage:
  pcaps/merged-*.pcap
  zeek-logs/merged-*.pcap.zeek
  suricata/eve-merged-*.json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path


def move_if_present(src: Path, dst: Path) -> bool:
    if not src.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        if src.is_dir():
            shutil.rmtree(src)
        else:
            src.unlink()
        return False
    shutil.move(str(src), str(dst))
    return True


def rewrite_manifest(manifest_path: Path, merge_path: Path) -> None:
    if not manifest_path.exists():
        return
    try:
        with open(manifest_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        return

    payload["merge_path"] = str(merge_path.resolve())
    payload["merge_basename"] = merge_path.name

    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def cleanup_empty_parents(path: Path, stop_at: Path) -> None:
    current = path.parent
    stop_at = stop_at.resolve()
    while current.exists() and current.resolve() != stop_at:
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent


def flatten_pcap(workdir: Path, pcap_path: Path) -> str:
    pcap_path = pcap_path.resolve()
    flat_pcap = workdir / "pcaps" / pcap_path.name
    manifest_src = Path(f"{pcap_path}.manifest.json")
    flat_manifest = workdir / "pcaps" / manifest_src.name

    if pcap_path != flat_pcap:
        move_if_present(pcap_path, flat_pcap)
        move_if_present(manifest_src, flat_manifest)
        rewrite_manifest(flat_manifest, flat_pcap)
        cleanup_empty_parents(pcap_path, workdir / "pcaps")
    else:
        rewrite_manifest(flat_manifest if flat_manifest.exists() else manifest_src, flat_pcap)

    zeek_src = workdir / "zeek-logs" / pcap_path.parent.name / f"{pcap_path.name}.zeek"
    zeek_dst = workdir / "zeek-logs" / f"{flat_pcap.name}.zeek"
    if zeek_src != zeek_dst:
        moved = move_if_present(zeek_src, zeek_dst)
        if moved:
            cleanup_empty_parents(zeek_src, workdir / "zeek-logs")

    eve_src = workdir / "suricata" / pcap_path.parent.name / f"eve-{pcap_path.stem}.json"
    eve_dst = workdir / "suricata" / f"eve-{flat_pcap.stem}.json"
    fast_src = workdir / "suricata" / pcap_path.parent.name / f"fast-{pcap_path.stem}.log"
    fast_dst = workdir / "suricata" / f"fast-{flat_pcap.stem}.log"
    moved_any = False
    if eve_src != eve_dst:
        moved_any = move_if_present(eve_src, eve_dst) or moved_any
        moved_any = move_if_present(fast_src, fast_dst) or moved_any
        if moved_any:
            cleanup_empty_parents(eve_src, workdir / "suricata")

    return str(flat_pcap.resolve())


def main() -> int:
    parser = argparse.ArgumentParser(description="Flatten continuous artifacts out of day folders")
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--pcap", action="append", default=[], help="Merged PCAP path(s) to flatten")
    args = parser.parse_args()

    workdir = Path(args.workdir).resolve()
    for pcap in args.pcap:
        print(flatten_pcap(workdir, Path(pcap)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
