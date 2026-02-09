#!/usr/bin/env python3
"""HomeNetSec: build analyzed digest JSON from candidates + local evidence.

Inputs:
- output/state/YYYY-MM-DD.candidates.json
- output/state/feedback.json (optional)
- Zeek dns.log files under output/zeek-logs/YYYY-MM-DD/**/dns.log (optional)
- AdGuard Home client list (optional; uses ADGUARD_ENV or ADGUARD_URL/USER/PASS)

Output:
- output/state/YYYY-MM-DD.digest.json

Design goals:
- incorporate src_ip -> src_name via AdGuard clients registry
- correlate dst_ip -> domain via Zeek dns answers
- hide items dismissed in feedback

This script is deterministic and contains no secrets in output.
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import re
import sys
from urllib.request import Request, urlopen


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json_atomic(path: str, obj) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def now_iso_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def load_feedback(feedback_path: str, day: str) -> dict:
    try:
        db = load_json(feedback_path)
        return (db.get("days") or {}).get(day, {}) or {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def is_dismissed(feedback_for_day: dict, alert_id: str) -> bool:
    rec = feedback_for_day.get(alert_id) or {}
    return bool(rec.get("dismissed"))


def adguard_login_cookie(url: str, user: str, pw: str) -> str:
    login_url = f"{url}/control/login"
    body = json.dumps({"name": user, "password": pw}).encode("utf-8")
    resp = urlopen(
        Request(login_url, data=body, method="POST", headers={"Content-Type": "application/json"}),
        timeout=20,
    )
    cookies = resp.headers.get_all("Set-Cookie") or []
    resp.read()
    return "; ".join([c.split(";", 1)[0] for c in cookies if c])


def adguard_client_map(adguard_env: str | None) -> dict[str, str]:
    """Return {ip_or_id: name} from AdGuard registered clients.

    In AdGuard, client objects have fields like:
      {"name": "Doorbell Camera", "ids": ["192.168.1.X", ...]}
    """

    # Load env file if provided
    if adguard_env and os.path.exists(adguard_env):
        # Minimal .env parser: KEY="VALUE"
        for line in open(adguard_env, "r", encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and v and k not in os.environ:
                os.environ[k] = v

    url = (os.environ.get("ADGUARD_URL") or "").rstrip("/")
    user = os.environ.get("ADGUARD_USER") or ""
    pw = os.environ.get("ADGUARD_PASS") or ""

    if not (url and user and pw):
        return {}

    try:
        cookie = adguard_login_cookie(url, user, pw)
        raw = urlopen(Request(f"{url}/control/clients", headers={"Cookie": cookie}), timeout=20).read()
        payload = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return {}

    out: dict[str, str] = {}
    for c in payload.get("clients") or []:
        if not isinstance(c, dict):
            continue
        name = (c.get("name") or "").strip()
        ids = c.get("ids") or []
        if not name:
            continue
        if isinstance(ids, list):
            for cid in ids:
                if isinstance(cid, str) and cid.strip():
                    out[cid.strip()] = name
    return out


_DNS_RE = re.compile(r"^lan-(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})\.pcap")


def zeek_dns_domains_for_ip(zeek_logs_root: str, day: str, dst_ip: str, limit: int = 3) -> list[str]:
    """Return up to N query names whose DNS answers contained dst_ip."""
    domains: list[str] = []
    pattern = os.path.join(zeek_logs_root, day, "**", "dns.log")
    for p in sorted(glob.glob(pattern, recursive=True)):
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not line or line.startswith("#"):
                        continue
                    if dst_ip not in line:
                        continue
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) < 11:
                        continue
                    q = parts[9]
                    if q and q not in domains:
                        domains.append(q)
                        if len(domains) >= limit:
                            return domains
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return domains


def build_digest(candidates: dict, feedback_for_day: dict, client_map: dict[str, str], zeek_logs_root: str, enrichment_host_ip: str) -> dict:
    day = candidates.get("day") or ""
    signals = (candidates.get("signals") or {})

    items = []

    # Today we triage primarily RITA beacons (as that tends to be the most actionable periodicity signal).
    for b in (signals.get("rita_beacons") or []):
        if not isinstance(b, dict):
            continue
        src = b.get("src_ip") or ""
        dst = b.get("dst_ip") or ""
        if not src or not dst:
            continue

        alert_id = f"rita_beacon|{src}|{dst}"
        if is_dismissed(feedback_for_day, alert_id):
            continue

        src_name = client_map.get(src, "")
        domains = zeek_dns_domains_for_ip(zeek_logs_root, day, dst)
        domain = domains[0] if domains else ""

        score = float(b.get("score") or 0.0)
        severity = "med" if score >= 0.99 else "low"

        title = f"Periodic connections: {src} → {dst}"
        if src_name:
            title = f"Periodic connections: {src_name} ({src}) → {dst}"
        if domain:
            title += f" (DNS: {domain})"

        verdict = "needs_review"
        # If evidence points strongly to NTP, mark likely benign.
        if domain.endswith(".pool.ntp.org") or "ntp" in (b.get("dst_rdns") or ""):
            verdict = "likely_benign"

        ev_notes = []
        if b.get("dst_rdns"):
            ev_notes.append(f"dst_rdns={b.get('dst_rdns')}")
            if enrichment_host_ip:
                ev_notes.append(f"rdns_source=enrichment (resolver traffic originates from {enrichment_host_ip})")
        if domains:
            ev_notes.append("dns_queries=" + ", ".join(domains))

        items.append(
            {
                "id": alert_id,
                "severity": severity,
                "verdict": verdict,
                "title": title,
                "what": f"RITA beacon-style periodic connections from {src} to {dst}.",
                "why_flagged": f"RITA score={b.get('score')} top_interval={b.get('top_interval')} connections={b.get('connections')}",
                "most_likely_explanation": "Needs attribution via DNS/SNI unless clearly routine (e.g., NTP).",
                "confidence": 0.55 if verdict == "needs_review" else 0.8,
                "evidence": {
                    "src_ip": src,
                    "src_name": src_name,
                    "dst_ip": dst,
                    "dst_port": int(b.get("dst_port") or 0) if str(b.get("dst_port") or "").isdigit() else 0,
                    "domain": domain,
                    "rdns": b.get("dst_rdns") or "",
                    "notes": ev_notes,
                    "enrichment": {
                        "host_ip": enrichment_host_ip,
                        "note": "rDNS/ASN enrichments are performed by the analysis host and may appear in AdGuard query logs as PTR lookups from host_ip; they should not be interpreted as client DNS behavior.",
                    },
                },
                "recommendation": {
                    "action": "monitor" if verdict == "likely_benign" else "investigate",
                    "steps": [
                        "Confirm the device identity for src_ip (client name is included when available).",
                        "If not already attributed, correlate with Zeek dns.log/ssl.log for domain/SNI.",
                    ],
                },
                "allowlist_suggestion": {
                    "type": "none",
                    "value": "",
                    "scope": "network",
                    "reason": "Provide allowlisting instructions in alert comments; the UI does not include allowlist controls.",
                    "ttl_days": 0,
                },
            }
        )

    posture = "ok" if not items else "review"

    notes = [
        "Device friendly names are sourced from AdGuard Home registered clients when available.",
        "DNS correlation uses Zeek dns.log answers when present.",
        "Dismissed items (from dashboard feedback) are hidden.",
    ]
    if enrichment_host_ip:
        notes.append(
            f"Enrichment lookups (e.g., rDNS) originate from the analysis host ({enrichment_host_ip}) and may show up in AdGuard query logs; do not treat those PTR lookups as device behavior."
        )

    return {
        "day": day,
        "generated_at": now_iso_utc(),
        "summary": {
            "posture": posture,
            "headline": f"{len(items)} recurring beacon candidates (RITA).",
            "notes": notes,
        },
        "items": items,
        "allowlist_decisions": [],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--day", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--adguard-env", default=os.environ.get("ADGUARD_ENV") or os.path.expanduser("~/.openclaw/credentials/adguard.env"))
    args = ap.parse_args()

    workdir = args.workdir
    day = args.day

    cand_path = os.path.join(workdir, "state", f"{day}.candidates.json")
    digest_path = os.path.join(workdir, "state", f"{day}.digest.json")
    feedback_path = os.path.join(workdir, "state", "feedback.json")
    zeek_root = os.path.join(workdir, "zeek-logs")

    candidates = load_json(cand_path)
    feedback_for_day = load_feedback(feedback_path, day)
    client_map = adguard_client_map(args.adguard_env)

    enrichment_host_ip = os.environ.get("HOMENETSEC_ENRICHMENT_HOST_IP", "").strip()
    digest = build_digest(candidates, feedback_for_day, client_map, zeek_root, enrichment_host_ip)
    save_json_atomic(digest_path, digest)

    print(digest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
