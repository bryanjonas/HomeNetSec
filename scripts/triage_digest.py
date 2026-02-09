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
import sqlite3
import sys
from collections import Counter, defaultdict
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


def _parse_rita_summary_bytes(rita_summary_path: str) -> dict[tuple[str, str], dict]:
    """Parse rita-summary-YYYY-MM-DD.txt beacons table and return mapping (src,dst)->metrics."""
    out: dict[tuple[str, str], dict] = {}
    if not os.path.exists(rita_summary_path):
        return out
    in_beacons = False
    for line in open(rita_summary_path, "r", encoding="utf-8", errors="replace"):
        line = line.strip()
        if line.startswith("Top beacons:"):
            in_beacons = True
            continue
        if in_beacons and (not line or line.startswith("(") or line.startswith("Top ")):
            # end section
            if line.startswith("Top "):
                in_beacons = False
            continue
        if not in_beacons:
            continue
        # CSV row: Score,Source IP,Destination IP,Connections,Avg. Bytes,Total Bytes,...
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 6 or parts[0] == "Score":
            continue
        try:
            src = parts[1]
            dst = parts[2]
            conns = int(parts[3])
            avg_bytes = int(float(parts[4]))
            total_bytes = int(float(parts[5]))
            out[(src, dst)] = {"connections": conns, "avg_bytes": avg_bytes, "total_bytes": total_bytes}
        except Exception:
            continue
    return out


def _db_connect(db_path: str):
    if not os.path.exists(db_path):
        return None
    try:
        return sqlite3.connect(db_path)
    except Exception:
        return None


def _seen_dst_for_src(conn, src_ip: str, dst_ip: str, lookback_days: int, day: str) -> bool:
    """Was dst_ip seen as an external destination for src_ip in the prior lookback window?"""
    if conn is None:
        return False
    try:
        cur = conn.execute(
            """
            SELECT 1
            FROM day_dest_unique
            WHERE src_ip=? AND dst_ip=? AND day < ? AND day >= date(?, ?)
            LIMIT 1
            """,
            (src_ip, dst_ip, day, day, f"-{lookback_days} day"),
        )
        return cur.fetchone() is not None
    except Exception:
        return False


def _dns_nxdomain_stats(conn, day: str, lookback_days: int = 7):
    """Return per-client today's NXDOMAIN ratio and historical avg ratio."""
    if conn is None:
        return {}
    out = {}
    try:
        # today totals
        cur = conn.execute(
            """
            SELECT client_ip,
                   SUM(count) as total,
                   SUM(CASE WHEN rcode='NXDOMAIN' THEN count ELSE 0 END) as nx
            FROM day_dns_counts
            WHERE day=?
            GROUP BY client_ip
            """,
            (day,),
        )
        today = {r[0]: {"total": int(r[1] or 0), "nx": int(r[2] or 0)} for r in cur.fetchall()}

        # historical ratios
        cur2 = conn.execute(
            """
            SELECT day, client_ip,
                   SUM(count) as total,
                   SUM(CASE WHEN rcode='NXDOMAIN' THEN count ELSE 0 END) as nx
            FROM day_dns_counts
            WHERE day < ? AND day >= date(?, ?) 
            GROUP BY day, client_ip
            """,
            (day, day, f"-{lookback_days} day"),
        )
        hist_by_client = defaultdict(list)
        for d, ip, total, nx in cur2.fetchall():
            total = int(total or 0)
            nx = int(nx or 0)
            if total <= 0:
                continue
            hist_by_client[ip].append(nx / total)

        for ip, t in today.items():
            total = t["total"]
            nx = t["nx"]
            ratio = (nx / total) if total else 0.0
            hist = hist_by_client.get(ip) or []
            hist_avg = sum(hist) / len(hist) if hist else 0.0
            out[ip] = {"today_ratio": ratio, "today_total": total, "hist_avg_ratio": hist_avg}
        return out
    except Exception:
        return {}


def _suricata_summarize(workdir: str, day: str, src_dst_interest: set[tuple[str, str]]):
    """Summarize Suricata evidence.

    - TLS fingerprints (JA4) from EVE tls events
    - Alerts from fast.log (reliable even when EVE alert events are disabled)

    Returns:
      {
        "alerts": [{"key": str, "count": int, "priority": int}],
        "alerts_by_sig": { key: {"priority": int, "count": int, "top_tuples": [{"src_ip":..,"dst_ip":..,"dst_port":..,"count":..}] } },
        "tls_fp": {"src|dst": [{"ja4":...,"count":...}, ...]}
      }

    Keep it cheap: only scan a handful of recent eve-*.json files, and only the tail of fast.log.
    """
    suri_dir = os.path.join(workdir, "suricata", day)
    if not os.path.isdir(suri_dir):
        return {"alerts": [], "alerts_by_sig": {}, "tls_fp": {}}

    # Prefer per-merged EVE files; fall back to eve.json
    eve_files = sorted(glob.glob(os.path.join(suri_dir, "eve-*.json")))
    if not eve_files and os.path.exists(os.path.join(suri_dir, "eve.json")):
        eve_files = [os.path.join(suri_dir, "eve.json")]

    eve_files = sorted(eve_files, key=lambda p: os.path.getmtime(p))[-6:]

    ja4_counts = Counter()  # (src,dst,ja4)
    for p in eve_files:
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        continue

                    if ev.get("event_type") != "tls":
                        continue
                    src = ev.get("src_ip")
                    dst = ev.get("dest_ip")
                    if not src or not dst:
                        continue
                    if src_dst_interest and (src, dst) not in src_dst_interest:
                        continue
                    tls = ev.get("tls") or {}
                    ja4 = tls.get("ja4")
                    if ja4:
                        ja4_counts[(src, dst, str(ja4))] += 1
        except Exception:
            continue

    fp_by_tuple = defaultdict(list)
    for (src, dst, fp), c in ja4_counts.most_common(80):
        fp_by_tuple[(src, dst)].append({"ja4": fp, "count": c})

    # Alerts from fast.log tail
    fast_path = os.path.join(suri_dir, "fast.log")
    alert_counts = Counter()
    alert_prio = {}
    tuple_counts = Counter()  # (sig_key, src_ip, dst_ip, dst_port)

    try:
        if os.path.exists(fast_path):
            from collections import deque

            dq = deque(maxlen=50000)
            with open(fast_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    dq.append(line.rstrip("\n"))

            # Example fast.log line:
            # 02/09/2026-05:06:30.889307  [**] [1:2260002:1] SURICATA ... [**] [Classification: ...] [Priority: 3] {TCP} 192.168.1.X:53104 -> 204.80.128.1:443
            re_sig = re.compile(r"\[\*\*\]\s*\[(\d+):(\d+):(\d+)\]\s*([^\[]+?)\s*\[\*\*\]")
            re_prio = re.compile(r"\[Priority:\s*(\d+)\]")
            re_tuple = re.compile(r"\}\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)")

            for line in dq:
                m = re_sig.search(line)
                if not m:
                    continue
                gid, sid, rev, sig = m.group(1), m.group(2), m.group(3), m.group(4).strip()
                key = f"{gid}:{sid}:{rev}:{sig}"

                mp = re_prio.search(line)
                prio = int(mp.group(1)) if mp else 3
                # keep the lowest priority number seen for this signature
                alert_prio[key] = min(prio, alert_prio.get(key, prio))

                alert_counts[key] += 1

                mt = re_tuple.search(line)
                if mt:
                    src_ip, src_port, dst_ip, dst_port = mt.group(1), mt.group(2), mt.group(3), mt.group(4)
                    tuple_counts[(key, src_ip, dst_ip, int(dst_port))] += 1
    except Exception:
        pass

    top_alerts = [
        {"key": k, "count": c, "priority": int(alert_prio.get(k, 3))}
        for k, c in alert_counts.most_common(20)
    ]

    alerts_by_sig = {}
    for ent in top_alerts:
        k = ent["key"]
        pr = ent.get("priority", 3)
        # gather top tuples
        tups = []
        for (kk, src_ip, dst_ip, dst_port), c in tuple_counts.most_common(200):
            if kk != k:
                continue
            tups.append({"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port, "count": c})
            if len(tups) >= 8:
                break
        alerts_by_sig[k] = {"priority": pr, "count": int(ent["count"]), "top_tuples": tups}

    return {
        "alerts": top_alerts,
        "alerts_by_sig": alerts_by_sig,
        "tls_fp": {f"{src}|{dst}": v for (src, dst), v in fp_by_tuple.items()},
    }


def build_digest(candidates: dict, feedback_for_day: dict, client_map: dict[str, str], zeek_logs_root: str, enrichment_host_ip: str, workdir: str) -> dict:
    day = candidates.get("day") or ""
    signals = (candidates.get("signals") or {})

    # Baseline DB (for per-device novelty + DNS anomalies)
    baseline_db_path = os.path.join(workdir, "state", "baselines.sqlite")
    db = _db_connect(baseline_db_path)

    # RITA beacon extra metrics (bytes)
    rita_summary_path = os.path.join(workdir, "rita-data", f"rita-summary-{day}.txt")
    rita_metrics = _parse_rita_summary_bytes(rita_summary_path)

    # Interest set for Suricata TLS/alerts filtering
    src_dst_interest: set[tuple[str, str]] = set()
    for b in (signals.get("rita_beacons") or []):
        if isinstance(b, dict) and b.get("src_ip") and b.get("dst_ip"):
            src_dst_interest.add((b.get("src_ip"), b.get("dst_ip")))

    suri = _suricata_summarize(workdir, day, src_dst_interest)

    items = []

    # 2) Per-device novelty (dst_ip not seen for this src in 30d)
    # 3) Beacon quality scoring (use bytes per conn from RITA summary when available)
    lookback_days = 30

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

        seen_before = _seen_dst_for_src(db, src, dst, lookback_days, day)

        score = float(b.get("score") or 0.0)
        severity = "med" if score >= 0.99 else "low"
        if not seen_before and severity == "low":
            severity = "med"  # new-for-device gets bumped

        title = f"Periodic connections: {src} → {dst}"
        if src_name:
            title = f"Periodic connections: {src_name} ({src}) → {dst}"
        if domain:
            title += f" (DNS: {domain})"

        verdict = "needs_review"
        if domain.endswith(".pool.ntp.org") or "ntp" in (b.get("dst_rdns") or ""):
            verdict = "likely_benign"

        # Beacon quality heuristics
        bm = rita_metrics.get((src, dst)) or {}
        avg_bytes = bm.get("avg_bytes")
        total_bytes = bm.get("total_bytes")
        conns = int(b.get("connections") or 0)
        bytes_per_conn = (total_bytes / conns) if (total_bytes and conns) else None

        quality_notes = []
        if bytes_per_conn is not None:
            quality_notes.append(f"bytes_per_conn≈{bytes_per_conn:.1f}")
            if bytes_per_conn < 400:
                quality_notes.append("pattern=small-periodic (NTP/keepalive-like)")
            elif bytes_per_conn > 5000:
                quality_notes.append("pattern=larger-periodic (worth attribution)")

        ev_notes = []
        if b.get("dst_rdns"):
            ev_notes.append(f"dst_rdns={b.get('dst_rdns')}")
            if enrichment_host_ip:
                ev_notes.append(f"rdns_source=enrichment (resolver traffic originates from {enrichment_host_ip})")
        if domains:
            ev_notes.append("dns_queries=" + ", ".join(domains))
        if not seen_before:
            ev_notes.append(f"novelty=new-for-device (not seen for {src} in prior {lookback_days}d)")
        ev_notes.extend(quality_notes)

        # JA4 evidence if present in suricata scan
        fp_key = f"{src}|{dst}"
        ja4_list = (suri.get("tls_fp") or {}).get(fp_key) or []
        if ja4_list:
            ev_notes.append(f"ja4_top={ja4_list[0].get('ja4')}")

        items.append(
            {
                "id": alert_id,
                "kind": "rita_beacon",
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

    # 4) DNS anomalies (NXDOMAIN spikes)
    dns_stats = _dns_nxdomain_stats(db, day, lookback_days=7)
    for ip, st in dns_stats.items():
        total = st.get("today_total") or 0
        ratio = st.get("today_ratio") or 0.0
        hist = st.get("hist_avg_ratio") or 0.0
        if total < 200:
            continue
        if ratio < 0.25:
            continue
        if ratio < hist * 2 and ratio < 0.4:
            continue

        name = client_map.get(ip, "")
        title = f"DNS NXDOMAIN spike: {ip}"
        if name:
            title = f"DNS NXDOMAIN spike: {name} ({ip})"

        items.append(
            {
                "id": f"dns_nxdomain|{ip}|{day}",
                "kind": "dns_nxdomain_spike",
                "severity": "med",
                "verdict": "needs_review",
                "title": title,
                "what": f"High NXDOMAIN ratio today ({ratio:.1%}) over {total} DNS queries.",
                "why_flagged": f"NXDOMAIN ratio {ratio:.1%} vs 7d avg {hist:.1%}",
                "most_likely_explanation": "Misconfiguration, blocked tracking, or DGA-like lookups; needs context.",
                "confidence": 0.55,
                "evidence": {
                    "src_ip": ip,
                    "src_name": name,
                    "notes": [f"today_total={total}", f"today_nxdomain_ratio={ratio:.3f}", f"hist_avg_ratio={hist:.3f}"]
                },
                "recommendation": {
                    "action": "investigate",
                    "steps": [
                        "Check AdGuard query log for top NXDOMAIN qnames for this client.",
                        "If expected (tracker blocking), comment and consider dismissing.",
                    ],
                },
                "allowlist_suggestion": {"type": "none", "value": "", "scope": "network", "reason": "", "ttl_days": 0},
            }
        )

    # 6) Suricata alerts: promote ONLY Priority 1–2 signatures as individual digest items.
    # Priority 3 is currently dominated by decoder/capture artifacts and is treated as junk by default.
    top_alerts = suri.get("alerts") or []
    alerts_by_sig = suri.get("alerts_by_sig") or {}

    p12 = [a for a in top_alerts if int(a.get("priority", 3)) in (1, 2)]

    for a in p12[:8]:
        key = a.get("key")
        if not key:
            continue
        meta = alerts_by_sig.get(key) or {}
        prio = int(meta.get("priority", a.get("priority", 3)) or 3)
        cnt = int(meta.get("count", a.get("count", 0)) or 0)

        alert_id = f"suricata_sig|{key}|{day}"
        if is_dismissed(feedback_for_day, alert_id):
            continue

        tuples = meta.get("top_tuples") or []
        rep = tuples[0] if tuples else {}
        src_ip = rep.get("src_ip", "")
        dst_ip = rep.get("dst_ip", "")
        dst_port = int(rep.get("dst_port") or 0)

        src_name = client_map.get(src_ip, "") if src_ip else ""
        domains = zeek_dns_domains_for_ip(zeek_logs_root, day, dst_ip) if dst_ip else []
        domain = domains[0] if domains else ""

        sig_text = key.split(":", 3)[-1]
        title = f"Suricata P{prio}: {sig_text}"
        if src_ip and dst_ip:
            left = f"{src_name} ({src_ip})" if src_name else src_ip
            right = dst_ip + (f":{dst_port}" if dst_port else "")
            if domain:
                right += f" (DNS: {domain})"
            title = f"Suricata P{prio}: {left} → {right}"

        ev_notes = [f"priority={prio}", f"count={cnt}"]
        if tuples:
            ev_notes.append(
                "top_tuples=" + "; ".join(
                    [
                        f"{t.get('src_ip')}→{t.get('dst_ip')}:{t.get('dst_port')} ({t.get('count')})"
                        for t in tuples[:5]
                    ]
                )
            )

        items.append(
            {
                "id": alert_id,
                "kind": "suricata_signature_alert",
                "severity": "high" if prio == 1 else "med",
                "verdict": "needs_review",
                "title": title,
                "what": "Suricata signature matched traffic observed in offline PCAP processing.",
                "why_flagged": f"Suricata Priority {prio} signature matched ({cnt} hits).",
                "most_likely_explanation": "Depends on signature; correlate to DNS/SNI and device context.",
                "confidence": 0.55,
                "evidence": {
                    "src_ip": src_ip,
                    "src_name": src_name,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "domain": domain,
                    "notes": ev_notes,
                },
                "recommendation": {
                    "action": "investigate",
                    "steps": [
                        "Review the ET/Open signature meaning (rule text).",
                        "Correlate dst_ip to domain via Zeek dns.log and/or AdGuard query log.",
                        "If expected, comment and dismiss; if not, investigate further.",
                    ],
                },
                "allowlist_suggestion": {"type": "none", "value": "", "scope": "network", "reason": "", "ttl_days": 0},
            }
        )

    # Keep a small summary card ONLY for Priority 1–2 if any exist.
    if p12:
        items.append(
            {
                "id": f"suricata_alerts_p12|{day}",
                "kind": "suricata_alert_summary",
                "severity": "info",
                "verdict": "needs_review",
                "title": "Suricata alerts (Priority 1–2)",
                "what": "High-priority Suricata signatures (Priority 1–2) observed in offline processing.",
                "why_flagged": "Priority 1–2 signatures are surfaced as individual items above.",
                "most_likely_explanation": "Review each signature item; dismiss those confirmed benign.",
                "confidence": 0.65,
                "evidence": {"notes": [f"{x.get('count')}× P{x.get('priority')} {x.get('key')}" for x in p12[:8]]},
                "recommendation": {"action": "investigate", "steps": ["Review the per-signature items above."]},
                "allowlist_suggestion": {"type": "none", "value": "", "scope": "network", "reason": "", "ttl_days": 0},
            }
        )

    posture = "ok" if not items else "review"

    notes = [
        "Device friendly names are sourced from AdGuard Home registered clients when available.",
        "Per-device novelty is computed from baselines.sqlite (day_dest_unique).",
        "DNS NXDOMAIN anomaly checks use baselines.sqlite (day_dns_counts).",
        "DNS correlation uses Zeek dns.log answers when present.",
        "TLS JA4 evidence is pulled from recent Suricata EVE tls events when present.",
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
            "headline": f"{len(items)} items surfaced (beacons + anomalies + alerts).",
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
    digest = build_digest(candidates, feedback_for_day, client_map, zeek_root, enrichment_host_ip, workdir)
    save_json_atomic(digest_path, digest)

    print(digest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
