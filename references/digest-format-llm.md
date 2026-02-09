# HomeNetSec Daily Digest format (LLM-oriented)

This document describes the **LLM-generated digest output** that powers the HomeNetSec dashboard.

## Input

The LLM triage step should read:
- `output/state/YYYY-MM-DD.candidates.json` (baseline-driven candidate alerts)
- optionally: `output/reports/YYYY-MM-DD.txt` (roll-up text)
- optionally: selected Zeek/Suricata/RITA artifacts for evidence

## Output

Write a JSON file:

- `output/state/YYYY-MM-DD.digest.json`

### Minimal schema (v1)

```json
{
  "day": "YYYY-MM-DD",
  "generated_at": "ISO-8601",
  "summary": {
    "posture": "ok|review|urgent",
    "headline": "short human sentence",
    "notes": ["optional bullet", "..."]
  },
  "items": [
    {
      "id": "stable-id-string",
      "kind": "rita_beacon|dns_nxdomain_spike|suricata_signature_alert|suricata_alert_summary|...",
      "severity": "info|low|med|high",
      "verdict": "likely_benign|needs_review|suspicious",
      "title": "one-line title",
      "what": "what happened",
      "why_flagged": "why it appeared as a candidate",
      "most_likely_explanation": "your best guess",
      "confidence": 0.0,
      "evidence": {
        "src_ip": "optional",
        "src_name": "optional (DNS/DHCP client name for src_ip, if available)",
        "dst_ip": "optional",
        "dst_port": 0,
        "domain": "optional",
        "rdns": "optional",
        "asn": "optional",
        "org": "optional",
        "notes": ["small evidence bullets"]
      },
      "recommendation": {
        "action": "ignore|monitor|investigate",
        "steps": ["next step", "..."]
      },
      "allowlist_suggestion": {
        "type": "domain|domain_suffix|dst_ip|rdns_suffix|none",
        "value": "string",
        "scope": "device|network",
        "reason": "why allowlisting is safe",
        "ttl_days": 0
      }
    }
  ],
  "allowlist_decisions": [
    {
      "type": "domain|domain_suffix|dst_ip|rdns_suffix",
      "value": "string",
      "scope": "device|network",
      "reason": "why",
      "ttl_days": 0
    }
  ]
}
```

Notes:
- Include a stable `kind` so the dashboard can render badges/sections consistently.
- Suricata signatures: by default, only Priority 1–2 signatures should be promoted to individual digest items; Priority 3 is often dominated by decoder/capture noise.
- `allowlist_suggestion` is the LLM’s recommendation; it must **not** imply firewall changes.
- If the system auto-applies allowlist updates, record them in `allowlist_decisions` (and surface in the daily summary).
- The dashboard can still accept user feedback per-item; this file is the machine-produced baseline digest.
