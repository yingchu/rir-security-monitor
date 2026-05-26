[繁體中文](README.zh.md) | English

# RIR Security Monitor

**[→ Live Demo (English)](https://yingchu.github.io/rir-security-monitor/)** | **[繁體中文](https://yingchu.github.io/rir-security-monitor/zh.html)**

Early-warning pipeline for anomalous Internet number resource acquisition across all five Regional Internet Registries (RIRs): **APNIC, RIPE NCC, ARIN, LACNIC, AFRINIC**.

## Why This Exists

RIRs' own security tooling (RPKI, ARTEMIS, RIS) operates at the **routing layer** — they detect what happens *after* resources are announced. This pipeline works one layer upstream: it detects suspicious **allocation patterns** in delegation records before any BGP announcement occurs.

### Why don't the RIRs build this themselves?

Several structural reasons:

- **Conflict of interest** — RIRs are member-funded organisations whose members vote on governance. Flagging a paying member as suspicious creates legal and political risk that an independent tool does not face.
- **Mandate boundary** — RIRs verify resource applications at the point of request (one-time due diligence). Ongoing post-allocation behavioural monitoring is outside their stated remit.
- **Siloed by region** — Each RIR operates independently. Cross-RIR analysis requires coordination that is both technically and politically costly. This pipeline combines all five by default.
- **No one owns this layer** — The gap between allocation-time checks (RIR) and route-announcement checks (RPKI/ARTEMIS) has no institutional owner. RIRs consider it out of scope; commercial security vendors lack access to delegation data.
- **False-positive cost** — If an RIR publicly flags one of its own members and turns out to be wrong, the reputational damage outweighs the benefit. An independent tool operates with more analytical freedom.

This is structurally similar to credit-rating agencies assessing bonds issued by their clients: the analysis is most credible when performed by an independent third party, not the issuing institution. **The tool's independence is a feature, not a limitation.**

Signals it looks for:

| Type | Signal | Why It Matters |
|------|--------|----------------|
| A | Rapid IP accumulation (≥65536 IPs in 90 days, same entity) | Attack infrastructure build-up |
| B | ASN country burst (z-score ≥2.5 new ASNs in 30 days) | Coordinated registration campaign |
| C | Cross-country holdings (same opaque_id, ≥5 countries) | Proxy concealment of true controller |
| D | Large single allocation (≥/16 in 90 days) | High-volume resource grab |
| E | Coordinated acquisition (ASN + IPv4 same week, same entity) | Routing infrastructure setup — highest urgency |

## Requirements

```bash
pip install -r requirements.txt
```

Python 3.10+. The `whois` CLI must also be available on your system (`brew install whois` on macOS, `apt install whois` on Debian/Ubuntu).

## Usage

Run steps in order. Each step depends on the previous one.

```bash
# Step 1 — Download & parse delegation files from all 5 RIRs
python3 step1_download_and_parse.py

# Step 2 — Exploratory analysis per RIR
python3 step2_explore.py

# Step 3 — Anomaly detection → rir_data/alerts/security_alerts_YYYYMMDD.xlsx
python3 step3_detect_anomalies.py

# Step 4 — HTML alert report (Chinese)
python3 step4_alert_report.py

# Step 4 (EN) — HTML alert report (English), suitable for sending to RIR security contacts
python3 step4_alert_report_en.py
```

### Output

```
rir_data/
├── delegated-{rir}-latest.txt          # Raw delegation files (overwritten each run)
├── {rir}_delegation_YYYYMMDD.xlsx      # Parsed data per RIR
├── {rir}_explore_YYYYMMDD.xlsx         # Exploratory analysis per RIR
└── alerts/
    ├── security_alerts_YYYYMMDD.xlsx   # Structured alerts (all detection types)
    ├── security_report_YYYYMMDD.html    # Shareable report (Chinese) — includes WHOIS enrichment
    └── security_report_YYYYMMDD_en.html # Shareable report (English) — includes WHOIS enrichment
```

## Detection Logic

### A — Rapid IP Accumulation
Aggregates IPv4 blocks by `opaque_id` over the past 90 days. Flags any entity with ≥65536 IPs accumulated. Threat level scales with volume (≥1M → High, ≥256K → Medium).

### B — ASN Country Burst
Counts new ASNs per country per RIR over the past 30 days, computes a z-score within each RIR. Flags countries at z ≥ 2.5. High at z ≥ 4.0, Medium at z ≥ 3.0.

### C — Cross-Country Holdings
Groups all allocations by `opaque_id` and counts distinct country codes. Flags any entity spanning ≥5 countries.

### D — Large Single Allocation
Flags any single IPv4 allocation with value ≥65536 (≥/16) made in the past 90 days.

### E — Coordinated Acquisition
For each `opaque_id`, finds cases where an ASN and at least one IPv4 block were allocated within the same 7-day window.

## WHOIS Enrichment

High-risk alerts are automatically enriched with WHOIS data at report generation time (`whois_enrich.py`). For each flagged `opaque_id`, the pipeline:

1. Looks up the associated IPv4 start address or ASN from the delegation files
2. Runs a system `whois` query against it
3. Parses entity name, description, and registered country
4. Embeds the results in a summary table at the top of the HTML report

This lets recipients immediately see who holds the flagged resource without performing manual WHOIS lookups. Results should be verified independently — WHOIS data may be incomplete or inaccurate.

## Key Concepts

**opaque_id** — An RIR-internal token that tracks the same resource holder across multiple allocations. It is the key to detecting accumulation and cross-country patterns without requiring WHOIS identity.

**Delegation Extended format** — Pipe-delimited: `registry|cc|type|start|value|date|status|opaque_id`. Lines starting with `#` or `2|` are headers/summaries and are skipped. `cc=ZZ/*` indicates reserved space.

## RIR Security Contacts

| RIR      | Region                        | Contact                  |
|----------|-------------------------------|--------------------------|
| APNIC    | Asia Pacific                  | security@apnic.net       |
| RIPE NCC | Europe / Middle East / CIS    | abuse@ripe.net           |
| ARIN     | North America                 | abuse@arin.net           |
| LACNIC   | Latin America / Caribbean     | abuse@lacnic.net         |
| AFRINIC  | Africa                        | abuse@afrinic.net        |

## Automation

To run daily, add a cron job or system scheduler entry that executes all four steps in sequence. Outputs are date-stamped so historical runs accumulate without overwriting.

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

You are free to use, modify, and distribute this software under the terms of the GPL-3.0. Derivative works must be distributed under the same license.
