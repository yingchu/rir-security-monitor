# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

Security monitoring pipeline for all 5 global RIRs (APNIC, RIPE NCC, ARIN, LACNIC, AFRINIC).
Downloads daily delegation snapshots, detects anomalous resource acquisition patterns, and generates
shareable early-warning reports for RIR security contacts.

## Running the Pipeline

```bash
# Full pipeline (run in order)
python step1_download_and_parse.py      # Download & parse all 5 RIRs → Excel summary
python3 step2_explore.py                # Exploratory analysis per RIR → Excel workbooks
python3 step3_detect_anomalies.py       # Anomaly detection → rir_data/alerts/security_alerts_YYYYMMDD.xlsx
python3 step4_alert_report.py           # HTML report (Chinese) → rir_data/alerts/security_report_YYYYMMDD.html
python3 step4_alert_report_en.py        # HTML report (English) → rir_data/alerts/security_report_YYYYMMDD_en.html
```

Dependencies: `pip install requests pandas openpyxl numpy`

Each step depends on the previous — step2–4 require `rir_data/delegated-*-latest.txt` from step1.

## Architecture

```
step1_download_and_parse.py
  SOURCES: 5 RIRs (apnic/ripencc/arin/lacnic/afrinic)
  ├─ download()   → rir_data/delegated-{rir}-latest.txt  (overwritten each run)
  ├─ parse()      → pd.DataFrame (filters ZZ/*, converts date)
  └─ to_excel()   → rir_data/{rir}_delegation_YYYYMMDD.xlsx
                     sheets: 全部資料 / 國家統計 / 狀態統計

step2_explore.py
  ├─ parse()              → stricter (filters invalid status/type, value=0 fallback)
  ├─ analyze_recent()     → last 90 days allocated blocks
  ├─ analyze_top_holders()→ top 50 opaque_id by IPv4 count
  ├─ analyze_country()    → per-country IPv4/IPv6/ASN breakdown
  ├─ analyze_yearly_trend()→ allocation counts by year
  ├─ analyze_fresh_asn()  → ASNs allocated in last 180 days
  └─ process_one()        → rir_data/{rir}_explore_YYYYMMDD.xlsx

step3_detect_anomalies.py
  Five detection functions, each returns a DataFrame with 威脅等級 (高/中/低):
  A detect_rapid_accumulation()   → opaque_id with ≥65536 IPv4 in 90 days
  B detect_asn_burst()            → countries with z-score ≥2.5 new ASNs in 30 days
  C detect_cross_country_holders()→ opaque_id spanning ≥5 countries
  D detect_large_single_allocation()→ single IPv4 block ≥65536 in 90 days
  E detect_coordinated_acquisition()→ opaque_id with ASN+IPv4 in same 7 days
  → rir_data/alerts/security_alerts_YYYYMMDD.xlsx
     sheets: 預警摘要 / 高風險預警 / A–E / 偵測說明

step4_alert_report.py
  Reads alerts Excel → renders standalone HTML (Chinese) with:
  - KPI bar (高/中/低/total counts)
  - Per-detection-type sections with recommendations
  - RIR security contact table (5 RIRs with abuse emails)
  → rir_data/alerts/security_report_YYYYMMDD.html

step4_alert_report_en.py
  Same as step4, but fully in English — for sharing with RIR security contacts:
  - Translates threat levels (高/中/低 → High/Medium/Low) and detection type names
  - Translates all column headers and UI text
  → rir_data/alerts/security_report_YYYYMMDD_en.html
```

## Key Concepts

- **opaque_id**: RIR internal token tracking the same resource holder across allocations. Core to detecting accumulation and cross-country patterns.
- **Delegation Extended format**: Pipe-delimited (`registry|cc|type|start|value|date|status|opaque_id`). Lines starting with `#` or `2|` are headers/summary — skip. `cc=ZZ/*` = reserved.
- **Threat signals ranked by severity**:
  - Type E (coordinated: ASN + IPv4 same week) → attack infra setup, highest urgency
  - Type A (rapid IP accumulation ≥1M IPs) → high; ≥256K → medium
  - Type B (ASN burst z≥4.0) → high; z≥3.0 → medium
- **Output locations**: `.txt` source files overwritten each run; date-stamped `.xlsx`/`.html` accumulate in `rir_data/` and `rir_data/alerts/`.

## RIR Security Contacts (built into step4)

| RIR      | Email                |
|----------|----------------------|
| APNIC    | security@apnic.net   |
| RIPE NCC | abuse@ripe.net       |
| ARIN     | abuse@arin.net       |
| LACNIC   | abuse@lacnic.net     |
| AFRINIC  | abuse@afrinic.net    |
