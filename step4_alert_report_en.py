"""
Step 4 (EN): RIR Security Alert Report Generator — English version
Reads step3 alert Excel and outputs a shareable HTML report in English.
"""

import pandas as pd
from pathlib import Path
from datetime import datetime
import html
import glob
from whois_enrich import enrich as whois_enrich

OUTPUT_DIR = Path("rir_data")
ALERT_DIR  = OUTPUT_DIR / "alerts"
TODAY      = datetime.today()
DATE_STR   = TODAY.strftime("%Y%m%d")

RIR_CONTACTS = {
    "APNIC":    {"region": "Asia Pacific",              "security": "security@apnic.net", "url": "https://www.apnic.net"},
    "RIPE NCC": {"region": "Europe / Middle East / CIS","security": "abuse@ripe.net",     "url": "https://www.ripe.net"},
    "ARIN":     {"region": "North America",             "security": "abuse@arin.net",     "url": "https://www.arin.net"},
    "LACNIC":   {"region": "Latin America / Caribbean", "security": "abuse@lacnic.net",   "url": "https://www.lacnic.net"},
    "AFRINIC":  {"region": "Africa",                    "security": "abuse@afrinic.net",  "url": "https://www.afrinic.net"},
}

THREAT_COLORS = {"High": "#d32f2f", "Medium": "#f57c00", "Low": "#388e3c"}
THREAT_BG     = {"High": "#ffebee", "Medium": "#fff3e0", "Low": "#e8f5e9"}

LEVEL_MAP = {"高": "High", "中": "Medium", "低": "Low"}

DTYPE_MAP = {
    "A - 高速IP資源累積": "A - Rapid IP Accumulation",
    "B - 新ASN國家爆發":  "B - ASN Country Burst",
    "C - 跨國資源持有":   "C - Cross-Country Holdings",
    "D - 巨型單次分配":   "D - Large Single Allocation",
    "E - 協同取得模式":   "E - Coordinated Acquisition",
}

COL_MAP = {
    "涵蓋國家":   "Countries",
    "新增ASN數":  "New ASNs",
    "新增IPv4區塊": "New IPv4 Blocks",
    "IPv4總量":   "Total IPv4",
    "最早日期":   "First Date",
    "最近日期":   "Latest Date",
    "威脅等級":   "Threat Level",
    "偵測類型":   "Detection Type",
    "國家數":     "Country Count",
    "總IP數量":   "Total IPs",
    "區塊數":     "Block Count",
    "最近分配":   "Latest Allocation",
    "距今天數":   "Days Ago",
    "新增區塊數": "New Blocks",
    "累積IP數量": "Accumulated IPs",
    "CIDR前綴長度": "CIDR Prefix",
}

DETECTION_DESC = {
    "A - Rapid IP Accumulation":  ("🔴", "Same entity accumulated large IPv4 volume within 90 days — possible attack infrastructure build-up"),
    "B - ASN Country Burst":      ("🟠", "Statistically anomalous surge in new ASNs from a specific country — possible coordinated action"),
    "C - Cross-Country Holdings": ("🟡", "Same opaque_id holds resources across ≥5 countries — possible proxy concealment of true controller"),
    "D - Large Single Allocation":("🟠", "Single IPv4 allocation ≥/16 — high risk if assigned to an unknown entity"),
    "E - Coordinated Acquisition":("🔴", "Same entity acquired ASN + IPv4 within 7 days — consistent with routing infrastructure setup"),
}

RECOMMENDATIONS = {
    "A - Rapid IP Accumulation": [
        "Identify the entity name and business background linked to the opaque_id",
        "Verify whether a legitimate operational need justifies the scale",
        "Monitor BGP route announcements for the related IP blocks",
        "If unverifiable, notify the relevant RIR for enhanced scrutiny",
    ],
    "B - ASN Country Burst": [
        "Contact the national NIC or relevant authority to verify ASN application legitimacy",
        "Increase BGP monitoring for newly issued ASNs from the country",
        "Share intelligence with MANRS routing-security initiative partners",
        "Evaluate whether to raise the ASN application review threshold for that country",
    ],
    "C - Cross-Country Holdings": [
        "Review whether cross-country holdings comply with each RIR's transfer policy",
        "Verify the accuracy and completeness of WHOIS data",
        "Consider requiring additional identity verification from the holder",
        "Cross-reference the same opaque_id allocation records across other RIRs",
    ],
    "D - Large Single Allocation": [
        "Contact the allocating RIR to confirm applicant identity and stated purpose",
        "Confirm the allocation passed normal resource request review procedures",
        "Enable enhanced monitoring to track subsequent BGP route announcements",
        "If route announcements appear within 30 days, escalate to high priority immediately",
    ],
    "E - Coordinated Acquisition": [
        "Immediately track BGP route announcement status for related ASNs",
        "Confirm whether ASN and IP applications were submitted by the same organization",
        "If routes are already announced, notify downstream ISPs and RPKI validators",
        "Assess whether this matches the precursor pattern of a BGP hijack",
    ],
}


def load_latest_alerts() -> pd.DataFrame | None:
    pattern = str(ALERT_DIR / f"security_alerts_{DATE_STR}.xlsx")
    files = glob.glob(pattern)
    if not files:
        all_files = sorted(glob.glob(str(ALERT_DIR / "security_alerts_*.xlsx")))
        if not all_files:
            return None
        files = [all_files[-1]]

    try:
        xl = pd.ExcelFile(files[0])
        dfs = []
        for sheet in xl.sheet_names:
            if sheet not in ("預警摘要", "偵測說明"):
                try:
                    dfs.append(pd.read_excel(xl, sheet_name=sheet))
                except Exception:
                    pass
        if not dfs:
            return None
        df = pd.concat(dfs, ignore_index=True)

        # Translate threat levels and detection types
        if "威脅等級" in df.columns:
            df["威脅等級"] = df["威脅等級"].map(LEVEL_MAP).fillna(df["威脅等級"])
        if "偵測類型" in df.columns:
            df["偵測類型"] = df["偵測類型"].map(DTYPE_MAP).fillna(df["偵測類型"])

        # Rename columns to English
        df = df.rename(columns=COL_MAP)
        return df
    except Exception as e:
        print(f"Failed to load alert file: {e}")
        return None


def render_summary_cards(df: pd.DataFrame) -> str:
    cards = []
    dtype_col = "Detection Type"
    level_col = "Threat Level"
    for dtype, grp in df.groupby(dtype_col):
        icon, desc = DETECTION_DESC.get(dtype, ("⚪", dtype))
        high = len(grp[grp[level_col] == "High"])
        mid  = len(grp[grp[level_col] == "Medium"])
        low  = len(grp[grp[level_col] == "Low"])
        dominant = "High" if high else ("Medium" if mid else "Low")
        border_color = THREAT_COLORS[dominant]
        bg_color = THREAT_BG[dominant]
        cards.append(f"""
        <div class="card" style="border-left:5px solid {border_color};background:{bg_color}">
          <div class="card-icon">{icon}</div>
          <div class="card-body">
            <div class="card-title">{html.escape(dtype)}</div>
            <div class="card-desc">{html.escape(desc)}</div>
            <div class="card-counts">
              <span class="badge high">High {high}</span>
              <span class="badge mid">Medium {mid}</span>
              <span class="badge low">Low {low}</span>
            </div>
          </div>
        </div>""")
    return "\n".join(cards)


def render_alert_table(df: pd.DataFrame, dtype: str) -> str:
    dtype_col = "Detection Type"
    level_col = "Threat Level"
    subset = df[df[dtype_col] == dtype].copy() if dtype_col in df.columns else df.copy()
    if subset.empty:
        return "<p>No alerts of this type.</p>"

    subset = subset.drop(columns=[c for c in [dtype_col] if c in subset.columns])
    # Drop columns that are entirely NaN
    subset = subset.dropna(axis=1, how="all")

    rows_html = []
    for _, row in subset.iterrows():
        level = str(row.get(level_col, ""))
        color = THREAT_COLORS.get(level, "#555")
        bg    = THREAT_BG.get(level, "#fff")
        cells = "".join(
            f"<td>{html.escape(str(v)) if pd.notna(v) else ''}</td>"
            for v in row.values
        )
        rows_html.append(f'<tr style="background:{bg}">{cells}</tr>')

    headers = "".join(f"<th>{html.escape(c)}</th>" for c in subset.columns)
    return f"""
    <div class="table-wrap">
      <table>
        <thead><tr>{headers}</tr></thead>
        <tbody>{"".join(rows_html)}</tbody>
      </table>
    </div>"""


def render_rir_contact_table() -> str:
    rows = []
    for rir, info in RIR_CONTACTS.items():
        rows.append(f"""
        <tr>
          <td><strong>{html.escape(rir)}</strong></td>
          <td>{html.escape(info['region'])}</td>
          <td><a href="mailto:{info['security']}">{info['security']}</a></td>
          <td><a href="{info['url']}" target="_blank">{info['url']}</a></td>
        </tr>""")
    return "".join(rows)


def render_whois_section(df: pd.DataFrame) -> str:
    level_col = "Threat Level"
    high = df[df[level_col] == "High"].copy()
    # opaque_id column may still be named opaque_id (not translated)
    opaque_ids = set(high["opaque_id"].dropna()) if "opaque_id" in high.columns else set()
    if not opaque_ids:
        return ""

    print(f"  WHOIS lookup: {len(opaque_ids)} high-risk items…")
    enriched = whois_enrich(opaque_ids, OUTPUT_DIR)

    rows = []
    for _, row in high.drop_duplicates("opaque_id").iterrows():
        oid = row.get("opaque_id", "")
        if not oid or oid not in enriched:
            continue
        info = enriched[oid]
        dtype = html.escape(str(row.get("Detection Type", "") or row.get("偵測類型", "")))
        cc    = html.escape(str(row.get("Countries", "") or row.get("country", "") or row.get("涵蓋國家", "")))
        query = html.escape(info.get("query", ""))
        name  = html.escape(info.get("name", "") or info.get("descr", ""))
        descr = html.escape(info.get("descr", ""))
        ctry  = html.escape(info.get("country", ""))
        indicators = info.get("cidrs", []) + info.get("asns", [])
        indicators_html = "<br>".join(f"<code>{html.escape(i)}</code>" for i in indicators[:15])
        rows.append(f"""
        <tr>
          <td><code>{html.escape(str(oid))}</code></td>
          <td>{dtype}</td>
          <td>{cc}</td>
          <td><code>{query}</code></td>
          <td><strong>{name}</strong></td>
          <td>{descr}</td>
          <td>{ctry}</td>
          <td style="min-width:160px"><div style="max-height:80px;overflow-y:auto">{indicators_html}</div></td>
        </tr>""")

    if not rows:
        return ""

    return f"""
  <div class="whois-section">
    <h2>🔍 WHOIS Lookup — High-Risk Items</h2>
    <p class="section-desc">Automated WHOIS lookup results for each high-risk opaque_id. Use as a starting point for entity verification — always confirm WHOIS accuracy independently before escalating.</p>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>opaque_id</th><th>Detection Type</th><th>Country</th>
          <th>Queried</th><th>Entity Name</th><th>Description</th><th>Registered Country</th><th>IP Blocks / ASNs</th>
        </tr></thead>
        <tbody>{"".join(rows)}</tbody>
      </table>
    </div>
  </div>"""


def generate_html(df: pd.DataFrame) -> str:
    level_col = "Threat Level"
    dtype_col = "Detection Type"
    total   = len(df)
    n_high  = len(df[df[level_col] == "High"])
    n_mid   = len(df[df[level_col] == "Medium"])
    n_low   = len(df[df[level_col] == "Low"])
    n_types = df[dtype_col].nunique()

    summary_cards = render_summary_cards(df)
    whois_html = render_whois_section(df)

    sections = []
    for dtype in df[dtype_col].unique():
        icon, desc = DETECTION_DESC.get(dtype, ("⚪", dtype))
        recs = RECOMMENDATIONS.get(dtype, [])
        rec_items = "".join(f"<li>{html.escape(r)}</li>" for r in recs)
        table_html = render_alert_table(df, dtype)
        sections.append(f"""
        <section>
          <h2>{icon} {html.escape(dtype)}</h2>
          <p class="section-desc">{html.escape(desc)}</p>
          <h3>Recommended Actions</h3>
          <ul>{rec_items}</ul>
          <h3>Alert List</h3>
          {table_html}
        </section>""")

    contact_rows = render_rir_contact_table()
    sections_html = "\n".join(sections)
    run_time = TODAY.strftime("%Y-%m-%d %H:%M")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>RIR Network Security Alert Report {DATE_STR}</title>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ font-family:"Segoe UI","Helvetica Neue",Arial,sans-serif; background:#f5f7fa; color:#222; }}
    header {{ background:#1a237e; color:#fff; padding:32px 40px; }}
    header h1 {{ font-size:1.6rem; font-weight:700; }}
    header p  {{ margin-top:6px; font-size:.9rem; opacity:.85; }}
    .container {{ max-width:1200px; margin:0 auto; padding:32px 24px; }}
    .kpi-bar {{ display:flex; gap:16px; margin-bottom:32px; flex-wrap:wrap; }}
    .kpi {{ background:#fff; border-radius:8px; padding:20px 28px; flex:1;
             min-width:140px; box-shadow:0 1px 4px rgba(0,0,0,.1); text-align:center; }}
    .kpi .num {{ font-size:2.2rem; font-weight:700; }}
    .kpi .label {{ font-size:.8rem; color:#666; margin-top:4px; }}
    .kpi.high .num {{ color:#d32f2f; }}
    .kpi.mid  .num {{ color:#f57c00; }}
    .kpi.low  .num {{ color:#388e3c; }}
    .cards {{ display:flex; flex-direction:column; gap:14px; margin-bottom:36px; }}
    .card {{ display:flex; align-items:flex-start; gap:16px; padding:18px 20px;
             border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,.08); }}
    .card-icon {{ font-size:2rem; line-height:1; }}
    .card-title {{ font-weight:700; font-size:1rem; margin-bottom:4px; }}
    .card-desc  {{ font-size:.85rem; color:#444; }}
    .card-counts {{ margin-top:10px; display:flex; gap:8px; }}
    .badge {{ padding:2px 10px; border-radius:12px; font-size:.78rem; font-weight:600; color:#fff; }}
    .badge.high {{ background:#d32f2f; }}
    .badge.mid  {{ background:#f57c00; }}
    .badge.low  {{ background:#388e3c; }}
    section {{ background:#fff; border-radius:8px; padding:28px 32px;
               margin-bottom:28px; box-shadow:0 1px 4px rgba(0,0,0,.08); }}
    section h2 {{ font-size:1.15rem; font-weight:700; margin-bottom:8px; border-bottom:2px solid #e0e0e0; padding-bottom:8px; }}
    .section-desc {{ color:#555; font-size:.9rem; margin-bottom:16px; }}
    section h3 {{ font-size:.95rem; font-weight:700; margin:18px 0 8px; color:#1a237e; }}
    ul {{ padding-left:20px; }}
    ul li {{ font-size:.88rem; margin-bottom:4px; color:#333; }}
    .table-wrap {{ overflow-x:auto; margin-top:8px; }}
    table {{ border-collapse:collapse; width:100%; font-size:.8rem; }}
    th {{ background:#1a237e; color:#fff; padding:8px 12px; text-align:left; white-space:nowrap; }}
    td {{ padding:7px 12px; border-bottom:1px solid #e0e0e0; white-space:nowrap; }}
    .contact-section {{ background:#fff; border-radius:8px; padding:28px 32px;
                        box-shadow:0 1px 4px rgba(0,0,0,.08); margin-bottom:28px; }}
    .contact-section h2 {{ font-size:1.1rem; font-weight:700; margin-bottom:16px; }}
    .contact-section a {{ color:#1565c0; text-decoration:none; }}
    .whois-section {{ background:#fff; border-radius:8px; padding:28px 32px;
                      box-shadow:0 1px 4px rgba(0,0,0,.08); margin-bottom:28px;
                      border-top:4px solid #d32f2f; }}
    .whois-section h2 {{ font-size:1.15rem; font-weight:700; margin-bottom:8px; }}
    footer {{ text-align:center; font-size:.78rem; color:#888; padding:24px; }}
    .exec-summary {{ background:#e8eaf6; border-left:5px solid #1a237e; border-radius:8px;
                     padding:24px 32px; margin-bottom:32px; }}
    .exec-summary h2 {{ font-size:1rem; font-weight:700; color:#1a237e; margin-bottom:12px; }}
    .exec-summary ol {{ padding-left:20px; }}
    .exec-summary li {{ font-size:.9rem; margin-bottom:8px; color:#333; line-height:1.6; }}
  </style>
</head>
<body>
<header>
  <div style="text-align:right;font-size:.85rem;margin-bottom:8px;">
    <a href="zh.html" style="color:#90caf9;">繁體中文</a> | English
  </div>
  <h1>🌐 RIR Network Security Alert Report</h1>
  <p>Generated: {run_time} &nbsp;|&nbsp; Coverage: APNIC &middot; RIPE NCC &middot; ARIN &middot; LACNIC &middot; AFRINIC</p>
</header>
<div class="container">

  <div class="exec-summary">
    <h2>📋 About This Report</h2>
    <ol>
      <li><strong>Data source</strong>: This report analyses public Delegation Extended records from all five Regional Internet Registries — APNIC, RIPE NCC, ARIN, LACNIC, and AFRINIC. Files are downloaded daily and processed by a statistical detection pipeline to flag anomalous Internet number resource acquisition patterns.</li>
      <li><strong>What is detected</strong>: Five detection types (A–E) cover rapid IP accumulation, statistically anomalous ASN surges by country, cross-country resource holdings, large single allocations, and coordinated acquisition (ASN + IPv4 obtained by the same entity within 7 days). These signals correspond to pre-announcement behaviours — routing infrastructure setup, IP hoarding, or proxy concealment — occurring before any BGP route is ever advertised.</li>
      <li><strong>Recommended actions</strong>: Prioritise High-risk items. For each flagged opaque_id, perform a WHOIS lookup to identify the holding entity, and monitor the associated IP blocks for BGP route announcements. If the holder cannot be verified, notify the relevant RIR security contact (listed at the bottom of this report) to initiate enhanced review.</li>
    </ol>
  </div>

  <div class="kpi-bar">
    <div class="kpi high"><div class="num">{n_high}</div><div class="label">High-Risk Alerts</div></div>
    <div class="kpi mid"> <div class="num">{n_mid}</div> <div class="label">Medium-Risk Alerts</div></div>
    <div class="kpi low"> <div class="num">{n_low}</div> <div class="label">Low-Risk Alerts</div></div>
    <div class="kpi">     <div class="num">{total}</div> <div class="label">Total Alerts</div></div>
    <div class="kpi">     <div class="num">{n_types}</div><div class="label">Detection Types Triggered</div></div>
  </div>

  {whois_html}

  <div class="cards">
    {summary_cards}
  </div>

  {sections_html}

  <div class="contact-section">
    <h2>📬 RIR Security Contacts</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>RIR</th><th>Region</th><th>Security Contact</th><th>Website</th></tr></thead>
        <tbody>{contact_rows}</tbody>
      </table>
    </div>
  </div>

</div>
<footer>
  Auto-generated by RIR Security Monitor &nbsp;|&nbsp; Data source: Public Delegation Extended files from each RIR
</footer>
</body>
</html>"""


def main():
    print("RIR Security Alert Report Generator (EN)")
    print(f"Generated: {TODAY.strftime('%Y-%m-%d %H:%M')}")

    df = load_latest_alerts()
    if df is None or df.empty:
        print("No alert data found. Please run step3_detect_anomalies.py first.")
        return

    print(f"Loaded {len(df)} alerts")

    report_html = generate_html(df)
    out_path = ALERT_DIR / f"security_report_{DATE_STR}_en.html"
    out_path.write_text(report_html, encoding="utf-8")

    print(f"\nReport saved: {out_path}")
    print("Open in a browser or attach to email for RIR security contacts.")
    print()
    for rir, info in RIR_CONTACTS.items():
        print(f"  {rir:10s} {info['security']}")


if __name__ == "__main__":
    main()
