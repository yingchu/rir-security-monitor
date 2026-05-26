"""
步驟四：預警報告產生器
========================
讀取 step3 產生的預警 Excel，輸出可分享的 HTML 安全報告。
HTML 報告適合直接寄送給各 RIR 的安全聯絡窗口。

報告內容：
  - 執行摘要（各威脅類型統計）
  - 高風險預警清單（含具體建議動作）
  - 各 RIR 預警分布圖表

執行前請先完成 step1 至 step3。

執行方式：
  python3 step4_alert_report.py
"""

import pandas as pd
from pathlib import Path
from datetime import datetime
import html
import glob
from whois_enrich import enrich as whois_enrich

OUTPUT_DIR = Path("rir_data")
ALERT_DIR = OUTPUT_DIR / "alerts"
TODAY = datetime.today()
DATE_STR = TODAY.strftime("%Y%m%d")

# 5 大 RIR 安全聯絡資訊
RIR_CONTACTS = {
    "APNIC":    {"region": "亞太地區",          "security": "security@apnic.net",    "url": "https://www.apnic.net"},
    "RIPE NCC": {"region": "歐洲/中東/中亞",    "security": "abuse@ripe.net",        "url": "https://www.ripe.net"},
    "ARIN":     {"region": "北美洲",             "security": "abuse@arin.net",        "url": "https://www.arin.net"},
    "LACNIC":   {"region": "拉丁美洲/加勒比海", "security": "abuse@lacnic.net",      "url": "https://www.lacnic.net"},
    "AFRINIC":  {"region": "非洲",              "security": "abuse@afrinic.net",     "url": "https://www.afrinic.net"},
}

THREAT_COLORS = {"高": "#d32f2f", "中": "#f57c00", "低": "#388e3c"}
THREAT_BG     = {"高": "#ffebee", "中": "#fff3e0", "低": "#e8f5e9"}

DETECTION_DESC = {
    "A - 高速IP資源累積": ("🔴", "同一實體90天內累積大量IPv4，可能建立攻擊基礎設施"),
    "B - 新ASN國家爆發":  ("🟠", "特定國家新增ASN數量達統計異常，可能為協調性行動"),
    "C - 跨國資源持有":   ("🟡", "同一opaque_id跨多國持有資源，可能代理隱匿控制者"),
    "D - 巨型單次分配":   ("🟠", "單筆IPv4分配超過/16，若分配給不知名實體則高風險"),
    "E - 協同取得模式":   ("🔴", "同一實體7天內同時取得ASN與IPv4，符合路由基礎設施建置特徵"),
}

RECOMMENDATIONS = {
    "A - 高速IP資源累積": [
        "查詢 opaque_id 對應的實體名稱與業務背景",
        "確認是否有合法的業務規模需求",
        "監控相關 IP 區塊的 BGP 路由公告",
        "若無法核實，通知相關 RIR 啟動加強審查",
    ],
    "B - 新ASN國家爆發": [
        "聯繫該國的 NIC 或相關機構確認 ASN 申請正當性",
        "加強對該國新 ASN 的 BGP 路由監控",
        "與 MANRS（路由安全倡議）合作夥伴共享資訊",
        "評估是否需要提高該國 ASN 申請的審查門檻",
    ],
    "C - 跨國資源持有": [
        "審查跨國持有是否符合各 RIR 的轉移政策",
        "確認 WHOIS 資料的真實性與完整性",
        "評估是否需要要求持有人提供額外身分驗證",
        "與其他 RIR 交叉比對同一 opaque_id 的分配記錄",
    ],
    "D - 巨型單次分配": [
        "聯繫分配端 RIR 確認申請人身分與用途聲明",
        "確認是否已通過正常的資源申請審查程序",
        "啟動加強監控，追蹤後續 BGP 路由公告",
        "若 30 天內出現路由公告，立即升級為高優先事項",
    ],
    "E - 協同取得模式": [
        "立即追蹤相關 ASN 的 BGP 路由公告狀態",
        "確認 ASN 與 IP 申請是否由同一組織提交",
        "若已出現路由公告，通知下游 ISP 和 RPKI 驗證機構",
        "評估是否符合 BGP 劫持的前期準備特徵",
    ],
}


def load_latest_alerts() -> pd.DataFrame | None:
    pattern = str(ALERT_DIR / f"security_alerts_{DATE_STR}.xlsx")
    files = glob.glob(pattern)
    if not files:
        # 嘗試找最新的
        all_files = sorted(glob.glob(str(ALERT_DIR / "security_alerts_*.xlsx")))
        if not all_files:
            return None
        files = [all_files[-1]]

    try:
        # 讀取所有偵測類型分頁合併
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
        return pd.concat(dfs, ignore_index=True)
    except Exception as e:
        print(f"讀取預警檔案失敗：{e}")
        return None


def render_summary_cards(df: pd.DataFrame) -> str:
    cards = []
    for dtype, grp in df.groupby("偵測類型"):
        icon, desc = DETECTION_DESC.get(dtype, ("⚪", dtype))
        high = len(grp[grp["威脅等級"] == "高"])
        mid  = len(grp[grp["威脅等級"] == "中"])
        low  = len(grp[grp["威脅等級"] == "低"])
        dominant = "高" if high else ("中" if mid else "低")
        border_color = THREAT_COLORS[dominant]
        bg_color = THREAT_BG[dominant]

        cards.append(f"""
        <div class="card" style="border-left:5px solid {border_color};background:{bg_color}">
          <div class="card-icon">{icon}</div>
          <div class="card-body">
            <div class="card-title">{html.escape(dtype)}</div>
            <div class="card-desc">{html.escape(desc)}</div>
            <div class="card-counts">
              <span class="badge high">高風險 {high}</span>
              <span class="badge mid">中風險 {mid}</span>
              <span class="badge low">低風險 {low}</span>
            </div>
          </div>
        </div>""")
    return "\n".join(cards)


def render_alert_table(df: pd.DataFrame, dtype: str) -> str:
    subset = df[df["偵測類型"] == dtype].copy() if "偵測類型" in df.columns else df.copy()
    if subset.empty:
        return "<p>無此類型預警。</p>"

    # 移除內部欄位
    drop_cols = [c for c in ["偵測類型"] if c in subset.columns]
    subset = subset.drop(columns=drop_cols)

    rows_html = []
    for _, row in subset.iterrows():
        level = str(row.get("威脅等級", ""))
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
    high = df[df["威脅等級"] == "高"].copy()
    opaque_ids = set(high["opaque_id"].dropna())
    if not opaque_ids:
        return ""

    print(f"  查詢 WHOIS：{len(opaque_ids)} 筆高風險項目…")
    enriched = whois_enrich(opaque_ids, OUTPUT_DIR)

    rows = []
    for _, row in high.drop_duplicates("opaque_id").iterrows():
        oid = row.get("opaque_id", "")
        if not oid or oid not in enriched:
            continue
        info = enriched[oid]
        dtype = html.escape(str(row.get("偵測類型", "")))
        cc    = html.escape(str(row.get("涵蓋國家", "") or row.get("country", "")))
        query = html.escape(info.get("query", ""))
        name  = html.escape(info.get("name", "") or info.get("descr", ""))
        descr = html.escape(info.get("descr", ""))
        ctry  = html.escape(info.get("country", ""))
        rows.append(f"""
        <tr>
          <td><code>{html.escape(str(oid))}</code></td>
          <td>{dtype}</td>
          <td>{cc}</td>
          <td><code>{query}</code></td>
          <td><strong>{name}</strong></td>
          <td>{descr}</td>
          <td>{ctry}</td>
        </tr>""")

    if not rows:
        return ""

    return f"""
  <div class="whois-section">
    <h2>🔍 高風險項目 WHOIS 查詢結果</h2>
    <p class="section-desc">以下為系統對各高風險 opaque_id 自動查詢 WHOIS 所取得的持有實體資訊，供初步研判使用。請進一步核實 WHOIS 資料的完整性與真實性。</p>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>opaque_id</th><th>偵測類型</th><th>國家</th>
          <th>查詢對象</th><th>實體名稱</th><th>描述</th><th>登記國</th>
        </tr></thead>
        <tbody>{"".join(rows)}</tbody>
      </table>
    </div>
  </div>"""


def generate_html(df: pd.DataFrame) -> str:
    total   = len(df)
    n_high  = len(df[df["威脅等級"] == "高"])
    n_mid   = len(df[df["威脅等級"] == "中"])
    n_low   = len(df[df["威脅等級"] == "低"])
    n_types = df["偵測類型"].nunique()

    summary_cards = render_summary_cards(df)
    whois_html = render_whois_section(df)

    # 各偵測類型分節
    sections = []
    for dtype in df["偵測類型"].unique():
        icon, desc = DETECTION_DESC.get(dtype, ("⚪", dtype))
        recs = RECOMMENDATIONS.get(dtype, [])
        rec_items = "".join(f"<li>{html.escape(r)}</li>" for r in recs)
        table_html = render_alert_table(df, dtype)
        sections.append(f"""
        <section>
          <h2>{icon} {html.escape(dtype)}</h2>
          <p class="section-desc">{html.escape(desc)}</p>
          <h3>建議動作</h3>
          <ul>{rec_items}</ul>
          <h3>預警清單</h3>
          {table_html}
        </section>""")

    contact_rows = render_rir_contact_table()
    sections_html = "\n".join(sections)
    run_time = TODAY.strftime("%Y-%m-%d %H:%M")

    return f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>RIR 網路安全預警報告 {DATE_STR}</title>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ font-family:"Noto Sans TC","Segoe UI",sans-serif; background:#f5f7fa; color:#222; }}
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
  <h1>🌐 RIR 網路安全預警報告</h1>
  <p>產生時間：{run_time} ｜ 涵蓋 RIR：APNIC・RIPE NCC・ARIN・LACNIC・AFRINIC</p>
</header>
<div class="container">

  <div class="exec-summary">
    <h2>📋 關於本報告</h2>
    <ol>
      <li><strong>資料來源</strong>：本報告分析來自 APNIC、RIPE NCC、ARIN、LACNIC、AFRINIC 五大 RIR 的公開 Delegation Extended 記錄，每日自動下載並以統計模型偵測異常的網路號碼資源取得行為。</li>
      <li><strong>偵測範圍</strong>：涵蓋五種威脅類型（A–E），包括高速 IP 累積、特定國家新 ASN 異常爆發、跨國資源持有、巨型單次分配，以及同一實體在 7 天內同時取得 ASN 與 IPv4 的協同取得模式。這些訊號對應的是路由基礎設施建置、IP 囤積或代理隱匿等前期行為，早於任何 BGP 路由公告發生。</li>
      <li><strong>建議行動</strong>：請優先查看「高風險」項目，透過 WHOIS 查詢確認 opaque_id 對應的持有實體身分，並監控相關 IP 區塊的 BGP 路由公告。若無法核實持有人身分，建議通知該資源所屬 RIR 啟動進一步審查。</li>
    </ol>
  </div>

  <div class="kpi-bar">
    <div class="kpi high"><div class="num">{n_high}</div><div class="label">高風險預警</div></div>
    <div class="kpi mid"> <div class="num">{n_mid}</div> <div class="label">中風險預警</div></div>
    <div class="kpi low"> <div class="num">{n_low}</div> <div class="label">低風險預警</div></div>
    <div class="kpi">     <div class="num">{total}</div> <div class="label">預警總計</div></div>
    <div class="kpi">     <div class="num">{n_types}</div><div class="label">觸發偵測類型</div></div>
  </div>

  {whois_html}

  <div class="cards">
    {summary_cards}
  </div>

  {sections_html}

  <div class="contact-section">
    <h2>📬 RIR 安全聯絡窗口</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>RIR</th><th>服務區域</th><th>安全聯絡信箱</th><th>官方網站</th></tr></thead>
        <tbody>{contact_rows}</tbody>
      </table>
    </div>
  </div>

</div>
<footer>
  本報告由 RIR Security Monitor 自動產生 ｜ 資料來源：各 RIR 公開 Delegation Extended 檔案
</footer>
</body>
</html>"""


def main():
    print(f"RIR 安全預警報告產生器")
    print(f"執行時間：{TODAY.strftime('%Y-%m-%d %H:%M')}")

    df = load_latest_alerts()
    if df is None or df.empty:
        print("找不到預警資料！請先執行 step3_detect_anomalies.py")
        return

    print(f"載入預警資料：{len(df)} 筆")

    report_html = generate_html(df)
    out_path = ALERT_DIR / f"security_report_{DATE_STR}.html"
    out_path.write_text(report_html, encoding="utf-8")

    print(f"\n報告已輸出：{out_path}")
    print(f"請用瀏覽器開啟，或直接附件寄送給各 RIR 安全聯絡窗口。")
    print()
    print("各 RIR 安全聯絡信箱：")
    for rir, info in RIR_CONTACTS.items():
        print(f"  {rir:10s} {info['security']}")


if __name__ == "__main__":
    main()
