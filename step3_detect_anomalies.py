"""
步驟三：安全異常偵測引擎
==========================
跨全球 5 大 RIR（APNIC、RIPE NCC、ARIN、LACNIC、AFRINIC）自動偵測
潛在網路安全威脅，輸出結構化預警清單。

偵測項目：
  A. 高速 IP 資源累積  — 短期大量取得 IPv4 的 opaque_id
  B. 新 ASN 爆發      — 最近 30 天內新增 ASN 數量異常的國家
  C. 跨國資源持有      — 同一 opaque_id 跨 5 個以上國家持有資源
  D. 巨型單次分配      — 單筆 IPv4 分配超過 65536 個位址（/16 或更大）
  E. 協同取得模式      — 同週在同一 RIR 取得大量 ASN + IP 的 opaque_id

執行前請先完成 step1（取得 .txt 檔）。

執行方式：
  python3 step3_detect_anomalies.py
"""

import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta

OUTPUT_DIR = Path("rir_data")
TODAY = datetime.today()
ALERT_DIR = OUTPUT_DIR / "alerts"
ALERT_DIR.mkdir(exist_ok=True)

VALID_STATUS = {"allocated", "assigned"}
RIR_DISPLAY = {
    "apnic":   "APNIC",
    "ripencc": "RIPE NCC",
    "arin":    "ARIN",
    "lacnic":  "LACNIC",
    "afrinic": "AFRINIC",
}

# ── 嚴格解析（只保留有效分配記錄）──────────────────────────
def parse(filepath: Path) -> pd.DataFrame:
    rows = []
    with open(filepath, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("2|"):
                continue
            parts = line.split("|")
            if len(parts) < 7:
                continue
            registry, cc, rtype, start, value, date, status = parts[:7]
            opaque_id = parts[7].strip() if len(parts) > 7 else ""

            if cc in ("ZZ", "*") or not cc:
                continue
            if status not in VALID_STATUS:
                continue
            if rtype not in ("ipv4", "ipv6", "asn"):
                continue

            rows.append({
                "registry":  registry.strip(),
                "country":   cc.strip(),
                "type":      rtype.strip(),
                "start":     start.strip(),
                "value":     int(value) if value.strip().isdigit() else 0,
                "date":      date.strip(),
                "status":    status.strip(),
                "opaque_id": opaque_id,
            })

    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df["date"] = pd.to_datetime(df["date"], format="%Y%m%d", errors="coerce")
    return df


# ── 偵測 A：高速 IP 資源累積 ─────────────────────────────
def detect_rapid_accumulation(df: pd.DataFrame, days: int = 90,
                               threshold_ips: int = 65536) -> pd.DataFrame:
    """
    在過去 N 天內累積超過 threshold_ips 個 IPv4 位址的 opaque_id。
    代表可能的大規模基礎設施建置。
    """
    cutoff = TODAY - timedelta(days=days)
    recent_ipv4 = df[
        (df["type"] == "ipv4") &
        (df["date"] >= cutoff) &
        (df["opaque_id"] != "")
    ].copy()

    if recent_ipv4.empty:
        return pd.DataFrame()

    agg = (recent_ipv4.groupby(["registry", "opaque_id"])
           .agg(
               新增區塊數=("start", "count"),
               累積IP數量=("value", "sum"),
               涵蓋國家=("country", lambda x: ", ".join(sorted(x.unique()))),
               國家數=("country", "nunique"),
               最早日期=("date", "min"),
               最近日期=("date", "max"),
           )
           .reset_index())

    alerts = agg[agg["累積IP數量"] >= threshold_ips].sort_values("累積IP數量", ascending=False)
    alerts["距今天數"] = (TODAY - alerts["最近日期"]).dt.days
    alerts["威脅等級"] = alerts["累積IP數量"].apply(
        lambda x: "高" if x >= 1_048_576 else ("中" if x >= 262_144 else "低")
    )
    alerts["偵測類型"] = "A - 高速IP資源累積"
    return alerts


# ── 偵測 B：新 ASN 國家爆發 ──────────────────────────────
def detect_asn_burst(df: pd.DataFrame, days: int = 30,
                     z_threshold: float = 2.5) -> pd.DataFrame:
    """
    計算過去 N 天各國新增 ASN 數量，找出統計上的異常值（z-score）。
    新 ASN 是建立攻擊基礎設施的第一步。
    """
    cutoff = TODAY - timedelta(days=days)
    asn_df = df[(df["type"] == "asn") & (df["date"] >= cutoff)].copy()

    if asn_df.empty:
        return pd.DataFrame()

    country_asn = asn_df.groupby(["registry", "country"]).size().reset_index(name="新增ASN數")

    def calc_zscore(x):
        if len(x) < 3 or x.std() == 0:
            return pd.Series(0.0, index=x.index)
        return (x - x.mean()) / x.std()

    country_asn["z_score"] = country_asn.groupby("registry")["新增ASN數"].transform(calc_zscore)
    alerts = country_asn[country_asn["z_score"] >= z_threshold].sort_values("z_score", ascending=False)
    alerts["威脅等級"] = alerts["z_score"].apply(
        lambda z: "高" if z >= 4.0 else ("中" if z >= 3.0 else "低")
    )
    alerts["偵測類型"] = "B - 新ASN國家爆發"
    return alerts[["registry", "country", "新增ASN數", "z_score", "威脅等級", "偵測類型"]]


# ── 偵測 C：跨國資源持有 ─────────────────────────────────
def detect_cross_country_holders(df: pd.DataFrame,
                                  min_countries: int = 5) -> pd.DataFrame:
    """
    同一 opaque_id 跨多個國家持有資源，可能是代理持有或隱匿真實持有人。
    """
    ipv4 = df[(df["type"] == "ipv4") & (df["opaque_id"] != "")].copy()
    if ipv4.empty:
        return pd.DataFrame()

    agg = (ipv4.groupby(["registry", "opaque_id"])
           .agg(
               國家數=("country", "nunique"),
               涵蓋國家=("country", lambda x: ", ".join(sorted(x.unique()))),
               總IP數量=("value", "sum"),
               區塊數=("start", "count"),
               最近分配=("date", "max"),
           )
           .reset_index())

    alerts = agg[agg["國家數"] >= min_countries].sort_values("國家數", ascending=False)
    alerts["距今天數"] = (TODAY - alerts["最近分配"]).dt.days
    alerts["威脅等級"] = alerts["國家數"].apply(
        lambda x: "高" if x >= 10 else ("中" if x >= 7 else "低")
    )
    alerts["偵測類型"] = "C - 跨國資源持有"
    return alerts


# ── 偵測 D：巨型單次分配 ─────────────────────────────────
def detect_large_single_allocation(df: pd.DataFrame, days: int = 90,
                                    min_ips: int = 65536) -> pd.DataFrame:
    """
    最近 N 天內單筆 IPv4 分配超過 min_ips 位址（預設 /16）。
    大型單次分配若來自不知名實體，是高風險訊號。
    """
    cutoff = TODAY - timedelta(days=days)
    recent = df[
        (df["type"] == "ipv4") &
        (df["date"] >= cutoff) &
        (df["value"] >= min_ips)
    ].copy().sort_values("value", ascending=False)

    if recent.empty:
        return pd.DataFrame()

    recent["CIDR前綴長度"] = recent["value"].apply(
        lambda v: f"/{32 - int(np.log2(v))}" if v > 0 and (v & (v-1)) == 0 else "非標準"
    )
    recent["距今天數"] = (TODAY - recent["date"]).dt.days
    recent["威脅等級"] = recent["value"].apply(
        lambda x: "高" if x >= 1_048_576 else ("中" if x >= 262_144 else "低")
    )
    recent["偵測類型"] = "D - 巨型單次分配"
    return recent[["registry", "country", "type", "start", "value",
                   "CIDR前綴長度", "date", "距今天數", "opaque_id", "威脅等級", "偵測類型"]]


# ── 偵測 E：協同取得模式 ─────────────────────────────────
def detect_coordinated_acquisition(df: pd.DataFrame, days: int = 7) -> pd.DataFrame:
    """
    在同一週內同時取得 ASN 和 IPv4 的 opaque_id。
    同步取得 ASN + IP 是建立路由基礎設施的典型動作。
    """
    cutoff = TODAY - timedelta(days=days)
    recent = df[df["date"] >= cutoff].copy()
    if recent.empty:
        return pd.DataFrame()

    has_asn = set(recent[recent["type"] == "asn"]["opaque_id"].dropna().unique())
    has_ipv4 = set(recent[recent["type"] == "ipv4"]["opaque_id"].dropna().unique())
    coordinated = has_asn & has_ipv4 - {""}

    if not coordinated:
        return pd.DataFrame()

    rows = []
    for oid in coordinated:
        grp = recent[recent["opaque_id"] == oid]
        asn_grp = grp[grp["type"] == "asn"]
        ipv4_grp = grp[grp["type"] == "ipv4"]
        rows.append({
            "opaque_id":   oid,
            "registry":    grp["registry"].iloc[0],
            "涵蓋國家":    ", ".join(sorted(grp["country"].unique())),
            "新增ASN數":   len(asn_grp),
            "新增IPv4區塊": len(ipv4_grp),
            "IPv4總量":    ipv4_grp["value"].sum(),
            "最早日期":    grp["date"].min(),
            "最近日期":    grp["date"].max(),
            "威脅等級":    "高",
            "偵測類型":    "E - 協同取得模式",
        })

    return pd.DataFrame(rows).sort_values("IPv4總量", ascending=False)


# ── 主程式 ───────────────────────────────────────────────

def process_rir(filepath: Path) -> dict[str, pd.DataFrame]:
    short_name = filepath.name.replace("delegated-", "").replace("-latest.txt", "")
    display = RIR_DISPLAY.get(short_name, short_name.upper())
    print(f"\n{'='*55}")
    print(f"  偵測中：{display}  ({filepath.name})")
    print(f"{'='*55}")

    df = parse(filepath)
    if df.empty:
        print(f"  [警告] 無有效資料，跳過")
        return {}
    print(f"  有效記錄：{len(df):,} 筆")

    results = {}

    a = detect_rapid_accumulation(df)
    b = detect_asn_burst(df)
    c = detect_cross_country_holders(df)
    d = detect_large_single_allocation(df)
    e = detect_coordinated_acquisition(df)

    for label, result in [("A_高速IP累積", a), ("B_ASN爆發", b),
                           ("C_跨國持有", c), ("D_巨型分配", d), ("E_協同取得", e)]:
        count = len(result) if result is not None else 0
        print(f"  [{label}] 發現 {count} 筆預警")
        if count:
            results[label] = result

    return results


def main():
    date_str = TODAY.strftime("%Y%m%d")
    print(f"RIR 安全異常偵測引擎")
    print(f"執行時間：{TODAY.strftime('%Y-%m-%d %H:%M')}")
    print(f"涵蓋 RIR：APNIC、RIPE NCC、ARIN、LACNIC、AFRINIC")

    files = sorted(OUTPUT_DIR.glob("delegated-*-latest.txt"))
    if not files:
        print("找不到資料檔案！請先執行 step1_download_and_parse.py")
        return

    all_alerts: list[pd.DataFrame] = []

    for filepath in files:
        results = process_rir(filepath)
        for df in results.values():
            if not df.empty:
                all_alerts.append(df)

    if not all_alerts:
        print("\n未發現異常，無需預警。")
        return

    combined = pd.concat(all_alerts, ignore_index=True)

    # 輸出整合預警 Excel
    out_path = ALERT_DIR / f"security_alerts_{date_str}.xlsx"
    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:

        # 摘要頁
        summary_rows = []
        for dtype, grp in combined.groupby("偵測類型"):
            high = len(grp[grp["威脅等級"] == "高"])
            mid  = len(grp[grp["威脅等級"] == "中"])
            low  = len(grp[grp["威脅等級"] == "低"])
            summary_rows.append({
                "偵測類型": dtype,
                "高風險": high,
                "中風險": mid,
                "低風險": low,
                "合計": len(grp),
            })
        pd.DataFrame(summary_rows).to_excel(writer, sheet_name="預警摘要", index=False)

        # 高風險獨立頁
        high_risk = combined[combined["威脅等級"] == "高"]
        if not high_risk.empty:
            high_risk.to_excel(writer, sheet_name="高風險預警", index=False)

        # 各偵測類型分頁
        sheet_map = {
            "A - 高速IP資源累積": "A_高速IP累積",
            "B - 新ASN國家爆發":  "B_新ASN爆發",
            "C - 跨國資源持有":   "C_跨國持有",
            "D - 巨型單次分配":   "D_巨型分配",
            "E - 協同取得模式":   "E_協同取得",
        }
        for dtype, sheet_name in sheet_map.items():
            subset = combined[combined["偵測類型"] == dtype]
            if not subset.empty:
                subset.to_excel(writer, sheet_name=sheet_name, index=False)

        # 說明頁
        notes = pd.DataFrame({
            "偵測代號": ["A", "B", "C", "D", "E"],
            "威脅名稱": [
                "高速IP資源累積",
                "新ASN國家爆發",
                "跨國資源持有",
                "巨型單次分配",
                "協同取得模式",
            ],
            "說明": [
                "同一實體（opaque_id）在90天內累積超過65,536個IPv4位址，可能建立大規模攻擊基礎設施",
                "特定國家在30天內新增ASN數量達統計異常（z-score≥2.5），可能為協調性行動",
                "同一opaque_id在5個以上國家持有資源，可能透過代理隱匿真實控制者",
                "單筆IPv4分配超過65,536個位址（/16），若分配給不知名實體則為高風險",
                "同一opaque_id在7天內同時取得ASN與IPv4，符合建立路由基礎設施的標準流程",
            ],
            "建議動作": [
                "查詢 opaque_id 對應實體，確認是否有合法業務需求；監控路由公告",
                "向該國 NIC 確認 ASN 申請正當性；加強 BGP 路由監控",
                "審查跨國持有合規性；確認是否符合 RIR 政策",
                "聯繫分配端 RIR 確認申請人身分；啟動加強審查程序",
                "立即追蹤 BGP 路由公告；若出現路由則視為高優先事項",
            ],
        })
        notes.to_excel(writer, sheet_name="偵測說明", index=False)

    print(f"\n預警報告已輸出：{out_path}")
    print(f"總計 {len(combined)} 筆預警，其中高風險：{len(combined[combined['威脅等級']=='高'])} 筆")
    print("建議優先查看「高風險預警」工作表。")


if __name__ == "__main__":
    main()
