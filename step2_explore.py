"""
步驟二：深入探索 Delegation 資料
==================================
從今天下載的快照中找出有意義的模式，包括：
  1. 最近 90 天新分配的 IP 區塊
  2. 持有最多資源的 opaque_id（大戶名單）
  3. 各國資源分布
  4. 各年份分配趨勢
  5. 最近半年新出現的 ASN

支援全球 5 大 RIR：APNIC、RIPE NCC、ARIN、LACNIC、AFRINIC

執行前請先完成 step1，確認 rir_data/ 資料夾存在。

執行方式：
  python3 step2_explore.py
"""

import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
import glob

# ── 設定 ──────────────────────────────────────────────
OUTPUT_DIR = Path("rir_data")
TODAY = datetime.today()
DAYS_RECENT = 90  # 「最近」的定義，可自由調整

# ── 解析函式（修正版，過濾 +1000 問題）────────────────
VALID_STATUS = {"allocated", "assigned", "available", "reserved"}

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
            opaque_id = parts[7] if len(parts) > 7 else ""

            # 過濾無效記錄
            if cc in ("ZZ", "*"):
                continue
            if status not in VALID_STATUS:
                continue
            if rtype not in ("ipv4", "ipv6", "asn"):
                continue

            rows.append({
                "registry":  registry,
                "country":   cc,
                "type":      rtype,
                "start":     start,
                "value":     int(value) if value.isdigit() else 0,
                "date":      date,
                "status":    status,
                "opaque_id": opaque_id,
            })

    df = pd.DataFrame(rows)
    df["date"] = pd.to_datetime(df["date"], format="%Y%m%d", errors="coerce")
    return df


# ── 分析函式 ──────────────────────────────────────────

def analyze_recent(df: pd.DataFrame, days: int = 90) -> pd.DataFrame:
    """最近 N 天新分配的區塊"""
    cutoff = TODAY - timedelta(days=days)
    recent = df[(df["date"] >= cutoff) & (df["status"] == "allocated")].copy()
    recent = recent.sort_values("date", ascending=False)
    recent["距今天數"] = (TODAY - recent["date"]).dt.days
    return recent[["registry", "country", "type", "start", "value",
                    "date", "距今天數", "opaque_id"]]


def analyze_top_holders(df: pd.DataFrame, top_n: int = 50) -> pd.DataFrame:
    """持有最多 IP 的 opaque_id（排除空值）"""
    ipv4 = df[(df["type"] == "ipv4") & (df["opaque_id"] != "")].copy()
    holder = (ipv4.groupby("opaque_id")
                  .agg(
                      IP區塊數=("start", "count"),
                      總IP數量=("value", "sum"),
                      涵蓋國家=("country", lambda x: ", ".join(sorted(x.unique()))),
                      最早分配=("date", "min"),
                      最近分配=("date", "max"),
                  )
                  .reset_index()
                  .sort_values("總IP數量", ascending=False)
                  .head(top_n))
    holder["最近分配距今"] = (TODAY - holder["最近分配"]).dt.days.astype(str) + " 天前"
    return holder


def analyze_country(df: pd.DataFrame) -> pd.DataFrame:
    """各國資源分布"""
    result = []
    for country, grp in df[df["status"] == "allocated"].groupby("country"):
        ipv4_count = grp[grp["type"] == "ipv4"]["value"].sum()
        ipv6_count = len(grp[grp["type"] == "ipv6"])
        asn_count  = len(grp[grp["type"] == "asn"])
        result.append({
            "國家代碼": country,
            "IPv4 位址數": ipv4_count,
            "IPv6 前綴數": ipv6_count,
            "ASN 數量":    asn_count,
        })
    return (pd.DataFrame(result)
              .sort_values("IPv4 位址數", ascending=False)
              .reset_index(drop=True))


def analyze_yearly_trend(df: pd.DataFrame) -> pd.DataFrame:
    """逐年分配趨勢（了解哪一年分配最活躍）"""
    df2 = df[df["status"] == "allocated"].copy()
    df2["year"] = df2["date"].dt.year
    trend = (df2.groupby(["year", "type"])
                .size()
                .unstack(fill_value=0)
                .reset_index()
                .rename(columns={"year": "年份"}))
    return trend.sort_values("年份")


def analyze_fresh_asn(df: pd.DataFrame, days: int = 180) -> pd.DataFrame:
    """最近半年新出現的 ASN（新 ASN 是監控重點）"""
    cutoff = TODAY - timedelta(days=days)
    fresh = df[(df["type"] == "asn") &
               (df["date"] >= cutoff) &
               (df["status"] == "allocated")].copy()
    fresh = fresh.sort_values("date", ascending=False)
    fresh["距今天數"] = (TODAY - fresh["date"]).dt.days
    return fresh[["registry", "country", "start", "date", "距今天數", "opaque_id"]]


# ── 主程式 ────────────────────────────────────────────

RIR_DISPLAY = {
    "apnic":   "APNIC",
    "ripencc": "RIPE NCC",
    "arin":    "ARIN",
    "lacnic":  "LACNIC",
    "afrinic": "AFRINIC",
}

def process_one(filepath: Path):
    short_name = filepath.name.replace("delegated-", "").replace("-latest.txt", "")
    name = RIR_DISPLAY.get(short_name, short_name.upper())
    print(f"\n{'='*50}")
    print(f"分析：{name}  ({filepath.name})")
    print(f"{'='*50}")

    df = parse(filepath)
    print(f"有效記錄：{len(df):,} 筆")

    # 執行各項分析
    recent     = analyze_recent(df, DAYS_RECENT)
    holders    = analyze_top_holders(df, top_n=50)
    country    = analyze_country(df)
    trend      = analyze_yearly_trend(df)
    fresh_asn  = analyze_fresh_asn(df, days=180)

    print(f"  最近 {DAYS_RECENT} 天新分配：{len(recent):,} 筆")
    print(f"  新 ASN（半年內）：{len(fresh_asn):,} 筆")
    print(f"  涵蓋國家：{country['國家代碼'].nunique()} 個")

    # 輸出 Excel
    out_path = OUTPUT_DIR / f"{short_name}_explore_{TODAY.strftime('%Y%m%d')}.xlsx"

    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:

        recent.to_excel(writer, sheet_name=f"最近{DAYS_RECENT}天新分配", index=False)
        holders.to_excel(writer, sheet_name="最大資源持有人 Top50", index=False)
        country.to_excel(writer, sheet_name="各國資源分布", index=False)
        trend.to_excel(writer, sheet_name="逐年分配趨勢", index=False)
        fresh_asn.to_excel(writer, sheet_name="最近半年新ASN", index=False)

        # 說明工作表
        notes = pd.DataFrame({
            "工作表名稱": [
                f"最近{DAYS_RECENT}天新分配",
                "最大資源持有人 Top50",
                "各國資源分布",
                "逐年分配趨勢",
                "最近半年新ASN",
            ],
            "內容說明": [
                f"過去 {DAYS_RECENT} 天內 allocated 的 IP 區塊，按日期由新到舊排列",
                "持有 IPv4 位址最多的前 50 個 opaque_id，同一 ID 代表同一持有人",
                "各國持有的 IPv4 位址數、IPv6 前綴數、ASN 數量",
                "每年新增分配記錄數，觀察整體趨勢",
                "過去半年內新分配的 ASN，新 ASN 是攻擊基礎設施的常見特徵",
            ],
            "安全偵測用途": [
                "新取得的 IP 空間若快速出現在路由表，值得關注",
                "持有人異常集中或短期大量取得，是潛在風險訊號",
                "國家層級的異常增長，可能反映區域性事件",
                "分配量突然激增的年份，背後可能有特定事件",
                "新 ASN 是建立攻擊基礎設施的第一步",
            ],
        })
        notes.to_excel(writer, sheet_name="說明", index=False)

    print(f"  輸出完成：{out_path}")
    return df


def main():
    print(f"RIR 資料探索分析")
    print(f"執行時間：{TODAY.strftime('%Y-%m-%d %H:%M')}")

    files = sorted(OUTPUT_DIR.glob("delegated-*-latest.txt"))
    if not files:
        print("找不到資料檔案！請先執行 step1_download_and_parse.py")
        return

    for f in files:
        process_one(f)

    print(f"\n全部完成！請開啟 rir_data/ 資料夾中的 *_explore_*.xlsx 檔案。")
    print(f"建議先看「最近{DAYS_RECENT}天新分配」和「最近半年新ASN」這兩個工作表。")


if __name__ == "__main__":
    main()
