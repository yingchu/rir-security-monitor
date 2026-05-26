"""
步驟一：下載並解析 RIR Delegation 檔案
======================================
用途：取得全球 5 大 RIR（APNIC、RIPE NCC、ARIN、LACNIC、AFRINIC）
      的 IP/ASN 分配資料，輸出成 Excel 方便在後續步驟分析。

執行方式：
  python step1_download_and_parse.py

需要安裝：
  pip install requests pandas openpyxl
"""

import requests
import pandas as pd
from datetime import datetime
from pathlib import Path

# ── 設定 ──────────────────────────────────────────────
OUTPUT_DIR = Path("rir_data")
OUTPUT_DIR.mkdir(exist_ok=True)

SOURCES = {
    "apnic":   "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "arin":    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "lacnic":  "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}

# ── 下載函式 ──────────────────────────────────────────
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024  # 200 MB — RIR files are typically 5–30 MB

def download(name: str, url: str) -> Path:
    out_path = OUTPUT_DIR / f"delegated-{name}-latest.txt"
    print(f"[{name}] 下載中... {url}")
    resp = requests.get(url, timeout=60, verify=True)
    resp.raise_for_status()
    if len(resp.content) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"[{name}] 下載檔案異常龐大 ({len(resp.content) // 1024 // 1024} MB)，已中止")
    out_path.write_bytes(resp.content)
    print(f"[{name}] 完成，共 {out_path.stat().st_size // 1024:,} KB")
    return out_path

# ── 解析函式 ──────────────────────────────────────────
def parse(filepath: Path) -> pd.DataFrame:
    """
    Delegation Extended 檔案格式（每行 8 個欄位，以 | 分隔）：
    
    registry | cc | type | start | value | date | status | extensions
    -------- | -- | ---- | ----- | ----- | ---- | ------ | ----------
    apnic    | TW | ipv4 | 1.34.0.0 | 65536 | 20110223 | allocated | opaque-id
    
    前兩行（以 # 開頭）是註解，以 2| 開頭的是版本摘要行，跳過。
    """
    rows = []
    with open(filepath, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            # 跳過註解與版本摘要行
            if line.startswith("#") or line.startswith("2|"):
                continue
            parts = line.split("|")
            if len(parts) < 7:
                continue
            
            registry, cc, rtype, start, value, date, status = parts[:7]
            opaque_id = parts[7] if len(parts) > 7 else ""
            
            # 跳過保留/特殊用途區塊
            if cc in ("ZZ", "*"):
                continue
            
            rows.append({
                "registry":  registry,   # RIR 名稱
                "country":   cc,         # 國家代碼 (ISO 3166)
                "type":      rtype,      # ipv4 / ipv6 / asn
                "start":     start,      # 起始 IP 或 ASN 號碼
                "value":     int(value) if value.isdigit() else value,  # IP 數量或 ASN 數量
                "date":      date,       # 分配日期 YYYYMMDD
                "status":    status,     # allocated / assigned / available / reserved
                "opaque_id": opaque_id,  # 內部識別碼（可追蹤同一持有人的多個資源）
            })
    
    df = pd.DataFrame(rows)
    
    # 日期轉換
    df["date"] = pd.to_datetime(df["date"], format="%Y%m%d", errors="coerce")
    
    return df

# ── 輸出成 Excel ──────────────────────────────────────
def to_excel(df: pd.DataFrame, name: str):
    out_path = OUTPUT_DIR / f"{name}_delegation_{datetime.today().strftime('%Y%m%d')}.xlsx"
    
    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
        # 工作表一：完整資料
        df.to_excel(writer, sheet_name="全部資料", index=False)
        
        # 工作表二：各國統計
        summary = (df.groupby(["country", "type"])
                     .agg(資源數量=("start", "count"),
                          最早分配=("date", "min"),
                          最近分配=("date", "max"))
                     .reset_index()
                     .rename(columns={"country": "國家", "type": "資源類型"}))
        summary.to_excel(writer, sheet_name="國家統計", index=False)
        
        # 工作表三：各狀態統計
        status_summary = df.groupby(["type", "status"]).size().reset_index(name="筆數")
        status_summary.to_excel(writer, sheet_name="狀態統計", index=False)
    
    print(f"[{name}] 輸出完成：{out_path}")
    return out_path

# ── 主程式 ────────────────────────────────────────────
def main():
    print("=" * 50)
    print("RIR Delegation 資料下載與解析工具")
    print(f"執行時間：{datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 50)
    
    for name, url in SOURCES.items():
        try:
            filepath = download(name, url)
            print(f"[{name}] 解析中...")
            df = parse(filepath)
            print(f"[{name}] 解析完成，共 {len(df):,} 筆記錄")
            
            # 簡單統計
            print(f"  IPv4 記錄：{len(df[df.type=='ipv4']):,} 筆")
            print(f"  IPv6 記錄：{len(df[df.type=='ipv6']):,} 筆")
            print(f"  ASN  記錄：{len(df[df.type=='asn']):,} 筆")
            print(f"  涵蓋國家：{df.country.nunique()} 個")
            
            to_excel(df, name)
            print()
            
        except Exception as e:
            print(f"[{name}] 錯誤：{e}")
    
    print("全部完成！請開啟 rir_data/ 資料夾中的 .xlsx 檔案。")

if __name__ == "__main__":
    main()
