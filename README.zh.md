繁體中文 | [English](README.md)

# RIR 安全監控系統

**[→ 示範報告頁面（中文）](https://yingchu.github.io/rir-security-monitor/zh.html)** ｜ **[English](https://yingchu.github.io/rir-security-monitor/)**

針對全球五大區域網路資訊中心（RIR）的網路號碼資源異常取得行為進行早期預警：**APNIC、RIPE NCC、ARIN、LACNIC、AFRINIC**。

## 為什麼需要這個工具

RIR 現有的安全工具（RPKI、ARTEMIS、RIS）都在**路由層**運作——它們偵測的是資源被宣告之後的異常。本工具的切入點更上游：在任何 BGP 路由公告發生之前，從 delegation 記錄中偵測可疑的**資源分配行為模式**。

### 為什麼五大 RIR 自己沒做這件事？

有幾個結構性的原因：

- **角色衝突** — RIR 是會員制組織，會員繳費並參與治理投票。將付費會員標記為可疑，在法律與政治上風險極高，獨立工具則沒有這個顧慮。
- **授權邊界** — RIR 的盡職調查發生在資源申請當下（一次性審查），分配之後的持續行為監控不在其明定職責範圍內。
- **各自為政** — 五大 RIR 彼此獨立運作，跨 RIR 合併分析在技術與政治上都有高昂的協調成本。
- **沒有人擁有這一層** — 申請時審查（RIR）與路由公告審查（RPKI/ARTEMIS）之間的空白地帶，沒有任何機構認領。RIR 認為不在職責範圍，商業資安廠商又缺乏存取 delegation 資料的動機。
- **誤報的政治代價** — RIR 若公開標記自家會員並事後發現誤判，信譽損失遠大於建置這個系統的收益。獨立工具的分析空間更大，政治代價更小。

這在結構上類似信評機構評等發債公司：分析由獨立第三方執行，比由發行機構自己執行更具可信度。**工具的獨立性本身就是設計特點，而非限制。**

偵測的訊號類型：

| 類型 | 訊號 | 意涵 |
|------|------|------|
| A | 高速 IP 累積（同一實體 90 天內累積 ≥65536 個 IPv4）| 攻擊基礎設施建置 |
| B | 新 ASN 國家爆發（z-score ≥2.5，30 天內）| 協調性申請行動 |
| C | 跨國資源持有（同一 opaque_id 跨 ≥5 個國家）| 代理隱匿真實控制者 |
| D | 巨型單次分配（90 天內單筆 IPv4 分配 ≥/16）| 大規模資源囤積 |
| E | 協同取得（同一實體在 7 天內同時取得 ASN 與 IPv4）| 路由基礎設施建置，最高緊急程度 |

## 安裝需求

```bash
pip install -r requirements.txt
```

需要 Python 3.10 以上版本。系統也需要安裝 `whois` 指令（macOS：`brew install whois`；Debian/Ubuntu：`apt install whois`）。

## 使用方式

依序執行各步驟，每個步驟依賴前一步的輸出。

```bash
# 步驟一：下載並解析 5 大 RIR 的 delegation 檔案
python3 step1_download_and_parse.py

# 步驟二：各 RIR 探索性分析
python3 step2_explore.py

# 步驟三：異常偵測 → rir_data/alerts/security_alerts_YYYYMMDD.xlsx
python3 step3_detect_anomalies.py

# 步驟四：產生 HTML 預警報告（中文版）
python3 step4_alert_report.py

# 步驟四（英文版）：適合直接寄送給各 RIR 安全聯絡窗口
python3 step4_alert_report_en.py
```

### 輸出檔案結構

```
rir_data/
├── delegated-{rir}-latest.txt              # 原始 delegation 檔（每次執行覆寫）
├── {rir}_delegation_YYYYMMDD.xlsx          # 各 RIR 解析後資料
├── {rir}_explore_YYYYMMDD.xlsx             # 各 RIR 探索性分析
└── alerts/
    ├── security_alerts_YYYYMMDD.xlsx       # 結構化預警（含各偵測類型分頁）
    ├── security_report_YYYYMMDD.html       # 可分享報告（中文）— 含 WHOIS 自動查詢結果
    └── security_report_YYYYMMDD_en.html    # 可分享報告（英文）— 含 WHOIS 自動查詢結果
```

## 偵測邏輯說明

### A — 高速 IP 資源累積
依 `opaque_id` 彙整過去 90 天的 IPv4 分配記錄，標記累積量 ≥65536 的實體。威脅等級依累積量遞增：≥1M → 高，≥256K → 中。

### B — 新 ASN 國家爆發
統計各國在各 RIR 過去 30 天內的新 ASN 數量，並計算 z-score。標記 z ≥ 2.5 的國家。z ≥ 4.0 → 高，z ≥ 3.0 → 中。

### C — 跨國資源持有
依 `opaque_id` 彙整所有分配記錄，計算涵蓋的不同國家數。標記跨越 ≥5 個國家的實體。

### D — 巨型單次分配
標記過去 90 天內單筆 IPv4 分配量 ≥65536（即 ≥/16）的記錄。

### E — 協同取得模式
針對每個 `opaque_id`，找出在同一個 7 天窗口內同時取得 ASN 與至少一個 IPv4 區塊的情形。

## WHOIS 自動查詢

產生報告時，`whois_enrich.py` 會自動對所有高風險預警進行 WHOIS 查詢。針對每個標記的 `opaque_id`，流程如下：

1. 從 delegation 檔案找出對應的 IPv4 起始位址或 ASN
2. 執行系統 `whois` 指令查詢
3. 解析實體名稱、描述與登記國
4. 在 HTML 報告頂部的摘要表格中呈現結果

收到報告的人可以直接看到被標記資源的持有者，無需手動查詢 WHOIS。查詢結果仍應獨立核實——WHOIS 資料可能不完整或有誤。

## 關鍵概念

**opaque_id** — RIR 內部識別符，用於追蹤同一資源持有者的跨次分配記錄。無需 WHOIS 身分資料，即可偵測累積與跨國持有模式。

**Delegation Extended 格式** — 以管線符號分隔：`registry|cc|type|start|value|date|status|opaque_id`。以 `#` 或 `2|` 開頭的行為標頭或摘要，略過不處理。`cc=ZZ/*` 表示保留位址空間。

## 各 RIR 安全聯絡窗口

| RIR      | 服務區域               | 聯絡信箱               |
|----------|------------------------|------------------------|
| APNIC    | 亞太地區               | security@apnic.net     |
| RIPE NCC | 歐洲／中東／中亞       | abuse@ripe.net         |
| ARIN     | 北美洲                 | abuse@arin.net         |
| LACNIC   | 拉丁美洲／加勒比海     | abuse@lacnic.net       |
| AFRINIC  | 非洲                   | abuse@afrinic.net      |

## 自動化執行

可透過 cron 或系統排程器設定每日自動依序執行全部步驟。各輸出檔案均附有日期戳記，歷史執行結果不會互相覆蓋。

## 授權條款

GNU 通用公共授權條款第 3 版（GPL-3.0）— 詳見 [LICENSE](LICENSE)。

本軟體可自由使用、修改與散布，但衍生作品須以相同授權條款發布。
