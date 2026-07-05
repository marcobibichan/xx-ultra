# GrainTURN (xx-ultra)

一個專為 Cloudflare Workers 與 Durable Objects 設計的極致效能、超低 CPU 佔用率（CPU Time）的 Outbound 中繼代理系統。

本專案完美實現了 **RFC 6062 (TCP Relay)**、**XUDP (UDP Datagram Bypass)** 以及基於動態 URL Path 路由的 **無狀態直通數據面（Stateless Direct Pass-Through Mode）**。透過雙層記憶體快取池（Double-Layer Cache Pool），將重度的控制面認證與輕量化的數據面盲轉完美分離。

---

## 🚀 核心設計架構

### 1. 控制面與數據面徹底分離 (Control/Data Plane Separation)
* **控制面 (Control Plane - Durable Object):** 負責處理重度計算。包含對向 TURN 伺服器的二進位握手、MD5 雜湊計算、HMAC-SHA1 簽章生成（`Allocate` 與 `CreatePermission` 指令）。一旦驗證成功並取得權限，DO 將狀態回傳並進入休眠，不參與任何下游的高頻數據盲轉。
* **數據面 (Data Plane - Worker Fetch Handler):** 專職處理高速數據流。透過攔截 WebSocket 並解析 Early Data (`sec-websocket-protocol`)，直接與遠端 Socket 對接。

### 2. 雙層高效記憶體快取池 (Two-Tier Memory Cache)
為了將 Worker 的 CPU Time 壓制在微秒（μs）級別，避免每次請求都呼叫 Durable Object：
* **L1 快取 (Worker 全域作用域 Map):** 以 `Host:Port` 為鍵值。若命中，則以 **0ms 延遲** 立即獲取已認證的 TURN 簽章狀態，完全不觸發 DO RPC。
* **L2 快取 (Durable Object 類別作用域 Map):** 當 L1 未命中時，Worker 請求 DO，DO 會從記憶體快取中秒級返回已簽章狀態，免去重複與遠端 TURN 進行三次握手與認證。

### 3. 動態雙軌路由 (TCP/UDP Dual-Track Splitting)
* **TCP 軌道 (RFC 6062 Stream Mode):** 內建高效封包聚合引擎（`GrainTCP`）。採用非阻塞隊列將零碎的小資料塊動態聚合成大塊（如 16KB/32KB）後一次性寫入 Socket，大幅度降低 V8 事件循環（Event Loop）的上下文切換開銷。
* **UDP 軌道 (XUDP Datagram Mode):** 專為語音、遊戲等低延遲場景優化。完全繞過 TCP 的緩衝聚合隊列，維持原始 Datagram 封包邊界，實現零延遲直通。


## ⚙️ 配置與部署

### 1. Wrangler 配置 (`wrangler.toml`)
確保你的環境中正確綁定了 Durable Object：

```toml
name = "xx-ultra"
main = "src/GrainTURN.js"
compatibility_date = "2024-04-01"
compatibility_flags = [ "nodejs_compat" ]

[[durable_objects.bindings]]
name = "CONTROL_PLANE_DO"
class_name = "ControlPlaneDO"

[[migrations]]
tag = "v1"
new_classes = ["ControlPlaneDO"]

```

### 2. 客戶端連接指引 (Client Connection URL)

你的客戶端可以透過極具隱蔽性的動態路徑直接發起請求，Worker 會自動解析並代理至目標伺服器：

```text
ws://your-worker.pages.dev/turn://username:password@140.111.67.17:3478

```

---

## 📦 編譯與混淆 (Obfuscation & Build)

本專案代碼採用現代 ECMAScript Class 與 Modules 語法。若要進行混淆保護，請使用支援 ES2022+ 的編譯器。

**使用 `javascript-obfuscator` 編譯：**

```bash
javascript-obfuscator src/GrainTURN.js --output ./worker.js

```

---

## 📜 許可證

基於 AGPL3.0 License 開源。請盡情享受極致網速與微秒級延遲的快感！

