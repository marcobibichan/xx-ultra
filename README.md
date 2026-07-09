# GrainTURN_XHTTP (xx-ultra)

一個專為 Cloudflare Workers 與 Durable Objects 設計的極致效能、超低 CPU 佔用率（CPU Time）的 Outbound 全 TURN 中繼代理系統。

本專案完美實現了 **RFC 6062 (TCP Relay over TURN)**、**XUDP (UDP ChannelData 盲轉)** 以及基於 **XMUX 幀多路復用** 的 **無狀態直通數據面（Stateless Direct Pass-Through Mode）**。透過雙層記憶體快取池（L1/L2 Cache Pool），將重度的控制面認證（MD5 + HMAC-SHA1）與輕量化的數據面盲轉完美分離。ControlPlaneDO 僅在認證階段存活 ~5ms，隨即休眠，絕不參與任何高頻數據轉發。

---

## 🚀 核心設計架構

### 1. 控制面與數據面徹底分離 (Control/Data Plane Separation)

```
┌─ ControlPlaneDO (Durable Object) ──── 活躍時間 ~5ms ─────┐
│ • 僅在 L1 cache miss 時被 RPC 喚醒                          │
│ • 建立暫存 TCP 連線 → TURN Allocate 握手                    │
│ • MD5(user:realm:pass) → HMAC-SHA1 簽章                    │
│ • 回傳 { key, aa } JSON → 立即休眠 💤                       │
│ • 計費：僅 5ms Active Duration，非整個連線時長              │
└───────────────────────────────────────────────────────────┘
                           │ JSON RPC (可跨 Isolate)
                           ▼
┌─ Worker Fetch Handler (數據面) ───── 長連線維持 ──────────┐
│ • L1 Cache (Global Map) 命中 → 0ms 延遲，不喚醒 DO          │
│ • 自行建立 TURN control + data socket (Worker Isolate)      │
│ • ctx.waitUntil() 鎖定生命週期                              │
│ • TCP: GrainTCP 聚合 → TURN data socket → RFC 6062          │
│ • UDP: Send Indication 盲轉 → ChannelData                   │
│ • 下行: stream-one 裸字節 / 多 session XMUX 幀封裝          │
│ • 計費：Web Streams pipe 不計 CPU Time                      │
└───────────────────────────────────────────────────────────┘
```

* **控制面 (ControlPlaneDO):** 負責處理重度計算。包含對向 TURN 伺服器的二進位握手、MD5 雜湊計算、HMAC-SHA1 簽章生成（`Allocate` 與 `CreatePermission` 指令）。一旦驗證成功並取得 `{ key, USER, REALM, NONCE }` 狀態，DO 立即回傳 JSON 並進入休眠，不參與任何下游的高頻數據盲轉。
* **數據面 (Worker Fetch Handler):** 專職處理高速數據流。透過攔截 HTTP POST 並解析 VLESS header + Early Data，自行建立對向 TURN 的 control connection 與 data socket，利用 `ctx.waitUntil()` 接管全部 TCP/UDP 管道的生命週期。

### 2. 雙層高效記憶體快取池 (Two-Tier Memory Cache)

為了將 Worker 的 CPU Time 壓制在微秒（μs）級別，避免每次請求都呼叫 Durable Object：

* **L1 快取 (Worker 全域作用域 `Map`):** 以 `Host:Port:User:Transport` 為鍵值。若命中，則以 **0ms 延遲** 立即獲取已認證的 TURN 簽章狀態（`key` + `aa` attributes），完全不觸發 DO RPC。過期時間 10 分鐘。
* **L2 快取 (Durable Object 類別作用域 `Map` + `state.storage`):** 當 L1 未命中時，Worker 透過 RPC 呼叫 DO。DO 優先從記憶體快取（`doCache`）返回已簽章狀態；若 L2 也未命中，DO 建立暫存 TCP 連線與遠端 TURN 完成完整認證握手，將結果存入 L2 並持久化到 `state.storage`，免去後續請求的重複三次握手。

```
請求 → L1 (Worker Global Map) ──命中──→ 0ms 返回 auth state
         │ 未命中
         ▼
      L2 (DO doCache) ──命中──→ ~1ms RPC 返回
         │ 未命中
         ▼
      DO 建立暫存連線 → TURN handshake → ~5ms 返回 + 寫入 L1/L2
```

### 3. UDP/TCP 雙軌分離連線 (Dual Transport Isolation)

嚴格遵循 RFC 5766 §6.2：**同一 5-tuple 不可同時持有 UDP 與 TCP allocation**。

* **UDP 軌道 (`createTURNUDPPool`, transport=17):** 一條持久 control connection。所有 UDP session 共享此連線，透過 `Send Indication` (method 0x016) 盲轉上行數據，`Data Indication` (method 0x017) 接收下行數據。下行封裝為 XUDP 回應包 → XMUX 幀 → `controller.enqueue()`。
* **TCP 軌道 (`createTURNTCPConnection`, transport=6):** 每個 TCP session 建立**獨立**的 control connection。完整 RFC 6062 流程：`Allocate` → `Permission` + `Connect` (pipeline) → 開啟 data socket → `ConnectionBind`。Control connection 由 Worker 維持至 session 結束。Data socket 對接 GrainTCP 聚合引擎。

```
UDP Pool (1 條持久 control conn)
  ├─ Session A (Send Indication / Data Indication)
  ├─ Session B
  └─ Session C

TCP Factory (每 session 獨立 control conn)
  ├─ Session 0: ctrl₀ → data socket₀ → GrainTCP
  ├─ Session 1: ctrl₁ → data socket₁ → GrainTCP
  └─ Session 2: ctrl₂ → data socket₂ → GrainTCP
```

### 4. GrainTCP 封包聚合引擎 (Packet Aggregation Engine)

* **TCP 軌道內建高效封包聚合引擎（`mkGrainTCP`）。** 採用非阻塞隊列將零碎的小資料塊動態聚合成大塊（預設 32KB）後一次性寫入 TURN data socket，大幅度降低 V8 事件循環（Event Loop）的上下文切換開銷。
* **UDP 軌道完全繞過聚合隊列。** 維持原始 Datagram 封包邊界，實現零延遲直通（Zero-Latency Pass-Through）。

### 5. XMUX 多路復用與 Stream-One 模式

| 模式 | VLESS cmd | 上行 | 下行 |
|------|-----------|------|------|
| **Stream-One** | `0x01` (TCP) | 裸 TCP 字節流（或 XMUX 幀） | 裸 TCP 字節流（零包裝） |
| **XMUX 多路** | `0x03` (MUX) 或 SESS_NEW 幀 | XMUX 幀流 | XMUX SESS_KEEP 幀封裝 |

* **Stream-One 模式：** VLESS header 指定單一 TCP 目標。下行使用裸字節流，確保 TLS 記錄層（Record Layer）完整無損——Google 的小憑證與 YouTube 的大憑證鏈均能完美通過 Firefox 的憑證校驗。
* **XMUX 模式：** 單一 HTTP POST 承載多個 TCP/UDP session。上行解析 `SESS_NEW` / `SESS_KEEP` / `SESS_END` 幀；下行每個 session 的數據獨立封裝為 `SESS_KEEP` 幀（8 字節頭 + payload），字節邊界絕對精確。

### 6. 流式緩衝區 (Stream Buffer)

上行 XMUX 幀解析採用嚴格的流式緩衝區（`uploadBuffer`）：若當前 chunk 只包含半個幀頭（不足 4 字節），保留至下一 chunk 拼接後再解析。**1 位元組都不漏。**

---

## ⚙️ 配置與部署

### 1. Wrangler 配置 (`wrangler.toml` / `wrangler.jsonc`)

```toml
name = "xx-ultra"
main = "GrainTURN.js"
compatibility_date = "2024-04-03"
compatibility_flags = [ "nodejs_compat" ]

[[durable_objects.bindings]]
name = "CONTROL_PLANE_DO"
class_name = "ControlPlaneDO"

[[migrations]]
tag = "v1"
new_classes = ["ControlPlaneDO"]
```

```jsonc
// wrangler.jsonc 等效配置
{
  "name": "xx-ultra",
  "main": "GrainTURN.js",
  "compatibility_date": "2024-04-03",
  "compatibility_flags": ["nodejs_compat"],
  "durable_objects": {
    "bindings": [
      { "name": "CONTROL_PLANE_DO", "class_name": "ControlPlaneDO" }
    ]
  },
  "migrations": [
    { "tag": "v1", "new_classes": ["ControlPlaneDO"] }
  ]
}
```

### 2. Worker 內置常量

部署前修改 `GrainTURN.js` 頂部的 `CFG` 常量：

```javascript
const CFG = {
  UUID: '78f076f9-35f8-4847-8722-d44fe7942752',  // 替換為你的 VLESS UUID
  PATH: '/bibichan',                                // 替換為你的路由路徑
  CHUNK: 64 * 1024,
  DN_PACK: 32 * 1024,    // GrainTCP 聚合塊大小
  DN_TAIL: 512,          // 聚合觸發閾值
  DN_MS: 0,              // 聚合延遲 (ms)
  CONCUR: 4,
  MAX_SESSIONS: 128,
  SESSION_IDLE_MS: 30_000,
  MUX_METALEN_MAX: 512,
};
```

### 3. 客戶端連接指引 (Client Connection)

客戶端透過 HTTP POST 發起請求，`X-Turn` header 指定 TURN server：

```text
POST /bibichan HTTP/1.1
Host: your-worker.workers.dev
X-Turn: turn://username:password@coturn.example.com:3478
Content-Type: application/octet-stream

[VLESS header][XMUX frames or raw TCP data]
```

**`X-Turn` header 格式：**

```
turn://<host>:<port>:<username>:<password>
```

無認證 TURN server：
```
turn://<host>:<port>
```

或簡寫：
```
<host>:<port>:<username>:<password>
```

### 4. TURN Server 要求

* 支援 RFC 5766 (TURN) 與 RFC 6062 (TCP Relay)
* 同時監聽 UDP 與 TCP（預設 port 3478）
* 若使用 coturn，確保 `turnserver.conf` 中**未設定** `no-tcp-relay`
* Long-term credential mechanism (lt-cred-mech)

---

## 📦 編譯與混淆 (Obfuscation & Build)

本專案代碼採用現代 ECMAScript Modules 語法。若要進行混淆保護：

```bash
javascript-obfuscator GrainTURN.js --output ./worker.js \
  --compact true \
  --control-flow-flattening true \
  --dead-code-injection true \
  --string-array-encoding 'rc4' \
  --string-array-threshold 0.75
```

---

## 🔬 協議棧 (Protocol Stack)

```
┌─────────────────────────────────────────┐
│ 應用層 (Browser / curl)                  │
├─────────────────────────────────────────┤
│ TLS (HTTPS)                             │
├─────────────────────────────────────────┤
│ XHTTP / XMUX (客戶端 → Worker)           │
│ • VLESS header (UUID + target)          │
│ • XMUX frames (SESS_NEW/KEEP/END)       │
│ • Stream-one raw TCP fallback           │
├─────────────────────────────────────────┤
│ HTTP POST (Worker 傳輸層)                │
├─────────────────────────────────────────┤
│ TURN (Worker → TURN Server)             │
│ • RFC 5766: Allocate, Permission        │
│ • RFC 6062: Connect, ConnectionBind     │
│ • STUN: Send/Data Indication            │
├─────────────────────────────────────────┤
│ TCP (TURN Server → Target)              │
└─────────────────────────────────────────┘
```

### VLESS Header 結構

| Offset | Bytes | Field |
|--------|-------|-------|
| 0 | 1 | Version (0x00) |
| 1 | 16 | UUID (binary, no dashes) |
| 17 | 1 | AddInfoLen (M) |
| 18 | M | AddInfo (proto string) |
| 18+M | 1 | Command (0x01=TCP, 0x02=UDP, 0x03=MUX) |
| 19+M | 2 | Port (big-endian) |
| 21+M | 1 | Address Type (1=IPv4, 2=Domain, 3=IPv6) |
| 22+M | 4/16/N | Address Body |

### XMUX Frame 結構

| Offset | Bytes | Field |
|--------|-------|-------|
| 0 | 2 | MetaLen (≥4, ≤512) |
| 2 | 2 | Session ID |
| 4 | 1 | Status (0x01=NEW, 0x02=KEEP, 0x03=END, 0x04=KEEPALIVE) |
| 5 | 1 | Option (0x01=DATA, 0x02=ERR) |
| 6 | N | Status-dependent metadata |
| 2+MetaLen | 2 | DataLen |
| 4+MetaLen | N | Data Payload |

#### SESS_NEW metadata

| Offset | Bytes | Field |
|--------|-------|-------|
| 6 | 1 | Network (0x01=TCP, 0x02=UDP) |
| 7 | 2 | Port |
| 9 | N | Address (same encoding as VLESS) |

---

## 🧠 關鍵設計決策與 RFC 合規

| 決策 | 原因 |
|------|------|
| UDP/TCP 分離 control connection | RFC 5766 §6.2：同一 5-tuple 不可有雙 allocation，否則 TURN server 回 437 Allocation Mismatch |
| ControlPlaneDO 僅做 auth，不做數據轉發 | DO 按 Active Duration 計費；若維持 2 小時 YouTube 連線將耗盡免費額度 |
| L1/L2 雙層快取 | 避免每次請求喚醒 DO；L1 命中 → 0ms，L2 命中 → ~1ms RPC |
| `ctx.waitUntil()` 顯式鎖定 | Web Streams 隱式保持 Worker 存活，顯式 `waitUntil` 更安全，且便於 cleanup |
| 流式緩衝區 (`uploadBuffer`) | 跨 chunk 保留不完整 XMUX 幀頭，防止字節遺失導致幀解析錯位 |
| GrainTCP 聚合 (32KB blocks) | 減少 `writer.write()` 呼叫次數，降低 V8 事件循環開銷 |
| stream-one 裸字節下行 | TLS 記錄層完整無損；XMUX 幀僅在多 session 時啟用 |
| Control connection 不提早關閉 | TURN allocation 生命週期綁定 control conn；關閉即觸發 allocation release |
| `dw.releaseLock()` 先於 `getWriter()` | WritableStream 同一時刻僅允許一個 writer |

---

## 📜 許可證

基於 AGPL v3.0 License 開源。請盡情享受極致網速與微秒級延遲的快感！



