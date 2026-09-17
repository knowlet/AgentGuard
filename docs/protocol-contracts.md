# 協定、Policy 與資料契約

狀態：2026-09-17 設計稿。上游依據見 [S1–S4](sources.md)；範例分為「已讀取的 v1.5.0 wire 形狀」與「本專案 proposed schema」。本文件不是可直接啟動的 Gateway 設定。

## 1. 必須先驗收的 LLM wire

AgentGateway v1.5.0 原生 guard webhook 預設使用 `POST /request` 與 `POST /response`。請求與回應並非整個 OpenAI HTTP body，而是上游定義的 normalized messages／choices。須用固定版本 golden fixtures 確認 role、text、tool calls／results、所有 choices、provider-specific 欄位與歷史訊息的實際覆蓋；未看見的欄位不能聲稱已檢查。[S3–S4]

以下僅展示外層形狀；空陣列不表示允許空 chat request，Message 子欄位仍須 P0 固定版本 fixture 驗證。

```json
{"body":{"messages":[]}}
```

hook 的回傳 `action` 是 untagged object，不是 `{"action":"deny"}`。依已讀取的 Rust 結構，基本形狀如下；內部 Decision 一定要經專用 adapter，不能直接送給 Gateway。

```json
{"action":{"reason":"POLICY_ALLOW"}}
```

```json
{"action":{"status_code":403,"body":"Request blocked","reason":"SECRET_DETECTED"}}
```

request masking 以 `action.body.messages` 傳回改寫結果；response masking 以 `action.body.choices`。必須保留並驗證未更動的必要結構，不僅回傳抽取後的純文字。上游 untagged 解析的寬鬆程度也是測試項：錯誤的動作 key、缺欄位或意外空物件不可被我們的 serializer 產生；相容性測試要確認它不會被誤當允許。

認證 context 用受信 Gateway 計算後的 headers 傳遞，adapter 驗證呼叫來源。任何需要 `model`、`stream` 或完整 schema 的 ingress policy，要驗證該欄位在其執行點可用；不足時使用經測試的原生 policy／ExtProc 或拒絕該功能。不能任意添加 webhook 原本不存在的欄位。

### MVP 支援矩陣

| 表面 | 初始狀態 | 升級 gate |
|---|---|---|
| `/v1/chat/completions` 文字、`stream=false` | P0 驗收後支援 | 單輪、多輪 history、所有 choices、mask/reject、body 上限 |
| LLM function/tool-call 相關欄位 | 預設 unverified，必要時拒絕整個功能 | wire 中每個相關欄位的輸入／輸出 fixture + 結構化 mutation |
| `stream=true` / SSE | MVP 拒絕，且在呼叫上游前拒絕 | 跨 chunk／UTF-8／JSON 邊界及 cancel/backpressure；檢查前不得發出敏感 bytes |
| Responses／Files／embeddings／音訊／圖像等 | 未驗收即拒絕 | 各自的欄位、協定、body semantics 與資料生命週期測試 |
| raw DOCX/PDF、multipart、遠端 URL/file ID | MVP 拒絕，非文字 prompt | 隔離 ingestion、解壓限制、可信 extracted text/provenance、惡意文件測試 |

若未來只採 sliding-window streaming，必須標示它無法保證任何長度秘密都不在較早 chunk 洩漏。零已知秘密外流的嚴格模式需先完整 buffer/inspect，或對該類輸出拒絕串流；不能宣稱 streaming-safe 同時先把未檢查 token 發出。

## 2. ExtMCP wire 與不可忽略的邊界

以 `crates/protos/proto/ext_mcp.proto@v1.5.0` 生成 stubs；package 是 `agentgateway.dev.ext_mcp`，service 是 `ExtMcp`，RPC 為 `CheckRequest`／`CheckResponse`。[S2]

| 欄位／結果 | 真正語意 | AgentGuard 規則 |
|---|---|---|
| `service_names` | native、unmuxed backend names；fanout 可多個 | 授權與 tool identity 包含 backend，不只比對可見 tool name |
| `metadata_context` | Gateway CEL evaluation 的 context | 僅接受配置白名單中的可信身分／resource；缺必要欄位即拒絕 |
| `mcp_request` | JSON-RPC **params** bytes，可缺省 | 不當作完整 JSON-RPC envelope；依 method schema parse |
| `mcp_response` | JSON-RPC **result** bytes | 檢查 method-specific 結構，不任意改寫 envelope |
| request `mutated` | 替換 params，Gateway **不重跑 RBAC** | 新 params 必須 schema validate + 自己重新授權；MVP 禁止改寫 tool identity |
| response `mutated` | 替換 result，無效結構視協定違規 | tools/list 保持 schema、pagination 與 metadata 合法 |
| `headers`／header mutation | headers 是 bytes，HTTP 與 stdio 行為不同 | 不假定每個值 UTF-8；禁止改寫授權根、路由根或跨 tenant headers |
| JSON-RPC error | **不經過 CheckResponse** | 不宣稱錯誤內容已被掃描；見以下補償 gate |

MCPGuard 對 error path 的方案按 route 選擇：可信 backend 保證 error 不帶機敏內容並有契約測試；或使用經 E2E 驗證的 HTTP body 補充檢查／sanitizer；否則敏感 route 不列為 protected 並拒絕啟用。單靠 ExtMCP success-result hook 無法證明所有錯誤都不外洩；HTTP/SSE 補洞不可在未驗證下稱已解決。

Processor method mapping 必須設 catch-all（官方 selector 支援 `*`），因為沒有匹配的 method 可能不觸發 processor。最具體規則優先；`tools/list` 要有 response phase，`tools/call` 至少 request phase，需要輸出治理則 full。catch-all 仍不代表每種 notification／server-initiated flow 天然都進 hook；initialization、capability negotiation、resources、prompts、sampling、elicitation、subscriptions／notifications 逐項列 coverage，無法安全處理者關閉其 capability。[S18]

Adapter unavailable、deadline、invalid JSON、malformed mutated result、oversize response、未知 enum、丟失身分都加入 failClosed 測試。正常 `initialize`／`ping` 可以有顯式 allow，不以「未知一律放行」維持相容性。

`tools/list` 與 `tools/call` 共用 capability catalog：filter 不能取代執行授權；兩個同名工具來自不同 backend 不可混用。list cache key 含 tenant、authorization scope、backend catalog version、policy revision；分頁和 list_changed 要保持一致。確認 gateway 的 fanout 實際 callback 行為後建立 fixture，不靠猜測合併名稱。

## 3. 本專案內部決策契約（proposed）

`GuardContext`：request_id、可信 trace context（有才記錄）、tenant、subject/scopes、protocol、direction、method、resource、policy revision、content segments、coverage、deadline。

`ContentSegment`：原始 JSON path、媒體／文字類型、來源信任等級、raw text、分析視圖、original-offset mapping。raw text 僅在必要執行記憶體中存在；一般 log 只記 span 類型與數量。Python code-point、UTF-8 byte、JS UTF-16 的 offset 定義分清，adapter 邊界顯式轉換並測試 emoji／組合字。

`Finding`：detector_id/version、category、confidence（可缺）、severity、原始 span、coverage、reason_code、latency。Detector 回傳 findings 或 typed failure；不回傳使用者角色、不選擇目的 backend、不批准 tool。

`Decision`：effect=`allow|deny|mutate`、would_effect（shadow 時）、reason_codes、policy revision/digest、coverage、obligations、findings summary、timings。mutation payload 與可記錄的摘要分開。三態以外的 `error/unsupported/incomplete` 是處理狀態，必須經 failure policy 對應 effect，不能當 allow。

### 決策次序

1. 驗證協定／身分／資源與 size limits；不支援或未授權先 deny。
2. 讀取 request-bound immutable bundle，選擇必需 detector；任何必需項失敗按 failure policy 處理。
3. 建立受限分析視圖；正規化和解碼只供檢測，不執行 payload，不自動改寫使用者原文。
4. 彙整 findings，明確 deny 優先；沒有 deny 才嘗試被允許的安全 mutation。
5. mutation 後驗證 schema、重新檢測需保護的 invariant、重新授權；無法證明完成就 deny。
6. durable append 最小 decision event，再由 adapter 回傳 wire action；記錄最終 effect，不能只記 detector 意圖。

相同 bundle、context 與固定 findings 產生相同 decision，這才是 deterministic governance。推論本身可能非決定性，必須保存模型版本、閾值與可回放的 findings summary；不能聲稱 GPU 推論天然 bitwise deterministic。

mask 不是一律優先於 deny。若 policy 明確要求「PII 可去識別後通過」，該條規則產生 mutation obligation 而非 deny；任何獨立的秘密／授權 deny 仍優先。多 detector span 重疊採可重現 union/type precedence，禁止 nested replacement 導致原始值殘留。假名化 mapping 需要時按 tenant+session scope 隔離、TTL 與加密；不跨 tenant 共用，也不默默還原到外部輸出。

## 4. Canonical policy 草案

下例也是 [獨立 YAML 範例](../examples/policies/strict-local.proposed.yaml)，**不是 AgentGateway 原生設定、尚無對應 compiler/runtime**。P1 需制定 JSON Schema，禁用未知欄位與任意 script，並做 schema migration。

```yaml
apiVersion: agentguard.dev/v1alpha1
kind: PolicyBundle
metadata:
  name: strict-local
  revision: draft-1
spec:
  mode: enforce
  identity:
    requireVerifiedSubject: true
    tenantSource: verified_claim
  llm:
    allowedEndpoints: [/v1/chat/completions]
    allowedContentTypes: [application/json]
    streaming: deny
    incompleteCoverage: deny
  mcp:
    defaultAction: deny
    authorizeEveryCall: true
    requireBackendQualifiedTool: true
    allowRequestIdentityMutation: false
    errorResponseProtection: required
  detectors:
    - id: presidio-local
      purpose: pii
      required: true
      action: mask
    - id: deterministic-secrets
      purpose: secrets
      required: true
      action: deny
  failures:
    requiredDetector: deny
    invalidMutation: deny
    unknownCapability: deny
    auditAppend: deny
  audit:
    payloadMode: metadata_only
```

此 policy 故意沒有授予任何 MCP method/tool；P2 由明確 scope 的 grants 配置所需 initialize/ping/read-only tools。未配置時預設拒絕，不把範例當作開箱可用或含語意 injection detector。`errorResponseProtection: required` 代表必須有已驗收能力，不是 ExtMCP 自動提供該能力。

## 5. 長文、變形與失效預算

pplx 原模型預設截斷到 4,096 tokens；以 tokenizer 實際長度切塊、overlap、原文 offset 合併及跨邊界測試，不能把未讀內容算已掃描。[S6] 解碼器針對 Base64／zero-width 等產生獨立 bounded view，記錄 transform chain；建議初始最多兩層解碼、明確 expansion ratio／總 bytes／chunk 數／deadline，數值由 P0/P3 負載測試固定。

chunking 對局部 PII 可降低邊界漏失，但不等於模型已理解所有跨 chunk 的 injection／多輪關聯；超出 detector 能力時不能標 complete semantic coverage。roleplay 也不是可用 regex 完整涵蓋的編碼變形。

請求總 deadline 分配給解析、CPU、模型排隊、推論、mutation 及稽核。bounded queues、併發限制、circuit breaker 防止慢 detector 拖垮 Gateway；必需 detector timeout 不得因重試耗盡後自動 failOpen。非必需 shadow detector 可丟棄工作，但記錄 dropped／not evaluated，不能記成 safe。
