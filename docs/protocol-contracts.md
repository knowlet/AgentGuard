# 協定、Policy 與資料契約

2026-09-17 review 修訂；[來源](sources.md)、[完整 gate registry](review-gates.md)。下列上游 wire 來自固定 v1.5.0；本專案 policy 仍是 proposed schema，沒有 compiler/runtime。來源查核、helper 自測與真實 Gateway E2E 是不同證據。

## 1. LLM webhook 與已確認的 fail-open

v1.5.0 預設 POST /request、POST /response；body 為 normalized messages/choices，不是完整 OpenAI HTTP body。[S3–S4]

```json
{"body":{"messages":[]}}
```

這只展示外層，不表示空 chat request 合法。Message 子欄位、所有 choices、tool calls/results 與 provider fields 需 G0-COVERAGE 外部 oracle 驗證。

回傳 action 是 untagged object，而非字串。合法形狀示例：

```json
{"action":{"reason":"POLICY_ALLOW"}}
```

```json
{"action":{"status_code":403,"body":"Request blocked","reason":"SECRET_DETECTED"}}
```

request mask 透過 action.body.messages，response mask 透過 action.body.choices；必須保持必要 schema/非目標資料並檢查 mutation 語意，不能只回純文字。

**已知 fall-through：** Mask→Reject→Pass；Pass.reason optional 且未知欄位被忽略。空 action、錯字 status、字串 status_code、空 mask body 可成功成為 Pass。failClosed 只處理 Err，不能阻止成功的 Pass。並非任何物件都會成功：不符合前兩個分支且 reason 為 number 等型別時仍可解析失敗。[S4,S25,S27]

G0-WIRE 區分「原版漏洞診斷」與「受保護部署」。原版注入負向 fixture 應重現問題，狀態 VULNERABILITY_REPRODUCED，不是 protected PASS。部署必須修補 parser 或驗收不可繞過的 webhook response validation boundary；本變更沒有該修補。

canonical 契約要求：唯一分支、嚴格型別、必要欄位、拒絕未知/duplicate keys、合法 reject status、正確方向的 mutation schema。Pass 必須有明確非空 reason；只加 deny_unknown_fields 仍不會拒絕空物件。Reason 是記錄，不是授權來源。

AgentGuard serializer 以 typed Decision 生成 bytes，再用獨立嚴格 decoder 檢查 effect/variant/status/mutation 相等。僅用同一個 permissive parser round-trip 不足；serializer 是 defense-in-depth，不能修復原版 Gateway。`tools/assurance_contract.py` 只提供 allow/reject 子集的測試 helper，mask 故意拒絕，不能當 production adapter。

負向 fixtures 在 `tests/fixtures/webhook-negative.json`；request 路徑斷言 upstream_calls=0；response hook 已在 upstream 之後，斷言 client-visible payload/canary 洩漏=0，不能要求已執行呼叫歸零。正常 pass/reject/mask controls 也必須成功，避免全拒絕偽通過。

## 2. 原始 context 與 coverage ground truth

allowedEndpoints、allowedContentTypes、streaming: deny 都是 obligation，不是 webhook 天然提供的能力。G0-CONTEXT 需證明原始 ingress route/media-type 控制、可信 CEL context、stream/model 的原始/有效狀態。

移除每個必要 header、CEL 求值失敗、client 偽造/重複 header、route active 後 context 遺失，都必須測試。缺 deployment evidence 不得 activate protected route；runtime 缺 context 用 CONTEXT_UNAVAILABLE deny，request upstream_calls=0。未知 stream 絕不預設 false；只有實際觀察到原始 schema 省略 stream 才能依端點契約採 default。Hook 自己的 application/json 不代表原始 Content-Type。

Client 內部 header 先剝除再由 Gateway 覆寫，adapter 驗證 caller。確切 CEL expressions 經 fixture 證明後才放入部署配置；不填看似可執行但未驗證的表達式。需要完整 body 的控制使用已驗收 native policy/ExtProc，否則拒絕能力。

G0-COVERAGE 由外部 Assurance runner 持有原始欄位 manifest，觀察 client→Gateway、Gateway→hook、Gateway→backend、backend→client。在 system/user/assistant、tool args/results、name、tool schema、image_url、provider extensions、多 choices 注入不同 markers。Marker 到 hook 不等於 detector 掃描，需 spy/expected findings 與 payload preservation 驗證。

矩陣按 gateway/config/adapter digest 記 source JSON pointer、轉換位置、lossiness、hook/上游觀察、native enforcement、fixture/artifact hash；狀態 observed_inspected/ingress_rejected/forwarded_uninspected/unknown。只可對宣告 schema/內容義務聲稱覆蓋，不推論未知未來欄位或任意語意完整性。

未知原始欄位必須 normalize 前拒絕；hook 無法知道已丟棄的資料。缺原始 envelope 檢查或有效 field matrix，不可把 incompleteCoverage: deny 標為滿足。未支援 image_url 等可用已證明 ingress reject 滿足封閉 profile，不要求硬塞進文字 detector。證據輸出位置見 review-gates；本次沒有生成 runtime coverage matrix。

| 表面 | MVP 政策 | 升級條件 |
|---|---|---|
| /v1/chat/completions 文字、非串流 | G0 四項通過後才支持 | history/choices/body limits/mutation、context、原始欄位驗收 |
| LLM tool/function-call fields | unverified 即拒絕該功能 | 逐欄位 ingress/hook/egress fixture與安全 mutation |
| stream=true/SSE | 上游前拒絕 | 跨 chunk/UTF-8/JSON、cancel/backpressure、輸出前檢查 |
| Responses/Files/embeddings/多模態 | 未驗收即拒絕 | 各自 protocol/欄位/生命週期證據 |
| raw PDF/DOCX/multipart/file ID/URL | 不是文字 prompt，MVP 拒絕 | 隔離 ingestion、解壓限制、extraction provenance、安全測試 |

Sliding-window 不保證任意長秘密不從較早 chunk 洩漏；嚴格輸出模式需完整 buffer/inspect 或拒絕 streaming，不能先發未檢查 bytes 再宣稱零洩漏。

## 3. ExtMCP wire 與 error protection

從 `ext_mcp.proto@v1.5.0` 生成 stubs；package agentgateway.dev.ext_mcp，service ExtMcp，RPC CheckRequest/CheckResponse。[S2]

| 契約 | AgentGuard 要求 |
|---|---|
| service_names 是 native/unmuxed backend；fanout 可多個 | 身分包含 backend，不能只看可見 tool name |
| metadata_context 由 CEL 產生 | 只信配置白名單與驗證身分，缺值拒絕 |
| mcp_request 是 params raw JSON bytes，可缺省 | 不當完整 JSON-RPC envelope，依 method parse |
| mcp_response 是 result raw JSON bytes | method-specific schema，非任意 envelope |
| request mutated 替換 params，Gateway 不重跑 RBAC | mutation 後自行 schema validate/re-authorize；MVP 禁改 tool identity |
| response mutated 替換 result | 保持 schema、pagination、必要 metadata；invalid 不 allow |
| headers 為 bytes；HTTP/stdio 行為不同 | 不假設 UTF-8；禁改授權根/路由根/tenant |
| JSON-RPC errors 不進 CheckResponse | 不宣稱所有 MCP 輸出已檢查，須 G2-ERROR |

method selector 設 catch-all 並逐項測 phase/coverage；tools/list 需要 response，tools/call 至少 request，治理 result 需 full。[S18] catch-all 不保證所有 notification/server-initiated flow 都到 hook。initialize/ping 顯式 allow；resources/prompts/sampling/elicitation/notifications/subscriptions 各自列能力，未支持者關閉或拒絕。

工具列表與執行授權共用 catalog，但每次 tools/call 重新檢查。Cache key 含 tenant/auth scope/backend catalog/policy revision；pagination/list_changed/fanout/callback 行為用真實 fixture，不猜測 multiplexed 名称。Session 不可保留已撤銷權限。

Error 模式明確分為 error_sanitized、backend_attested、unsupported。**只有通過 G2-ERROR 的 sanitizer 路徑才可在此維度標 protected；attestation 永遠是 attested_unprotected。** 可信 backend fixture 不洩漏，不能證明未來錯誤安全。Strict policy 不接受 attestation 代替保護。

G2-ERROR 用沙箱在 error.message/data/巢狀欄位注入 run-specific canary，涵蓋 initialize/list/call、HTTP 200 JSON-RPC error、非 2xx、支援 transport；檢查 client-visible headers/body/trailers。sanitized 路徑要移除/替換整個敏感 error payload，故障仍不得洩漏；attested 路徑若洩漏記契約違反且不可標 protected。輸出治理不回滾已發生工具副作用。

## 4. 本專案内部決策契約（proposed）

GuardContext：request_id、可信 trace context、tenant/subject/scopes、protocol/direction/method/resource、policy revision、segments、coverage、deadline。ContentSegment 含原始 JSON path、media type、信任等級、raw text、分析視圖/offset mapping；Python code point、UTF-8 byte、JS UTF-16 明確轉換，測 emoji/組合字。

Finding：detector/version/category/confidence/severity/span/coverage/reason/latency；不授權、不選 backend。Coverage 只描述已宣告可見範圍，不能替代外部 oracle。Decision：allow/deny/mutate、would_effect、reason codes、policy digest、obligations、findings summary、timings；mutation payload 與可記錄摘要分開。error/unsupported/incomplete 依 failure policy 處理，不直接算 allow。

決策順序：驗證身分/協定/size→固定 snapshot→必需 detectors→deny 優先→允許且可安全實作的 mutation→schema/必要 invariant/授權重驗→durable 最小稽核→wire。相同 bundle/context/findings 產生相同 decision，不聲稱 GPU inference bitwise deterministic。Span overlap 採可回放規則；mapping 依 tenant/session 隔離、TTL/加密，不跨租戶還原。

## 5. Policy 草案：要求不等於已具備能力

[獨立 YAML](../examples/policies/strict-local.proposed.yaml) 是 canonical 草案，不是原生 Gateway configuration。未知欄位/任意 script 禁止，P1 要建 schema/migration。`compatibilityEvidenceRef: null` 故意代表無證據，compiler 必須拒絕 activation；不得把本範例標可部署。

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
  deploymentRequirements:
    compatibilityEvidenceRef: null # Missing evidence MUST reject activation.
    webhookActionBoundary: strict_verified
    requiredTrustedContext: [original_path, original_media_type, effective_stream, requested_model]
    fieldCoverageOracle: external_per_version
    rejectUnknownFieldsBeforeNormalization: true
    onMissingEvidence: reject_activation
    webhookBudgetMs: 8000 # Proposed, not measured.
    transportReserveMs: 500
    safetyMarginMs: 1000
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
    errorResponseMode: error_sanitized
    allowBackendAttestationAsProtection: false
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
    missingTrustedContext: deny
    invalidMutation: deny
    unknownCapability: deny
    auditAppend: deny
  audit:
    payloadMode: metadata_only
```

此草案沒有授予 MCP method/tool；未配置 grants 即拒絕，也沒有宣稱語意 injection detector。errorResponseProtection 是需求，不是 ExtMCP 自動提供的能力。語言、模型 readiness、strict wire boundary、external evidence 都需滿足才能 activate。

## 6. 長文、變形與 deadline

pplx 原版預設截斷至 4,096 tokens，需 tokenizer-aware chunks/overlap/原文 span mapping；不能把未读資料標已掃描。[S6] chunking 不代表跨 chunk/跨輪 injection 語意完整。Base64/zero-width 等僅建立 bounded analysis view，不執行內容、不自動改寫原文；decode depth/expansion bytes/chunk count/deadline 固定並測試，roleplay 不當編碼問題處理。

G0-DEADLINE：guard_budget + transport_reserve + safety_margin < effective_gateway_timeout。v1.5.0 的 webhook 預設 BackendRequestTimeout 為 10 秒，不是整段 LLM latency SLO。[S25] queue/解析/推論/mutation/序列化/durable audit 全計入；bounded queues/並行限制/circuit breakers 防拖垮 Gateway。

GUARD_DEADLINE_EXCEEDED、GATEWAY_GUARD_TIMEOUT、GUARD_UNAVAILABLE 與 policy deny 分開。Guard crash 沒有 decision event 時，由獨立 Gateway access event/runner 關聯，不能偽造 Guard 決策。測 below/near/above deadline、writer 阻塞與 cancel；必要 detector 失敗不得 retry 後 failOpen。Shadow 任務可丟棄但標 dropped/not evaluated。Timeout 不算 detector 成功防禦；ASR/availability 記帳見 review-gates §6。
