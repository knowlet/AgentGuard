# AgentGuard 技術選型與分階段實作計畫

基準日：2026-09-17。狀態：**提案／尚未完成 runtime 驗收**。
Repository 基準：`knowlet/AgentGuard`，`develop@beda43c9b2589566ef292ef58b81c4b7822632c8`；該版本只有 README。本文不把其他本機專案、過去 PoC 或上游示範當成本 repository 已實作功能。

相關文件：[協定與 policy 契約](protocol-contracts.md)、[Assurance、資料與營運](assurance-and-operations.md)、[一手來源與證據狀態](sources.md)。

## 1. 結論與產品邊界

採用「一個 enforcement plane、共用 deterministic decision core、可替換 detectors、獨立控制與測試平面」。AgentGateway 負責執行 allow／reject／mutation；PromptGuard 與 MCPGuard 提供協定 adapter；policy-core 根據可信身分、版本化 policy 與 detector findings 做決策。**Detector 分數不是授權，LLM 的說明文字也不能授予權限。**

首個安全 MVP 是：真實 AgentGateway + 文字非串流 LLM + Presidio／秘密規則 + ExtMCP 授權與 tools/list 過濾 + 可回放 decision log + CPU E2E。不是一次串接所有 guardrail 框架。可提供「只有 deterministic controls」的明確設定檔，但不得宣稱它具備可靠的語意 prompt-injection 防護。

第一版不承諾：所有 OpenAI 相容端點、串流零洩漏、任意附件解析、圖像／音訊／影片防護、多 agent 軌跡完整分析、自動合規、完全阻擋 prompt injection。MCP backend 錯誤內容的檢查有已知 hook 缺口，必須按契約處理。未通過相容性測試的功能預設拒絕或標示 unavailable，不默默 passthrough。

## 2. 架構與責任

```text
Client / agent harness
          |
          v
AgentGateway [identity, routing, enforcement, protocol handling]
  |                    |                       |
  | LLM guard webhook  | ExtMCP gRPC            | allowed traffic
  v                    v                       v
PromptGuard          MCPGuard             vLLM / MCP backends
  \                    /
   policy-core + immutable policy snapshot
           |
           +-- deterministic rules / Presidio
           +-- isolated detector workers (pplx, SingGuard, optional validators)

Browser -> Policy Studio (FastAPI) -> PostgreSQL + policy compiler/publisher
                                      | stage / acknowledge / activate
                                      v
                              guard runtime snapshots

Isolated Assurance workers -> actual Gateway endpoints -> sandbox fixtures
Decision JSONL ---------> Alloy file pipeline -----> Loki
Gateway OTLP Logs ------> Alloy OTLP pipeline -----> Loki
Metrics ---------------> Prometheus --------------> Grafana provisioning
```

AgentGateway 不被 Python reverse proxy 取代。若原生 LLM webhook 無法提供必要的完整 body 欄位，先驗證 Gateway native policy 或固定版本 ExtProc 的補充能力；不得假造 webhook 已看過該欄位。ExtProc 是選擇性補洞 adapter，不是 MCP 語意的替代品。

控制平面不在每個 request 的同步關鍵路徑。已載入有效 policy 的 runtime 可在控制平面離線時繼續服務；沒有有效 snapshot、必要 detector 未 ready 或必需稽核寫入失敗時依明確 failure policy 阻擋。控制平面不能任意執行 shell、安裝 validator、啟停 host containers 或存取 Docker socket。

### 信任模型

對手可控制 prompt、工具輸出、MCP metadata、外部文件、客户端 header，甚至惡意 MCP backend。信任根為部署者、簽署／授權發布的 policy、驗證後的身分與固定供應鏈。Gateway／host 已被攻陷不在本層可獨立解決的範圍。模型、MCP backend 與上游 API 不得有可繞過 Gateway 的客户端網路路徑。

`tenant_id`、subject、roles 來自驗證後 JWT／mTLS 或受信 adapter；入口先移除客户端冒充的內部 header。Prompt 內的「我是管理員」、自由輸入的 `x-tenant`、MCP 自稱安全 annotations 都不是授權依據。不同 tenant 的 cache、tool catalog、policy revision 與日誌查詢都必須隔離。

## 3. 技術選型與取捨

以下是採用建議，不是效能實測排行榜。套件／模型／資料三種授權分開記錄；專案自身 LICENSE 由維護者決定，本提案不擅自指定。

| 項目 | 建議 | 原因與限制 | 導入點 |
|---|---|---|---|
| AgentGateway | 以已查核的 v1.5.0 作相容性基線，鎖 image digest、proto 與設定 schema | 官方 release 與 ExtMCP wire 已確認；版本升級重跑 contract suite，不能跟著 latest 漂移 [S1–S4] | P0 |
| policy-core | Python typed models + pure decision functions；與 adapter 共用套件 | 最少跨語言政策差異；昂貴推論不在事件迴圈執行。效能量測真的不足才考慮搬移熱路徑 | P1 |
| Presidio | 預設 PII 基線，加自訂 recognizers | 可組合規則與 NLP；繁中與公司資料需自建辨識器、語料及閾值，不是裝好就支援完整多語 PII [S5] | P1 |
| secrets | 格式／checksum／情境規則 + 合成 canary；entropy 只作輔助 | 可追蹤且可回歸；避免把所有高熵 hash 誤判為秘密，也不記錄完整命中值 | P1 |
| pplx-pii | 可替換 PII detector，先 shadow/bake-off | 原模型是 token-classification + sensitivity；不是 chat 模型。長文切塊與 span 對齊、版本及授權需驗收 [S6–S7] | P3 |
| SingGuard | 明確選 SingGuard-NSFA 為 agent-security 候選，先比較 0.8B／2B，再決定較大模型 | 分類 heads 與生成模式是兩條路；不能把 A100 分類延遲套到 vLLM 生成模式。單輪文字能力不等於多輪或多模態保障 [S8] | P3 |
| NeMo Guardrails | 選用 adapter，適合需要對話／流程 rails 的場景 | 不讓第二套 DSL 成為授權真相來源，也不為了統一而重包所有請求。鎖當前 API 與 runtime 行為 [S9] | P3 後 |
| Guardrails AI | 選用 validators／結構化輸出檢查 | 官方已公告 validators 遷往一般 PyPI packages、停止 hosted remote inference；不以舊 Hub 雲端路徑當離線部署基線。逐 validator 查網路行為與授權 [S10] | P3 後 |
| Promptfoo | 第一個 Assurance runner | 用固定案例、CI、對照組與報表快速建基線；強制本地 provider／judge 與網路出口控制 [S11] | P0 起 |
| PyRIT | 多輪／自適應攻擊 runner | 獨立 worker/environment，透過共用 result schema 整合，不進 production request path [S12] | P3/P5 |
| DeepTeam | 可選的攻擊／風險覆蓋 runner | 不重複造 runner，也不讓第三套輸出格式污染核心資料模型 [S13] | P5 |
| Control plane | FastAPI、Pydantic、PostgreSQL、SQLAlchemy／Alembic | policy lifecycle、RBAC、稽核與 job 狀態用明確 schema；初期不用 Redis／Celery／K8s 增加依賴 | P4 |
| Browser UI | React + TypeScript + Vite；JSON Schema 表單 renderer + AJV | 先做 catalog、開關、作用範圍、驗證與差異預覽；不先做任意節點拖拉的流程語言 | P4 |
| Observability | Prometheus + Loki + Grafana + Alloy | decision 與 access logs 雙管線，Grafana provisioning 版本化；Studio 不重做 Grafana 的監控功能 [S14–S16] | P0 起 |
| Inference | vLLM serving workload LLM；支持的 guard 模型獨立部署 | pooling/token classification 不能當 chat completion；自訂分類頭保留專用 Transformers worker，須做輸出 parity [S7,S17] | P3 |

不預設所有 detector 串聯，也不把多個模型信心分數平均成「安全分數」。依政策需求、資料類型與可用能力選擇 detector；回傳標準 findings。相同資料的 shadow 比較先量測收益，再決定是否進同步鏈。

## 4. PromptGuard 與 MCPGuard 產品行為

PromptGuard：結構驗證／route 限制 → 可信 context → 檢測視圖正規化 → 必要 detectors → deterministic decision → allow／mask／reject → evidence-minimized log。回應端必須涵蓋所有已宣告支援的 choices／content segments。對無法安全改寫的 JSON tool arguments、簽章內容或 schema-critical 欄位，預設 reject，不盲目字串替換。

第一階段 PII 範圍：姓名、生日、身分證識別碼、Email、地址、電話、公司全名、IP。分類上區分個人資料、公司機敏資料與秘密；公司名稱不一律等於 PII，IP 依情境處理。臺灣識別碼採格式與校驗規則加上下文；姓名、地址、公司辨識採測試資料與 recognizer 組合，不聲稱 regex 能完整辨識。

MCPGuard：每次 `tools/call` 都重新檢查，`tools/list` 隱藏只是 UX／資訊暴露控制。授權 tuple 至少包括 tenant、subject、native backend、native tool、method、argument constraints、policy revision。敏感類別如檔案寫入／刪除、shell、網路外傳、憑證讀取、公開發布及有費用副作用，預設未授權即拒絕。UI 的「低風險」標籤不得自動授權 backend 自報的 tool。

高風險操作的 approval 後續採有期限、一次性、綁定 identity/backend/tool/arguments digest/policy revision 的授權，配合工具本身 idempotency。ExtMCP 不被當成可無限等待的人工作業流程；尚無 approval 系統時直接 deny，不用自由 header 充當批准。

## 5. Policy Studio 與發布模型

### 圖形化操作流程

Policy catalog 顯示「保護對象、偵測器、支援語言、作用階段、代價、失效行為」。使用者選模板 → 勾選 guard → 設定 route／tenant／tool 範圍 → 選 block／mask／shadow → 以合成案例試跑 → 看變更 diff／預期影響 → 發布。預設提供 Strict local、Balanced、Evaluation 三個模板；Evaluation 不得停用基本身分授權或被標成 production-ready。

表單與 YAML 使用同一 canonical schema，必須 round-trip 等價。`unavailable`、`unverified`、`unsupported_language`、`model_not_ready` 是獨立能力狀態；不能顯示可選卻無法執行的開關。需要尚未 ready 的必需 detector 時，發布失敗，或明確切換成另一份不宣稱該能力的 policy。

### 草稿與發布

流程：Draft → schema validation → semantic/capability validation → replay simulation → approval → Stage → per-runtime ACK → Activate → observe／Rollback。發布生成 immutable bundle，含 revision、digest、相依模型版本與 capability requirements；使用者不可直接修改 active bundle。

Gateway config 與 guard snapshot 的發布是一個協調變更，不假設跨程序天然原子切換。各 runtime 必須回報有效版本；新 request 固定一份 snapshot，長 MCP session 不能永遠綁舊權限，後續操作讀取有效政策。版本不相容、部分部署或尚無 ACK 時不得把整組標為 active；必要時停止該路由、或繼續明確允許的 last-known-good bundle。撤權須有顯式立即生效／drain 策略，不能被 rollback 恢復已撤銷的身分。

### 建議資料與 API

資料表：`policies`、`policy_versions`、`deployments`、`deployment_acks`、`detector_catalog`、`evaluation_runs`、`evaluation_results`、`audit_events`。每筆有 tenant scope；job payload 只放資料集與 artifact 參照，不放 production 原始 prompt。大型測試 artifact 分開保存，PostgreSQL 保留索引、hash 與 ACL。

建議 API（本專案契約，非現有上游 API）：`GET /api/v1/catalog`、`POST /api/v1/policies`、`POST /api/v1/policies/{id}/versions`、`POST /api/v1/validations`、`POST /api/v1/simulations`、`POST /api/v1/deployments`、`GET /api/v1/deployments/{id}`、`POST /api/v1/deployments/{id}/rollback`、`POST /api/v1/evaluations`、`GET /api/v1/evaluations/{id}`。版本更新要求 expected revision；重複發布／測試 job 用 idempotency key；非同步 worker 有 lease、retry 上限、取消與逾時。

角色區分 viewer、editor、publisher、auditor。支援 OIDC；cookie 模式加 CSRF 保護。伺服器端強制 tenant ACL，不能只在瀏覽器隱藏按鈕。顯示攻擊 payload 時 escape HTML；連線與模型端點只允許受控 catalog，避免 Studio 成為 SSRF／命令執行入口。秘密參照由部署端解析，永不顯示 secret 明文。

## 6. 分階段實作與 PR 切分

以下是依賴與 exit gate，不是已通過的測試，也不是對尚未量測硬體的交付日期承諾。P0 起每個 PR 都帶測試與可觀測性。安全 MVP 在 P2 完成；具語意偵測的可用版本需 P3 驗收，完整圖形化產品需 P4。

| 階段 | PR-sized 工作包 | 依賴／完成條件 |
|---|---|---|
| P0 真實協定最小閉環 | AG-001 workspace／locks／CPU compose；002 pinned Gateway + mock LLM/MCP；003 HTTP webhook + ExtMCP stubs；004 protocol E2E + minimal telemetry | 真實 v1.5.0 容器路徑下 pass/reject/mutate 都可證明；deny 時 upstream hit count 為零；未知 endpoint／stream 明確拒絕；故障測試有結果。未通過不得開始宣稱 guarded endpoint |
| P1 Policy core + PromptGuard | AG-101 canonical schema／pure reducer；102 trusted identity；103 Presidio + secrets；104 safe mutation／coverage limits；105 JSONL／metrics／CLI stage/activate | deterministic golden cases 全數通過；必需 detector outage 不放行；合成秘密不出現在外部回應或一般 log；同 inputs+findings+bundle 可回放同 decision |
| P2 MCPGuard 安全 MVP | AG-201 method+backend+tool authorization；202 tools/list filter；203 argument constraints／mutation 再授權；204 pagination/caches/session revocation；205 error-path capability gate | 隱藏工具直接呼叫仍被拒絕；同名跨 backend 不混淆；未知 methods／不支援 notifications 依能力表處理；錯誤 hook 缺口有拒絕或經測試的補償控制 |
| P3 語意偵測與比較 | AG-301 common detector contract／worker limits；302 pplx span parity；303 SingGuard classification/generation adapters；304 shadow bake-off；305 optional NeMo／Guardrails validators | 固定語料、獨立 holdout、zh-TW/en 誤判及延遲報告；超長輸入不漏掃；vLLM／原生 worker 輸出差異已記錄；未達 gate 的 detector 保持 candidate |
| P4 Policy Studio | AG-401 FastAPI+DB migrations+RBAC；402 catalog/forms/YAML round-trip；403 validate/simulate/diff；404 stage/ACK/activate/rollback；405 decision drilldown/Grafana links | 無效或缺能力 policy 無法發布；越權／跨 tenant 失敗；雙 editor 衝突可見；版本偏斜與失敗 rollback 的 E2E 通過；瀏覽器流程測試通過 |
| P5 Assurance 產品化 | AG-501 registry/fetch/licence gates；502 Promptfoo reports；503 PyRIT adaptive runner；504 optional DeepTeam；505 CI schedules/comparisons | 同一結果 schema；來源／變形不跨 split 洩漏；本地 provider 不對未授權網域出站；安全、效用、延遲與 unknown 分開報告；發版門檻接入 CI |
| P6 生產化 | AG-601 network/mTLS/secret handling；602 audit retention/integrity；603 load/chaos/capacity；604 supply-chain/SBOM/offline install；605 upgrade/recovery runbooks | network bypass 測試失敗即不得發版；restart／disk-full／OOM／timeout／version skew 有可重現結果；負載 SLO 在指定機器與輸入分布上核准 |

Assurance 的基本 runner 在 P0 即啟用，P5 是擴充管理與自適應能力，不是拖到最後才測試。Grafana provisioning 隨 P1 加入，不等 UI 完成。P3/P4 可在契約固定後部分平行，但不得繞過 P0/P2 安全 gate。

### Repository 目標結構（尚待實作）

```text
services/{promptguard,mcpguard,controlplane,assurance_worker}/
packages/{policy_core,contracts,detectors,assurance_contracts}/
web/policy-studio/
proto/vendor/agentgateway/<version>/
policies/{templates,schemas}/
deploy/compose/  deploy/observability/{alloy,prometheus,loki,grafana}/
datasets/{registry,manifests}/
tests/{unit,contract,integration,e2e,security,performance}/
reports/  docs/
```

MVP 使用 Python + TypeScript monorepo；`uv` 鎖 Python 依賴、前端 lockfile 鎖 JS，proto generation 可重現。不同 ML／Assurance 重依賴用不同 images，不共用一個超大 virtualenv。初期不再加 Go／Rust 改寫 Gateway、OPA＋自訂引擎雙授權、任意 policy scripting、多租戶 Kubernetes operator 或一般 workflow orchestrator；有量測與需求再做 ADR。

## 7. 發版判準與本次驗證狀態

發版必須附 endpoint/capability matrix、pin manifest、測試命令、log／report artifact 與已知限制。所有延遲、召回率與誤判率都需標示模型、精度、CPU/GPU、context、batch、concurrency、樣本數與 policy revision。未測項標 `NOT RUN`，不把 mock adapter 測試叫做真實 Gateway E2E，也不把作者 benchmark 叫本機效能。

本次完成的是 repository／上游文件與固定版本程式碼查核，以及規劃文件撰寫。當前工作環境沒有可用的 docker、nerdctl、nvidia-smi，因此未執行 Compose、Gateway runtime、vLLM、模型或資料集 benchmark。這是 P0/P3 的待辦驗收，不是已有測試結果。
