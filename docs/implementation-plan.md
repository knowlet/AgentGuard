# AgentGuard 技術選型與分階段實作計畫

2026-09-17，PR #1 review 修訂。狀態：設計與測試契約；沒有已驗收的 Guard stack。原始規劃保存在 git 歷史 `a20b4d3`；本版將已知風險提升為可失敗的 release gate。

相關文件：[協定與 policy](protocol-contracts.md)、[Assurance／營運](assurance-and-operations.md)、[來源](sources.md)、[Review gate registry](review-gates.md)。

## 1. 結論與責任邊界

採用一個 enforcement plane、共用 deterministic policy-core、可替換 detectors、獨立控制與測試平面。Gateway 執行 allow/reject/mutation；PromptGuard 與 MCPGuard 提供協定 adapter；policy-core 根據可信身分、immutable policy 與 findings 決策。Detector 分數或 LLM 說明不能授予權限。

```text
Client/harness -> AgentGateway -> permitted vLLM / MCP backends
                      | LLM webhook       | ExtMCP gRPC
                      v                   v
                 PromptGuard           MCPGuard
                      \                   /
                        deterministic policy-core
                         | rules / Presidio
                         | isolated pplx / SingGuard / optional workers

Browser -> FastAPI Policy Studio -> PostgreSQL + compiler/publisher
                                     -> Stage / ACK / Activate snapshots
Isolated Assurance -> real Gateway -> sandbox fixtures
Guard JSONL -> Alloy file pipeline -> Loki
Gateway OTLP logs -> Alloy OTLP pipeline -> Loki
Metrics -> Prometheus -> provisioned Grafana
```

AgentGateway 不被 Python reverse proxy 取代。需要原始 body 的控制先驗證 native policy 或 ExtProc 的實際能力；ExtProc 不能取代 MCP 語意。若選用 webhook response validator 補漏洞，必須另立不可繞過邊界 ADR、鎖版本與故障測試，不能只在圖上加一層就宣稱安全。

**v1.5.0 只作相容性／漏洞重現基線，不是可直接採用的安全部署版。** 已確認其 untagged action 可從 malformed Mask/Reject 落入 Pass；failClosed 與 typed serializer 均不能修復 Gateway parser。G0-WIRE 要求實際 parser 修補或經驗收的不可繞過 validation boundary。規劃 PR 的文件 merge gate 和產品 P0/P2 release gate 分開，不能拿文件或 helper 自測綠燈代替 runtime 證據。[S4,S25]

## 2. 範圍、信任模型與技術選型

MVP：非串流文字 LLM、deterministic controls、Presidio/秘密規則、MCP method/tool authorization、tools/list 過濾、最小 decision log、CPU E2E。語意 injection detector 必須在 P3 通過獨立評估才宣稱能力。不承諾任意附件、所有 OpenAI endpoints、串流零洩漏、多模態、完整 agent trajectory 或自動合規。unknown/unsupported 不可靜默 passthrough。

對手可控制 prompt、工具結果、外部文件、client headers 與不可信 MCP backend。信任根為部署者、授權發布的 policy、驗證身分及固定供應鏈；Gateway/host 被攻陷不是本層可獨立解決的情境。backend/vLLM 不可有繞過 Gateway 的公開路徑。

Tenant/subject/scopes 來自驗證 JWT/mTLS；入口剝除偽造內部 header。自由輸入 x-tenant、prompt 自稱管理員、MCP annotations 不構成授權。Cache、catalog、policy、資料庫與 log 查詢均按 tenant 隔離。控制平面不在每次 request 的同步路徑；沒有有效 snapshot 或必要能力時不能啟用 protected route。

| 元件 | 決策與限制 | 階段 |
|---|---|---|
| AgentGateway | v1.5.0 作基線，鎖 digest/proto/schema；部署需 G0-WIRE。每次 image/config/adapter 變更重跑 suite [S1–S4,S25] | P0 |
| policy-core | Python typed models、純決策函式，共用契約；先量測再考慮 Go/Rust 熱路徑，不造兩套授權語意 | P1 |
| Presidio＋secret rules | PII 基線＋本地 recognizers；臺灣格式/校驗、姓名/地址正負例；entropy 只作輔助 [S5] | P1 |
| pplx-pii | PII 替代/補充候選，token classification；長文切塊、offset、span parity，原版/打包授權分審 [S6–S7] | P3 |
| SingGuard-NSFA | injection/agent-security 候選；分類 heads 與生成模式分測，不把作者 A100 數字當本機 SLO [S8] | P3 |
| NeMo Guardrails | 選用對話/流程 adapter；不讓第二套 DSL 成為權限真相來源 [S9] | P3 實驗；驗收後才採用 |
| Guardrails AI | 選用 validators；逐項查授權/網路行為，不依賴舊 hosted Hub 推論路徑 [S10] | P3 實驗；驗收後才採用 |
| Assurance | Promptfoo 優先、PyRIT adaptive、DeepTeam 選用；獨立 images、共用 cases/results [S11–S13] | P0 起 |
| Studio | FastAPI/Pydantic、PostgreSQL、SQLAlchemy/Alembic；React/TS/Vite、JSON Schema 表單/AJV | P4 |
| Observability | Prometheus/Loki/Grafana/Alloy；兩種 logs 分流；provisioning 版本化 [S14–S16] | P0 起 |
| Inference | workload vLLM＋獨立 classifier workers；pooling/custom heads 不能假裝 chat-completions [S7,S17] | P3 |

MVP 使用 Python/TypeScript monorepo，uv 與 JS lockfile 鎖依賴，proto generation 可重現。ML/Assurance 重依賴分 images，不共用超大 virtualenv。初期不引進 Redis/Celery、Kubernetes operator、另一個一般 workflow engine 或額外授權引擎；有量測需求再作 ADR。程式碼、模型、資料各自審查授權，不擅改專案 LICENSE。

## 3. Guard 行為與政策決策

PromptGuard：原始 ingress schema/route 限制→可信 context→bounded 檢測視圖→必需 detectors→pure decision→安全 mutation/deny→最小稽核→adapter。秘密/授權 deny 優先；只在 policy 允許且無獨立 deny 時執行 masking。改寫 JSON tool arguments、簽章或 schema-critical 欄位無法保證正確時拒絕。原文不因檢測 normalization 自動變更。

PII 初期涵蓋姓名、生日、識別碼、Email、地址、電話；公司全名/IP 依情境分類為個資、公司機敏或其他資訊，不一概都叫 PII。合成 canary 只供受控 Assurance；一般 log 不保存原始值。

MCP 每次 tools/call 都授權；tools/list 過濾不能取代執行授權。授權 tuple 包含 tenant/subject/native backend/native tool/method/argument constraints/policy revision。寫入、刪除、shell、外傳、憑證、公開發布或有費用副作用，未明確授權即拒絕。參數 mutation 後自行重新授權，Gateway 不重跑 RBAC。[S2]

Approval 後續使用一次性、有期限且綁定 identity/backend/tool/arguments digest/policy revision 的授權，配合 backend idempotency；不是自由 header，也不在 ExtMCP RPC 中無限等待。未有 approval 系統即 deny。工具結果檢查不能撤銷已發生副作用。

## 4. Policy Studio 與發布

流程：catalog→選 Strict local/Balanced/Evaluation 模板→勾 guard→選 route/tenant/tool scope→block/mask/shadow→合成案例試跑→diff→發布。Evaluation 不能關閉基本授權或被標 production-ready。卡片顯示 detector、語言、phase、成本、failure behavior 與 ready/capability 狀態；unverified/unavailable/unsupported_language 不能偽裝成可執行開關。

表單與 YAML 共用 canonical schema並 round-trip 等價。編譯器需要原始 ingress/context/coverage/runtime evidence；policy 的 streaming: deny 只是要求，不是完成證明。缺 CEL bindings、未知原始欄位或有效證據缺失，strict route 拒絕啟用，不只顯示警告。

Draft→schema/semantic/capability validation→replay→approval→Stage→各 runtime ACK→Activate→observe/rollback。Bundle immutable，含 revision/digest/model versions/capability requirements。Gateway config 與 guard snapshot 是協調發布，不假定跨程序天然原子性；新 request 綁固定 snapshot，MCP 後續操作仍要讀取有效授權。

部分 ACK、版本偏斜不得標 active；可繼續明確允許的 last-known-good 或停止路由。撤權有立即生效/drain 策略，rollback 不恢復已撤銷身分。並行編輯使用 expected revision；發布與 jobs 使用 idempotency key。Worker 有 lease、retry 上限、cancel/deadline。

建議資料表：policies、policy_versions、deployments、deployment_acks、detector_catalog、evaluation_runs/results、audit_events。Artifact 放受限 storage，DB 保存索引/hash/ACL，不放 production prompt。API：catalog/policies/versions/validations/simulations/deployments/rollback/evaluations（/api/v1），均為 proposed，不是現有 API。

OIDC＋viewer/editor/publisher/auditor；伺服器強制 tenant ACL，cookie 模式 CSRF，攻擊文字 HTML escape，endpoint catalog 限制 SSRF。Studio 不得任意執行 shell、安裝 validator、掛 Docker socket；secret 只用部署端 reference，不呈現明文。

## 5. 分階段 backlog 與硬性 exit gate

以下不是交付日期或已通過的成果。Gate 的具體 fixtures、oracle、計數和失敗條件見 [review-gates.md](review-gates.md)。

| 階段 | PR-sized 工作包 | Exit gate |
|---|---|---|
| P0 | AG-001 workspace/locks/CPU Compose；002 pinned Gateway+mock backends；003 HTTP/ExtMCP stubs；004 negative contracts＋context/coverage/deadline＋minimal telemetry | **G0-WIRE/CONTEXT/COVERAGE/DEADLINE** 全有真實 evidence。原版 fall-through 診斷不是 protected PASS；request deny 上游零，response deny client 洩漏零，合法 controls 成功。缺 CEL context/field matrix 不 activate |
| P1 | AG-101 schema/pure reducer；102 trusted identity；103 Presidio/secrets；104 mutation/limits；105 JSONL/metrics/CLI stage/activate | golden cases、replay、必需 detector 故障拒絕、最小稽核；保持 P0 gates，全拒絕不能偽通過 |
| P2 | AG-201 method/backend/tool auth；202 list filter；203 mutation 再授權；204 cache/pagination/revocation；205 error protection | **G2-MUTATION/G2-ERROR**。隱藏工具仍不可直接 call；error.message/data run-specific canary 不出 client；backend_attested 永不等於 protected |
| P3 | AG-301 worker contracts/limits；302 pplx parity；303 SingGuard adapters；304 separate-arm bake-off；305 optional rails/validators 實驗與驗收 | **G3-STATS**：預註冊 CI/power/family/樣本，FPR upper、recall lower 及 availability/utility 同過；B4a PII 與 B4b injection 分開歸因；AG-305 未驗收不可成為 production 相依 |
| P4 | AG-401 FastAPI/DB/RBAC；402 catalog/form/YAML；403 validate/simulate/diff；404 stage/ACK/activate/rollback；405 decision drilldown/Grafana | 缺 evidence/能力不可發布；跨 tenant 拒絕；並行編輯、版本偏斜、rollback/API/browser E2E |
| P5 | AG-501 registry/license；502 Promptfoo；503 PyRIT；504 DeepTeam；505 scheduled comparisons | **G5-ORACLE**：success predicate、budget、canary seed 先註冊；lineage split 不汙染；unknown/timeouts 不偽裝安全；發版 gate 進 CI |
| P6 | AG-601 network/mTLS/secrets；602 audit durability/integrity；603 load/chaos；604 SBOM/offline；605 recovery/upgrade | bypass、disk-full、OOM、timeout、restart、version skew 可重現；指定硬體/負載 SLO 通過 |

P2 為 deterministic/MCP MVP，P3 才有經驗證語意防護，P4 為完整 GUI。Assurance runner 在 P0 即啟用，但**只報協定/context/coverage/counter/故障與延遲，不報 ASR/FPR**；Grafana 顯示 NOT_EVALUATED 而非 0%。Grafana provisioning 從 P1 加入；P3/P4 可在契約固定後部分並行。

目標目錄：services/{promptguard,mcpguard,controlplane,assurance_worker}、packages/{policy_core,contracts,detectors,assurance_contracts}、web/policy-studio、proto/vendor、policies/{templates,schemas}、deploy/{compose,observability}、datasets/{registry,manifests}、tests/{unit,contract,integration,e2e,security,performance}、reports/docs。

## 6. 本次證據狀態

來源級查核確認 untagged fall-through、10 秒 webhook timeout 與 ExtMCP 邊界；Python 非 masking wire/statistics/accounting helper 自測可執行。**未執行原生 Serde、Compose、Gateway E2E、vLLM/GPU、資料集 benchmark 或 browser tests；helper 綠燈不表示上述 runtime gates 通過。**

發版要附固定 image/source/config/adapter/model/data/policy digests、capability matrix、命令與 raw observations。NOT_RUN、UNKNOWN、缺 artifact 不可 PASS，不以 mock 或 xfail 取代 protected gate。未修補的 v1.5.0 仍不能被推薦為已通過 G0-WIRE 的部署版。
