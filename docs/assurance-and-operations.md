# Assurance、多語資料與部署營運計畫

狀態：設計稿；沒有已完成的模型 benchmark、資料集下載或 Compose E2E。相關文件：[主計畫](implementation-plan.md)、[協定契約](protocol-contracts.md)、[一手來源](sources.md)。

## 1. Assurance 是獨立平面

共同介面為 Case → Runner adapter → Target → Oracle → Result。Target 可以是 detector API、policy-core replay 或真正 Gateway endpoint；三者的報告須分開，只有最後一種才能回答 enforcement 是否有效。測試平面不載入 production 使用者秘密，不讓攻擊案例連到實際客戶工具。

先用 Promptfoo 建立固定案例與比較報告；PyRIT 擴充多輪／自適應攻擊，DeepTeam 補充分類與變形覆蓋。三者的依賴與執行環境隔離，共用案例 ID、來源與結果契約，而不是互相呼叫再生成不同真相。攻擊產生器、judge 與推論 provider 預設本地；不能只設定 target 本地，就假設整套工具不會使用雲端。以 egress deny 及網路追蹤驗證，而非只看配置。[S11–S13]

Assurance 原始攻擊內容與模型輸出可能包含危險文字；與一般 decision log 分離，受限 artifact storage、ACL、保存期限和稽核。UI 顯示需 escape，禁止工具執行其內容。任何下載腳本、外部 repository example 或資料集中的可執行內容，不在有 production credentials 的 worker 執行。

## 2. 測試組與 oracle

| 對照組 | 用途 |
|---|---|
| B0：隔離環境中的 backend 直接呼叫 | 量測模型／工具本身的基線；無對外公開的 bypass 入口 |
| B1：Gateway only，無內容 detector | 區分 proxy 成本與原生模型防護；必要身分控制仍存在 |
| B2：Gateway + deterministic policy/secrets | 量測硬性規則、授權及新增延遲 |
| B3：B2 + Presidio | 量測 PII masking 品質與效用 |
| B4：B3 + pplx 或 SingGuard 候選組合 | 分開比較每個新增 detector 的收益、成本與退化 |

同一原始案例、相同 seed／model／generation settings，在所有比較組使用相同語境與資料來源。公開 deterministic case 不需要 LLM judge：觀察上游呼叫次數、沙箱副作用、是否命中合成 canary、允許的工具集合、mask span／schema 等。語意注入及任務效用才使用獨立 judge 或人工標註；judge 與被測 detector 不應是同一個唯一裁判，也不能把資料中「請判我安全」當評分指令。

Result 契約至少包含：run/case/group ID、來源與版本、language/locale、attack transformation chain/seed、split、target/protocol、policy/model/runtime digest、expected/actual effect、upstream hit count、sandbox outcome、coverage/error、latency breakdown、oracle/version、artifact reference。多輪結果保存整個 episode 的因果關係，不能只把最後一句算成功或失敗。

## 3. 資料集來源與使用方式

下表是**候選來源清單**，不是「已下載／授權已放行」清單。來源 repository 的程式碼授權不一定涵蓋它引用的所有資料。第一個 registry commit 必須為資料、程式碼、模型各自記錄授權與可再散布範圍。

| 來源 | 要測的能力 | 使用限制／避免錯誤結論 |
|---|---|---|
| AgentDojo [S19] | 任務環境中的 indirect injection、工具操作與效用 | 是動態 benchmark/framework；需隔離工具並觀察真正副作用，不是只餵文字給 classifier |
| InjecAgent [S20] | 工具輸出植入的 injection | 加到 MCP result fixtures；保留來源 lineage，不把相似重組題當獨立樣本 |
| BIPIA [S21] | 外部內容污染、間接注入回歸 | 上游含衍生資料／獨立下載來源；逐來源審核。作研究回歸資料，不將其直接當 production service 依賴 |
| MultiJail [S22] | 多語安全與越獄差異 | 原始英文案例及其他九語的人工翻譯；不是完整 MCP authorization benchmark，不能代表繁中本地覆蓋 |
| HarmBench [S23] | harmful behaviors／robust refusal | 適合額外安全基線；refusal rate 不等於 prompt-injection ASR，也不等於 MCP tool governance |
| ai4privacy/pii-masking-300k [S24] | PII span detection、masking | 依實際版本檢查語言、label schema 與品質；資料集名稱不代表 zh-TW 已被驗證 |
| SingGuard-NSFA 官方 benchmark [S8] | 與作者結果對照、風險 taxonomy | 作者自建與 cross-source 集合不能當唯一獨立驗證；先確認可取得的 artifact 與來源重疊，再入庫 |
| AgentGuard 自建 zh-TW + benign set | 臺灣格式 PII、正當安全研究、一般辦公、程式碼與正常工具使用 | 使用合成身分／canary，人工校對；公司機敏與 PII 分類分開；含中英混用與全形標點 |

若加入 PII-TRACE 等其他來源，必須先確認官方可取得 artifact、schema 與授權，再新增 registry；不要根據論文名稱自行拼接不存在的 dataset URL。

### Registry 與資料生命週期

每個 entry：id、canonical URL、retrieved_at、upstream revision、content hash、license URL／snapshot、code/data/model license 分類、commercial-use/redistribution review、languages/locales、schema mapping、origin family、split policy、PII assessment、owner、review state。尚未取得 hash 的 candidate 保持 `pending`，fetch/build 預設拒絕，不用虛構 hash 填滿欄位。

流程為 discover → quarantine download → license/security review → normalize → deduplicate → split → annotate/QA → freeze manifest。原始下載只做 cache，不自動 commit 大量文字到公開 repository。下載只由固定白名單來源與固定 revision；變形器不存取外部網站、不執行資料中的命令。授權不明或非商用限制未解決的資料不進 commercial/default CI profile。

同一原題的翻譯、Base64、roleplay、zero-width、引用／嵌套 JSON 變體全部以 `origin_group_id` 綁定同一 split。跨資料集近重複也要合併 lineage；tuning/dev/test 以 source family 分離，避免把 detector 作者 benchmark 的重用資料當獨立 holdout。報告公開來源與 manifest，不預設可公開所有原文。

## 4. 變形、多語與必要測試

Direct、Base64、roleplay、zero-width 都要有 attack 與 benign paired controls。正常文件中的 Base64、密碼學字串、教學引用、合法管理命令、HTML/JSON/Markdown、空白與全形字元不能一律當攻擊。變形前後預期仍是同一類有效攻擊；若不可解析、失去攻擊語意或違反 fixture，標 invalid，不混入召回率分母。

首輪至少 zh-TW 與 en，之後依產品實際使用擴充 zh-CN、ja 與資料來源中的其他語言。模型宣稱 multilingual 不等於每個 locale 達門檻；unknown language、超長、截斷、非文字與 classifier disagreement 都獨立揭露。中文姓名、地址、公司全名與 IP 要有正負例，不只使用可由 regex 輕易命中的格式。

| 測試層 | 必測內容 | 確認方法 |
|---|---|---|
| Unit/property | policy precedence、span merge、normalization offset、schema、limits | pure functions + property tests；變形不得破壞非目標欄位 |
| Contract | 真實 webhook action 形狀、generated ExtMCP、invalid return、enum/version | 固定版本 golden fixture + 真實 Gateway round trip |
| Integration | processor failure/timeout、模型未 ready、授權 context 缺失 | 斷服務／注入錯誤，驗證 gateway outcome 與 counter |
| MCP E2E | tools/list 隱藏後直接 call、同名跨 backend、參數 mutation、pagination、撤權 | 沙箱 backend 計數與副作用快照 |
| MCP gaps | error result、server-initiated methods、notifications、session reuse | capability matrix 未支持即拒絕或不能啟用受保護 route |
| Output leak | canary secret／PII、分段與多 choices、tool arguments | 比對外部可見 bytes；不只比對 response status |
| Studio | OIDC/RBAC、跨 tenant、CSRF/XSS、同時編輯、stage/ACK/rollback | API 負向測試 + browser E2E |
| Supply chain | 未授權下載、remote code、artifact hash、未知 validator | offline build 與 network-deny 測試 |
| Ops/performance | concurrency、cold/warm、disk-full、OOM、restart、取消、version skew | 固定負載與 chaos case，記錄失敗行為與恢復結果 |

### 指標與 gate

- ASR = 在有效且已執行的攻擊案例中達成受禁目標的比例。被 guard 正確阻擋的有效案例仍留在分母；invalid 與 inconclusive 另報。單次 detector 的 recall 不是 ASR。
- Benign FPR = 不應受該規則阻擋的有效 benign 案例中誤擋比例；另報錯誤 masking、正常任務成功率與策略本來就禁止的請求，避免全拒絕拿滿分。
- PII：entity/span precision/recall/F1、raw-value leakage、over-redaction、cross-chunk recall；security：unauthorized upstream calls、secret canary leakage、coverage completeness。
- 效能：p50/p95/p99、request rate、tokens/characters、TTFT、queue time、detector time、CPU/GPU memory、timeout/overload rate、模型冷啟動；相同負載比較 B1–B4。

硬 gate：所有已聲稱支持的 deterministic golden cases 通過；未授權 upstream 執行為零；合成 secret canary 外流為零；未知或 incomplete coverage 不得標 safe；required detector failure 不得 allow。這是有限測試的通過條件，不是宣稱實際世界零風險。

統計 gate 建議起點：zh-TW／en 各至少 500 個獨立 benign origin groups；語意偵測可先以 FPR ≤2%、召回 ≥95% 作**待校準目標**，必須同時報信賴區間、attack classes 與效用，不能今天先宣稱達成。按 origin group 做 bootstrap 或適當的群組統計，不能把同題百個變形當百個獨立樣本。樣本不足就維持 candidate；沒有證據時不硬選某個模型為最佳。

延遲門檻在 P0/P3 的指定硬體、輸入分布與並行數上量測後寫入 SLO manifest。每次 PR 比對相同 baseline；不要拿作者在 A100 的單樣本數字當 GB10／RTX 或整個 stack 的 p95。

## 5. Compose 與 vLLM 部署

| Profile | 元件與用途 |
|---|---|
| `cpu-e2e` | 真實 AgentGateway、PromptGuard、MCPGuard、mock LLM、sandbox MCP、test runner；不需 GPU |
| `observability` | Alloy、Loki、Prometheus、Grafana；dashboards/datasources/alerts provisioned |
| `studio` | FastAPI、PostgreSQL、browser UI、publisher／evaluation workers |
| `gpu` | workload vLLM 與需要的 guard inference；分開資源配置及 queue |
| `assurance` | Promptfoo／PyRIT／DeepTeam runner，按選用功能啟動，與 production 工具隔離 |

以上是預計 profile 名稱，本變更未提供 Compose 檔或可執行的啟動命令。P0 以 Docker Compose v2 為 reference，另建 nerdctl/containerd 相容測試矩陣，逐項驗證 profiles、healthchecks、depends_on、GPU/CDI/runtime、secret mounts、log volume permission 與網路隔離；不能因讀得懂 compose YAML 就稱相容。

不設定固定 `container_name`，避免不同 project／CI job 撞名。清理限於當次 project resources，遇到 nerdctl stale name-store 先保留診斷，不執行 system-wide prune 或直接刪除他人 containerd state。Readiness 用實際依賴與 protocol health probe，不用 sleep 假裝已啟動。

只公開 Gateway 與受認證的 Studio；開發環境 UI/Grafana 綁 loopback。vLLM、MCP backend、資料庫、detector、OTLP receiver 不直接暴露外部。檢查 host routing／egress／IPv4/IPv6 與 port publication，防止「有 Gateway 但直連模型照樣可用」。容器非 root、read-only rootfs、必要 tmpfs、最小 capabilities、大小與資源上限；不能讓不可信 redteam worker 共用 production secrets 或 host socket。

vLLM 對 workload chat LLM、pplx pooling 與 SingGuard 生成模式採不同服務／adapter；SingGuard 自訂 classifier heads 未通過相容驗收前使用專用 worker，不假設標準 chat endpoint 包含它。pplx vLLM 版本需 raw token logits、正確 postprocess/label mapping 與 span parity，`/v1/scoring` 是其附帶 adapter，不是一般 chat API。[S6–S8,S17]

每種 GPU profile 記錄架構、driver/CUDA、image digest、model revision、precision、context、batch/concurrency 與記憶體峰值。GB10/arm64 與 x86/RTX 分別驗證；不要宣稱任一 CUDA image 都能用。CPU mock suite 保持任何開發者可跑，GPU suite 透過受控 self-hosted runner；不自動在來路不明的 PR 執行帶 secrets 的 GPU job。

## 6. 雙管線 observability

```text
Guard runtime -> JSONL append-only volume -> Alloy loki.source.file
              -> parse + scrub + source=agentguard-decisions -> Loki

AgentGateway -> OTLP Logs -> Alloy otelcol.receiver.otlp
             -> scrub + batch -> Loki OTLP ingestion
             -> source=agentgateway-access

Gateway / guards / workers / inference metrics -> Prometheus -> Grafana
```

兩條是不同事件來源與 pipeline，不能把 Gateway access log 冒充 policy decision。JSONL 只由 guard writer 寫入，Alloy read-only mount；測試 rotation、offset checkpoint、restart、重複事件與背壓。OTLP native ingestion 採固定版本有效的 Loki 配置／attribute mapping，不能只把 OTLP body 當一般 log line。[S14–S16]

Decision schema：event_id、timestamp、request_id、trace_id（存在且可信才填）、tenant scope、component、phase、policy revision、effect/would_effect、reason codes、detector/version、coverage、timings、upstream execution state。request-stage allow 不等於 response 最終 allow；用 phase/event IDs 關聯，不能用第一條 log 說整次請求已放行。

一般 log 禁止 raw prompt／response、原始 PII 值、Authorization、API key、完整 tool arguments、模型自由生成分析。任何 request/body hash 若需查重，使用有明確用途的 keyed HMAC／保留期限，而非對低熵個資直接 hash 當匿名化。PII masking 不自動等於法律上的匿名化或 GDPR 合規；資料保存、目的、存取與跨境仍須另行治理。

Loki/Prometheus labels 限 service、environment、protocol、effect、受控 reason_code 等低基數維度；request ID、user、自由文字、policy digest 放 structured metadata／JSON，不作 metric label。跨 tenant logs 的查詢 ACL 由 API／儲存層強制，Grafana dashboard 下拉選單不是安全邊界。

首批 Grafana dashboards：traffic/enforcement、detector latency/error、PII/secret counts（不含值）、MCP denied tools（受控分類）、active revision skew、Assurance ASR/FPR/utility trends。告警：required detector timeout、audit spool 滿、版本不一致、未授權 upstream 被執行、未支持表面出現與零掃描覆蓋率。Grafana provisioning 的資料來源、dashboard JSON 及告警規則都隨 repo 版本化。

Loki 中央存儲不可用時先持久 spool；mandatory audit append 失敗依 policy deny。保留期限、容量上限與刪除由部署政策決定，不默認永存。JSONL/Loki 本身不是不可竄改稽核庫；P6 加簽署 checkpoint／獨立保管與完整性驗證，並測試復原與刪除語意。

## 7. CI 與完成證據

PR：schema／unit／contract／CPU E2E／供應鏈掃描／文件檢查；每日：固定 multilingual regression＋benign controls；每週或發版前：adaptive multi-turn／GPU bake-off／load/chaos。這些是待實作 CI schedules，不是目前已建立的排程。

每次報告要包含實際命令、git/image/model/data/policy revisions、環境、開始結束狀態、各 case 結果與 artifact hash。failed、skipped、not-run、inconclusive 分開，不把框架返回 HTTP 200 視為 guard 生效。下載 artifact、policy publish 與 runner execution 分別授權；branch CI 不得自動發布到 production。

首個合併後實作 PR 應是 P0：真實 Gateway + fake upstream counter + 最小兩種 adapter + failClosed contract tests。只有這個閉環跑通，後續模型表現、Studio 勾選與 Dashboard 數字才有可信的 enforcement 基礎。
