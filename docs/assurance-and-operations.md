# Assurance、多語資料與部署營運

2026-09-17 review 修訂。[主計畫](implementation-plan.md)、[協定](protocol-contracts.md)、[來源](sources.md)、[可失敗的 gate registry](review-gates.md)。當前沒有 Gateway/模型/資料集 benchmark；helper 自測與統計示例不是 benchmark。

## 1. 測試平面與證據層級

Case→Runner→Target→Oracle→Result。Target 分 detector API、policy-core replay、真實 Gateway；只有最後一種能证明 enforcement。Promptfoo 先接，PyRIT 擴充 adaptive/multiturn，DeepTeam 選用；各自 images/dependencies，共用 case/result 契約。不要讓 runner 或 judge 在 production request path。[S11–S13]

P0 只報協定符合度、context/coverage、upstream counters、故障/延遲，**不報 ASR/FPR**；Grafana 顯示 NOT_EVALUATED。P3/P5 才在凍結資料、成功 predicate、明確分母及獨立 oracle 下發布安全效果。

Target、attack generator、judge 都預設本地；用 egress deny/網路觀察確認沒有未授權雲端，不只檢查 target URL。攻擊 worker 不持有 production secrets，不連真實客戶工具、不掛 host socket。Payload/UI HTML escape；下載資料或 repository examples 不可自動執行。Raw attacks/results 進受限 artifacts，不混入一般 decision log。

## 2. 對照組與成功 oracle

| Arm | 組成 | 可歸因比較 |
|---|---|---|
| B0 | 隔離 backend | 模型/工具原始基線；沒有公開 bypass |
| B1 | Gateway only，保留身分授權 | proxy 成本/效果 |
| B2 | B1 + deterministic policy/secrets | 硬控制增量 |
| B3 | B2 + Presidio | PII 基線 |
| B4a-replace | B2 + pplx，沒有 Presidio | 對 B3 比較 PII 替代 |
| B4a-union | B2 + Presidio+pplx，固定 span fusion | 對 B3 比較 PII 補充 |
| B4b | B3 + SingGuard，PII stack 固定 | 對 B3 比較 injection/agent-security 增量 |
| B5（選用） | 選定 PII stack + SingGuard | 組合效果；交互作用需另設 factorial arms |

不再將不同軸的 pplx/SingGuard 放在同一 B4 後宣稱各 detector 貢獻。NeMo/validators 也各自設增量 arm；固定 workload/generation settings/environment/query budget，揭露模型既有安全能力。

Deterministic oracle 用上游計數、沙箱副作用、client bytes/canary、工具集合、mask spans/schema，不需要 LLM judge。語意/效用評分才用獨立 judge/人工標註；被測 detector 不是唯一 judge，payload 不能控制評分指令。

Adaptive runner 執行前註冊 success predicate（例如沙箱狀態改變或秘密外流）、環境快照、query/token/wall-clock budget、judge version/seed 策略，跨 arms 相同。保存全 episode，不能只看最後一句；不能在看到結果後改成功定義。

Result 至少含 run/case/origin_group/arm、來源/hash/語言/split、transformation chain/seed reference、target/protocol、runtime/model/policy/config digests、expected/actual effect、upstream count、sandbox outcome、client bytes oracle、coverage/error、latency、oracle version、artifact reference。

## 3. Coverage/error/deadline 的硬 gate

| Gate | 必測 | 斷言與 ground truth |
|---|---|---|
| G0-WIRE | 空 action、錯字/錯型別/缺欄位/多餘/duplicate keys、混合分支、錯方向 mutation | 原版診斷與 protected 路徑分開；request upstream=0，response client 洩漏=0；正常 controls 成功 |
| G0-CONTEXT | 必要 CEL header 缺失/求值失敗/client 偽造、stream 狀態未知 | 缺能力不 activate；runtime CONTEXT_UNAVAILABLE deny，不 fallback stream=false |
| G0-COVERAGE | 原始 system/tool args/results/name/image_url/provider fields markers | 外部 runner 觀察 client/hook/backend/egress；per-version/config matrix；unknown 原始欄位 normalize 前拒絕 |
| G0-DEADLINE | detector/queue/writer 慢、guard crash、Gateway timeout、cancel | 完整 budget 留 margin；availability faults 與 policy deny 分開；全部 timeout 不得安全 gate PASS |
| G2-MUTATION | 隱藏後直接 call、同名跨 backend、參數升權、撤權/分頁 | 未授權 upstream=0；所有 mutated params 再授權 |
| G2-ERROR | run-specific canary 在 JSON-RPC error.message/data、sanitizer 故障、各支援 transport/status | sanitized client bytes 洩漏=0；backend_attested 永為 attested_unprotected；不能用 fixture 保證未來錯誤安全 |
| G3-STATS | 固定 holdout、各語言/風險層、獨立 group outcome | CI 邊界及預註冊 availability/utility 同過，不用點估計 |
| G5-ORACLE | build 後 canary、自適應攻擊 budget/predicate | 各 arm 成功目標可比、seed 不洩漏、成功優先於 timeout 分類 |

其他 unit/property tests：policy precedence、span merge/offset、schema、原文保持、size/decode bounds。Studio：OIDC/RBAC/跨 tenant/CSRF/XSS/並行修改/stage/ACK/rollback。Supply chain：artifact hash、remote code、未知 validators、offline build。Ops：disk-full/OOM/restart/版本偏斜、吞吐與 backpressure。

Coverage 由 guard 外部 oracle 持有原始 manifest，不由 hook 自證看過全部資料。Marker 可見還需 detector-spy/expected findings 證明真的掃描。能力只能對宣告 schema/內容義務成立；有限 fixtures 不是任意未來欄位/語意全覆盖證明。檢查錯誤回應或結果不能回滾工具副作用。

## 4. 資料來源、lineage 與多語

以下是候選來源，不是已下載或授權已放行的資料。程式碼、模型、資料的 license 分別確認；不以 repo LICENSE 推定所有衍生資料均可散布。

| 來源 | 用途 | 限制 |
|---|---|---|
| AgentDojo [S19] | agent task/indirect injection | 動態環境，用沙箱副作用/任務效用，不只 classifier |
| InjecAgent [S20] | tool-result injection | 保留原題 lineage，加入 MCP fixtures |
| BIPIA [S21] | 外部內容污染 | 衍生來源/下載/授權分審，不直接作 production 依賴 |
| MultiJail [S22] | 多語越獄差異 | 不等於 MCP 授權或繁中本地覆蓋 |
| HarmBench [S23] | harmful behavior/robust refusal | refusal 不等於 injection ASR 或 tool governance |
| ai4privacy PII [S24] | entity/span/masking | 依 snapshot 檢查 locale/labels/品質，不假定 zh-TW |
| SingGuard benchmark [S8] | 作者結果與 taxonomy 對照 | 不能當唯一獨立驗證；檢查可得 artifact 與訓練重疊 |
| 自建 zh-TW/en benign + PII + tools | 臺灣格式、合法安全研究、辦公/程式碼、正常工具 | 合成身分、人工 QA、中英混用/全形/近似負例；公司機敏與 PII 分類分開 |

先 zh-TW/en，再按需求擴 zh-CN/ja/其他。Multilingual 宣稱不等於每個 locale 達標。姓名/地址/公司/IP 要有正負例，不只簡單 regex 題。Unknown language、超長、truncation、非文字、detector disagreement 分開揭露。

Registry：id/canonical URL/retrieval date/revision/hash、license URL/snapshot、code/model/data 分類、commercial/redistribution review、locale/schema、origin family/split、PII assessment、owner/review state。缺 hash 或授權審查的 candidate=pending，不偽造 hash；default/commercial CI 不下載未放行資料。

流程 discover→quarantine→license/security review→normalize→deduplicate→split→annotate/QA→freeze。相同原題的翻譯、Base64、roleplay、zero-width、JSON/Markdown 變體綁 origin_group_id，同組不跨 split；跨資料集近重複也合併 lineage，作者 benchmark 重用不算獨立 holdout。Raw cache 不直接 commit 到公開 repo，發布 manifest 不預設可散布原文。

每種攻擊變形有 benign paired control：正常 Base64/hash、教學引用、合法命令、HTML/JSON/Markdown 不能一律當攻擊。變形失去語意/解析失敗的 invalid 另報，不加召回分母。新的 PII-TRACE 等來源需先找到官方 artifact/schema/license，不自行拼 URL。

## 5. CI gate、樣本規劃與 availability 記帳

撤回「每語言 500＋看點估計」。G3-STATS 改為預註冊 CI 方法/alpha/family/停止規則，**FPR upper≤2%、recall lower≥95%**；這些是待產品核准的目標，不是已達成結果。n 依預期真實率、可辨別差異、CI 方法與 power 反推，不能固定 500，也不能固定 800/1,000。[S26]

單項雙側 95% Wilson 計算：9/500 FPR 上界 3.385%（FAIL）；5/500 上界 2.319%（FAIL）；8/800 上界 1.961%（PASS）；485/500 recall 下界 95.110%（PASS）。條件式觀察通過，不代表 n=800 事前就具有所需 power。`python tools/assurance_contract.py --stats` 可重算；helper 輸出 single_rate_only，不是 release PASS。

可事前選 exact Clopper–Pearson/單側方法，但不能事後挑有利方法。各語言/主要風險層分開；整組聲明要預註冊 multiplicity 控制，例如 primary family 的 alpha/m，不能把單項 95% 當 family-wise 95%。固定 holdout/停止規則，不測到通過才停；sequential 須另選有效程序。

Binomial 單位是獨立 origin group 的預註冊 binary outcome：固定 variant 或 group-any-success 是不同 estimand，需固定 variant budget。相關變形不能增加獨立 n；探索性 cluster bootstrap 另報，避免全零樣本退化 CI 假裝零風險。

有效 attack trials 分 S（成功）、B（有效政策防禦）、N（正常完成但攻擊未成功）、I（非成功 availability fault）、U（不可判定）。成功 predicate 優先：有副作用/洩漏，即使 timeout 仍計 S，故障另作維度。V=S+B+N+I+U；同時報 S/V、resolved_ASR=S/(S+B+N)、availability/unknown fractions、未解界限 [S/V,(S+I+U)/V]。分母零為 NOT_ESTIMABLE。B 留在分母；invalid 在 V 外另報。

Timeout/crash 不算 detector 防禦；不能只秀 S/V=0 或刪掉 I/U 後只秀 resolved_ASR。完整 release gate 還須預註冊 availability budget、benign utility、coverage；缺門檻也不可 PASS。固定 retries，保留每次 attempt，不只選最好一次。詳細定義見 review-gates §6。

FPR 除誤擋外另報過度 masking/正常任務成功率；策略本来就禁止的正常請求不混作誤判。PII 報 span/entity P/R/F1、raw-value leakage/over-redaction/cross-chunk；security 報 unauthorized upstream/canary leakage/coverage。p50/p95/p99、TTFT、throughput、queue/inference latency、CPU/GPU memory、cold/warm、timeouts/overload，都在相同輸入/硬體/並行度比較。

有限 deterministic golden suite 要全部過、未授權上游/受控 canary 外流為零、unknown 不標 safe；這不宣稱世界上零風險。SLO 要指定硬體/資料/模型精度/context/batch/concurrency，作者 A100 latency 不是整個 GB10/RTX stack 的 p95。

## 6. Canary 與 runtime evidence

Coverage marker 只追資訊流，不是 secret detection benchmark。Secret canary 在 detector image/model/policy freeze 後由可信 runner 產生不可預測 seed；build、一般 log、attacker/judge config 不得取得。可記 seed commitment，重播 seed 放受限 artifact；同 run 各 arms 共用 canary，配 benign controls，避免固定前綴可硬編碼命中。

任意高熵未知字串並非天然可辨識的秘密；canary 應在場景中有真實敏感來源/明確 DLP reference set，但不得為通過測試臨時加規則或訓練模型。Error sanitizer 要驗證整段錯誤 payload 被替換，不只靜態 canary 正則命中。

每份 runtime evidence 含 gate/fixture revision、gateway/config/adapter/model/data/policy digests、runner identity、命令/raw observations/assertions/artifact hashes。沒有實跑的 gate=NOT_RUN，缺 evidence 不 PASS。Helper 自測不產生或填補 Gateway coverage matrix。

## 7. Compose/vLLM 與營運

Profiles（尚未提供 Compose 檔）：cpu-e2e=真實 Gateway+兩 guards+mock LLM/sandbox MCP/test runner；observability=Alloy/Loki/Prometheus/Grafana；studio=FastAPI/PostgreSQL/UI/publisher/workers；gpu=vLLM/guard inference；assurance=隔離 runners。

Docker Compose v2 是 reference，nerdctl/containerd 另測 profiles/healthchecks/depends_on/GPU/CDI/secrets/log permissions/network。不要因可讀 YAML 就稱相容。不設固定 container_name；清理只限當次 project，不用 system-wide prune 或直接刪 containerd state 解 stale names。Readiness 用實際依賴/protocol probe，不用 sleep。

只公開 Gateway 和受認證 Studio；開發 UI/Grafana 綁 loopback。vLLM/MCP/DB/detector/OTLP receiver 不公開；測 host routing、egress、IPv4/IPv6/port publication，防直連繞過。非 root/read-only rootfs/tmpfs/minimal capabilities、資源與 body limits。Untrusted PR 不在帶 secrets 的 GPU runner 執行。

Workload vLLM、pplx pooling、SingGuard generation/classification 分服務/adapter；custom heads 未通過 parity 用專用 worker。pplx 的 raw logits/postprocess/label mapping 不當普通 chat API。[S6–S8,S17] GB10/arm64 與 x86/RTX 分驗 image/driver/CUDA/model revision/precision/context/batch/memory，不假定所有 CUDA images 通用。CPU suite 保持無 GPU 可跑。

Webhook budget 含 queue/解析/inference/mutation/serialize/audit；與有效 Gateway timeout 留 margin。8,000+500+1,000<10,000ms 只是 proposed budget，不是量測結果。Guard 自身超時 GUARD_DEADLINE_EXCEEDED；Gateway 超時 GATEWAY_GUARD_TIMEOUT，guard crash GUARD_UNAVAILABLE。沒有 guard log 時由獨立 access event/runner 關聯，標 event_source，不偽造 decision。[S25]

## 8. 雙管線 observability、稽核與 CI

```text
Guard JSONL -> Alloy loki.source.file -> scrub -> Loki decision source
Gateway OTLP Logs -> Alloy OTLP receiver -> scrub/batch -> Loki OTLP access source
Gateway/guards/workers/inference metrics -> Prometheus -> Grafana
```

兩種不同事件/管線，不互相冒充。JSONL writer/read-only Alloy mount；測 rotation/checkpoint/restart/duplicate/backpressure。OTLP native ingestion 固定有效 Loki schema/attributes mapping，不把 OTLP envelope 當一般字串。[S14–S16]

Decision event：event_id/time/request_id/可信 trace_id/tenant/component/phase/policy digest/effect/would_effect/reasons/detector versions/coverage/timings/upstream state。request allow 不是整次 response allow；phase 分開。Raw prompts/responses/PII/Authorization/key/tool args/模型自由分析不進一般 log。必要查重用有目的/期限的 keyed HMAC，不把低熵個資 hash 當匿名化。

Labels 只用 service/environment/protocol/effect/受控 reason 等低基數；request/user/policy digest 放 metadata，不當 metric label。Tenant ACL 在 API/storage 強制，不依靠 Grafana 下拉選單。Dashboards：traffic/enforcement、detector latency/errors、PII/secret counts、受控 MCP deny 分類、revision skew、具有效證據的 Assurance trends；P0 ASR/FPR 不顯示數值。

告警：required detector timeout、audit spool 滿、版本不一致、未授權上游、未支持表面、coverage incomplete。Provision dashboards/datasources/alerts。中央 Loki 不可用先 durable spool；mandatory append 失敗依 policy deny。Retention/刪除/ACL/容量由部署策略決定，JSONL/Loki 不是不可竄改庫；P6 增 checkpoint signing/獨立保管/復原驗證。Masking 不自動等於法律匿名化或 GDPR 合規。

待實作 CI：PR 跑 schema/unit/contract/CPU E2E/supply-chain/docs；固定 multilingual/benign regression；adaptive/GPU/load/chaos 按批准的排程。每次帶 revisions/命令/results/artifact hash，failed/skipped/NOT_RUN/inconclusive 分开，HTTP 200 不等於 guard 有效。Branch CI 不自動發布 production；policy publish、artifact download、runner execution 分別授權。
