# AgentGuard

AgentGuard 是以 **AgentGateway 作為 enforcement plane** 的 protocol-aware agent security stack。

> 狀態：P0 實作中，尚無 production-ready Guard stack。已有真實 Gateway／Compose 診斷、evidence preflight、固定 v1.5.0 的下游 strict webhook parser patch，以及 guard-deadline 預算的宣告閘門與 Gateway timeout 邊界切片。**原版 v1.5.0 仍有已重現的 fail-open；下游 patch 的 scoped wire 驗收不等於完整 P0、PII 或 prompt-injection 防護。** 實際結果須查看對應 commit 的 CI 與 raw artifacts。

## 目前實作與能力邊界

| 部分 | 已提供 | 不代表 |
|---|---|---|
| Stock diagnostic | checksum-pinned 真實 AgentGateway、HTTP fixtures、upstream counters、mask 結構檢查、CPU Compose | 診斷綠燈只代表 VULNERABILITY_REPRODUCED，不是 protected PASS |
| Strict wire patch | 在 Gateway 內驗證唯一 action、物件形狀、欄位與型別、phase、reject status、HTTP 故障；exact-source installer | 不是上游官方 release 修復，也不是另一個 reverse proxy |
| Patched acceptance | 6 個合法 controls、84 個負向 phase cases、10 個 transport faults 與 10 次 recovery；Serde、native Gateway、Compose 分層驗證 | 不涵蓋原始 request field coverage、所有 timeout/load、MCP 或 detector 效果 |
| 雙向 context | 原始 request snapshot 的 CEL mapping、37 組 request/response 案例、每階段決策與 payload 保存驗證 | 不是 authentication、任意欄位 coverage 或 route activation |
| Guard deadline | 宣告閘門（stage／reserve／margin 需小於 10 秒有效 Gateway timeout）、9 組真實 Gateway below／at／above budget 案例（含提前斷線負向 control）、以單次呼叫的 Gateway log slice 區分 guard 決策、真正 timeout 與 transport 故障 | 不是 latency SLO、detector 延遲、queue／backpressure／cancel，也不是完整 G0-DEADLINE |
| Evidence preflight | artifact hash、external field matrix、雙 phase row contract、完整 Gateway config／route digest、native evidence 欄位與 freshness；runtime 狀態固定為 NOT_EVALUATED | 不是 native／Compose coverage runner、完整 policy compiler、簽章驗證服務或 route activation |
| 統計與結果契約 | Wilson CI、固定樣本規劃、獨立 availability-fault 記帳與回歸測試 | 不是已執行的模型 benchmark 或完整 joint release evaluator |

### CPU 測試

在 repository root 執行；stock binary／Compose profile 限 Linux/amd64，無需 GPU 或模型 API key。

```bash
python3 -m unittest discover -s tests -v
python3 -m tools.fetch_gateway --output /tmp/agentgateway-v1.5.0
python3 -m tools.gateway_probe --gateway-bin /tmp/agentgateway-v1.5.0 --report reports/gateway-stock.json
docker compose -f deploy/compose/compose.yaml --profile cpu-e2e run --build --rm diagnostic
```

Stock 結果應為 `diagnostic_status=VULNERABILITY_REPRODUCED`、`protected_wire_gate=FAIL`。不能用 stock workflow 的綠燈替代 protected release gate。

### 下游 patch 與真實驗收

設計、breaking wire contract 與限制見 [ADR-001](docs/adr-001-strict-gateway-wire.md)。[完整 CI workflow](.github/workflows/p0-patched.yml) 固定 upstream commit 與 Cargo.lock，套 patch、編譯 Gateway、產生包含實際 binary SHA-256 的 manifest，再跑原生及 Compose E2E。每次都有 source snapshot 與 raw evidence artifacts；單看 workflow 名稱或某個 unit step 不足以宣稱 PASS。

`deploy/compose/compose.patched.yaml` **需要先完成上述 build**，準備 `reports/patched-bin/agentgateway` 與 `reports/patch-manifest.json`；不能在 fresh checkout 直接假定 binary 已存在。兩個 Compose profiles 都是封閉測試環境，不是執行不可信程式碼的 production sandbox。

```text
Stock diagnostic:     VULNERABILITY_REPRODUCED / protected wire FAIL
Patched acceptance:   PASS、FAIL 或 ERROR，依該次實際 observations 計算
Full P0 release:      NOT_EVALUATED
ASR / FPR:            NOT_EVALUATED
```

## 後續產品架構

PromptGuard 將保護 LLM request/response、PII、secret 與 deterministic decisions；MCPGuard 將透過 ExtMCP 執行 method/tool authorization、tools/list mutation。Assurance 是隔離測試平面；Policy Studio 為 FastAPI control plane＋browser，負責 catalog、表單、驗證、模擬與版本發布。Observability 規劃使用 Prometheus、Loki、Grafana provisioning、Alloy；Guard JSONL 與 Gateway OTLP access logs 分流。這些完整服務、detectors 與 UI 尚未交付。

P0 仍缺：可信身分、G0-COVERAGE 的 native／Compose runtime matrix 與 runner、normalize 前封閉原始 schema 的實際 Gateway enforcement、queue／backpressure／cancel／durable audit 的實際故障，以及 route activation。缺 evidence 的 strict policy 不可 activate；agentguard.coverage 的 preflight 結果不會把 runtime gate 標成 PASS。P2 另須驗證 MCP error sanitizer；backend attestation 永遠不等於 protected。

Detector 提供 evidence，不能授權；tools/list 隱藏不能替代 tools/call 授權；unknown／缺 context／缺 evidence 不靜默 allow。

## 文件與規劃

| 文件 | 內容 |
|---|---|
| [P0 第一個實作切片](docs/p0-implementation.md) | stock diagnostic、evidence preflight 與起始驗證範圍 |
| [Strict parser ADR](docs/adr-001-strict-gateway-wire.md) | 下游 patch、canonical wire、驗收與建置修正 |
| [Guard deadline ADR](docs/adr-002-guard-deadline-budget.md) | 預算宣告閘門、fixture-modeled adapter、9 組案例、逐筆決策契約與未涵蓋範圍 |
| [技術選型與 P0–P6](docs/implementation-plan.md) | 架構、元件取捨、PR-sized backlog 與 exit gates |
| [協定與 policy](docs/protocol-contracts.md) | wire、可信 context、coverage oracle、ExtMCP/error 邊界 |
| [Review 硬 gate](docs/review-gates.md) | fixtures、oracle、統計／故障與 release gates |
| [Assurance／部署營運](docs/assurance-and-operations.md) | PII/injection 對照組、多語資料、Compose/vLLM／雙 logs |
| [一手來源與證據](docs/sources.md) | 原始設計的 S1–S27 來源與限制 |
| [Policy 草案](examples/policies/strict-local.proposed.yaml) | 唯一 proposed schema 範例；不是 Gateway 原生配置 |

2026-09-17 的 review-verification、sources 與規劃文件保留當時的驗證快照；其中的 NOT_RUN 描述不應覆蓋後續 CI 的實際結果，也不能反過來把新版本的測試追溯套用舊版本。

專案 LICENSE 未變更。第三方程式碼、模型與資料分別審查授權；本階段未加入第三方模型權重或資料集原文。

## Review 整併與下一個 P0 切片

PR #7 與 #8 原為重複實作；#7 已由 #8 取代，保留 #8 作為唯一整併入口。修正與 scope 見 [review consolidation](docs/review-consolidation.md)。

新增 `agentguard.context` 的封閉 CEL mapping／route preflight，與 `tools.context_probe` 真實 Gateway 雙向測試：37 組案例分別驗證 request／response 的缺 header、CEL 失敗、client 偽造 context、streaming 與模型拒絕。Response webhook 沒有 `llmRequest`；兩階段改讀原始 `json(request.body)` snapshot。只有原始 JSON 成功解析且省略 stream 欄位時才採協定預設，缺 context 不會默認放行。此窄 profile 仍拒絕 transformations／provider model override。這仍不是完整 Studio/compiler/identity/ingress coverage。

Patched build 與 acceptance 現在分為不同 CI jobs。手動驗收必須從受信 build job 取得 `BUILD_MANIFEST_SHA256`；不要對任意下載的 manifest 自行計算 hash 後當作受信來源。Compose 也要求此值。完整 build 流程以 `.github/workflows/p0-patched.yml` 為準；PR run 不產生 production approval。

建置入口從固定 upstream Git object 重算 patch，不信任 manifest 自報的 patched hash；使用乾淨的 Cargo home／target 與完整工具鏈 pin。安裝輸出使用 no-follow 目錄 handles，拒絕 symlink 父目錄。每項修正都有可失敗的回歸測試，完整結果以目前 head 的 CI artifacts 為準。

Guard deadline 切片見 [ADR-002](docs/adr-002-guard-deadline-budget.md)：`agentguard/deadline.py` 只提供宣告閘門，`tools/deadline_probe.py` 對真實 patched Gateway 跑 9 組案例。guard 超預算必須是**已送達**的 fail-closed 503；Gateway 逾時必須由 Gateway 自己的 log 顯示 `upstream call timeout`，提前斷線則顯示 `connection closed before message completed`。兩者都以 availability fault 記帳，但只有前者支持 timeout 邊界，也不得把逾時算成防禦。`p0-patched` workflow 同時改為不限制 base branch，讓 stacked P0 PR 跑同一組真實驗收。
