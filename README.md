# AgentGuard

AgentGuard 是以 **AgentGateway 作為 enforcement plane** 的 protocol-aware agent security stack。

> 狀態：P0 實作中，尚無 production-ready Guard stack。已有真實 Gateway／Compose 診斷、evidence preflight，以及固定 v1.5.0 的下游 strict webhook parser patch。**原版 v1.5.0 仍有已重現的 fail-open；下游 patch 的 scoped wire 驗收不等於完整 P0、PII 或 prompt-injection 防護。** 實際結果須查看對應 commit 的 CI 與 raw artifacts。

## 目前實作與能力邊界

| 部分 | 已提供 | 不代表 |
|---|---|---|
| Stock diagnostic | checksum-pinned 真實 AgentGateway、HTTP fixtures、upstream counters、mask 結構檢查、CPU Compose | 診斷綠燈只代表 VULNERABILITY_REPRODUCED，不是 protected PASS |
| Strict wire patch | 在 Gateway 內驗證唯一 action、物件形狀、欄位與型別、phase、reject status、HTTP 故障；exact-source installer | 不是上游官方 release 修復，也不是另一個 reverse proxy |
| Patched acceptance | 6 個合法 controls、84 個負向 phase cases、10 個 transport faults 與 10 次 recovery；Serde、native Gateway、Compose 分層驗證 | 不涵蓋原始 request field coverage、所有 timeout/load、MCP 或 detector 效果 |
| Evidence preflight | artifact hash、Gateway/config/compiler/adapter digests、scope、freshness、必要 context/coverage/gates | 不是完整 policy compiler、簽章驗證服務或 route activation |
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

P0 下一步是 G0-CONTEXT／COVERAGE／DEADLINE：可信身分及 CEL context、normalize 前封閉原始 schema、外部 per-digest field matrix、包含 queue/audit 的 deadline 故障測試。缺 evidence 的 strict policy 不可 activate。P2 另須驗證 MCP error sanitizer；backend attestation 永遠不等於 protected。

Detector 提供 evidence，不能授權；tools/list 隱藏不能替代 tools/call 授權；unknown／缺 context／缺 evidence 不靜默 allow。

## 文件與規劃

| 文件 | 內容 |
|---|---|
| [P0 第一個實作切片](docs/p0-implementation.md) | stock diagnostic、evidence preflight 與起始驗證範圍 |
| [Strict parser ADR](docs/adr-001-strict-gateway-wire.md) | 下游 patch、canonical wire、驗收與建置修正 |
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

新增 `agentguard.context` 的封閉 CEL mapping／route preflight，與 `tools.context_probe` 真實 Gateway 測試：缺 header、CEL 求值失敗、client 偽造 context、streaming 與模型拒絕。Provider model override 會改變 `llmRequest.model`，此原始模型 profile 明確拒絕該配置，不將有效模型誤稱客戶端原始模型。這仍不是完整 Studio/compiler/identity/ingress coverage。

Patched build 與 acceptance 現在分為不同 CI jobs。手動驗收必須從受信 build job 取得 `BUILD_MANIFEST_SHA256`；不要對任意下載的 manifest 自行計算 hash 後當作受信來源。Compose 也要求此值。完整 build 流程以 `.github/workflows/p0-patched.yml` 為準；PR run 不產生 production approval。
