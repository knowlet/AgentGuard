# AgentGuard

AgentGuard 是以 **AgentGateway 作為 enforcement plane** 的 protocol-aware agent security stack。

> 狀態：P0 實作中，尚無 production-ready Guard stack。官方 stock v1.5.0 是漏洞重現基線；專案另維護 strict parser build 及真實 Gateway/Compose 驗收。Wire 驗收不等於完整 P0 或路由已受保護。

## 系統邊界

PromptGuard 保護 LLM request/response、PII、secret 與 deterministic decisions；MCPGuard 透過 ExtMCP 執行 method/tool authorization、tools/list mutation。Assurance 是隔離的測試平面；Policy Studio 為 FastAPI control plane＋browser，負責 catalog/表單/驗證/模擬/版本發布。Prometheus、Loki、Grafana provisioning、Alloy 提供 observability，Guard JSONL 與 Gateway OTLP access logs 分流。

## P0 可執行實作

[Stock 診斷](docs/p0-implementation.md)、[Strict parser／protected acceptance](docs/p0-protected-implementation.md)、[邊界與相容性 ADR](docs/adr/0001-strict-gateway-parser.md)。

`p0-stock-diagnostic` 保留官方 binary 的 fail-open 重現；`p0-protected` 在固定 upstream source 內編譯嚴格 parser，驗證合法 controls、負向 actions、HTTP status／disconnect／timeout 與 Compose evidence 持久化。最新結果以相應 commit 的 CI artifact 為準，不以 job 名稱判斷安全通過。

## 規劃文件

| 文件 | 內容 |
|---|---|
| [技術選型與 P0–P6](docs/implementation-plan.md) | 元件取捨、架構、Studio、PR-sized backlog 與 exit gates |
| [協定與 policy](docs/protocol-contracts.md) | wire、可信 context、外部 coverage oracle、ExtMCP/error 邊界 |
| [Assurance／部署營運](docs/assurance-and-operations.md) | PII/injection 分開的對照組、多語資料、CI/availability、Compose/vLLM/雙 logs |
| [Review 硬 gate](docs/review-gates.md) | G0/G2/G3/G5 fixtures、可失敗斷言、CI 邊界、canary/timeout/oracle |
| [Review 核驗與樣本規劃](docs/review-verification.md) | 規劃階段自測紀錄、CI／power 差異、可執行事前樣本規劃與 NOT_RUN 邊界 |
| [一手來源與證據](docs/sources.md) | S1–S27 與規劃階段的證據狀態 |
| [Policy 草案](examples/policies/strict-local.proposed.yaml) | proposed schema；缺 evidence 必須拒絕 activation，不是 Gateway 原生配置 |

## 可執行的測試輔助程式

```bash
python -m unittest discover -s tests -v
python tools/assurance_contract.py --stats
python -m tools.plan_statistics --metric fpr --threshold 0.02 --expected-rate 0.01 --power 0.80
python -m tools.plan_statistics --metric recall --threshold 0.95 --expected-rate 0.97 --power 0.90
```

Python tests 涵蓋 canonical action、負向 fixture、Wilson rate gate、timeout/unknown 記帳、build/evidence binding，以及固定 n 的單項 CI gate power 規劃。它們**不取代原生 Rust、真實 Gateway E2E 或模型 benchmark**。`assurance_contract.py` 的 masking helper 尚未實作，刻意拒絕；Gateway 原生 mask 驗收則由獨立的 protected suite 執行。planner 必須在收集 holdout 前使用，不能用於測到過關才停止；不計算 multiplicity 或 joint release power。

P0 需真實 Gateway 跑 G0-WIRE/CONTEXT/COVERAGE/DEADLINE；原版漏洞重現成功不是 protected PASS。P0 只報協定/context/coverage/counters/故障延遲，ASR/FPR 為 NOT_EVALUATED。P2 必須以含秘密的 MCP errors 驗收 sanitizer；backend attestation 不等於 protected。

Detector 提供 evidence，不能授權；tools/list 隱藏不能代替 tools/call 授權；unknown/缺 context/缺 evidence 不靜默 allow。沒有有效 policy snapshot 與已證明能力的 strict route 不啟用。

Stock Gateway/Compose 診斷已有實跑紀錄；strict build 結果見對應 CI artifacts。vLLM/GPU、detector 資料集 benchmark 與完整 Guard stack 尚未完成。專案 LICENSE 待維護者決定；第三方程式碼、模型與資料分別審查授權。
