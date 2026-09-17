# AgentGuard

AgentGuard 是以 **AgentGateway 作為 enforcement plane** 的 protocol-aware agent security stack。

> 狀態：規劃與驗收契約，尚無可部署 Guard stack。2026-09-17 review 修訂：v1.5.0 是相容性／漏洞重現基線，已知 untagged webhook action fall-through 未被本 PR 修補，不能宣稱它通過 protected deployment gate。

## 系統邊界

PromptGuard 保護 LLM request/response、PII、secret 與 deterministic decisions；MCPGuard 透過 ExtMCP 執行 method/tool authorization、tools/list mutation。Assurance 是隔離的測試平面；Policy Studio 為 FastAPI control plane＋browser，負責 catalog/表單/驗證/模擬/版本發布。Prometheus、Loki、Grafana provisioning、Alloy 提供 observability，Guard JSONL 與 Gateway OTLP access logs 分流。

## 規劃文件

| 文件 | 內容 |
|---|---|
| [技術選型與 P0–P6](docs/implementation-plan.md) | 元件取捨、架構、Studio、PR-sized backlog 與 exit gates |
| [協定與 policy](docs/protocol-contracts.md) | wire、可信 context、外部 coverage oracle、ExtMCP/error 邊界 |
| [Assurance／部署營運](docs/assurance-and-operations.md) | PII/injection 分開的對照組、多語資料、CI/availability、Compose/vLLM/雙 logs |
| [Review 硬 gate](docs/review-gates.md) | G0/G2/G3/G5 fixtures、可失敗斷言、CI 邊界、canary/timeout/oracle |
| [一手來源與證據](docs/sources.md) | S1–S27 與尚未實跑的能力 |
| [Policy 草案](examples/policies/strict-local.proposed.yaml) | proposed schema；缺 evidence 必須拒絕 activation，不是 Gateway 原生配置 |

## 可執行的測試輔助程式

```bash
python -m unittest discover -s tests -v
python tools/assurance_contract.py --stats
```

測試涵蓋非 masking canonical action、負向 fixture、Wilson rate gate、timeout/unknown 記帳。它們**不是原生 Serde 重現、Gateway adapter、Gateway E2E 或模型 benchmark**。Masking 尚未在 helper 實作，刻意拒絕；原版 Gateway 的 source-derived 行為列在 fixtures，不冒充 runtime 觀察。

P0 需真實 Gateway 跑 G0-WIRE/CONTEXT/COVERAGE/DEADLINE；原版漏洞重現成功不是 protected PASS。P0 只報協定/context/coverage/counters/故障延遲，ASR/FPR 為 NOT_EVALUATED。P2 必須以含秘密的 MCP errors 驗收 sanitizer；backend attestation 不等於 protected。

Detector 提供 evidence，不能授權；tools/list 隱藏不能代替 tools/call 授權；unknown/缺 context/缺 evidence 不靜默 allow。沒有有效 policy snapshot 與已證明能力的 strict route 不啟用。

本 PR 未執行 Compose、Gateway runtime、vLLM/GPU 或資料集 benchmark。專案 LICENSE 待維護者決定；第三方程式碼、模型與資料分別審查授權。
