# AgentGuard

AgentGuard 是以 **AgentGateway 作為 enforcement plane** 的 protocol-aware agent security stack。

> 狀態：架構與分階段實作規劃。此 repository 尚未提供可部署的 Guard stack；文件中的驗收目標不代表已通過測試。規劃基準日：2026-09-17。

## 系統邊界

- **PromptGuard**：LLM request/response inspection、prompt injection detection、PII masking、secret leakage prevention、deterministic policy decisions。
- **MCPGuard**：透過 AgentGateway ExtMCP 執行 MCP method/tool authorization、`tools/list` mutation 與 tool-result inspection。
- **Assurance**：隔離的測試平面；整合 Promptfoo、PyRIT、DeepTeam，評估安全效果、誤判、效能與協定完整性。
- **Policy Studio**：FastAPI control plane 與 browser UI，提供 policy catalog、圖形化編輯、驗證、模擬、版本發布與 rollback。
- **Observability**：Prometheus、Loki、Grafana provisioning、Alloy；Guard JSONL decision logs 與 AgentGateway OTLP access logs 分流收集。

## 規劃文件

| 文件 | 內容 |
|---|---|
| [技術選型與實作計畫](docs/implementation-plan.md) | 架構、取捨、Studio、P0–P6 milestones 與 PR-sized backlog |
| [協定與 policy 契約](docs/protocol-contracts.md) | v1.5.0 webhook／ExtMCP、coverage、deterministic decisions、proposed policy |
| [Assurance 與部署營運](docs/assurance-and-operations.md) | 多語資料來源、對照組、測試門檻、Compose／vLLM、雙管線 telemetry |
| [一手來源與證據狀態](docs/sources.md) | 上游來源與尚未驗證的能力，區分原始碼查核和 runtime 實測 |
| [Policy YAML 草案](examples/policies/strict-local.proposed.yaml) | 本專案 schema 設計示意；不是可直接執行的 Gateway configuration |

## 開發原則

Gateway 負責 enforcement；detectors 提供證據，不能自行授權。先驗證固定版本的真實協定整合，再擴充 detector、UI 與部署拓撲。任何尚未支援的 endpoint、content type、streaming mode 或 guard capability 都必須明確顯示，不能默默放行。

第一個實作階段為 P0：真實 AgentGateway、mock LLM／MCP backends、HTTP／gRPC adapters 與 failClosed E2E。文件內 proposed API／policy／目錄不是已完成的實作；本次未執行 Compose、GPU 或模型 benchmark。

專案授權尚待維護者決定；第三方程式碼、模型權重與資料集需分別確認授權。
