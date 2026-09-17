# AgentGuard

AgentGuard 是以 **AgentGateway 作為 enforcement plane** 的 protocol-aware agent security stack。

> 狀態：架構與分階段實作規劃。此 repository 尚未提供可部署的 Guard stack；文件中的驗收目標不代表已通過測試。規劃基準日：2026-09-17。

## 系統邊界

- **PromptGuard**：LLM request/response inspection、prompt injection detection、PII masking、secret leakage prevention、deterministic policy decisions。
- **MCPGuard**：透過 AgentGateway ExtMCP 執行 MCP method/tool authorization、`tools/list` mutation 與 tool-result inspection。
- **Assurance**：隔離的測試平面；整合 Promptfoo、PyRIT、DeepTeam，評估安全效果、誤判、效能與協定完整性。
- **Policy Studio**：FastAPI control plane 與 browser UI，提供 policy catalog、圖形化編輯、驗證、模擬、版本發布與 rollback。
- **Observability**：Prometheus、Loki、Grafana provisioning、Alloy；Guard JSONL decision logs 與 AgentGateway OTLP access logs 分流收集。

## 開發原則

Gateway 負責 enforcement；detectors 提供證據，不能自行授權。先驗證固定版本的真實協定整合，再擴充 detector、UI 與部署拓撲。任何尚未支援的 endpoint、content type、streaming mode 或 guard capability 都必須明確顯示，不能默默放行。

完整規劃文件將以獨立變更集加入。專案授權尚待維護者決定；第三方程式碼、模型權重與資料集需分別確認授權。
