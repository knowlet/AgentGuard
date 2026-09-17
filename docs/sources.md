# 一手來源與證據狀態

查核基準：2026-09-17。文件中 `[S#]` 對應下表。`latest` 文件是查核當日參考，不是 dependency lock；P0/P3 必須固定實際 artifact revision/digest。下表不是對每個上游的安全背書，也不表示已在本機部署。

| ID | 一手來源 | 本提案引用範圍 |
|---|---|---|
| S1 | [AgentGateway v1.5.0 release](https://github.com/agentgateway/agentgateway/releases/tag/v1.5.0) | 查核時 latest stable；發布日 2026-08-27；用作契約基線 |
| S2 | [v1.5.0 ExtMCP proto](https://github.com/agentgateway/agentgateway/blob/v1.5.0/crates/protos/proto/ext_mcp.proto) | RPC、params/result bytes、mutation 不重跑 RBAC、error 不進 response hook |
| S3 | [v1.5.0 LLM guard example](https://github.com/agentgateway/agentgateway/blob/v1.5.0/examples/llm-prompt-guard/README.md) | HTTP hook 路徑與配置、headers/context |
| S4 | [v1.5.0 webhook implementation](https://github.com/agentgateway/agentgateway/blob/v1.5.0/crates/agentgateway/src/llm/policy/webhook.rs) | normalized body、untagged actions 與 mask/reject 形狀；已查讀前 260 行 |
| S5 | [Presidio documentation](https://presidio.dataprivacystack.org/) | 可配置 PII recognizers／anonymization；本地語言與 entity 支持需驗收 |
| S6 | [pplx-pii-masking model card](https://huggingface.co/perplexity-ai/pplx-pii-masking) | 原模型的 token classification、4,096-token truncation、span 與 sensitivity |
| S7 | [pplx-pii-masking-vllm model card](https://huggingface.co/perplexity-ai/pplx-pii-masking-vllm) | pooling/logits/postprocess 專用路徑；與原模型的 packaging／授權不同，需另審 |
| S8 | [SingGuard-NSFA repository](https://github.com/inclusionAI/SingGuard-NSFA)；[9B model card](https://huggingface.co/inclusionAI/SingGuard-NSFA-9B) | 分類 heads／生成雙模式、單輪文字 scope；作者 benchmark 不作本機 SLA |
| S9 | [NeMo Guardrails overview](https://docs.nvidia.com/nemo/guardrails/about-nemo-guardrails-library/overview) | 可選流程／對話 guardrails；版本與 API 另外鎖定 |
| S10 | [Guardrails AI repository](https://github.com/guardrails-ai/guardrails) | validators／結構化輸出；2026-07-06 公告 PyPI migration 和 hosted inference 停止計畫 |
| S11 | [Promptfoo red teaming](https://www.promptfoo.dev/docs/red-team/) | Primary assurance runner；離線與出口行為需實測 |
| S12 | [Microsoft PyRIT](https://github.com/Azure/PyRIT) | 多輪／自適應 red teaming adapter |
| S13 | [DeepTeam](https://github.com/confident-ai/deepteam) | 可選 attack/vulnerability runner |
| S14 | [Alloy loki.source.file](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.file/) | JSONL file collection；rotation/checkpoint 行為待部署驗收 |
| S15 | [Loki OTLP ingestion](https://grafana.com/docs/loki/latest/send-data/otel/) | OTLP 原生接收與 attributes mapping |
| S16 | [AgentGateway standalone documentation](https://agentgateway.dev/docs/standalone/latest/) | observability/config 參考；精確 OTLP/Grafana provisioning 檔尚未產生或執行 |
| S17 | [vLLM online serving](https://docs.vllm.ai/en/latest/serving/online_serving/) | 本地推論服務；模型與 endpoint 能力逐一驗證 |
| S18 | [MCP guardrails protocol behavior](https://docs.solo.io/agentgateway/standalone/latest/documentation/mcp/guardrails/about/)；[OSS MCP guardrails](https://agentgateway.dev/docs/standalone/latest/mcp/guardrails/) | method selector、phase、failure behavior；採購／edition 能力不得僅由產品文件推定，OSS 以 S2 和 runtime test 為準 |
| S19 | [AgentDojo](https://github.com/ethz-spylab/agentdojo) | agent 任務環境與 indirect-injection benchmark |
| S20 | [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | 工具輸出的 indirect-injection cases |
| S21 | [BIPIA](https://github.com/microsoft/BIPIA) | 間接注入研究資料；部分來源需獨立取得與授權 |
| S22 | [MultiJail original repository](https://github.com/DAMO-NLP-SG/multilingual-safety-for-LLMs) | 多語越獄；英文加其他九語的人工作業來源 |
| S23 | [HarmBench](https://github.com/centerforaisafety/HarmBench) | harmful behavior 與 robust refusal benchmark |
| S24 | [ai4privacy/pii-masking-300k](https://huggingface.co/datasets/ai4privacy/pii-masking-300k) | 候選 PII span 資料；實際 snapshot、語言、授權及 QA 待入庫審查 |

## 尚未解決、不應隱藏的問題

1. 上游已讀取的 webhook struct 不足以證明所有 provider-specific／tool-call 欄位都被覆蓋；P0 必須逐欄位驗證。沒有模型或 JSON 欄位的資訊流，detector 就無從保護。
2. ExtMCP 錯誤回應缺口是已確認的協定限制；補洞路徑尚未跑 E2E，不應在圖上畫完就算修好。
3. SingGuard-NSFA 不與其他名為 SingGuard 的研究混用；其最快模式要驗證 custom heads，不拿生成服務冒充。
4. pplx 原版與 vLLM packaging 的 model card 授權標記不同；原版標 MIT 不足以替另一份 artifact 放行。模型卡的示範相容不等於我們的硬體與所有語言測試通過。
5. 上述資料來源沒有在本工作階段完整下載、人工審核或執行；清單不是已完成 benchmark。候選來源不能自動公開再散布。
6. 目前環境缺少 Docker／nerdctl／GPU runtime，只有文件與靜態查核；真正部署及性能數字留在 P0/P3/P6 的驗收紀錄中。

第三方原始程式碼、模型權重及資料未被本文件變更納入 repository；本文只記錄來源與 proposed interfaces，避免不必要的授權與供應鏈擴張。
