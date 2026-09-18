# 一手來源與證據狀態

2026-09-17 review 修訂。`[S#]` 對應下表；latest 網頁只是查核參考，部署須固定 revision/digest。文件/來源級推論、Python helper 自測、原生 Serde、真實 Gateway E2E、模型 benchmark 是不同層級。

| ID | 一手來源 | 引用範圍 |
|---|---|---|
| S1 | [AgentGateway v1.5.0 release](https://github.com/agentgateway/agentgateway/releases/tag/v1.5.0) | 2026-08-27 發布；作相容性／漏洞重現基線，不代表安全部署驗收 |
| S2 | [v1.5.0 ExtMCP proto](https://github.com/agentgateway/agentgateway/blob/v1.5.0/crates/protos/proto/ext_mcp.proto) | params/result bytes、RPC、mutation 不重跑 RBAC、error 跳過 response hook |
| S3 | [v1.5.0 LLM guard example](https://github.com/agentgateway/agentgateway/blob/v1.5.0/examples/llm-prompt-guard/README.md) | hook paths/config/CEL headers |
| S4 | [v1.5.0 webhook.rs](https://github.com/agentgateway/agentgateway/blob/v1.5.0/crates/agentgateway/src/llm/policy/webhook.rs) | normalized messages/choices、untagged Mask/Reject/Pass、optional reason、header expressions；review 重新查核 |
| S5 | [Presidio](https://presidio.dataprivacystack.org/) | recognizers/anonymization；locale/entity 支持待驗收 |
| S6 | [pplx-pii model](https://huggingface.co/perplexity-ai/pplx-pii-masking) | token classification、4,096-token truncation、span/sensitivity |
| S7 | [pplx vLLM packaging](https://huggingface.co/perplexity-ai/pplx-pii-masking-vllm) | pooling/logits/postprocess；打包和原版授權分審 |
| S8 | [SingGuard-NSFA repo](https://github.com/inclusionAI/SingGuard-NSFA)、[model card](https://huggingface.co/inclusionAI/SingGuard-NSFA-9B) | 分類 heads/生成模式、單輪文字 scope；作者 benchmark 非本機 SLA |
| S9 | [NeMo Guardrails](https://docs.nvidia.com/nemo/guardrails/about-nemo-guardrails-library/overview) | 選用流程/對話 rails；API/runtime 固定後驗收 |
| S10 | [Guardrails AI](https://github.com/guardrails-ai/guardrails) | validators、PyPI migration/hosted inference 公告；不假定舊雲端路徑可離線 |
| S11 | [Promptfoo red teaming](https://www.promptfoo.dev/docs/red-team/) | 第一個 runner；本地 provider/egress 仍需實測 |
| S12 | [PyRIT](https://github.com/Azure/PyRIT) | adaptive/multiturn runner |
| S13 | [DeepTeam](https://github.com/confident-ai/deepteam) | 選用攻擊/分類 runner |
| S14 | [Alloy loki.source.file](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.file/) | JSONL file pipeline |
| S15 | [Loki OTLP ingestion](https://grafana.com/docs/loki/latest/send-data/otel/) | native OTLP/attributes mapping |
| S16 | [AgentGateway docs](https://agentgateway.dev/docs/standalone/latest/) | observability/config 參考；未生成或執行本專案 provisioning |
| S17 | [vLLM serving](https://docs.vllm.ai/en/latest/serving/online_serving/) | model/endpoint 能力逐一驗收 |
| S18 | [MCP behavior](https://docs.solo.io/agentgateway/standalone/latest/documentation/mcp/guardrails/about/)、[OSS docs](https://agentgateway.dev/docs/standalone/latest/mcp/guardrails/) | selectors/phases/failure behavior；edition 差異不能推定，OSS 以 proto/runtime 為準 |
| S19 | [AgentDojo](https://github.com/ethz-spylab/agentdojo) | task/indirect injection benchmark |
| S20 | [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | tool-output injection |
| S21 | [BIPIA](https://github.com/microsoft/BIPIA) | 間接注入資料，衍生來源獨立審查 |
| S22 | [MultiJail](https://github.com/DAMO-NLP-SG/multilingual-safety-for-LLMs) | 多語 jailbreak，不代表 MCP/zh-TW 全覆蓋 |
| S23 | [HarmBench](https://github.com/centerforaisafety/HarmBench) | harmful behaviors/robust refusal |
| S24 | [ai4privacy PII](https://huggingface.co/datasets/ai4privacy/pii-masking-300k) | 候選 span data；snapshot/license/locale/QA 待審 |
| S25 | [v1.5.0 policy/mod.rs](https://github.com/agentgateway/agentgateway/blob/v1.5.0/crates/agentgateway/src/llm/policy/mod.rs) | 10 秒 with_default_timeout；evaluate_webhook_request/response 的 Err failure-mode 與 Pass 分支 |
| S26 | [NIST proportion confidence intervals](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm) | Wilson、單側/雙側、exact binomial；本文數字由 Python 計算，非 NIST benchmark |
| S27 | [Serde enum representations](https://serde.rs/enum-representations.html)、[container attributes](https://serde.rs/container-attrs.html) | untagged 第一個成功分支與未知欄位；搭配 S4/S25 支持來源級結論 |

## 已確認與仍未完成

已確認的來源級問題：malformed action 可被解析成 Pass，failClosed 不適用成功解析；headers/context 不是 normalized body 的天然欄位；ExtMCP errors 跳過 response hook，參數 mutation 不重跑 Gateway RBAC。`reason` 錯型別仍可能解析失敗，不能概括成所有物件都 allow。

這些問題已提升為 [G0/G2 hard gates](review-gates.md)，不再只寫「要驗證」。**本 PR 沒有修補 Gateway parser；v1.5.0 原版不得標 G0-WIRE 已通過。** 只加 typed serializer 或 deny_unknown_fields 並不足以完成所有負向 gate。

尚未取得真實原始欄位 coverage matrix；header/ingress/body 補洞與 JSON-RPC error sanitizer 未跑 E2E。Backend attestation 只代表風險接受，永不當完整 error protection。未知/缺 evidence 不可 activate strict route。

SingGuard 同名研究不混用；分類 heads 不用生成 latency 代替。pplx 兩種 packaging/model card 授權分審；作者模型卡與多語聲明不是本機能力證據。候選資料尚未完整下載、授權/人工 QA 或執行；不自動再散布。

先前每語言固定 500 的統計 gate 已撤回；採預註冊 CI 邊界、power、family 和停止規則。8/800 等是條件式統計示例，不是新的固定樣本門檻。Timeout/unknown 不算 detector 防禦成功，P0 不報 ASR/FPR。

目前環境缺 Docker/nerdctl/GPU/Rust runtime，外部網路解析亦不可用於本機下載。完成來源查核與 Python 非 masking wire/statistics/accounting helper 自測；**未執行原生 Serde、真實 Gateway/Compose、vLLM/GPU、資料集或 browser tests**。Helper 的 PASS 不填補 runtime gate；所有效能/安全結果須由後續真實 evidence 支持。

本變更不納入第三方模型/資料原文，不修改專案 LICENSE。原始規劃在 git 歷史可查；本次主要修正規範與驗收可執行性，而非宣稱完成 production 實作。
