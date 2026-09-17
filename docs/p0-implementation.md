# P0 第一個實作切片：真實 Gateway 診斷與 evidence preflight

狀態：已實作可執行的 stdlib runner、HTTP fixtures、digest-bound evidence validator 與單元測試；**不是完整 PromptGuard/MCPGuard，也不是 P0 protected PASS**。

## 執行

```bash
python3 -m unittest discover -s tests -v
python3 -m tools.fetch_gateway --output /tmp/agentgateway-v1.5.0
python3 -m tools.gateway_probe --gateway-bin /tmp/agentgateway-v1.5.0 \
  --report reports/gateway-stock.json
```

此 runner 只接受 Linux/amd64 stock v1.5.0 binary，其 SHA-256 為
`daca5cda76e8c5ab0c1a75912fecf2d6365095403f810db72029c49d14a37e7b`。
來源：[官方 release asset metadata](https://api.github.com/repos/agentgateway/agentgateway/releases/assets/532676395)。下載與執行各自驗 hash；沒有 GPU、外部 LLM、API key 或 production tools。沒有把 Gateway 換成 Python mock。

runner 啟動真正 Gateway process，以及隔離的 loopback HTTP webhook/LLM fixtures。先測 allow/reject/mask × request/response 共六個合法 controls，再按 22 個負向 fixture 的 phase 展開 42 個請求。對 request 檢查 upstream counter；對 response 檢查 client bytes。每個案例使用新的隨機 marker；marker 是 wire 資料流測試，不代表 secret detector recall。

## Exit code 與報告

Stock 的 malformed action 仍可能 allow，這正是預期要重現的已知問題。diagnostic exit 0 只代表觀察符合來源預期，報告為 `VULNERABILITY_REPRODUCED`，**protected_wire_gate 仍為 FAIL**。合法 controls 失敗、預期行為不符回 1；binary/config/startup/network 等錯誤回 2。

`--require-protected` 刻意回非零：本切片沒有 patched Gateway acceptance runner，不能用 stock diagnostic 綠燈宣稱受保護。P0 release 與 ASR/FPR 保持 NOT_EVALUATED。沒有 evidence 的情況不得用人工填 PASS 取代。

報告含 binary/config/fixture/runner hashes、每案 hook/upstream counters、HTTP status、client marker 是否可見與 response hash。完整受限 raw evidence、signed provenance、全欄位 coverage matrix 與 deadline fault suite 尚未實作。GitHub Actions 的 `p0-stock-diagnostic` job 印出報告及 Gateway log，執行失敗仍保留診斷；不是 production release workflow。

## Evidence validator

`agentguard.evidence.validate_evidence` 接受原始 artifact bytes，以及**由可信發布目錄提供**的預期 hash、四個 deployment digests、route/protocol/phase/schema scope、必需 JSON pointers 與時間限制。

拒絕 missing/mismatched artifact、Gateway image/config/compiler/adapter drift、過期/未來時間、任一 G0 gate 非 PASS、未知或缺欄位、缺 context、未拒絕原始未知欄位、重複 JSON keys。返回 EVIDENCE_VALIDATED，不宣稱已啟用路由。

它是未來 compiler 的 preflight 元件，不是簽章服務或完整 compiler。若 caller 把攻擊者自填 hash 當可信 hash，安全前提即不成立；hash 本身不證明報告是真的。測試內人工建立的 PASS doc 只驗 validator 邏輯，不可發布為 runtime evidence。

## Compose 包裝

```bash
docker compose -f deploy/compose/compose.yaml --profile cpu-e2e run --build --rm diagnostic
```

此 profile 是單一隔離診斷容器：Gateway 與 fixtures 同容器、runtime network=none、non-root、read-only、無 host port/socket、無固定 container_name。建置時下載已 pin 的 Gateway。Python base image 預設 tag 尚未 digest-pin，部署者可用 `PYTHON_IMAGE=python@sha256:...` 指定核准映像；不能宣稱已完成全供應鏈鎖定。Compose/nerdctl 相容驗收與多服務正式拓撲仍待後續完成。

## 尚未完成的 gate

G0-WIRE parser 修補及 protected acceptance；G0-CONTEXT 原始 ingress/CEL、G0-COVERAGE 真實全欄位 matrix、G0-DEADLINE timeout/queue/crash；正式 HTTP/ExtMCP adapters、PII/secret detectors、MCP error sanitizer、Policy Studio、vLLM 與 observability provisioning 均未由本切片完成。Issue #2 不能因此關閉。
