# P0 第一個實作切片：真實 Gateway 診斷與 evidence preflight

已實作 stdlib runner、HTTP fixtures、digest-bound evidence validator、單元測試與 CI。**不是完整 PromptGuard/MCPGuard，也不是 P0 protected PASS**。

## 執行

```bash
python3 -m unittest discover -s tests -v
python3 -m tools.fetch_gateway --output /tmp/agentgateway-v1.5.0
python3 -m tools.gateway_probe --gateway-bin /tmp/agentgateway-v1.5.0 \
  --report reports/gateway-stock.json
```

Runner 只接受 Linux/amd64 stock v1.5.0 binary，SHA-256：`daca5cda76e8c5ab0c1a75912fecf2d6365095403f810db72029c49d14a37e7b`。來源：[官方 release metadata](https://api.github.com/repos/agentgateway/agentgateway/releases/assets/532676395)。下載與執行分別驗 hash；不需 API key/GPU/外部 LLM，不把 Gateway 換成 Python mock。

啟動真正 Gateway process 與 loopback HTTP webhook/LLM fixtures。先測 request/response × allow/reject/mask 六個合法 controls，再依22個負向 fixture 展開42個 phase cases。Request 看 upstream counter，response 看 client bytes。每案新隨機 marker 只測資料流，不代表 detector recall。Native diagnostic 跑在臨時 CI runner；Compose 路徑另以 network=none 隔離。

## Assertions 與 exit code

Stock diagnostic exit0只表示已知漏洞重現且已定義的觀察相符：VULNERABILITY_REPRODUCED，不是 protected PASS。所有支援 expectations 各自有 assertion；not_verified/*_not_verified 仍執行及記錄，但 stock/protected assertions 為null，不計PASS或FAIL。Unknown仍不可讓完整protected suite過關，本runner永不發布protected PASS。

Request拒絕需HTTP4xx/5xx、hook一次、upstream0；response拒絕需HTTP4xx/5xx、hook一次、upstream1且不洩漏。Wrong reject status200即使未呼叫上游，也不算正確protected rejection。

Mask controls檢查system/user兩則訊息、prefix/suffix、[REDACTED]，及choices/index/role/finish_reason/model/usage等既定不變量。丟掉整段payload不會通過；這仍只是固定文字fixture，不是任意provider欄位coverage。

Controls或stock expectation失敗回1；binary/config/startup等error回2。`--require-protected`刻意非零；未有patched acceptance不可用stock綠燈放行。P0 release、ASR/FPR保持NOT_EVALUATED。

報告保存binary/config/fixture/runner hashes、HTTP/counters/marker觀察/結構不變量與response hash；不是signed provenance或完整raw artifact。執行前把驗hash後的bytes複製到私有tmpdir，固定argv、shell=False，不對argv做shell escaping，不執行client/webhook提供的命令。

## Field coverage preflight

agentguard.coverage 提供 G0-COVERAGE 的外部 matrix／evidence preflight primitive。它要求可信 matrix 綁定 gateway_image、gateway_config、compiler、adapter，scope 的 phase 固定為 both，並以實際 deployed binds/listeners/routes wrapper 的 digest 綁定 route selection。每個 request／response row 都要有 JSON pointer、normalized pointer、fixture／artifact digest、phase contract、hook/backend/client observations；每個 phase 至少要有一個 field_type=unknown 且 ingress_rejected 的 row，並附 native Gateway rejection evidence 欄位。

validate_coverage_route 只做 route/context/coverage preflight，不啟用 route。這個 slice 沒有 native 或 Compose field-coverage runner，所有通過結果都回傳 runtime_status=NOT_EVALUATED；人工或 synthetic artifact 不能把 G0-COVERAGE 標成 PASS。完整 runtime matrix、log artifact 的獨立產生與 activation caller 仍是後續工作。

## Evidence preflight

既有 agentguard.evidence.validate_evidence 保留早期通用 evidence contract；G0-COVERAGE 的新欄位與 route wrapper binding 使用 agentguard.coverage。兩者都只是 preflight primitive，不是 runtime runner、簽章驗證服務或 route activation。

agentguard.coverage.validate_coverage_evidence 接受 raw artifact 及由可信發布目錄提供的 matrix hash、artifact hash、gateway_image/config/compiler/adapter digests、both phase scope、route digest 與期限。

Missing/mismatched/expired/future evidence、任一G0非PASS、unknown/缺fields/context、normalize前未知欄位未拒絕、duplicate keys、不合法~0/~1 pointer都拒絕。Returns EVIDENCE_VALIDATED，不代表路由已啟用。這不是完整compiler或簽章服務；若caller相信攻擊者自填hash就破壞前提。測試人工PASS文件僅驗validator，不可冒充runtime evidence。

## Compose與持久診斷

```bash
docker compose -f deploy/compose/compose.yaml --profile cpu-e2e run --build --rm diagnostic
```

單一diagnostic container含Gateway+fixtures，non-root/read-only/network none/no host ports/socket/no固定container_name。建置時下載checksum-pinned binary。Python base預設tag尚未digest-pin，部署者可用PYTHON_IMAGE指定已核准digest，不宣稱供應鏈完整鎖定。

`diagnostic-evidence:/evidence`為project-scoped named volume，report與process log在--rm後保留；CLI成功/失敗均另印Gateway log至stderr。讀取保存報告：

```bash
docker compose -f deploy/compose/compose.yaml --profile cpu-e2e run --rm \
  --entrypoint cat diagnostic /evidence/gateway-stock.json
```

同project不要並行；CI用run-id/attempt區分project。`down -v`會刪evidence，只在取回後明確執行，不system-wide prune。GitHub Actions同時跑native binary與Compose診斷，結果以實際job為準。第一輪觀察见[p0-ci-observation.md](p0-ci-observation.md)；新runner/hash需重新執行。

## 尚未完成

Gateway parser patch與protected acceptance、G0-CONTEXT ingress/CEL、G0-COVERAGE native／Compose runtime matrix與activation、G0-DEADLINE故障suite；正式PromptGuard/ExtMCP adapters、PII/secret detectors、MCP error sanitizer、Policy Studio、vLLM、observability provisioning均未由此切片完成。Issue #2保持open，不能以診斷PR通過代替。
