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

Row pointer 是非空的 field-level JSON Pointer；document root `""` 不屬於這個 contract，`/` 代表空名稱 member。`lossiness=none` 的 inspected rows 在同一 phase 不得共用 normalized pointer。

validate_coverage_route 只做 route/context/coverage preflight，不啟用 route；它以 deployed config resolve 出的 actual route 作為唯一驗證與 digest authority，caller route 必須與其 canonical bytes 完全一致。這個 preflight API 不執行 native 或 Compose field-coverage runner，所有通過結果都回傳 runtime_status=NOT_EVALUATED；人工或 synthetic artifact 不能把 G0-COVERAGE 標成 PASS。完整 runtime matrix、每個 row 對應的 Gateway event／log slice、log artifact 的獨立產生與 activation caller 仍是後續工作。

## Evidence preflight

既有 agentguard.evidence.validate_evidence 保留早期通用 evidence contract；G0-COVERAGE 的新欄位與 route wrapper binding 使用 agentguard.coverage。兩者都只是 preflight primitive，不是 runtime runner、簽章驗證服務或 route activation。

agentguard.coverage.validate_coverage_evidence 接受 raw artifact 及由可信發布目錄提供的 matrix hash、artifact hash、gateway_image/config/compiler/adapter digests、both phase scope、route digest 與期限；成功回傳 `COVERAGE_PREFLIGHT_VALIDATED` 並固定 `runtime_status=NOT_EVALUATED`。既有 `agentguard.evidence.validate_evidence` 的成功回傳 `EVIDENCE_VALIDATED` 屬於另一個通用 envelope contract，不能用來宣稱 G0-COVERAGE runtime PASS。

Missing/mismatched/expired/future coverage evidence、任一 coverage contract 不符合、unknown/缺fields/context、normalize前未知欄位未拒絕、duplicate keys、非法 JSON Pointer escape 或 field-level root pointer 都拒絕。這只是 preflight，不代表路由已啟用；也不會把同一份 global Gateway artifact 自動視為每個 row 的獨立 event evidence。這不是完整 compiler、簽章服務或 runtime runner；若 caller 相信攻擊者自填 hash 就破壞前提。測試人工 PASS 文件僅驗 validator，不可冒充 runtime evidence。

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


## Field coverage probe 與 PromptGuard 測量鉤子

`agentguard/field_profile.py` 凍結 `text-nonstream-v1` 的封閉欄位集合：非串流文字 `/v1/chat/completions` 的 request／response 欄位（不同 message index 與 choice 以可區分合成資料覆蓋），以及 profile 外的 tool calls、圖片 content part、provider extension 與未知欄位。後者必須在 normalize 前拒絕，不能靜默轉送。

`agentguard/promptguard.py` 是測量用的最小確定性鉤子。它拒絕 malformed JSON、duplicate keys、非 JSON 常數與缺少 body 的 envelope；符合此最小 envelope 契約的輸入一律 allow，以便觀察 backend 與 client 傳播。text scanner 只遍歷 request messages／response choices 的文字 content，按 normalized pointer 與完整預期文字產生 spy 結果，不掃描 metadata 或把文件任何位置的 marker 當成文字檢查。它不產生 PII、secret 或 injection verdict；`detector_observed` 只證明本次事件的測量 spy 掃描到目標文字。

```bash
python3 -m tools.fetch_gateway --output /tmp/agentgateway-v1.5.0
python3 -m tools.field_coverage_probe --gateway-bin /tmp/agentgateway-v1.5.0 --report reports/field-coverage.json
```

runner 使用 checksum-pinned stock Gateway 與 loopback hook／backend fixture。文字欄位使用新隨機 marker 及 prefix／suffix；metadata 使用合法型別和值（temperature=0.75、choice index=0、system／user／assistant role、finish_reason=length）。`stream=true` 是 profile 外的拒絕案例，`stream=false` 由正向 control 使用。圖片案例的實際 pointer 為 `/messages/1/content/1`。

request 比對實際 ingress、hook 與 backend 收到的欄位，不要求 client 回音；response 比對 backend 實際送出的欄位、hook 與 client。來源存在性從實際紀錄解析，不由 fixture 宣告或呼叫計數推定。判定以 `pointer`／`normalized_pointer` 解析目標，精確比對完整 JSON 值、型別、陣列順序與祖先容器型別／長度，保留 object key 順序無關性。`structure` row 比對整個目標陣列；`type_value` row 不要求 NLP detector；`detector_text` row 另要求同一個 hook 事件的 spy 成功。缺少或多筆事件不拼湊為成功。`payload_preserved` 限定於該 row 的目標值與上述結構約束，不代表其他 sibling 欄位或整份 payload 已獲證明。

量測結果保留 `observed_inspected`、`forwarded_uninspected` 與 `unknown`。缺少 native Gateway 拒絕碼時，即使 HTTP 拒絕也不能宣稱 `ingress_rejected`；來源只有 backend response、但 hook/client 沒收到的未知欄位亦不能誤報 forwarded。Stock hook 省略的 metadata 與 normalization loss 必須保留為 findings。`coverage_gate`、`p0_release_gate` 與 `asr_fpr` 恆為 `NOT_EVALUATED`。Exit 0 與 `measurement_status=COMPLETED` 只表示量測完成且正向 control 成功；control 失敗回 1，binary／config／啟動錯誤回 2。

報告同時保存 binary/config/profile/runner/hook digests、逐 row 結果、Gateway log 與 `.observations.json` 原始合成資料。後者保留 ingress、hook body、spy 結果、backend request/response、HTTP 狀態與 client 原始 bytes（hex），並以 SHA-256 綁定報告。`p0-stock-diagnostic` CI 在 x86 runner 實際執行本工具，要求 control 成功、21 rows、22 筆 observations（含 control）、artifact digest 相符及各 gate 仍為 NOT_EVALUATED；報告、log 與 observations 會一併上傳。

Compose field-coverage 路徑、每 row 獨立 Gateway event／log-slice 綁定、normalize 前拒絕的原生執行，以及 activation 整合仍是後續工作。

## 尚未完成

Gateway parser patch與protected acceptance、G0-CONTEXT ingress/CEL、G0-COVERAGE 每 row 事件綁定、原生拒絕執行、Compose runtime matrix與activation、G0-DEADLINE故障suite；正式PromptGuard/ExtMCP adapters、PII/secret detectors、MCP error sanitizer、Policy Studio、vLLM、observability provisioning均未由此切片完成。Issue #2保持open，不能以診斷PR通過代替。
