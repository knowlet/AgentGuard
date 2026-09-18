# ADR 0001：在 Gateway 內建立嚴格 webhook action 邊界

日期：2026-09-18。狀態：實作；runtime 結果以 PR #7 的實際 CI artifact 為準。

## 決策

不增加一般 reverse proxy，也不把 AgentGuard serializer 當作 Gateway parser 的修補。以 AgentGateway v1.5.0 的 source commit `fe6732474a96a0363dfb9822859af4e9bab360fa` 建立專案內維護的嚴格 build。這不是官方上游已發布的修復版。

`tools/patch_gateway.py` 先驗原始 webhook.rs 的 Git blob identity 及 SHA-256，再替換四個入口的 Deserialize 實作：RequestAction、ResponseAction、GuardrailsPromptResponse、GuardrailsResponseResponse。新增模組位於 `patches/agentgateway/strict_action.rs`，編譯時植入 Gateway 內；兩條 HTTP send path 另要求 webhook 回應 status=200。

這是有意縮小的 **strict wire profile**：reason 對每個 action 都是必要、非空白字串；reject 的 status_code 必須是 400–599 整數；action/envelope 不容許額外欄位；mask 必須使用正確方向、非空 messages/choices，並在 upstream 原生型別 decode/encode 後完整保留該 body。原先省略 reason、使用非 200 webhook transport status 或非 canonical mask 的整合會被拒絕，不能假設無痛升級。

## 為什麼不只使用 deny_unknown_fields

空物件仍可能符合全 optional 的 Pass；型別不對的 reject 不能重新嘗試另一個 action。新的入口先遞迴拒絕重複 JSON keys，再依唯一欄位集合判斷 action。格式錯誤即返回 error，不再按 Mask→Reject→Pass 逐一嘗試。Error 訊息不帶回輸入值或輸入 key。

Masked body 用 upstream 真正的 PromptMessages/ResponseChoices schema，而不是維護另一套猜測 Message。型別轉換若會丟欄位、把 sequence 改成 object，round-trip equality 會拒絕。這不代表已驗證所有原始 LLM 欄位覆蓋，也不替代 adapter 的 mutation 授權與語意 invariants。

## 額外確認的 HTTP status 路徑

固定的 stock v1.5.0 會將 HTTP 500 裡的合法 `action.reason` 當成 Pass。2026-09-18 本地 loopback runtime 已觀察 request 仍到達上游、response canary 仍可見。原因是 send_request/send_response 直接對 response body 解碼，沒有先檢查 HTTP status。嚴格 build 在這兩處都先拒絕非 200 status。CI fault case 故意使用「500 + 合法 Pass」，不是只送無法解析的錯誤文字。

## 驗證與信任

保留 stock 診斷不變；protected runner 對原有 22 fixtures 展開的 42 個 phase cases 全部要求 reject，包括 stock 尚未評分的 4 個觀察。另加 15 fixtures/30 phase cases；6 個合法 controls 保證不是全部拒絕；兩個 phase 各注入 HTTP 500 + Pass、disconnect、超過 Gateway timeout 後的 Pass，再做 allow recovery。

Native/Compose 都使用真實 Gateway executable。Build manifest 同時綁原始/修改後 source、module、patcher、fixture、binary，以及 build profile/toolchain/features。Runner 的 trusted manifest hash 必須由受信 build job/release catalog 提供，不能讓未受信上傳者自填。SHA-256 並非簽章、來源證明或 proof of compilation；受信 build runner 仍是信任根。

每個案例留下 counters、body/header hashes、marker 可見性、結構保留與 timing；追加 JSONL observations 讓中途失敗仍有證據。只檢查這個非串流 fixture 的 client body/headers，不宣稱 trailers、streaming、多模態或任意 provider schema 受保護。

即使 wire acceptance PASS，G0-CONTEXT、G0-COVERAGE、完整 G0-DEADLINE、MCP error path、detectors、Studio、vLLM 均不因此完成。Strict route activation 仍需全部有效 evidence，Issue #2 保持 open。

## 部署界線

CI 採 Rust 1.98.0、dev/no debug symbols、Linux/amd64 GNU、crypto-aws-lc、停用預設 feature 集（Linux 目標仍使用 pprof-alloc 的 jemalloc）；這是功能驗收 build，不拿它與官方 release binary 做效能比較。該 dev build 缺少 feature-gated malloc_conf 匯出，runner 固定設定 `_RJEM_MALLOC_CONF=prof:true`，並將這個環境值寫入 report；未設定時已實際觀察到 startup error，而非 parser 測試結果。Compose 是 CPU 驗收容器，不是 production Guard stack。它 non-root/read-only/network-none/drop-ALL/no-new-privileges，report/log 存 named volume。exec tmpfs 僅為執行已驗 hash 的私有 executable copy；不提供一般 agent shell sandbox。

參考：上游 `webhook.rs`、`json.rs`、Serde untagged/Visitor 文件；固定 source 與 patch hashes 在每次 CI 的 build manifest 內。未修改上游 repository、未發布 production release。
