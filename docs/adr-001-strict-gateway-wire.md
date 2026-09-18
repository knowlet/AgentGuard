# ADR-001：在 Gateway 內實作 strict webhook decoder

2026-09-18。範圍：P0 G0-WIRE 的 normalized-text-v1，不是整個 P0 完成證明。

## 決策

選擇對固定 AgentGateway v1.5.0 source commit `fe6732474a96a0363dfb9822859af4e9bab360fa` 套用局部 patch，沒有以 Python reverse proxy 取代 Gateway，也不在 webhook 網路路徑加另一個可被繞過的 validator。原版 diagnostic 不變，與 patched acceptance 分開執行。

`tools/apply_gateway_patch.py` 同時核對 upstream HEAD 與 webhook.rs Git blob，拒絕 fuzzy patch、重複套用及不同來源。patch 加入兩個 action 的自訂 Deserialize 和封閉 response envelope。讀取所有 action keys 後選定唯一合法分支；有 body/status_code 的錯誤輸入不能退回 Pass。

## 契約

Pass 必須只有非空 reason。Reject 必須有 reason、string body、整數 400–599 status_code。Mask 必須有 reason 及與 phase 相符的 messages/choices，拒絕未知與重複欄位、空 list、超過 1,024 entries。normalized Message 僅 role/content 字串，ResponseChoice 僅 message。這是固定版本的 normalized webhook shape，不是所有原始 OpenAI/provider 欄位。

相容性變更是刻意的：省略/null/空白 reason、200 reject、額外 keys、空 mask 均不接受。既有寬鬆的第三方 webhook 必須先更新 serializer；不能用 failOpen 恢復相容性。受保護配置必須使用 failureMode=failClosed、enforce 而非 shadow/audit。沒有宣稱任意使用此 binary 的 route 都被保護。

HTTP webhook 外層必須回 200；非 200 即使 body 是合法 Pass 仍拒絕。這與 action.status_code（對 client 的拒絕狀態）是不同層級。

## 驗收

原版 suite 保持漏洞診斷。patched suite 使用原來 42 個 phase cases（不再跟隨 stock_source_expectation 的 unscored），另加 42 個 phase cases，包括 null body/status、duplicate Unicode key、混合分支、未知巢狀欄位、trailing JSON、超長 reason。另有 6 個合法 controls、10 個 HTTP/非 JSON/斷線/截斷/timeout 故障案例，以及每次故障後的 allow recovery。Request 拒絕要求 upstream=0；response 拒絕要求 upstream=1 且沒有 body marker；mask controls 檢查目標改寫與非目標結構保留。

Serde harness 使用實際 patched action/envelope 程式碼，但 Message/ResponseChoice 是形狀相同的 stand-ins，因此只算 Serde contract。完整 cargo build 加真實 Gateway HTTP E2E 才是產品 wire evidence。CI 附 source/config/decoder/installer/binary/lock digests，並上傳 raw artifacts。build manifest 是可信 CI 輸入，不是簽章或防偽機制，不能讓任意呼叫端自填 hash 當部署授權。

## 未涵蓋

本 patch 不證明原始 field coverage、可信 client identity/CEL context、deadline/load/所有故障、MCP error sanitation、PII/injection detector 效果。Body 解析沿用上游的 HTTP緩衝路徑，list 限制並不是配置前的整體記憶體/byte budget。只在測試內確認的正常 mask 不等於任意 mutation 已重授權。G0-WIRE 可以單獨取得 scoped PASS，P0 release 與 ASR/FPR 仍 NOT_EVALUATED。

Compose 是封閉診斷 profile，network none/non-root/read-only/drop ALL/no-new-privileges；exec tmpfs 僅用來執行 checksum 驗證後的 Gateway，不能當執行不可信程式碼的 production sandbox。

## 重跑

在乾淨的固定 upstream checkout 上執行：

```bash
python3 -m tools.apply_gateway_patch --source /path/to/upstream --manifest reports/patch-manifest.json
python3 -m tools.prepare_wire_harness --source /path/to/upstream --output /tmp/wire-harness
```

完整 build、manifest 綁定、原生/Compose E2E 的可重現步驟在 `.github/workflows/p0-patched.yml`。實際 PASS/FAIL 以該 commit 的 CI artifact 為準，不以本 ADR 的文字當測試證據。

## 建置與回歸修正

首次 run 35295990036 的 5 項 Serde tests 與完整 cargo build 成功，但採用 no-default-features 後，Linux app 固定選擇 Jemalloc 的啟動邏輯沒有對應 malloc_conf，啟動報 profiling unavailable。這不是 parser gate 的 PASS。本 PR 改用上游預設 build features，將 features 與 rustc 納入 manifest；沒有修改 allocator 原始碼。

HTTP 500 fixture 以合法 allow JSON 當 body，避免因壞 JSON 才被擋下的假證明。Acceptance evaluator 核對所有預註冊 case ID/phase，重新依 upstream/hook/status/marker/結構觀察計算，不只讀取 assertion_passed flag。CI 明確指定 bash，以 pipefail 避免 tee 隱藏錯誤。Compose JSON、config 和 process log 另複製至 artifact；完整 patch 包含新增 decoder 檔案。

陣列不能代替物件：加入 Object<T> wrapper，以 deserialize_map 與 MapAccessDeserializer 保留 map stream，不先轉 Value；envelope/messages/choices/message 都要求真正 JSON object，避免 serde struct 的 sequence 表示。這 10 個陣列形狀 phase cases 已包含在上述新增的 42 個 strict phase cases 中；總數為既有 42 + strict 42 = 84，不是另加成 94。Malformed JSON 的詳細錯誤在 Gateway hook 邊界轉成固定 AG_WIRE_INVALID_RESPONSE，避免未知欄位名稱或非法值進一般日誌。

## PR #7/#8 整併後的驗收要求

同目標的重複 PR #7 已關閉；#8 是唯一實作分支。G0-WIRE 的 malformed case 現在必須精確 HTTP 503，且逐 request 的 Gateway log slice 包含已遮蔽的 `AG_WIRE_INVALID_RESPONSE`；其他 4xx/5xx 或 generic failure 不可算通過。HTTP status fault 另要求 `AG_WIRE_HTTP_STATUS`。Timeout 與其後 recovery 只證明這個 fault fixture 的可用性行為，不充當 detector 防禦或完整 G0-DEADLINE。

Readiness 與每次測試前後皆以 Linux `/proc/<pid>/exe`、fd socket inode 和 LISTEN table 驗證目標 port 歸屬實際啟動的 child；不能只靠 TCP connect 判斷。沒有讀取權限或歸屬證據就停止測試。仍假設 CI kernel/host 和 runner 帳號可信，不宣稱能抵禦 ptrace/root 級對手。

Patch installer 對 decoder、webhook、manifest 全部先 staging，再依序 replace；捕捉寫入失敗後回復已變更檔案，並有逐輸出失敗注入測試。這不是跨檔案 crash-atomic transaction；SIGKILL、掉電或 rollback I/O 本身失敗時，必須丟棄暫存 upstream checkout 重建，不繼續編譯。

建置統一走 `tools.build_gateway`，實際驗證 upstream default features 與 `rustc 1.98.0`，固定 `RUSTUP_TOOLCHAIN=1.98`，不靠搜尋 workflow 裡的一行文字。上游已有 rust-toolchain.toml，因此先前的「必然用了 runner default」推斷不成立；顯式設定用來排除較高優先序 override，並留下可測試的契約。

Build 與 acceptance 分成不同 GitHub Actions jobs。Consumer 只下載 `needs.build` 回傳的 artifact ID，manifest SHA-256 由 GitHub job output 傳遞，不從待驗證的本機 manifest 自行重算成信任根；manifest 同時綁完整 fixture、runner、base probe、process/context adapter digests 及固定 84-case 集合。此處僅為同一 PR run 的完整性檢查：PR 作者仍可修改 workflow，沒有 release 簽章／獨立 publisher approval，報告固定 `deployment_approved=false`。不能拿這份 manifest 當 production policy activation 授權。
