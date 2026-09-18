# ADR-001：在 Gateway 內實作 strict webhook decoder

2026-09-18。範圍：P0 G0-WIRE 的 normalized-text-v1，不是整個 P0 完成證明。

## 決策

選擇對固定 AgentGateway v1.5.0 source commit `fe6732474a96a0363dfb9822859af4e9bab360fa` 套用局部 patch，沒有以 Python reverse proxy 取代 Gateway，也不在 webhook 網路路徑加另一個可被繞過的 validator。原版 diagnostic 不變，與 patched acceptance 分開執行。

`tools/apply_gateway_patch.py` 同時核對 upstream HEAD 與 webhook.rs Git blob，拒絕 fuzzy patch、重複套用及不同來源。patch 加入兩個 action 的自訂 Deserialize 和封閉 response envelope。讀取所有 action keys 後選定唯一合法分支；有 body/status_code 的錯誤輸入不能退回 Pass。

## 契約

Pass 必須只有非空 reason。Reject 必須有 reason、string body、整數 400–599 status_code。Mask 必須有 reason 及與 phase 相符的 messages/choices，拒絕未知與重複欄位、空 list、超過 1,024 entries。normalized Message 僅 role/content 字串，ResponseChoice 僅 message。這是固定版本的 normalized webhook shape，不是所有原始 OpenAI/provider 欄位。

相容性變更是刻意的：省略/null/空白 reason、200 reject、額外 keys、空 mask 均不接受。既有寬鬆的第三方 webhook 必須先更新 serializer；不能用 failOpen 恢復相容性。受保護配置必須使用 failureMode=failClosed、enforce 而非 shadow/audit。沒有宣稱任意使用此 binary 的 route 都被保護。

## 驗收

原版 suite 保持漏洞診斷。patched suite 使用原來 42 個 phase cases（不再跟隨 stock_source_expectation 的 unscored），另加 32 個 phase cases，包括 null body/status、duplicate Unicode key、混合分支、未知巢狀欄位、trailing JSON、超長 reason。另有 6 個合法 controls 與 8 個 HTTP/非 JSON/斷線/截斷故障案例。Request 拒絕要求 upstream=0；response 拒絕要求 upstream=1 且沒有 body marker；mask controls 檢查目標改寫與非目標結構保留。

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
