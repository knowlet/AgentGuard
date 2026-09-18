# ADR-002：Guard deadline 預算與 Gateway timeout 的邊界

2026-09-18。範圍：P0 G0-DEADLINE 的第一個可執行切片；不是 latency SLO，也不是完整 G0-DEADLINE。

## 決策

v1.5.0 對 webhook backend 插入 10 秒 `BackendRequestTimeout` [S25]。那是**有效 Gateway timeout**，不是整段 LLM 的 latency SLO。本切片把兩件事分開：

1. **宣告閘門**（`agentguard/deadline.py`）：guard budget 只能由固定的 stage 名稱組成，且 `guard_budget + transport_reserve + safety_margin < effective_gateway_timeout`。名稱漂移、bool／負數、過小的 margin、不足的 reserve 或超額預算一律拒絕。目前宣告為 queue／parse／detector／adjudication／serialization／audit 共 1,500 ms、reserve 500 ms、margin 1,000 ms，合計 3,000 ms < 10,000 ms。
2. **執行期分類**（`tools/deadline_probe.py`）：guard 自己超過預算是 `GUARD_DEADLINE_EXCEEDED`（fail-closed，回 HTTP 503）；Gateway 端的 timeout 或 hang 是 **availability fault**，不是 policy 防禦，也不算 guard 決策。兩者不可互換。

## 為什麼用 fixture-modeled adapter

真實 detector 的延遲需要模型與負載，不屬於本階段。fixture 因此消耗**宣告的** stage latency，並用同一個宣告值做預算比較，讓邊界可決定性重現；同時仍記錄 wall-clock elapsed、upstream 次數、client body，以及每個 hook 的決策是否**送達** Gateway。送達與否是區分「guard 超時」與「Gateway 超時」的關鍵觀察：Gateway 先放棄時，hook 的決策存在但 `delivered=false`。

## 驗收

8 組註冊案例（frozen registry，含 phase、宣告 stage 與預期類別；與邊界矛盾的註冊項會在跑之前就被拒絕）：

| 類別 | 案例 | 必要條件 |
|---|---|---|
| 預算內 | inside_budget request／response（1,200 ms） | HTTP 200、兩個 hook 都送達 allow、上游 1 次、結構與 marker 符合 |
| 邊界內 | at_budget_boundary_request（= 1,500 ms） | 花完預算仍算在預算內（比較為嚴格大於） |
| 超預算 | just_over_budget request／response（1,501 ms）、over_budget_request（4,000 ms） | HTTP 503 加固定 body、`delivered=true`、`GUARD_DEADLINE_EXCEEDED`、elapsed < 9,000 ms（由 guard 而非 Gateway 決定）、無 marker 洩漏 |
| 未設預算 | unbounded_stage request／response（11,000 ms） | Gateway 逾時、elapsed 9–16 秒、**沒有**送達的決策、分類為 availability fault；此列不得被當成防禦 |

`deadline_status()` 綁定 frozen registry，重新由 observations 計算分類，不讀 `assertion_passed`；缺列、重複、替換、把 guard deny 記成 200、把 Gateway timeout 記成 9 秒內、或替 availability fault 補一個送達決策，全部 FAIL。route 使用與 context 切片相同的 preflighted shape，`validate_route()` 失敗就不可能產生 deadline PASS。

## 未涵蓋

queue depth／backpressure、cancel、writer 阻塞、durable audit 的實際 I/O、detector 推論延遲、長文 chunking 成本、LLM 整體 latency SLO、跨版本 timeout 變更。超預算時的 policy 行為（shadow／drop）未定義。`full_P0_release`、`ASR/FPR` 仍 NOT_EVALUATED，`deployment_approved=false`。

## CI 邊界

`p0-patched` 不再限制 base branch：stacked P0 分支必須跑同一組真實驗收，不能沿用較早 head 的綠燈。Compose 仍需要 build job 產生的 binary／manifest，屬封閉診斷 profile，不是 production stack。
