# ADR-002：Guard deadline 預算與 Gateway timeout 的邊界

2026-09-18。範圍：P0 G0-DEADLINE 的第一個可執行切片；不是 latency SLO，也不是完整 G0-DEADLINE。

## 決策

v1.5.0 對 webhook backend 插入 10 秒 `BackendRequestTimeout` [S25]。那是**有效 Gateway timeout**，不是整段 LLM 的 latency SLO。本切片把三件事分開：

1. **宣告閘門**（`agentguard/deadline.py`）：guard budget 只能由固定 stage 名稱組成、值必須是非負整數、margin 至少 1,000 ms，且 `guard_budget + transport_reserve + safety_margin < effective_gateway_timeout`。目前宣告 queue／parse／detector／adjudication／serialization／audit 共 1,500 ms、reserve 500 ms、margin 1,000 ms，合計 3,000 ms < 10,000 ms。
2. **guard 結果**：adapter 自己超過預算時，決策仍**送達** Gateway 並回 HTTP 503；Gateway 自己的 access log 會記錄 `"action": "reject"`。這是 guard decision，不是 policy deny，也不是攻防成功。
3. **Gateway 結果**：hook 沒有回答時，原因是 Gateway 產生的，只能用 Gateway 自己的 log 判定為 `upstream call timeout`（真正的 10 秒逾時）或 `connection closed before message completed`（hook 提前死亡）。**兩者都以 availability fault 記帳，都不得算成防禦，但只有前者可以拿來支持 timeout 邊界。**

## 為什麼用 fixture-modeled adapter

真實 detector 的延遲需要模型與負載，不屬於本階段。fixture 因此消耗**宣告的** stage latency，並用同一個宣告值做預算比較，讓邊界可決定性重現；同時記錄 wall-clock elapsed、upstream 次數、client body，以及每個 hook 的決策是否送達。

`delivered` 只表示 `wfile.write()` 是否成功，**不等於 Gateway 已消費該決策**；因此每個決策另外記錄 `decision_write`（`ok`／`failed`／`not_attempted`），Gateway 端結果則一律由 log marker 決定。單靠「未送達＋時間窗」不足以區分這兩種失敗，這是前一版被指出的漏洞。

## 驗收

9 組註冊案例（frozen contract，含 phase、宣告 stage 與預期類別；與邊界矛盾的註冊項會在跑之前就被拒絕）：

| 類別 | 案例 | 必要條件 |
|---|---|---|
| 預算內 | inside_budget request／response（1,200 ms） | HTTP 200；兩筆決策依序為已送達的 request allow 與 response allow；上游 1 次；結構與 marker 符合；Gateway log 沒有 timeout／transport／reject marker |
| 邊界內 | at_budget_boundary_request（= 1,500 ms） | 花完預算仍算在預算內（比較為嚴格大於） |
| 超預算 | just_over_budget request／response（1,501 ms）、over_budget_request（4,000 ms） | HTTP 503 加固定 body；slow decision 已送達且為 `GUARD_DEADLINE_EXCEEDED`；elapsed < 9,000 ms；Gateway log 必須是該 phase 的 `"action": "reject"`，且不得出現 timeout／transport marker |
| Gateway 逾時 | unbounded_stage request／response（11,000 ms） | HTTP 4xx／5xx（閘門接受 400–599，本 head 實測 503）；slow decision **未送達**（`decision_write=failed`）；Gateway log 必須是該 phase 的 `upstream call timeout`，且不得出現 transport marker |
| 提前斷線（負向 control） | early_disconnect_request（9,000 ms 後關閉連線） | HTTP 4xx／5xx（本 head 實測 503）；slow decision 未送達且 `decision_write=not_attempted`；Gateway log 必須是該 phase 的 `connection closed before message completed`，且**不得**出現 timeout marker |

超預算列的 HTTP 503 是閘門硬性要求（guard 自己回的 status code），Gateway 故障列的 status 只要求 4xx／5xx，因為那是 Gateway 決定的。

每個 case 的**決策契約**逐筆比對：phase 身分與順序、是否為 slow phase、`allowed`／`reason`／`delivered`／`decision_write` 的型別與值。凡是已走到 response 的 case，前置 request 必須是明確且**已送達的 allow**；只有註冊的 slow phase 可以是 deadline deny 或未送達。決策筆數等於 request／response 的預期呼叫數。

Gateway 端的證據綁定在**單次呼叫的 log slice**（offset、長度、SHA-256 都寫進報告），因此分類是「Gateway 說發生什麼」，不是「花了多久」。client 可見的狀態也必須等於 Gateway access log 內同一次請求的 `http.status`。

`deadline_status()` 綁定**閘門自己**的 frozen contract（`EXPECTED_CONTRACT`，另由 `EXPECTED_CONTRACT_SHA256` 釘住），不讀 runner 的 `REGISTERED_CASES`；`cases()` 必須先確認兩份註冊一致才肯跑。缺列、重複、替換、把 guard deny 記成 200、把 Gateway timeout 記成 9 秒內、少一筆決策、phase 順序錯、slow phase 標錯、write outcome 不符、marker 指向另一種失敗、或替 availability fault 補送達決策，全部 FAIL。route 使用與 context 切片相同的 preflighted shape，`validate_route()` 失敗就不可能產生 deadline PASS。

## 未涵蓋

queue depth／backpressure、cancel、writer 阻塞、durable audit 的實際 I/O、detector 推論延遲、長文 chunking 成本、LLM 整體 latency SLO、跨版本 timeout 訊息變更。超預算時的 policy 行為（shadow／drop）未定義。`full_P0_release`、`ASR/FPR` 仍 NOT_EVALUATED，`deployment_approved=false`。

## CI 邊界

`p0-patched` 不再限制 base branch：stacked P0 分支必須跑同一組真實驗收，不能沿用較早 head 的綠燈。Compose 仍需要 build job 產生的 binary／manifest，屬封閉診斷 profile，不是 production stack。
