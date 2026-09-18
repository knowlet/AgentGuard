# Review 核驗與可執行樣本規劃

日期：2026-09-17。核驗基線：PR #1 的 `6c0352a24b726bd926d7d30375ba0a35cd5d3855`。

這個 revision 已有四份主文件、[硬 gate registry](review-gates.md)、policy 草案、22 個 wire 負向 fixtures 與 10 個 helper tests。本次保留既有修改，新增 `tools/plan_statistics.py`、10 個 planner tests 與本紀錄；**沒有修補上游 Gateway parser，也沒有執行真實 Gateway E2E**。

## 1. 合併、測試與部署不能混用

| 項目 | 本次觀察／狀態 |
|---|---|
| 已讀取上游 v1.5.0 與 Serde 語意 | untagged 成功落入 Pass 不進 failure-mode error branch；source-confirmed，不冒充 Rust/runtime 重現 |
| 非 masking canonical helper／負向集 | 本地 Python 自測通過；不是完整 production serializer、不是 parser 修補 |
| 事前統計規劃 | 現在可執行：列舉註冊的 n grid、CI 接受錯誤數、假定真實率下的 binomial passing probability |
| Gate registry G0/G2/G3/G5 | 驗收規格已列；對應的完整 runtime／dataset release evidence 未產生，不能標 PASS |
| Gateway／Rust／Compose／GPU | NOT_RUN；當前環境無 Docker、nerdctl、Rust、GPU runtime，且容器無法解析 GitHub DNS |

G0-WIRE 必須分開跑 stock diagnostic 與 protected acceptance；診斷重現成功不等於防護通過。只加 `deny_unknown_fields` 仍不足以拒絕 optional reason 的空 Pass；typed serializer 亦不能代替解析邊界修補。request-phase 要檢查未授權上游執行為零；response-phase 上游已執行，應檢查外部可見 bytes 不洩漏。詳見 [G0-WIRE 驗收契約](review-gates.md)。

G0-CONTEXT/G0-COVERAGE 要求外部 oracle 和 normalize 前的 ingress enforcement；marker 到達 hook 不等於 detector 掃描。G2-ERROR 的 backend_attested 仍為 attested_unprotected。這些都不能由本地 Python unit test 綠燈抵銷。

## 2. CI 邊界與事前 power

方法固定為 **雙側 95% Wilson interval、單一 rate gate、獨立且預註冊的 binary origin-group outcome**。NIST 的 Wilson 公式是計算依據；不宣稱 Wilson 是有限樣本 exact coverage。[NIST](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm)

| 觀察 | Wilson 95% CI | 單項結論 |
|---|---|---|
| FPR 10/500 = 2% | 1.090%–3.642% | upper > 2%，FAIL |
| FPR 9/500 = 1.8% | 0.950%–3.385% | upper > 2%，FAIL |
| FPR 5/500 = 1% | 0.428%–2.319% | upper > 2%，FAIL |
| FPR 8/800 = 1% | 0.508%–1.961% | 此單項 PASS，不是完整 release PASS |
| recall 485/500 = 97% | 95.110%–98.174% | 此單項 PASS，不是完整 release PASS |

`8/800` 的觀察能通過，不表示事前選 n=800 有足夠 power。若真實 FPR 假設為 1%，n=800 最多接受 8 個誤判，通過機率只有 **59.255%**。planner 使用 `P(E <= e_max(n))`，其中 E 是固定 n 下的 binomial 錯誤數；recall 使用 miss count，不把 recall 當 FPR。

以下是在 **事前註冊 n=100,200,...,5000** grid 的第一個可行值。它們是計算示例，不是已測到的 detector 品質或普遍最低樣本量。

| Gate | 假設真實率 | 目標 power | grid 首個 n | 可接受 errors/misses | 實際計算 power |
|---|---|---|---|---|---|
| FPR upper <= 2% | FPR 1% | 80% | 1,300 | 16 | 83.658% |
| FPR upper <= 2% | FPR 1% | 90% | 1,600 | 21 | 91.184% |
| recall lower >= 95% | recall 97% | 80% | 900 | 32 | 85.809% |
| recall lower >= 95% | recall 97% | 90% | 1,100 | 40 | 90.454% |

由於接受錯誤數是整數，power 不一定隨 n 單調增加，不能對 n 隨便二分搜尋；程式列舉預註冊 grid。計畫要在 holdout 收集前凍結，不能測到 CI 過關才停，或看到結果才改 expected_rate、CI 方法、alpha、grid。

上述均為單項：沒有自動處理多語／風險 family 的 multiplicity 或 joint power。整組宣稱、availability、utility、coverage 與 runtime gates 仍需另行驗收；更嚴格的 family 設計要重新規劃 n，不能直接採此表。沒有預註冊 binary group outcome 的相關變形數，也不能送進 binomial helper 當獨立樣本。

## 3. 執行與測試

從 repository root：

```bash
python -m unittest discover -s tests -v
python tools/assurance_contract.py --stats
python -m tools.plan_statistics --metric fpr --threshold 0.02 --expected-rate 0.01 --power 0.80
python -m tools.plan_statistics --metric recall --threshold 0.95 --expected-rate 0.97 --power 0.90
```

planner 只依賴 Python 標準庫。找不到可行 n 時輸出 `NOT_FOUND` 並 exit 1；輸入不合法 exit 2；找到計畫 exit 0，但輸出標記 `FIXED_N_PLANNING_NOT_BENCHMARK` 與 `single_rate_only`，不是 release PASS。

本地執行 **20 tests 全數通過**：原有 10 項與新增 10 項；原有負向集包含 22 raw cases。新增測試包含接受錯誤數邊界、小樣本 binomial 枚舉、CI 可接受不等於 power 達標、recall miss count、n 非單調性、缺樣本預算、錯誤參數與 CLI 非零失敗碼。沒有把 unit tests 命名為 Gateway integration tests。

既有 helper、既有 test module 與完整 fixture bytes 的 Git blob identity 已核對為：

```text
tools/assurance_contract.py                f981d3c8f02b36c488bfc9a9010169337d474475
tests/test_assurance_contract.py           e21aa4c1668effa2d8eaa2c4065dd6f9553e44c1
tests/fixtures/webhook-negative.json       62d83f1360d48dabf5225e3da8626e91768aff49
```

額外交叉計算：以 SciPy 1.17.0 的 `scipy.stats.binom.cdf` 比較 245 組 `(n,k,p)`，最大 absolute error 約 `8.40e-13`。SciPy 只用於本次獨立數值核對，不是 planner runtime dependency。這不是外部效度或正式驗證證明，也不保證所有浮點輸入的精確度。

**未完成的實作仍須保持阻擋狀態：Gateway parser boundary、可信 CEL bindings、原始 envelope coverage、MCP error sanitizer、deadline enforcement、真實資料集與 adaptive-oracle 驗收。**
