# P0 第一輪真實 Gateway CI 觀察

2026-09-17。這是從已完成 GitHub Actions job log 擷取的摘要，不是原始全量 report，也不是 P0 protected acceptance。

[Run 35241125364](https://github.com/knowlet/AgentGuard/actions/runs/35241125364)／[job 105269530431](https://github.com/knowlet/AgentGuard/actions/runs/35241125364/job/105269530431) 已完成 success。測試 head 為 `48966f9c7d141286e880877844a6078690bb0ef2`，GitHub event merge 為 `f724cfe8734a0b701147c66e782afc525891af51`（不是合併進 develop）。環境為 Ubuntu 24.04 hosted runner；48 項 Python tests 通過。

實際啟動官方 checksum-pinned AgentGateway v1.5.0 binary，並對 loopback HTTP fixtures 發送請求。六個合法 request/response × allow/reject/mask controls 全通過；22 個負向 fixtures 展開 42 個 phase 案例完成觀察。

四項 `empty_action`、`typo_status`、`string_status`、`invalid_mask_body` 都實際觀察到：request phase HTTP 200 且 upstream_calls=1；response phase HTTP 200 且 client_marker_visible=true。已由來源級推論前進到真正 Gateway runtime 重現。

報告為 `diagnostic_status=VULNERABILITY_REPRODUCED`、`diagnostic_violations=[]`、`protected_wire_gate=FAIL`、`p0_release_gate=NOT_EVALUATED`、`asr_fpr=NOT_EVALUATED`。42 個案例被執行不等於42個保護驗收通過；原始 runner 對部分 stock expectation 僅保存觀察，後續 revision 增加完整 dispatcher 及 mask 結構不變量驗收，必須另跑 CI。

Binary/config/fixtures/runner digests 與摘要位於 [observations JSON](../reports/observations/p0-stock-first-run.json)。此摘要不是完整 coverage matrix、可信簽章 artifact、Gateway parser 修補或獨立 detector benchmark。第一輪沒有跑 Compose；後續 workflow 加入 Compose 驗證，以其實際新 run 結果為準。
