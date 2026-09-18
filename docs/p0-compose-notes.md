# P0 diagnostic Compose 的執行權限與證據

2026-09-17。這是封閉的測試 profile，不是 production guard/harness sandbox。

在 run 35242732535 的真實 CI 中，native Gateway 診斷及 Docker build 成功，但容器內複製到 /tmp 的 verified binary 因 executable mount 權限不足而無法執行。Compose 現在明確設定 /tmp:rw,exec,nosuid,nodev。exec 僅供執行已驗 SHA-256 的固定 Gateway bytes；不把 webhook payload、模型输出或 client 指令當可執行內容。仍維持 network=none、non-root、read-only root、cap_drop=ALL、no-new-privileges，沒有 host port 或 Docker socket。

此選擇只適用此受控診斷拓撲；不可拿它當任意不可信 agent code 的 production sandbox。Docker 的 exec/noexec tmpfs 選項見 https://docs.docker.com/engine/storage/tmpfs/ 。

Report 與 Gateway process log 存在 project-scoped named volume /evidence，不寫到一次性 /tmp。CI 另外啟動第二個 container 讀取相同 volume，驗證第一個 --rm container 被移除後 JSON/log 仍存在、六個 controls 成功、42個phase案例已記錄、4個尚無來源預期者仍為unscored，以及protected gate保持FAIL。

這裡說明設定與驗收邏輯；是否通過以對應 revision 的實際 CI run 為準，不將先前失敗紀錄改寫成成功。
