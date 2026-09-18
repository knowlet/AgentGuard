# P0 strict Gateway parser 與 protected wire acceptance

這個切片接續 #1/#5；完整邊界與相容性變更見 [ADR 0001](adr/0001-strict-gateway-parser.md)。

## 實作

- `patches/agentgateway/strict_action.rs`：Gateway 原生 Rust 嚴格反序列化，含 upstream-native schema 回歸測試。
- `tools/patch_gateway.py`：只接受已審核 source，固定輸出 hash；非 200 webhook HTTP 回應先拒絕。
- `tools/protected_gateway_probe.py`：可信 build identity 檢查、72 個 negative phase cases、6 個合法 controls、6 個 fault cases 及各自 recovery；unknown/漏跑/全拒絕不可 PASS。
- `deploy/compose/compose.protected.yaml`：隔離 CPU 驗收，named volume 保存 JSON/JSONL/config/process log。
- `.github/workflows/p0-protected.yml`：固定 upstream source/Rust、編譯及原生 Rust tests、native acceptance、Compose acceptance、持久化驗證與 artifacts。

原本的 `tools/gateway_probe.py` 和 stock fixture 預期保留不變，仍應重現 stock 漏洞，不會為了測試變綠而修改原版預期。

## 重跑

Python helpers 不需要 Rust/Docker：

```bash
python3 -m unittest discover -s tests -v
```

完整 build 及 protected suite 使用 PR 的 `p0-protected` workflow；產出 `p0-gateway-build` artifact，包含 build/manifest.json、binary 與 reports。

從可信 CI artifact 解壓至 repository root 後，先從該 CI job 的 manifest SHA-256 確認來源與完整性；**不要自動採信第三方隨 binary 附上的 hash**。然後執行：

```bash
export TRUSTED_BUILD_MANIFEST_SHA256='<digest from authenticated build job or approved catalog>'
python3 -m tools.protected_gateway_probe \
  --gateway-bin build/agentgateway \
  --build-manifest build/manifest.json \
  --trusted-manifest-sha256 "$TRUSTED_BUILD_MANIFEST_SHA256" \
  --report reports/gateway-protected.json

docker compose -f deploy/compose/compose.protected.yaml run --build --rm protected
```

應使用與 artifact 相同的 parser/patcher/fixture revision；輸入變更必須重新 build/acceptance。每次 functional report 記錄實際 runner、shared helpers、config 與 extra-fixture hashes。產生報告 exit 0 只對該 wire suite 的 PASS；exit 1 表示斷言失敗；exit 2 表示 build binding、啟動或執行錯誤。錯誤不得轉成成功防禦。

## 結果不能越界解讀

Wire suite 只針對 webhook action enforcement 邊界；沒有 detector API 或實際工作模型，因此 ASR/FPR 為 NOT_EVALUATED。Availability faults 是獨立欄位。超時 fault 測 Gateway 的 failClosed/recovery，不代表 Guard 本身的 queue/inference/audit 全 deadline 預算已驗收。

GuardContext、封閉原始 ingress schema、external per-field coverage、完整 deadline、ExtMCP/error sanitizer、detectors 與 GUI 仍是後續工作。`agentguard/evidence.py` 不會接受這份 wire-only report 當完整可部署能力證據。
