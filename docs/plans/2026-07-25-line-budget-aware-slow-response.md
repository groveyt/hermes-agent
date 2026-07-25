# LINE Budget-Aware Slow Response Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** LINE 快任務維持免費 Reply；慢任務在額度安全時只自動 Push 最終答案一次，接近月額度上限或額度狀態未知時退回免費的 Get answer postback 流程。

**Architecture:** 保留現有 `postback` 行為作為向後相容預設，新增 opt-in `auto_push` 慢回覆模式。Adapter 在 slow threshold 到達、reply token 仍有效時先查 LINE quota／consumption；只有 1:1 DM 且預估 Push 使用量未達軟上限才保留自動 Push reservation，不先送卡片。若額度不足、API 失敗、資料異常或群組 recipient 數量未知，立即以原 reply token 發 postback 卡片。最終文字回覆若 reply token 尚有效仍免費 Reply；若已過期且 reservation 存在則只 Push 一次。

**Tech Stack:** Python 3.11、aiohttp、pytest、Hermes platform plugin/config。

**Non-goals:** 不改 cron／主動通知的既有 Push 行為；不把群組／room 自動 Push 納入第一版；不持久化跨 gateway restart 的執行中 LLM run；不修改目前 dirty 的 `gateway/slash_commands.py` 與 `package-lock.json`。

---

## Acceptance criteria

1. `postback` 預設模式行為完全不變。
2. `auto_push` 模式下，threshold 前完成使用 Reply，不計 quota。
3. threshold 後，1:1 DM 且 quota 安全時不送卡片；最終答案過期後只 Push 一次。
4. quota 達軟上限、quota/consumption API timeout、401、429、5xx、未知 quota type、缺欄位或錯誤值時，fail closed 為既有 postback 卡片。
5. group/room 一律 postback，避免一個 Push 依群組收件人數放大額度。
6. 同時多個慢任務透過 lock + in-process reservation estimate，不可一起穿透同一剩餘額度。
7. 最終在 45–50 秒間完成、reply token 仍有效時，釋放 reservation 並免費 Reply。
8. Push 失敗或 run interrupted 時釋放 reservation；Push 成功則保留本月估計用量，避免 consumption API 延遲造成超賣。
9. 不記錄 access token、reply token、chat ID、訊息內容；log 只含 mode、quota decision、usage/limit/soft-limit、HTTP status/request ID。
10. LINE profile 的 tool progress、interim messages、streaming、long-running notifications 均維持關閉；一般慢任務最多一個可計費的 Push request。

---

### Task 1: Quota API client and pure budget decision

**Objective:** 建立可測試、fail-closed 的 quota 查詢與 soft-limit 判斷。

**Files:**
- Modify: `plugins/platforms/line/adapter.py`
- Test: `tests/gateway/test_line_plugin.py`

**TDD tracer bullets:**
1. RED：quota client 正確解析 limited quota + consumption。
2. GREEN：新增 `_LineClient.get_quota()`／`get_quota_consumption()` 或單一 `get_quota_status()`，使用既有安全 HTTP/log 慣例。
3. RED：limited 200、ratio 0.8 時 usage 159 允許一個 reservation，160 拒絕。
4. GREEN：新增小型 budget gate；invalid ratio clamp/預設為 0.8。
5. RED/GREEN：unlimited 允許；unknown/malformed/API exception 全部拒絕並回傳 reason。
6. RED/GREEN：兩個併發 reservation 不可一起越過 soft limit；free Reply／Push failure 可 release，Push success commit estimate。

**Verification:**
```bash
./venv/bin/python -m pytest tests/gateway/test_line_plugin.py -q -o 'addopts='
```

---

### Task 2: Slow-response state routing

**Objective:** 將 quota gate 接到 `_keep_typing()` threshold 與最終 `send()` 路徑。

**Files:**
- Modify: `plugins/platforms/line/adapter.py`
- Test: `tests/gateway/test_line_plugin.py`

**TDD tracer bullets:**
1. RED：`slow_response_mode=auto_push` + safe quota + DM 時 threshold 不送卡片並建立 reservation。
2. GREEN：加入 per-chat reservation state；`postback` 預設維持舊流程。
3. RED/GREEN：quota denied/error、group、room 立即走原 postback。
4. RED/GREEN：final 在 reply token 有效時 Reply 並 release；token 過期時 Push 一次並 commit。
5. RED/GREEN：Push failure、空內容、interrupt 清理 reservation。
6. RED/GREEN：重複 threshold、同 chat pending button、system bypass 不產生重複 final Push。

**Verification:** 同上，並確認現有 78 個 LINE tests 無 regression。

---

### Task 3: Configuration, documentation, and observability

**Objective:** 提供非 secret 的 config.yaml 設定與可營運 log。

**Files:**
- Modify: `website/docs/user-guide/messaging/line.md`
- Modify: `plugins/platforms/line/adapter.py`
- Test: `tests/gateway/test_line_plugin.py`

**Configuration:**
```yaml
gateway:
  platforms:
    line:
      enabled: true
      extra:
        slow_response_mode: auto_push
        push_quota_soft_limit_ratio: 0.8
```

**Rules:**
- `slow_response_mode`: `postback`（default）或 `auto_push`。
- `push_quota_soft_limit_ratio`: default `0.8`，有效範圍 `(0, 1]`；錯誤值 fail closed／回到安全預設。
- 保留既有 `LINE_SLOW_RESPONSE_THRESHOLD` 相容性；部署時保持 `45`。
- 文件明確說明 Reply 不計、Push 計入 recipient count、群組第一版 fallback postback、quota API failure fail closed。
- 新增 decision logs，但不得含 PII/secrets/content。

**Verification:**
```bash
./venv/bin/python -m py_compile plugins/platforms/line/adapter.py
./venv/bin/python -m pytest tests/gateway/test_line_plugin.py -q -o 'addopts='
```

---

### Task 4: Independent review and integration verification

**Objective:** 做 spec review、code quality/security review 與相關 gateway regression。

**Commands:**
```bash
./venv/bin/python -m pytest tests/gateway/test_line_plugin.py tests/gateway/test_display_config.py -q -o 'addopts='
./venv/bin/python -m pytest tests/gateway/ -q -o 'addopts='
git diff --check
git diff -- plugins/platforms/line/adapter.py tests/gateway/test_line_plugin.py website/docs/user-guide/messaging/line.md
```

**Review gates:**
- Spec reviewer：所有 acceptance criteria 通過。
- Quality reviewer：安全、race、錯誤降級、測試隔離、log 隱私通過。
- 不得 stage/commit 他人的 dirty files。

---

### Task 5: Deploy and production verification

**Objective:** 先 default canary，再部署 wife/sister/dolphin；只對 default 做真實 LINE 測試。

**Steps:**
1. 對 default config 寫入 `slow_response_mode: auto_push`、ratio `0.8`，並將 LINE platform 的 tool progress/interim/streaming/long-running notifications 關閉。
2. 重啟 default gateway；驗證 system launchd/service、PID、8646 listener、local/public health。
3. 送一個明確的 default LINE canary，刻意超過 threshold；驗證：沒有 Get answer 卡片、只有一個 final Push、delivery receipt status 200、consumption 增量不超過 1。
4. 驗證快速回覆仍走 Reply，consumption 不增加。
5. 驗證 quota-denied path 使用 mock/integration test，不消耗真實 quota。
6. canary 通過後部署 wife/sister/dolphin config 並分別重啟；只驗證 listener/health/log，不傳測試訊息給家人。
7. 若任何 profile 失敗，回滾該 profile 為 `postback` 並重啟。

**Delivered definition:** default 真實 LINE 可見且 log/API consumption 證明路由正確；其他 profiles 僅標為 production-configured + adapter-health-verified，除非各自有真實 inbound 測試。
