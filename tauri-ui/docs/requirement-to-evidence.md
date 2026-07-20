# Tauri UI requirement-to-evidence

## Build identity

- `source_commit`: `daf20583f4a2cb89c86e57f110a15b9dccdc1177`
- `public_commit`: `8cbf784dc77507e79693b8e2aa7fe126d52e8f9a`
- `build_id`: `tauri-ui-29718577286-1`
- `run_id`: `29718577286`
- `artifact_class`: `tauri-ui-build-only` (`promotable=false`)
- `owner`: GitHub Actions Windows runner / FairyPam maintainer
- `timestamp`: 2026-07-20

该 build 的 UI ZIP 和 receipt 均由 GitHub Attestation 证明，并由同一 workflow 的独立
consumer job 验证。同步脚本再次校验 ZIP receipt、UI EXE、`Cargo.lock` 的 SHA-256 和大小后，
将解压产物写入 `agent/artifacts/public/<source_commit>/run-29718577286/ui/`。

## Requirement mapping

| Requirement | Status | Gate | Evidence | Remaining condition |
| --- | --- | --- | --- | --- |
| 普通权限唯一入口 | blocked | `WINDOWS-BUILD`, `TAURI-GUI-HUMAN` | `windows-app-manifest.xml`、Rust manifest/security contracts、Actions UI build 均通过；已部署 EXE 的 SHA-256 为 `05e0f3a465ba1c8836642f8439a37eaa5e03cb1003fc9d81a1addd514a5b7422`。 | 在交互桌面以普通用户启动，确认 Medium Integrity 且无 UAC。 |
| 最小 Capability 与 CSP | pass | `WINDOWS-BUILD` | `npm run check:security`、`npm run check:command-surface`、Rust `security_contract` 由 run `29718577286` 的 Tauri UI job 通过。 | 无。 |
| 领域状态与操作 | pass | `WINDOWS-LIVE-SMOKE` | `agentApi`/command allowlist/reducer tests 与 Actions Rust tests 通过；2026-07-20T05:32:32Z 在 `cleiagent` 的 Session 1 以 `Interactive + Limited` token 启动 UI，且同一 token 的 `agentctl status` 返回 `ConnectedIdle`。 | 离线提示由 `TAURI-GUI-HUMAN` 同时目视确认。 |
| 首次向导安全门禁 | blocked | `TAURI-GUI-HUMAN` | Vitest/RTL、safety invariants 和 axe gate 通过。 | 在真实 UI 中完成向导并确认结果不是 `Armed`，且没有真实输入。 |
| GUI 与 Agent 生命周期解耦 | blocked | `TAURI-GUI-HUMAN` | `tray_lifecycle`、command-surface 和静态负向扫描通过。 | 从托盘退出 UI 后，确认 Agent 仍可由 `fairypam-agentctl.exe status` 访问。 |
| 受控预览资源隔离 | blocked | `TAURI-GUI-HUMAN` | preview URL hook tests、Capability/CSP gate 通过。 | 在真实窗口中确认预览失败/刷新可解释且不影响 Agent。 |
| 可访问和可诊断的失败态 | pass | `WINDOWS-BUILD` | Vitest/RTL loading/empty/error/keyboard tests 与 axe gate 通过。 | Windows 人工检查作为 UI smoke 的一部分。 |

## Windows handoff

已部署的普通权限 UI 位于：

```text
C:\Users\clei\AppData\Local\FairyPam\ui-smoke\daf20583f4a2\fairypam-agent-tauri-ui.exe
```

在 **Windows 桌面的普通 PowerShell** 中启动，而不是 SSH 会话：

```powershell
$env:FAIRYPAM_AGENT_PIPE = '\\.\pipe\FairyPam.Agent.Dev.v1'
& 'C:\Users\clei\AppData\Local\FairyPam\ui-smoke\daf20583f4a2\fairypam-agent-tauri-ui.exe'
```

已记录的 `WINDOWS-LIVE-SMOKE`：UI PID `20372` 在 Session 1 运行，任务 Principal 为
`clei` / `Interactive` / `Limited`，同一 token 的 Agent status 为
`{"capture_active":false,"state":"ConnectedIdle"}`。仍需人工记录：无 UAC、首页/向导可见、
托盘关闭后 UI 隐藏、选择“退出界面”后 Agent 的 `fairypam-agentctl.exe status` 仍返回有效状态。
SSH token 与桌面 token 不同，不能替代该 gate。

## Scope statement

本 change 不实现安装器、Updater 或生产 Dev handler；它们保持 out-of-scope。UI 的 build-only
artifact 不能作为候选版本、签名发布包或安装更新证据。
