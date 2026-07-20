# Tauri UI requirement-to-evidence

## 历史 build identity

- `source_commit`: `daf20583f4a2cb89c86e57f110a15b9dccdc1177`
- `public_commit`: `8cbf784dc77507e79693b8e2aa7fe126d52e8f9a`
- `build_id`: `tauri-ui-29718577286-1`
- `run_id`: `29718577286`
- `artifact_class`: `tauri-ui-build-only` (`promotable=false`)
- `owner`: GitHub Actions Windows runner / FairyPam maintainer
- `timestamp`: 2026-07-20

该 build 的 UI ZIP 和 receipt 均由 GitHub Attestation 证明，并由同一 workflow 的独立
consumer job 验证。它仅是旧界面版本的历史证据，不能代替当前“受限注册 + 五页用户界面”
实现的 Windows 构建与人工 smoke。

## Requirement mapping

| Requirement | Status | Gate | Evidence | Remaining condition |
| --- | --- | --- | --- | --- |
| 普通主入口与受限注册辅助窗口 | blocked | `WINDOWS-BUILD`, `TAURI-GUI-HUMAN` | `asInvoker` manifest、实际提升 token + 固定参数检查、受限 handler 测试均通过。 | 在交互桌面确认普通打开无 UAC；点击注册时只出现一个 UAC 辅助窗口。 |
| 最小 Capability 与 CSP | pass | local static gate | `npm run check:security`、`npm run check:command-surface`、Rust `security_contract` 通过。 | Windows Actions 重新构建。 |
| 五页用户流程 | pass | Vitest/RTL | 五项导航、移除页面、环境检查、脱敏日志和游戏发现测试通过。 | Windows 人工检查赛博朋克视觉与文本状态。 |
| 固定登录启动与有界 Hub 观察 | blocked | `WINDOWS-BUILD`, `TAURI-GUI-HUMAN` | 固定任务 XML 的额外 trigger/action/argument 拒绝测试、6 次本地检查和两个 20 秒窗口的静态门禁通过。 | 真实 UAC 注册、登录触发、管道与 Hub 连接 smoke。 |
| GUI 与 Agent 生命周期解耦 | blocked | `TAURI-GUI-HUMAN` | 托盘左键显示、右键菜单和退出 UI 不停止 Agent 的测试通过。 | 从托盘退出后确认 Agent 仍运行。 |
| 可访问和可诊断的失败态 | pass | Vitest/RTL | 加载、失败、键盘导航与 axe gate 通过。 | Windows 人工检查作为 UI smoke 的一部分。 |
| 生产运行包不含开发者 CLI | pass | package contract | `test-agent-package-contract.sh` 与 public-mirror 同步契约通过；runtime 仅组合 Agent、Guardian、UI 和 `profiles/`。 | Windows 打包后检查实际目录。 |

## Windows handoff

当前实现需要新的 Windows Actions 产物；将完整 `runtime/` 部署到固定目录后，用户只需双击
`fairypam-agent-tauri-ui.exe`，不设置管道变量，也不使用 `fairypam-agentctl.exe`。在 **Windows
交互桌面**（不能是 SSH token）记录以下 smoke：普通打开无 UAC、注册时的单次 UAC、登录后的
固定 Agent 任务、20 秒内本地管道/Hub 状态、五项导航与托盘左/右键行为。

## Scope statement

本 change 不实现安装器、Updater 或生产 Dev handler；它们保持 out-of-scope。UI 的 build-only
artifact 不能作为候选版本、签名发布包或安装更新证据。
