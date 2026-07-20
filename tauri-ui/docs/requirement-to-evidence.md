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
consumer job 验证。它仅是旧的计划任务启动模型的历史证据，不能代替当前“普通 GUI +
高权限后台 Agent + 五页用户界面”实现的 Windows 构建与人工 smoke。

## Requirement mapping

| Requirement | Status | Gate | Evidence | Remaining condition |
| --- | --- | --- | --- | --- |
| 普通 GUI 与高权限后台 Agent | blocked | `WINDOWS-BUILD`, `TAURI-GUI-HUMAN` | 本机 Rust/静态契约已限制为 `Program Files` 固定同目录 Agent、空参数、无 reparse、整链当前用户不可写且访问异常即拒绝；旧 `asInvoker` 与辅助窗口证据不能替代新模型实测。 | 验证 Agent 已运行时无 UAC；缺失时只提升固定 Agent；拒绝 UAC 后安全离线。 |
| 最小 Capability 与 CSP | pass | local static gate | `npm run check:security` 与 `npm run check:command-surface` 通过。 | Windows Actions 运行 Tauri Rust `safety_invariants`。 |
| 五页用户流程 | pass | Vitest/RTL | 五项导航、移除页面、环境检查、脱敏日志和游戏发现测试通过。 | Windows 人工检查赛博朋克视觉与文本状态。 |
| 无控制台后台启动、Hub 注册与有界观察 | blocked | `WINDOWS-BUILD`, `TAURI-GUI-HUMAN` | 本机定向测试已覆盖 GUI subsystem、WinHTTP/Pipe deadline、重新注册确认与先验证后原子发布；旧固定任务 XML 与 `agentctl` 测试只服务开发者链路。 | UAC 后 Agent 无控制台窗口；确认拒绝不消费注册码；超时后下一条 Status/重试可完成；本地 Pipe/Hub 20 秒观察。 |
| Pipe 双向身份 | blocked | `WINDOWS-BUILD`, `WINDOWS-LIVE-SMOKE` | 静态实现要求 GUI 先验证高权限固定 Agent，Agent 对 `RegisterHub` 再验证固定 GUI caller。 | 用 fake server、非 GUI 同会话 client、错 session/image 做 Windows 负向测试。 |
| 注册状态可恢复与持久化脱敏审计 | blocked | `WINDOWS-BUILD`, `WINDOWS-LIVE-SMOKE` | 静态契约覆盖无效候选不发布 pointer、旧状态保留和生产审计不含秘密。 | 在 Windows 验证无效 URI/key/cert 与半开 claim 后仍可 Status/重试；检查真实 JSONL newline 与 ACL。 |
| GUI 与 Agent 生命周期解耦 | blocked | `TAURI-GUI-HUMAN` | 托盘左键显示、右键菜单和退出 UI 不停止 Agent 的测试通过。 | 从托盘退出后确认 Agent 仍运行。 |
| 可访问和可诊断的失败态 | pass | Vitest/RTL | 加载、失败、键盘导航与 axe gate 通过。 | Windows 人工检查作为 UI smoke 的一部分。 |
| 生产运行包不含开发者 CLI | pass | package contract | `test-agent-package-contract.sh` 与 public-mirror 同步契约通过；runtime 仅组合 Agent、Guardian、UI 和 `profiles/`。 | Windows 打包后检查实际目录。 |
| AuthentiCode/publisher | blocked | signed-release gate | 当前 GitHub Actions 工件未签名，只能用于 build/smoke。 | 正式发布前验证 Agent/GUI 签名链和允许的 publisher。 |

## Windows handoff

当前实现需要新的 Windows Actions 产物；将完整 `runtime/` 通过管理员安装流程部署到当前用户不可写、无 reparse 的固定 `Program Files` 目录后，用户只需双击
`fairypam-agent-tauri-ui.exe`，不设置管道变量，也不使用 `fairypam-agentctl.exe`。在 **Windows
交互桌面**（不能是 SSH token）记录以下 smoke：已运行 Agent 时普通打开无 UAC；Agent 缺失时
自动请求一次 UAC；只出现 UAC 而没有命令行窗口；拒绝 UAC 后安全离线；Hub 注册值不出现在命令行
、响应、日志或审计；fake Pipe server 与非 GUI caller 被拒绝；Hub/Pipe 超时后下一条 Status 和重试
仍可完成；无效候选不改变 `current` pointer；20 秒内本地管道/Hub 状态、五项导航与托盘左/右键行为。

## Scope statement

本 change 不实现安装器、Updater 或真正标准 Windows 账户的管理员部署；开发者 CLI/计划任务
保持开发用途，不是生产启动入口。UI 的 build-only artifact 不能作为候选版本、签名发布包或安装
更新证据；`%LOCALAPPDATA%\FairyPam\dev` 不能作为产品 UAC 来源。
