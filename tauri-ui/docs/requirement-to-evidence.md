# Tauri UI requirement-to-evidence

## 当前产品安装器候选

本 change 新增 `perMachine` Tauri NSIS setup 候选：安装器将 GUI、Agent、Guardian、安装辅助
程序和 `profiles/` 部署到固定的受保护 `Program Files` 目录，并将 Agent 状态根设为
`C:\ProgramData\FairyPam.Agent\Agent`。它先在固定 `Program Files` staging 目录完成校验，再 activate
为正式安装目录；失败时保留或恢复前一 slot。

GitHub Actions 产物为 `fairypam-agent-setup-windows.exe`，其 setup 与同源 receipt 均有 provenance
attestation；但该候选明确为 `promotable=false`，且未签名。Attestation 只证明产物来源，**不关闭
`WINDOWS-BUILD`、真实 Windows UAC/无控制台/DACL/reparse/rollback smoke 或签名发布门禁**；它们仍为
pending，不能把该候选作为发布包或安装验收证据。

## Requirement mapping

| Requirement | Status | Gate | Evidence | Remaining condition |
| --- | --- | --- | --- | --- |
| 普通 GUI 与高权限后台 Agent | pending | `WINDOWS-BUILD`, `TAURI-GUI-HUMAN` | attested 候选实现配置固定 `Program Files` 同目录 Agent、空参数、无 reparse、整链当前用户不可写且访问异常即拒绝；Windows CI 门禁尚未验收。 | 关闭 `WINDOWS-BUILD` 后，在交互桌面验证 Agent 已运行时无 UAC、缺失时只提升固定 Agent、拒绝 UAC 后安全离线。 |
| 最小 Capability 与 CSP | pass | local static gate | 已有本地 `npm run check:security`、`npm run check:command-surface` 与 Rust `safety_invariants` 静态证据。 | 这不证明安装器；候选仍须单独通过 `WINDOWS-BUILD`。 |
| 五页用户流程 | pass | Vitest/RTL | 五项导航、移除页面、环境检查、脱敏日志和游戏发现测试通过。 | Windows 人工检查赛博朋克视觉与文本状态。 |
| 无控制台后台启动、Hub 注册与有界观察 | pending | `WINDOWS-BUILD`, `TAURI-GUI-HUMAN` | attested 候选继续要求 GUI subsystem、WinHTTP/Pipe deadline、重新注册确认与先验证后原子发布；旧固定任务 XML 与 `agentctl` 测试只服务开发者链路。 | 关闭 `WINDOWS-BUILD` 后，确认 UAC 后 Agent 无控制台窗口、拒绝不消费注册码、超时后下一条 Status/重试可完成，并观察本地 Pipe/Hub 20 秒。 |
| Pipe 双向身份 | pending | `WINDOWS-LIVE-SMOKE` | 候选继续要求 GUI 写帧前验证高权限固定 Agent，Agent 对 `RegisterHub` 再验证固定 GUI caller；attestation 不代替 Windows 负向 smoke。 | 关闭 `WINDOWS-BUILD` 后，用 fake server、非 GUI 同会话 client、错 session/image 做 Windows 负向测试。 |
| 注册状态可恢复与持久化脱敏审计 | pending | `WINDOWS-LIVE-SMOKE` | 候选继续要求无效候选不发布 pointer、旧状态保留和生产审计不含秘密；attestation 不代替 Windows 状态恢复 smoke。 | 关闭 `WINDOWS-BUILD` 后，验证无效 URI/key/cert 与半开 claim 后仍可 Status/重试，并检查真实 JSONL newline 与 ACL。 |
| GUI 与 Agent 生命周期解耦 | pending | `TAURI-GUI-HUMAN` | 现有托盘行为测试是 UI 层证据，未覆盖已安装候选。 | 从已安装候选的托盘退出后确认 Agent 仍运行。 |
| 可访问和可诊断的失败态 | pass | Vitest/RTL | 加载、失败、键盘导航与 axe gate 通过。 | Windows 人工检查作为 UI smoke 的一部分。 |
| 受管产品安装器与状态根 | pending | static security review (`allow-ci`, P0/P1=0), `WINDOWS-BUILD`, `WINDOWS-LIVE-SMOKE` | 候选 NSIS setup 为 `perMachine`；attested receipt 声明受管布局与 `C:\ProgramData\FairyPam.Agent\Agent` 状态根。安装器静态安全复审已 `allow-ci`（P0/P1=0）；真实 Windows 验证仍未完成。 | 验证标准 Windows 账户中的受保护部署、状态根 ACL、DACL/reparse 防护和卸载/重装/rollback。 |
| 生产安装布局不含开发者 CLI | pending | `WINDOWS-BUILD`, `WINDOWS-LIVE-SMOKE` | attested receipt 声明 GUI、Agent、Guardian、安装辅助程序和 `profiles/`；开发者 CLI/Dev 脚本不是产品安装布局。 | 在真实安装后验证实际布局不含 `fairypam-agentctl.exe` 或 Dev 入口。 |
| AuthentiCode/publisher | pending | `SIGNED-RELEASE` | GitHub Actions setup 已 attested，但明确为 non-promotable、未签名。 | 正式发布前验证 Agent/GUI/安装器的 AuthentiCode 链和允许的 publisher。 |

## Windows handoff

产品用户入口是受管 NSIS setup；不要手工解包或部署 runtime，也不要使用 `fairypam-agentctl.exe`。
在上述 pending 门禁关闭前，不向用户交付该候选。届时须在 **Windows 交互桌面**（不能是 SSH token）
记录以下 smoke：已运行 Agent 时普通打开无 UAC；Agent 缺失时自动请求一次 UAC；只出现 UAC 而没有
命令行窗口；拒绝 UAC 后安全离线；Hub 注册值不出现在命令行、响应、日志或审计；fake Pipe server
与非 GUI caller 被拒绝；Hub/Pipe 超时后下一条 Status 和重试仍可完成；无效候选不改变 `current`
pointer；20 秒内本地管道/Hub 状态、五项导航与托盘左/右键行为。

## Scope statement

本 change 实现的是非 promotable、未签名的 Windows 产品安装器**候选链路**，不实现 Updater，
也不构成真正标准 Windows 账户的安装、实机 smoke、签名或发布验收。开发者 CLI/计划任务保持
开发用途，不是生产启动入口；`%LOCALAPPDATA%\FairyPam\dev` 不能作为产品 UAC 来源。`WINDOWS-BUILD`、
`WINDOWS-LIVE-SMOKE`、`TAURI-GUI-HUMAN` 和 `SIGNED-RELEASE` 仍是彼此独立且全部 pending 的门禁。
