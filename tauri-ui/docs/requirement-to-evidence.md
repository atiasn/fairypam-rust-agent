# Tauri UI requirement-to-evidence

## 当前产品安装器候选

本 change 新增 `perMachine` Tauri NSIS setup 候选：安装器将 GUI、Agent、Guardian、安装辅助
程序和 `profiles/` 部署到由 `windows/installer-hooks.nsh` 统一定义的受保护
`C:\Program Files\FairyPam` 目录，并将 Agent 状态根设为
`C:\ProgramData\FairyPam.Agent\Agent`。安装布局只有一个固定产品根：首次安装以最终 DACL 创建
该根，后续安装只覆盖声明的产品文件；若产品根、Agent 根或日志目录仍是当前安装用户对应的精确旧
ACL，提升后的安装辅助程序会先以不跟随 reparse point 的目录句柄固定并验证该入口，再将
owner/DACL 收敛为最终私有值，不删除或改写既有注册、审计与日志内容。其它 owner、额外 ACE、
`Everyone`/`Users` 写权限以及注册或审计目录 ACL 异常仍失败关闭；后续目录失败时恢复本次已修改
ACL，恢复失败以独立 validation detail `10` 失败关闭。安装器会固定并验证产品根不是 reparse point，并从该根内
受保护 bootstrap 子树启动同包验证程序；它会在任何既有产品载荷被写入或执行前验证完整树的
owner/DACL/MIC/reparse，再验证新的运行时载荷与状态根。安装器不再创建、激活、恢复或递归删除
`.installing`、`.previous` 或旧产品目录；因此残留的历史目录不会阻塞新安装，也不会被提升权限的
安装器跟随或删除。

精确 source `8f0fe571aaad68cb3a1645ed1da0502018955b0b` 已由 public commit
`27ca14d78f31a40d651431cb7d435a8bfa9c3175` 的 Actions run `30112108295` 完整构建并通过
consumer attestation。下载的 `fairypam-agent-setup-windows.exe` SHA256 为
`9aa172ceb00b49c20f57ef6c8cdddc3fdb33a005003962296412718d0dead81c`，与
`sync-receipt.json` 一致，`WINDOWS-BUILD` 已通过。该候选仍是 `promotable=false`、未签名；
构建来源不关闭完整 Windows DACL/reparse/rollback smoke 或签名发布门禁。

Installed lifecycle smoke 记录当前安装文件 hash 和运行行为，但把 `sync-receipt.json` 的
source/public/run 写入 smoke receipt 不会自动证明设备当前安装来源；本页的 exact candidate
结论同时依赖此前同一 setup 的安装取证。缺少该安装取证时，smoke 只能作为生命周期行为证据。

## Requirement mapping

| Requirement | Status | Gate | Evidence | Remaining condition |
| --- | --- | --- | --- | --- |
| 普通 GUI 与高权限 Agent Core | pending | `WINDOWS-BUILD`, `TAURI-GUI-HUMAN` | 静态与非正式 Windows 测试证明 GUI 直接 `runas` 启动固定同目录 Agent；Agent 在 Pipe/Hub 前验证 GUI PID、同用户/Session 并绑定，生命周期事务互斥且 Core 唯一。 | 安装精确新 candidate，确认 UAC、Pipe ready、唯一 Agent 与可见连接状态。 |
| 最小 Capability 与 CSP | pass | local static gate | 已有本地 `npm run check:security`、`npm run check:command-surface` 与 Rust `safety_invariants` 静态证据。 | 这不证明安装器；候选仍须单独通过 `WINDOWS-BUILD`。 |
| 五页用户流程 | pass | Vitest/RTL | 五项导航、移除页面、环境检查、脱敏日志和游戏发现测试通过。 | Windows 人工检查赛博朋克视觉与文本状态。 |
| 无控制台交互式启动、Hub 注册与有界观察 | pending | `WINDOWS-BUILD`, `TAURI-GUI-HUMAN`, `WINDOWS-LIVE-SMOKE` | 同一 Dev Core 由已验证前台进程直接启动后，Hub 已取得非黑原神加载帧；当前 Tauri direct-launch 实现的非正式 Windows tests 通过。 | 用精确产品 candidate 重跑 GUI direct launch、注册拒绝、超时后 Status/重试和脱敏审计负例。 |
| Pipe 双向身份 | pending | `WINDOWS-LIVE-SMOKE` | 候选继续要求 GUI 写帧前验证高权限固定 Agent，Agent 对 `RegisterHub` 再验证固定 GUI caller；CI 成功后的 attestation 也不代替 Windows 负向 smoke。 | 关闭 `WINDOWS-BUILD` 后，用 fake server、非 GUI 同会话 client、错 session/image 做 Windows 负向测试。 |
| 注册状态可恢复与持久化脱敏审计 | pending | `WINDOWS-LIVE-SMOKE` | 候选继续要求无效候选不发布 pointer、旧状态保留和生产审计不含秘密；CI 成功后的 attestation 也不代替 Windows 状态恢复 smoke。 | 关闭 `WINDOWS-BUILD` 后，验证无效 URI/key/cert 与半开 claim 后仍可 Status/重试，并检查真实 JSONL newline 与 ACL。 |
| GUI 拥有 Agent 日常生命周期 | pending | `TAURI-GUI-HUMAN`, `WINDOWS-LIVE-SMOKE` | 新实现会安全替换残留 Agent、只读打开全局实例 mutex、以同一个已验证 process handle 绑定 GUI；GUI/Agent 还必须属于 protected current active suite，更新 activation 会令 stale GUI 安全退出后由 installer 重启 target GUI。退出界面先完成 Agent 清理，窗口关闭仍进托盘。维护 owner 验证固定 High helper 父进程、拒绝设备/Hub 操作且不启动 gRPC supervisor。 | 用精确 candidate 验证正常/异常退出后 Agent/Guardian/输入/采集清零、A→B 后 GUI/Agent image/build_id/suite_version 全为 B、旧目录直接启动被拒、手工 `--maintenance` 与维护 Pipe 设备命令被拒、并发生命周期请求不重复弹 UAC。 |
| 可访问和可诊断的失败态 | pass | Vitest/RTL | 加载、失败、键盘导航与 axe gate 通过。 | Windows 人工检查作为 UI smoke 的一部分。 |
| 受管产品安装器与状态根 | partial | static security re-review, `WINDOWS-BUILD`, `WINDOWS-LIVE-SMOKE` | 精确 candidate 已完成 fresh install、trusted reinstall、固定任务 SID/ACL/action 验证和当前用户不可写的固定产品根验证。 | 恶意 ACL、完整 SDDL 回滚、Repair/卸载及 rollback 故障注入仍待验证。 |
| 生产安装布局只有单进程 Agent | pending | `WINDOWS-BUILD`, `WINDOWS-LIVE-SMOKE` | CI receipt 只声明 GUI 内嵌 Core、Guardian、安装辅助程序和 `profiles/`；独立 Core、CLI 与 Dev 脚本已从源码和 workflow 删除。 | 在真实安装后核对精确 executable allowlist。 |
| AuthentiCode/publisher | pending | `SIGNED-RELEASE` | 尚无本变更的 GitHub Actions setup；候选将为 non-promotable、未签名。 | 正式发布前验证 Agent/GUI/安装器的 AuthentiCode 链和允许的 publisher。 |

## Windows handoff

产品用户入口是受管 NSIS setup；不要手工解包或部署 runtime，也不存在本地 CLI 入口。
剩余门禁须在 **Windows 交互桌面**（不能只靠 SSH token）验证：安装根或成员为 reparse point
时失败且不改变既有安装；安装和卸载只请求必要的 UAC 且不显示命令行窗口；GUI 是唯一日常产品
进程并直接承载 Core；Hub 注册值不出现在命令行、响应、日志或审计；Hub 超时后同进程 runtime
仍可重试；五项导航与托盘左/右键行为符合产品设计。

## Scope statement

本 change 的 Phase A 实现 non-promotable、未签名的 Windows 产品安装器候选链路，不实现自动更新、
standalone Core、CLI、计划任务或独立 Updater，也不构成正式签名发布。此前 candidate receipt 只覆盖其对应旧 source，
不能关闭本次 owner/handoff source 的门禁；最新 source 仍需重新通过 `WINDOWS-BUILD`、
`TAURI-GUI-HUMAN` 和 `WINDOWS-LIVE-SMOKE`，`SIGNED-RELEASE` 仍独立 pending。
