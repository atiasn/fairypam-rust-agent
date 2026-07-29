# C# Windows Agent 开发入口

本目录承载 C# Windows Agent 的 WPF GUI/Core、Guardian、严格本机状态与 Windows preliminary build。
Slice 2A 已加入生成的 `fairypam.agent.v2` client contract、session/command identity、共享 canonical
payload digest/重放校验和 CSR-only enrollment response/certificate 校验；尚未创建 CNG key、安装证书
或连接 Hub、游戏、截图和输入。
preliminary 生成物的 `promotable` 固定为 `false`。

## 工程

| 路径 | 职责 |
| --- | --- |
| `src/FairyPam.Agent.Core` | 严格签名文档、Profile、JSONL ledger、v2 client/session contract、enrollment response 校验与 Guardian framing |
| `src/FairyPam.Agent` | 全程提权的单实例 WPF/托盘生命周期与受保护路径检查 |
| `src/FairyPam.Guardian` | 无输入能力的 Guardian 生命周期骨架；输入消息一律拒绝 |
| `tests/FairyPam.Agent.Tests` | 签名、schema、ledger recovery、v2 session/enrollment contract 与 framing 负例 |
| `tests/FairyPam.Agent.Windows.Tests` | Windows ACL、reparse 与机器级单实例负例 |

## 本地快速反馈

需要 .NET 10 SDK。macOS 没有本机 SDK 时，可用官方 SDK 容器验证跨平台 Core/tests：

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -w /workspace/agent/dotnet \
  mcr.microsoft.com/dotnet/sdk:10.0 \
  dotnet test tests/FairyPam.Agent.Tests/FairyPam.Agent.Tests.csproj
```

WPF/Guardian 的正式验证必须使用 private `CSHARP-WINDOWS-BUILD`。Windows 快速反馈：

```powershell
$env:FAIRYPAM_BOOTSTRAP_PUBLIC_KEY_HEX = '<64 lowercase hex public key>'
dotnet restore src/FairyPam.Agent/FairyPam.Agent.csproj --locked-mode -r win-x64
dotnet restore src/FairyPam.Guardian/FairyPam.Guardian.csproj --locked-mode -r win-x64
dotnet restore tests/FairyPam.Agent.Tests/FairyPam.Agent.Tests.csproj --locked-mode
dotnet restore tests/FairyPam.Agent.Windows.Tests/FairyPam.Agent.Windows.Tests.csproj --locked-mode -r win-x64
dotnet test tests/FairyPam.Agent.Tests/FairyPam.Agent.Tests.csproj -c Release --no-restore
dotnet test tests/FairyPam.Agent.Windows.Tests/FairyPam.Agent.Windows.Tests.csproj -c Release --no-restore
dotnet publish src/FairyPam.Agent/FairyPam.Agent.csproj -c Release -r win-x64 --no-restore `
  /p:FairyPamBootstrapPublicKeyHex=$env:FAIRYPAM_BOOTSTRAP_PUBLIC_KEY_HEX
dotnet publish src/FairyPam.Guardian/FairyPam.Guardian.csproj -c Release -r win-x64 --no-restore
```

Release build 不接受默认或环境运行时覆盖；public key 必须作为 MSBuild 输入嵌入 binary。
`agent-bootstrap.json`、detached signature 与签名 Profile 缺失或非法时，GUI 只显示安全失败状态。

## 正式证据与失败恢复

`.github/workflows/csharp-windows-candidate.yml` 当前只产出 Slice 2 preliminary compile evidence：两个
self-contained ZIP、逐文件 manifest 与绑定 source commit/run/build ID 的 receipt。receipt 固定
`evidence_kind=csharp-windows-slice2-preliminary`、`formal_gate_status=blocked` 和
`promotable=false`，不能关闭 `CSHARP-WINDOWS-BUILD`。正式 Gate 仍须等 Slice 5 的 NSIS
candidate/receipt；不得用 preliminary、Docker、本地或 Rust receipt 替代。

启动发现 ledger 截断、非法或未安全终结 attempt 时进入恢复阻断；不得删除 ledger、重写最后
一行或清空目录来恢复。Slice 4 提供真实 cleanup 前，只能保留证据并停止输入能力。
