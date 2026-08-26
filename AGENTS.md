# Rust Agent 局部规则

本文件只适用于 `agent/**`。全局 Git、安全、Agent 协作和 Gate 规则继承根
`AGENTS.md`，不在此重复。

- Rust workspace、依赖和 edition 以 `Cargo.toml`、`Cargo.lock` 为准。
- 协议源、Windows 生命周期、权限和 Shell 证据分别以 `agent/proto/`、`docs/specs/`、
  `docs/agents/tauri-gui-gate-matrix.md` 与源码测试为权威。
- 开发时本地 Cargo 检查只作快速反馈。除严格签名 profile-only 例外外，Rust
  `WINDOWS-BUILD` 只能由根规则规定的 Windows public candidate、artifact receipt 和 Wait Audit 关闭。
- `profiles/*/profile.json` 变更必须满足 profile catalog 的 schema、签名、精确 commit、Hub
  发布和设备 applied 回读；不得夹带 Rust 源码或构建配置变化。
