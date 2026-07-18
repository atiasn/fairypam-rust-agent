# FairyPam Rust Agent public mirror

公开镜像仅消费私有仓库显式导出的 source snapshot，并构建完整 Windows Agent
suite：Setup、Agent、Guardian、Updater、GUI、CLI、协议、Profile 与两份固定事务脚本。

`Windows Agent suite candidate` 只能手动触发。它执行 workspace 检查、测试、Clippy、
release/Tauri build 与精确成员打包，随后上传 `signed=false`、`promotable=false` 的短期
candidate。GitHub Actions 成功不会导入或提升 current；TUF metadata、Authenticode、
`cleiagent` CLI-safe、GUI-human 和设备人工门禁均必须在后续受控流程中绑定同一 build
identity 后单独完成。

导出脚本拒绝私钥、长期凭据、设备配置、用户数据和已构建 EXE/ZIP；公开仓库只负责
获准源码的 build/test/package，不成为源码权威或发布提升入口。
