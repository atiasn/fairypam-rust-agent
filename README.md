# FairyPam Rust Agent public mirror

这个模板为公开镜像增加 Windows Core、Dev 自动化和普通权限 Tauri 控制 UI 的构建流水线。
导出结果包含 Rust Cargo workspace、Agent/Guardian、protobuf、测试 Profile、构建脚本和
Tauri UI 源码；不包含 Backend、安装器、候选版本脚本、证书、密钥或运行配置。

`Windows core build` 只能手动触发。它分别上传短期保留的 `core-build-only`、
`dev-automation` 与 `tauri-ui-build-only` artifact；每个 ZIP 与 receipt 都有 GitHub
Attestation，并由独立 consumer job 验证。所有 receipt 固定 `promotable=false`；这些
artifact 不能导入候选版本池，也不能替代后续安装更新 change 的签名、打包和 GUI 人工门禁。
