# FairyPam Rust Agent public mirror

这个模板只为公开镜像增加 Windows Core 构建流水线。导出结果包含 Rust Cargo
workspace、Agent/Guardian、protobuf、测试 Profile 和构建脚本；不包含 Backend、
Tauri GUI、安装器、候选版本脚本、证书、密钥或运行配置。

`Windows core build` 只能手动触发。它运行 workspace 格式、检查、测试、Clippy
与 release build，并上传短期保留的 `core-build-only` artifact。receipt 中固定
`promotable=false`；该 artifact 不能导入候选版本池，也不能替代后续安装更新
change 的签名、打包和 GUI 人工门禁。
