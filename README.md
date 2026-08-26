# FairyPam Rust Agent public build mirror

该目录只定义固定公共镜像 `atiasn/fairypam-rust-agent` 的 Windows 产品 candidate。

`windows-candidate.yml` 构建并验证独立 Agent、Guardian、Win32 Worker、原生 Shell 与固定
MAA Runtime 的 NSIS 产品安装器。Tauri/WebView2、Dev CLI 和 Dev automation 不进入产品安装包。

正式入口：

```bash
bash ops/ci/rust-agent-public/sync.sh --profile all --timeout-minutes 25 \
  --enrollment-base-url https://hub.example.com
```

同步脚本只接受同时匹配私有 source commit、公共 mirror commit、Actions run 和
GitHub provenance 的 `product-installer` receipt。
