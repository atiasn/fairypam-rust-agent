# FairyPam Rust Agent public build mirror

该目录只定义固定公共镜像 `atiasn/fairypam-rust-agent` 的 Windows 产品 candidate。

`windows-candidate.yml` 仅构建、安装验证并 attest GUI 内嵌 Core 的 NSIS 产品安装器。
公共镜像不发布独立 Core、Dev CLI、Dev automation 或可直接部署的 runtime artifact。

正式入口：

```bash
bash scripts/sync-rust-agent-public.sh --profile all --timeout-minutes 25
```

同步脚本只接受同时匹配私有 source commit、公共 mirror commit、Actions run 和
GitHub provenance 的 `product-installer` receipt。
