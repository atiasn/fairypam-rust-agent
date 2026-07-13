# FairyPam Rust Agent build mirror

本仓库是 FairyPam 私有仓库中 Rust Agent 的只读源码快照与候选构建入口，不是源码权威，也不接受直接功能开发。

- `SOURCE_COMMIT`：对应 FairyPam 私有仓库的完整源码 commit。
- `Windows candidate`：只能从 GitHub Actions 手动触发，产出短期保留的 unsigned candidate artifact。
- 当前阶段不创建 GitHub Release、pre-release 或发布 Tag。
- candidate 不是稳定版本；只有导入 Hub 并通过 `RUST-CLI-SAFE` smoke 后，才可成为 Hub 的 `unsigned validated candidate`。
- 构建包不包含 `config.yaml`。真实配置和 API Key 只能由 FairyPam Hub/Web 单独生成。

## 手动构建

在 GitHub Actions 中选择 `Windows candidate`，点击 `Run workflow`。成功后下载名称含 run ID 的 artifact，并在 FairyPam 私有仓库使用 Hub candidate 管理脚本导入和验证。

## License

当前快照未附带开源许可证。公开可见不代表授予复制、修改或再分发许可。
