# FairyPam MAA Windows Runtime

FairyPam 只安装 `maa-runtime.lock.json` 固定并由 FairyPam 发布流程签名的官方
MaaFramework Windows SDK 子集。设备不解析 `latest`，也不直接采用上游 Release。

安装布局：

```text
runtime/maa/
├── versions/<sdk-version>/
├── staging/
├── active.json
└── licenses/
```

`versions/<sdk-version>/LICENSE.md` 来自锁定的官方 SDK。安装器同时将它复制到
`licenses/MAA-LICENSE.md`，并保留 Release URL、asset 与 SHA-256。
MaaFramework 和 `maa-framework-rs` 均采用 LGPL-3.0；FairyPam 动态加载未修改的官方 DLL，
不静态复制或链接 MaaFramework 源码。生产安装包同时附带
`THIRD-PARTY-NOTICES.md`，记录版权、版本和上游源码/Release 来源。
