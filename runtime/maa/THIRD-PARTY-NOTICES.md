# Third-party notices for the FairyPam MAA Windows Runtime

FairyPam distributes the following unmodified upstream components:

- MaaFramework Windows SDK 5.12.3, including `MaaFramework.dll`,
  `MaaWin32ControlUnit.dll` and their locked runtime dependencies. Copyright
  MaaFramework contributors. License: GNU LGPL-3.0. Source:
  <https://github.com/MaaXYZ/MaaFramework/tree/v5.12.3>. Release asset:
  <https://github.com/MaaXYZ/MaaFramework/releases/download/v5.12.3/MAA-win-x86_64-v5.12.3.zip>.
- maa-framework-rs 1.20.0 and maa-framework-sys 5.12.1, compiled into
  `fairypam-win32-worker.exe`. Copyright MaaFramework contributors. License:
  GNU LGPL-3.0. Source:
  <https://github.com/MaaXYZ/maa-framework-rs/tree/v1.20.0>.

The complete LGPL-3.0 text is installed as `licenses/MAA-LICENSE.md`. Exact
asset and file SHA-256 values are recorded in `maa-runtime.lock.json`.
FairyPam loads the official SDK DLLs dynamically from the active verified
runtime directory; it does not copy MaaFramework source code into FairyPam.
