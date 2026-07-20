@echo off
REM ============================================================
REM FairyPam Agent - Windows build and test helper
REM
REM Usage: build-and-test.bat [check|test|build|release|package|verify-package|all]
REM   check   - cargo check --locked
REM   test    - cargo test --locked
REM   build   - cargo build --locked
REM   release - cargo build --locked --release
REM   package - formal release build plus a staged Windows ZIP and metadata
REM   verify-package - recompute and validate staged ZIP metadata
REM   all     - run all steps
REM ============================================================

setlocal enabledelayedexpansion
set MODE=%1
if "%MODE%"=="" set MODE=all
set "EXTRA_CARGO_ARGS=%2 %3 %4 %5 %6 %7 %8 %9"
set "RELEASE_EXE=target\release\fairypam-agent.exe"
set "GUARDIAN_RELEASE_EXE=target\release\fairypam-agent-guardian.exe"
set "DEBUG_EXE=target\debug\fairypam-agent.exe"
set "GUI_RELEASE_EXE=tauri-ui\src-tauri\target\release\fairypam-agent-tauri-ui.exe"
if not "%CARGO_TARGET_DIR%"=="" (
    set "RELEASE_EXE=%CARGO_TARGET_DIR%\release\fairypam-agent.exe"
    set "GUARDIAN_RELEASE_EXE=%CARGO_TARGET_DIR%\release\fairypam-agent-guardian.exe"
    set "DEBUG_EXE=%CARGO_TARGET_DIR%\debug\fairypam-agent.exe"
    set "GUI_RELEASE_EXE=%CARGO_TARGET_DIR%\release\fairypam-agent-tauri-ui.exe"
)

cd /d "%~dp0\.."
echo ============================================================
echo FairyPam Agent Build Script
echo Working dir: %CD%
echo Mode: %MODE%
if not "!EXTRA_CARGO_ARGS!"=="" echo Cargo args:!EXTRA_CARGO_ARGS!
echo ============================================================

if /I "%MODE%"=="release" (
    echo !EXTRA_CARGO_ARGS! | findstr /I /C:"e2e-live-input" >nul
    if !ERRORLEVEL! EQU 0 (
        echo [ERROR] Formal release builds must not enable e2e-live-input.
        exit /b 1
    )
    echo !EXTRA_CARGO_ARGS! | findstr /I /C:"--all-features" >nul
    if !ERRORLEVEL! EQU 0 (
        echo [ERROR] Formal release builds must not enable all features.
        exit /b 1
    )
)
if /I "%MODE%"=="package" (
    echo !EXTRA_CARGO_ARGS! | findstr /I /C:"automation-cli" >nul
    if !ERRORLEVEL! EQU 0 (
        echo [ERROR] Formal release builds must not enable automation-cli.
        exit /b 1
    )
)

where cargo >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] cargo is not installed. Install Rust first: https://rustup.rs
    exit /b 1
)

echo [INFO] rustc:
rustc --version
echo [INFO] cargo:
cargo --version
echo.

if /I "%MODE%"=="verify-package" goto :do_verify_package
if /I "%MODE%"=="check" goto :do_check
if /I "%MODE%"=="all" goto :do_check
if /I "%MODE%"=="package" goto :do_check
goto :skip_check

:do_check
echo ============================================================
echo [1/4] cargo check...
echo ============================================================
cargo check --workspace --all-targets --locked !EXTRA_CARGO_ARGS!
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] cargo check failed
    exit /b 1
)
echo.

:skip_check

if /I "%MODE%"=="test" goto :do_test
if /I "%MODE%"=="all" goto :do_test
if /I "%MODE%"=="package" goto :do_test
goto :skip_test

:do_test
echo ============================================================
echo [2/4] cargo test...
echo ============================================================
cargo test --workspace --locked !EXTRA_CARGO_ARGS!
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] cargo test failed
    exit /b 1
)
echo.

:skip_test

if /I "%MODE%"=="all" goto :do_clippy
if /I "%MODE%"=="release" goto :do_clippy
if /I "%MODE%"=="package" goto :do_clippy
goto :skip_clippy

:do_clippy
echo ============================================================
echo [3/4] cargo clippy...
echo ============================================================
cargo clippy --workspace --all-targets --locked !EXTRA_CARGO_ARGS! -- -D warnings
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] cargo clippy failed
    exit /b 1
)
echo.

:skip_clippy

if /I "%MODE%"=="build" goto :do_build
if /I "%MODE%"=="release" goto :do_release
if /I "%MODE%"=="all" goto :do_build
if /I "%MODE%"=="package" goto :do_release
goto :skip_build

:do_release
echo ============================================================
echo [4/4] cargo build --release...
echo ============================================================
cargo build --workspace --locked --release !EXTRA_CARGO_ARGS!
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] release build failed
    exit /b 1
)
echo [OK] Release build succeeded
dir "!RELEASE_EXE!"
if /I "%MODE%"=="package" goto :do_package
goto :done

:do_build
echo ============================================================
echo [4/4] cargo build...
echo ============================================================
cargo build --workspace --locked !EXTRA_CARGO_ARGS!
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] debug build failed
    exit /b 1
)
echo [OK] Debug build succeeded
dir "!DEBUG_EXE!"
goto :done

:skip_build

:do_package
for /f "tokens=2 delims== " %%V in ('findstr /R /C:"^version = " Cargo.toml') do set "PACKAGE_VERSION=%%~V"
if "!PACKAGE_VERSION!"=="" (
    echo [FAIL] Could not read package version from Cargo.toml
    exit /b 1
)
for /f "tokens=2 delims== " %%V in ('findstr /R /C:"^version = " tauri-ui\src-tauri\Cargo.toml') do set "GUI_PACKAGE_VERSION=%%~V"
if "!GUI_PACKAGE_VERSION!"=="" (
    echo [FAIL] Could not read GUI package version from tauri-ui\src-tauri\Cargo.toml
    exit /b 1
)
if /I not "!PACKAGE_VERSION!"=="!GUI_PACKAGE_VERSION!" (
    echo [FAIL] CLI and GUI versions differ: !PACKAGE_VERSION! vs !GUI_PACKAGE_VERSION!
    exit /b 1
)
if not exist "!RELEASE_EXE!" (
    echo [FAIL] Release executable is missing: !RELEASE_EXE!
    exit /b 1
)
if not exist "!GUARDIAN_RELEASE_EXE!" (
    echo [FAIL] Guardian release executable is missing: !GUARDIAN_RELEASE_EXE!
    exit /b 1
)
echo ============================================================
echo [5/6] npm ci...
echo ============================================================
pushd tauri-ui
call npm ci
set "TAURI_INSTALL_ERROR=!ERRORLEVEL!"
if !TAURI_INSTALL_ERROR! NEQ 0 (
    popd
    echo [FAIL] Tauri UI dependency install failed
    exit /b 1
)
echo ============================================================
echo [5/6] npm run tauri -- build...
echo ============================================================
call npm run tauri -- build
set "TAURI_BUILD_ERROR=!ERRORLEVEL!"
popd
if !TAURI_BUILD_ERROR! NEQ 0 (
    echo [FAIL] Tauri GUI release build failed
    exit /b 1
)
if not exist "!GUI_RELEASE_EXE!" (
    echo [FAIL] GUI release executable is missing: !GUI_RELEASE_EXE!
    exit /b 1
)
set "PACKAGE_DIR=!CD!\dist"
if not "%FAIRYPAM_ARTIFACT_DIR%"=="" set "PACKAGE_DIR=%FAIRYPAM_ARTIFACT_DIR%"
set "PACKAGE_FILE=fairypam-agent-windows-x64-v!PACKAGE_VERSION!.zip"
set "PACKAGE_PATH=!PACKAGE_DIR!\!PACKAGE_FILE!"
set "MANIFEST_PATH=!PACKAGE_PATH!.metadata.json"
set "PACKAGE_BUILD_ID=local-v!PACKAGE_VERSION!"
if not "%FAIRYPAM_BUILD_ID%"=="" set "PACKAGE_BUILD_ID=%FAIRYPAM_BUILD_ID%"
set "PACKAGE_SOURCE_COMMIT=local"
if not "%FAIRYPAM_SOURCE_COMMIT%"=="" set "PACKAGE_SOURCE_COMMIT=%FAIRYPAM_SOURCE_COMMIT%"
set "PACKAGE_ATTESTATION_IDENTITY=local-build"
if not "%FAIRYPAM_ATTESTATION_IDENTITY%"=="" set "PACKAGE_ATTESTATION_IDENTITY=%FAIRYPAM_ATTESTATION_IDENTITY%"
echo ============================================================
echo [6/6] Packaging staged Windows artifact...
echo ============================================================
powershell -NoProfile -NonInteractive -Command "$ErrorActionPreference = 'Stop'; [void](New-Item -ItemType Directory -Force -Path $env:PACKAGE_DIR); $stage = Join-Path $env:PACKAGE_DIR '.agent-package-stage'; Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue; [void](New-Item -ItemType Directory -Path $stage); Copy-Item -LiteralPath $env:RELEASE_EXE -Destination (Join-Path $stage 'fairypam-agent.exe'); Copy-Item -LiteralPath $env:GUARDIAN_RELEASE_EXE -Destination (Join-Path $stage 'fairypam-agent-guardian.exe'); Copy-Item -LiteralPath $env:GUI_RELEASE_EXE -Destination (Join-Path $stage 'fairypam-agent-tauri-ui.exe'); Copy-Item -LiteralPath (Join-Path (Get-Location).Path 'profiles') -Destination (Join-Path $stage 'profiles') -Recurse; [IO.File]::WriteAllText((Join-Path $stage 'README.txt'), 'FairyPam Windows Agent package.', [Text.UTF8Encoding]::new($false)); $payload = [ordered]@{}; Get-ChildItem -LiteralPath $stage -File -Recurse | ForEach-Object { $name = $_.FullName.Substring($stage.Length + 1).Replace('\','/'); $payload[$name] = [ordered]@{ sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); size_bytes = [int64]$_.Length } }; $build = [ordered]@{ build_id = $env:PACKAGE_BUILD_ID; source_commit = $env:PACKAGE_SOURCE_COMMIT; tauri_gui_changed = $false; attestation_identity = $env:PACKAGE_ATTESTATION_IDENTITY; members = $payload }; [IO.File]::WriteAllText((Join-Path $stage 'BUILD-MANIFEST.json'), (ConvertTo-Json -InputObject $build -Depth 5), [Text.UTF8Encoding]::new($false)); Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $env:PACKAGE_PATH -Force; Remove-Item -LiteralPath $stage -Recurse -Force; $asset = Get-Item -LiteralPath $env:PACKAGE_PATH; $metadata = [ordered]@{ platform = 'windows-x64'; version = $env:PACKAGE_VERSION; file_name = $asset.Name; download_url = $null; sha256 = (Get-FileHash -LiteralPath $asset.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); size_bytes = $asset.Length; released_at = $null; status = 'unavailable'; release_status = 'staged'; layout = [ordered]@{ agent = 'fairypam-agent.exe'; guardian = 'fairypam-agent-guardian.exe'; gui = 'fairypam-agent-tauri-ui.exe'; profiles = 'profiles/'; manifest = 'BUILD-MANIFEST.json'; readme = 'README.txt' } }; $temporary = $env:MANIFEST_PATH + '.tmp'; [System.IO.File]::WriteAllText($temporary, (ConvertTo-Json -InputObject $metadata -Depth 3) + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false)); Move-Item -LiteralPath $temporary -Destination $env:MANIFEST_PATH -Force"
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Windows artifact packaging or metadata generation failed
    exit /b 1
)
echo [OK] Staged artifact: !PACKAGE_PATH!
echo [OK] Staged metadata: !MANIFEST_PATH!
echo [INFO] status remains unavailable until a release owner configures a verified download source.
call :do_verify_package
if %ERRORLEVEL% NEQ 0 exit /b 1
goto :done

:do_verify_package
for /f "tokens=2 delims== " %%V in ('findstr /R /C:"^version = " Cargo.toml') do set "PACKAGE_VERSION=%%~V"
if "!PACKAGE_VERSION!"=="" (
    echo [FAIL] Could not read package version from Cargo.toml
    exit /b 1
)
set "PACKAGE_DIR=!CD!\dist"
if not "%FAIRYPAM_ARTIFACT_DIR%"=="" set "PACKAGE_DIR=%FAIRYPAM_ARTIFACT_DIR%"
set "PACKAGE_FILE=fairypam-agent-windows-x64-v!PACKAGE_VERSION!.zip"
set "PACKAGE_PATH=!PACKAGE_DIR!\!PACKAGE_FILE!"
set "MANIFEST_PATH=!PACKAGE_PATH!.metadata.json"
if not exist "!PACKAGE_PATH!" (
    echo [FAIL] Staged artifact is missing: !PACKAGE_PATH!
    exit /b 1
)
if not exist "!MANIFEST_PATH!" (
    echo [FAIL] Staged metadata is missing: !MANIFEST_PATH!
    exit /b 1
)
powershell -NoProfile -NonInteractive -Command "$ErrorActionPreference = 'Stop'; Add-Type -AssemblyName System.IO.Compression.FileSystem; $asset = Get-Item -LiteralPath $env:PACKAGE_PATH; $metadata = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($env:MANIFEST_PATH)); $actualHash = (Get-FileHash -LiteralPath $asset.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); $zip = [System.IO.Compression.ZipFile]::OpenRead($asset.FullName); try { $expected = [string[]]@('BUILD-MANIFEST.json','README.txt','fairypam-agent.exe','fairypam-agent-guardian.exe','fairypam-agent-tauri-ui.exe','profiles/fairypam-test-window/profile.json','profiles/genshin-impact/profile.json'); $names = [string[]]($zip.Entries.FullName | Sort-Object); if ($metadata.platform -cne 'windows-x64' -or $metadata.version -cne $env:PACKAGE_VERSION -or $metadata.file_name -cne $asset.Name -or $metadata.sha256 -cne $actualHash -or [int64]$metadata.size_bytes -ne $asset.Length -or $metadata.status -cne 'unavailable' -or $metadata.release_status -cne 'staged' -or $null -ne $metadata.download_url -or $null -ne $metadata.released_at -or $metadata.layout.agent -cne 'fairypam-agent.exe' -or $metadata.layout.guardian -cne 'fairypam-agent-guardian.exe' -or $metadata.layout.gui -cne 'fairypam-agent-tauri-ui.exe' -or $metadata.layout.profiles -cne 'profiles/' -or $null -ne $metadata.layout.helper -or (Compare-Object $expected $names)) { throw 'staged artifact metadata or ZIP layout does not satisfy the update boundary' }; $manifestEntry = $zip.GetEntry('BUILD-MANIFEST.json'); $reader = [IO.StreamReader]::new($manifestEntry.Open(), [Text.Encoding]::UTF8); try { $manifest = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }; foreach ($name in $expected | Where-Object { $_ -ne 'BUILD-MANIFEST.json' }) { $entry = $zip.GetEntry($name); $stream = $entry.Open(); try { $hash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($stream)).Replace('-','').ToLowerInvariant() } finally { $stream.Dispose() }; if ($manifest.build_id -ne $env:PACKAGE_BUILD_ID -or $manifest.source_commit -ne $env:PACKAGE_SOURCE_COMMIT -or $null -eq $manifest.members.$name -or $manifest.members.$name.sha256 -ne $hash -or [int64]$manifest.members.$name.size_bytes -ne $entry.Length) { throw 'build manifest payload identity is invalid' } } } finally { $zip.Dispose() }"
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Staged artifact metadata verification failed
    exit /b 1
)
echo [OK] Staged artifact metadata matches ZIP; release status remains unavailable.
exit /b 0

:done
echo.
echo ============================================================
echo [DONE] FairyPam Agent build complete
echo ============================================================
endlocal
