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
set "DEBUG_EXE=target\debug\fairypam-agent.exe"
set "GUI_RELEASE_EXE=tauri-ui\src-tauri\target\release\fairypam-agent-tauri-ui.exe"
if not "%CARGO_TARGET_DIR%"=="" (
    set "RELEASE_EXE=%CARGO_TARGET_DIR%\release\fairypam-agent.exe"
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
    echo !EXTRA_CARGO_ARGS! | findstr /I /C:"automation-cli" >nul
    if !ERRORLEVEL! EQU 0 (
        echo [ERROR] Formal release builds must not enable automation-cli.
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
cargo check --locked !EXTRA_CARGO_ARGS!
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
cargo test --locked !EXTRA_CARGO_ARGS!
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
cargo clippy --locked !EXTRA_CARGO_ARGS! -- -D warnings
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
cargo build --locked --release !EXTRA_CARGO_ARGS!
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
cargo build --locked !EXTRA_CARGO_ARGS!
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
echo ============================================================
echo [6/6] Packaging staged Windows artifact...
echo ============================================================
powershell -NoProfile -NonInteractive -Command "$ErrorActionPreference = 'Stop'; [void](New-Item -ItemType Directory -Force -Path $env:PACKAGE_DIR); Compress-Archive -LiteralPath @($env:RELEASE_EXE, $env:GUI_RELEASE_EXE) -DestinationPath $env:PACKAGE_PATH -Force; $asset = Get-Item -LiteralPath $env:PACKAGE_PATH; $metadata = [ordered]@{ platform = 'windows-x64'; version = $env:PACKAGE_VERSION; file_name = $asset.Name; download_url = $null; sha256 = (Get-FileHash -LiteralPath $asset.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); size_bytes = $asset.Length; released_at = $null; status = 'unavailable'; release_status = 'staged'; layout = [ordered]@{ cli = 'fairypam-agent.exe'; gui = 'fairypam-agent-tauri-ui.exe' } }; $temporary = $env:MANIFEST_PATH + '.tmp'; [System.IO.File]::WriteAllText($temporary, (ConvertTo-Json -InputObject $metadata -Depth 3) + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false)); Move-Item -LiteralPath $temporary -Destination $env:MANIFEST_PATH -Force"
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
powershell -NoProfile -NonInteractive -Command "$ErrorActionPreference = 'Stop'; Add-Type -AssemblyName System.IO.Compression.FileSystem; $asset = Get-Item -LiteralPath $env:PACKAGE_PATH; $metadata = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($env:MANIFEST_PATH)); $actualHash = (Get-FileHash -LiteralPath $asset.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); $zip = [System.IO.Compression.ZipFile]::OpenRead($asset.FullName); try { $names = [string[]]$zip.Entries.FullName; if ($metadata.platform -cne 'windows-x64' -or $metadata.version -cne $env:PACKAGE_VERSION -or $metadata.file_name -cne $asset.Name -or $metadata.sha256 -cne $actualHash -or [int64]$metadata.size_bytes -ne $asset.Length -or $metadata.status -cne 'unavailable' -or $metadata.release_status -cne 'staged' -or $null -ne $metadata.download_url -or $null -ne $metadata.released_at -or $metadata.layout.cli -cne 'fairypam-agent.exe' -or $metadata.layout.gui -cne 'fairypam-agent-tauri-ui.exe' -or $names -notcontains 'fairypam-agent.exe' -or $names -notcontains 'fairypam-agent-tauri-ui.exe') { throw 'staged artifact metadata or ZIP layout does not satisfy the GUI release boundary' } } finally { $zip.Dispose() }"
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
