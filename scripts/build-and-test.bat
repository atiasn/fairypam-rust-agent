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
set "PRODUCTION_WORKSPACE_ARGS=--workspace --exclude fairypam-agent-dev-automation"
set "RELEASE_EXE=target\release\fairypam-agent.exe"
set "AGENTCTL_RELEASE_EXE=target\release\fairypam-agentctl.exe"
set "GUARDIAN_RELEASE_EXE=target\release\fairypam-agent-guardian.exe"
set "INSTALLER_RELEASE_EXE=target\release\FairyPamAgentSetup.exe"
set "UPDATER_RELEASE_EXE=target\release\fairypam-agent-updater.exe"
set "DEBUG_EXE=target\debug\fairypam-agent.exe"
set "GUI_RELEASE_EXE=tauri-ui\src-tauri\target\release\fairypam-agent-ui.exe"
if not "%CARGO_TARGET_DIR%"=="" (
    set "RELEASE_EXE=%CARGO_TARGET_DIR%\release\fairypam-agent.exe"
    set "AGENTCTL_RELEASE_EXE=%CARGO_TARGET_DIR%\release\fairypam-agentctl.exe"
    set "GUARDIAN_RELEASE_EXE=%CARGO_TARGET_DIR%\release\fairypam-agent-guardian.exe"
    set "INSTALLER_RELEASE_EXE=%CARGO_TARGET_DIR%\release\FairyPamAgentSetup.exe"
    set "UPDATER_RELEASE_EXE=%CARGO_TARGET_DIR%\release\fairypam-agent-updater.exe"
    set "DEBUG_EXE=%CARGO_TARGET_DIR%\debug\fairypam-agent.exe"
    set "GUI_RELEASE_EXE=%CARGO_TARGET_DIR%\release\fairypam-agent-ui.exe"
)

cd /d "%~dp0\.."
echo ============================================================
echo FairyPam Agent Build Script
echo Working dir: %CD%
echo Mode: %MODE%
if not "!EXTRA_CARGO_ARGS!"=="" echo Cargo args:!EXTRA_CARGO_ARGS!
echo ============================================================

if /I "%MODE%"=="release" (
    echo !EXTRA_CARGO_ARGS! | findstr /I /C:"dev-automation" >nul
    if !ERRORLEVEL! EQU 0 (
        echo [ERROR] Formal release builds must not enable dev-automation.
        exit /b 1
    )
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
    echo !EXTRA_CARGO_ARGS! | findstr /I /C:"dev-automation" >nul
    if !ERRORLEVEL! EQU 0 (
        echo [ERROR] Formal package builds must not enable dev-automation.
        exit /b 1
    )
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
cargo check !PRODUCTION_WORKSPACE_ARGS! --all-targets --locked !EXTRA_CARGO_ARGS!
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
cargo test !PRODUCTION_WORKSPACE_ARGS! --locked !EXTRA_CARGO_ARGS!
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
cargo clippy !PRODUCTION_WORKSPACE_ARGS! --all-targets --locked !EXTRA_CARGO_ARGS! -- -D warnings
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
cargo build !PRODUCTION_WORKSPACE_ARGS! --locked --release !EXTRA_CARGO_ARGS!
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] release build failed
    exit /b 1
)
echo [OK] Release build succeeded
dir "!RELEASE_EXE!"
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts\verify-production-local-capabilities.ps1 -AgentPath "!RELEASE_EXE!" -AgentctlPath "!AGENTCTL_RELEASE_EXE!"
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] production local capability scan failed
    exit /b 1
)
if /I "%MODE%"=="package" goto :do_package
goto :done

:do_build
echo ============================================================
echo [4/4] cargo build...
echo ============================================================
cargo build !PRODUCTION_WORKSPACE_ARGS! --locked !EXTRA_CARGO_ARGS!
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
set "PACKAGE_BUILD_ID=local-v!PACKAGE_VERSION!"
if not "%FAIRYPAM_BUILD_ID%"=="" set "PACKAGE_BUILD_ID=%FAIRYPAM_BUILD_ID%"
set "PACKAGE_SOURCE_COMMIT=local"
if not "%FAIRYPAM_SOURCE_COMMIT%"=="" set "PACKAGE_SOURCE_COMMIT=%FAIRYPAM_SOURCE_COMMIT%"
set "PACKAGE_PUBLIC_COMMIT=!PACKAGE_SOURCE_COMMIT!"
if not "%FAIRYPAM_PUBLIC_COMMIT%"=="" set "PACKAGE_PUBLIC_COMMIT=%FAIRYPAM_PUBLIC_COMMIT%"
echo ============================================================
echo [6/6] Packaging staged Windows artifact...
echo ============================================================
powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts\package-windows-agent-suite.ps1 -OutputDirectory "!PACKAGE_DIR!" -BuildId "!PACKAGE_BUILD_ID!" -SourceCommit "!PACKAGE_SOURCE_COMMIT!" -PublicCommit "!PACKAGE_PUBLIC_COMMIT!" -Workflow "local-package" -RunId "local" -RunAttempt "1" -SuiteVersion "!PACKAGE_VERSION!" -TargetDirectory "!CD!\target\release" -GuiExecutable "!GUI_RELEASE_EXE!"
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Windows artifact packaging or metadata generation failed
    exit /b 1
)
echo [OK] Unsigned suite candidate staged in !PACKAGE_DIR!; TUF, Authenticode and device gates remain pending.
goto :done

:do_verify_package
echo [ERROR] verify-package requires an exact build identity; use package mode in the public workflow.
exit /b 2

:done
echo.
echo ============================================================
echo [DONE] FairyPam Agent build complete
echo ============================================================
endlocal
