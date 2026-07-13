@echo off
REM ============================================================
REM FairyPam Agent - Windows build and test helper
REM
REM Usage: build-and-test.bat [check|test|build|release|all]
REM   check   - cargo check --locked
REM   test    - cargo test --locked
REM   build   - cargo build --locked
REM   release - cargo build --locked --release
REM   all     - run all steps
REM ============================================================

setlocal enabledelayedexpansion
set MODE=%1
if "%MODE%"=="" set MODE=all
set "EXTRA_CARGO_ARGS=%2 %3 %4 %5 %6 %7 %8 %9"
set "RELEASE_EXE=target\release\fairypam-agent.exe"
set "DEBUG_EXE=target\debug\fairypam-agent.exe"
if not "%CARGO_TARGET_DIR%"=="" (
    set "RELEASE_EXE=%CARGO_TARGET_DIR%\release\fairypam-agent.exe"
    set "DEBUG_EXE=%CARGO_TARGET_DIR%\debug\fairypam-agent.exe"
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

if /I "%MODE%"=="check" goto :do_check
if /I "%MODE%"=="all" goto :do_check
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

:done
echo.
echo ============================================================
echo [DONE] FairyPam Agent build complete
echo ============================================================
endlocal
