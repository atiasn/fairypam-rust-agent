#![cfg_attr(
    all(
        target_os = "windows",
        not(debug_assertions),
        not(feature = "automation-cli")
    ),
    windows_subsystem = "windows"
)]

//! FairyPam Agent main loop.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
#[cfg(feature = "automation-cli")]
use std::time::Duration;

use anyhow::{Context, Result};
#[cfg(feature = "automation-cli")]
use tokio::sync::watch;
use tracing_subscriber::fmt::time::FormatTime;

#[cfg(any(target_os = "windows", feature = "automation-cli"))]
use fairypam_agent::process;
use fairypam_agent::{agent_runtime, config};

#[cfg(any(target_os = "windows", feature = "automation-cli"))]
use process::current_process_privilege_level;
#[cfg(target_os = "windows")]
use process::{relaunch_with_runas, PrivilegeLevel};

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{CreateMutexW, OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};

const DEFAULT_CONFIG_PATH: &str = "config.yaml";
const DEFAULT_LOG_PATH: &str = "logs/agent.log";
const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
const RETAIN_LOG_BYTES: u64 = 2 * 1024 * 1024;
#[cfg(feature = "automation-cli")]
const AUTOMATION_START_PROBE_ATTEMPTS: usize = 20;
#[cfg(feature = "automation-cli")]
const AUTOMATION_START_PROBE_DELAY: Duration = Duration::from_millis(250);

struct LocalRfc3339Timer;

impl FormatTime for LocalRfc3339Timer {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        write!(w, "{}", chrono::Local::now().to_rfc3339())
    }
}

#[derive(Debug)]
#[cfg(target_os = "windows")]
struct SingleInstanceGuard {
    handle: HANDLE,
}

#[cfg(not(target_os = "windows"))]
struct SingleInstanceGuard;

#[cfg(target_os = "windows")]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

pub(crate) fn compact_log_file(log_path: &Path) -> Result<()> {
    let Ok(metadata) = std::fs::metadata(log_path) else {
        return Ok(());
    };
    if metadata.len() <= MAX_LOG_BYTES {
        return Ok(());
    }

    let retain_bytes = metadata.len().min(RETAIN_LOG_BYTES);
    let mut file = std::fs::File::open(log_path)
        .with_context(|| format!("failed to open log file: {}", log_path.display()))?;
    file.seek(SeekFrom::Start(metadata.len() - retain_bytes))
        .with_context(|| format!("failed to seek log file: {}", log_path.display()))?;

    let mut tail = Vec::new();
    file.read_to_end(&mut tail)
        .with_context(|| format!("failed to read log file: {}", log_path.display()))?;
    if metadata.len() > retain_bytes {
        if let Some(newline_index) = tail.iter().position(|byte| *byte == b'\n') {
            tail.drain(..=newline_index);
        }
    }

    let marker = format!(
        "{} log compacted; retained last {} bytes from oversized log\n",
        chrono::Local::now().to_rfc3339(),
        tail.len()
    );
    let mut compacted = marker.into_bytes();
    compacted.extend_from_slice(&tail);
    std::fs::write(log_path, compacted)
        .with_context(|| format!("failed to compact log file: {}", log_path.display()))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn acquire_single_instance_guard() -> Result<SingleInstanceGuard> {
    let mutex_name = "Local\\FairyPam.Agent";
    let mutex_name: Vec<u16> = mutex_name.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let handle = CreateMutexW(None, true, PCWSTR::from_raw(mutex_name.as_ptr()))
            .context("failed to create single-instance mutex")?;
        if GetLastError() == ERROR_ALREADY_EXISTS {
            let _ = CloseHandle(handle);
            anyhow::bail!("another FairyPam Agent is already running");
        }

        Ok(SingleInstanceGuard { handle })
    }
}

#[cfg(not(target_os = "windows"))]
fn acquire_single_instance_guard() -> Result<SingleInstanceGuard> {
    Ok(SingleInstanceGuard)
}

#[cfg(target_os = "windows")]
fn single_instance_running() -> bool {
    let mutex_name = "Local\\FairyPam.Agent";
    let mutex_name: Vec<u16> = mutex_name.encode_utf16().chain(Some(0)).collect();

    unsafe {
        match OpenMutexW(
            SYNCHRONIZATION_SYNCHRONIZE,
            false,
            PCWSTR::from_raw(mutex_name.as_ptr()),
        ) {
            Ok(handle) => {
                let _ = CloseHandle(handle);
                true
            }
            Err(_) => false,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.mode == Mode::Automation {
        let output = run_automation_cli(&args)?;
        if !output.is_empty() {
            println!("{output}");
        }
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        if single_instance_running() {
            anyhow::bail!("another FairyPam Agent is already running");
        }

        if current_process_privilege_level() != PrivilegeLevel::Elevated {
            let executable =
                std::env::current_exe().context("failed to locate current executable")?;
            let current_dir = std::env::current_dir().ok();
            let params = build_startup_command_line(&args);
            relaunch_with_runas(&executable, &params, current_dir.as_deref())?;
            std::process::exit(0);
        }
    }

    let _single_instance_guard = acquire_single_instance_guard()?;

    match args.mode {
        Mode::Gui => {
            launch_tauri_gui(&args.config_path, &args.log_path)?;
            return Ok(());
        }
        Mode::Run => {}
        Mode::Automation => unreachable!("automation mode returns before runtime startup"),
    }

    let runtime_context = agent_runtime::build_runtime_context(&args.config_path, &args.log_path)?;

    let app_config = config::load_config(&runtime_context.config_path)?;
    compact_log_file(&runtime_context.log_path)?;
    init_logging(&app_config.agent.log_level, &runtime_context.log_path)?;
    agent_runtime::append_log_line(&runtime_context.log_path, "logging initialized")?;

    agent_runtime::run_agent(
        app_config,
        runtime_context,
        automation_shutdown_receiver(),
        None,
    )
    .await
}

#[cfg(feature = "automation-cli")]
fn automation_shutdown_receiver() -> Option<tokio::sync::watch::Receiver<bool>> {
    let stop_file = std::env::var_os("FAIRYPAM_AUTOMATION_STOP_FILE").map(PathBuf::from)?;
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(async move {
        loop {
            if stop_file.exists() {
                let _ = stop_tx.send(true);
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    });
    Some(stop_rx)
}

#[cfg(not(feature = "automation-cli"))]
fn automation_shutdown_receiver() -> Option<tokio::sync::watch::Receiver<bool>> {
    None
}

fn launch_tauri_gui(config_path: &Path, log_path: &Path) -> Result<()> {
    let executable = locate_tauri_gui_executable()?;
    let agent_executable =
        std::env::current_exe().context("failed to locate current executable")?;
    let mut command = std::process::Command::new(&executable);
    command
        .env("FAIRYPAM_AGENT_CONFIG_PATH", config_path)
        .env("FAIRYPAM_AGENT_LOG_PATH", log_path)
        .env("FAIRYPAM_AGENT_RUNTIME_EXECUTABLE", agent_executable);
    if let Some(parent) = executable.parent() {
        command.current_dir(parent);
    }
    command
        .spawn()
        .with_context(|| format!("failed to launch Tauri GUI: {}", executable.display()))?;
    Ok(())
}

fn locate_tauri_gui_executable() -> Result<PathBuf> {
    let current_exe = std::env::current_exe().context("failed to locate current executable")?;
    let exe_name = if cfg!(target_os = "windows") {
        "fairypam-agent-tauri-ui.exe"
    } else {
        "fairypam-agent-tauri-ui"
    };
    let starts = [
        current_exe.parent().map(Path::to_path_buf),
        std::env::current_dir().ok(),
    ];
    for start in starts.into_iter().flatten() {
        for ancestor in start.ancestors() {
            for candidate in [
                ancestor.join(exe_name),
                ancestor
                    .join("tauri-ui")
                    .join("src-tauri")
                    .join("target")
                    .join("release")
                    .join(exe_name),
            ] {
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    anyhow::bail!("Tauri GUI executable not found: {exe_name}")
}

pub(crate) fn init_logging(log_level: &str, log_path: &Path) -> Result<()> {
    if let Some(parent) = log_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create log directory: {}", parent.display()))?;
        }
    }

    let log_path = log_path.to_path_buf();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| log_level.into()),
        )
        .with_timer(LocalRfc3339Timer)
        .json()
        .with_writer(move || {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .expect("failed to open agent log file")
        })
        .init();

    Ok(())
}

struct Args {
    config_path: PathBuf,
    log_path: PathBuf,
    mode: Mode,
    automation_args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Gui,
    Run,
    Automation,
}

impl Args {
    fn parse() -> Self {
        let mut args = std::env::args().skip(1);
        let mut parsed = Self {
            config_path: PathBuf::from(DEFAULT_CONFIG_PATH),
            log_path: PathBuf::from(DEFAULT_LOG_PATH),
            mode: Mode::Gui,
            automation_args: Vec::new(),
        };

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--gui" => parsed.mode = Mode::Gui,
                "--run" => parsed.mode = Mode::Run,
                "automation" => {
                    parsed.mode = Mode::Automation;
                    parsed.automation_args = args.collect();
                    break;
                }
                "--config" => {
                    if let Some(value) = args.next() {
                        parsed.config_path = PathBuf::from(value);
                    }
                }
                "--log-file" => {
                    if let Some(value) = args.next() {
                        parsed.log_path = PathBuf::from(value);
                    }
                }
                _ => {}
            }
        }

        parsed
    }
}

#[cfg(any(target_os = "windows", test))]
fn build_startup_command_line(args: &Args) -> String {
    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let current_exe =
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("fairypam-agent.exe"));
    format!(
        "cmd.exe /c cd /d \"{}\" && \"{}\" {} --config \"{}\" --log-file \"{}\"",
        current_dir.display(),
        current_exe.display(),
        args.mode.flag(),
        args.config_path.display(),
        args.log_path.display()
    )
}

impl Mode {
    #[cfg(any(target_os = "windows", test))]
    fn flag(self) -> &'static str {
        match self {
            Mode::Gui => "--gui",
            Mode::Run => "--run",
            Mode::Automation => "automation",
        }
    }
}

#[cfg(not(feature = "automation-cli"))]
fn run_automation_cli(_args: &Args) -> Result<String> {
    anyhow::bail!("automation CLI is not enabled in this build")
}

#[cfg(feature = "automation-cli")]
fn run_automation_cli(args: &Args) -> Result<String> {
    automation_cli_output(args)
}

#[cfg(feature = "automation-cli")]
fn automation_cli_output(args: &Args) -> Result<String> {
    let command = args.automation_args.first().map(String::as_str);
    match command {
        None | Some("help") | Some("--help") | Some("-h") => Ok(automation_usage().to_string()),
        Some("status") => automation_status(args),
        Some("config") if arg_at(&args.automation_args, 1) == Some("validate") => {
            automation_config_validate(args)
        }
        Some("runtime") if arg_at(&args.automation_args, 1) == Some("status") => {
            automation_runtime_status(args)
        }
        Some("runtime") if arg_at(&args.automation_args, 1) == Some("start") => {
            automation_runtime_start(args)
        }
        Some("runtime") if arg_at(&args.automation_args, 1) == Some("stop") => {
            automation_runtime_stop(args)
        }
        Some("logs") => automation_logs(args),
        Some("metrics") => automation_metrics(args),
        Some("self-test") if arg_at(&args.automation_args, 1) == Some("run") => {
            automation_self_test(args)
        }
        _ => anyhow::bail!(automation_usage()),
    }
}

#[cfg(feature = "automation-cli")]
fn automation_usage() -> &'static str {
    "usage: fairypam-agent automation status --json | config validate | runtime status|start|stop --test-only | metrics --json | logs tail|export | self-test run"
}

#[cfg(feature = "automation-cli")]
fn automation_status(args: &Args) -> Result<String> {
    let config = fairypam_agent::config::load_config(&args.config_path)?;
    let validation_errors = fairypam_agent::core_facade::validate_config(&config)
        .err()
        .into_iter()
        .map(|err| err.to_string())
        .collect::<Vec<_>>();
    let payload = serde_json::json!({
        "config_path": args.config_path.display().to_string(),
        "log_path": args.log_path.display().to_string(),
        "agent_name": config.agent.name,
        "hub_ws_url": config.hub.ws_url,
        "process_privilege": format!("{:?}", current_process_privilege_level()),
        "runtime": "stopped",
        "validation_errors": validation_errors,
    });
    if has_flag(&args.automation_args, "--json") {
        Ok(serde_json::to_string_pretty(&payload)?)
    } else {
        Ok(format!(
            "agent={} runtime=stopped config={}",
            payload["agent_name"].as_str().unwrap_or(""),
            args.config_path.display()
        ))
    }
}

#[cfg(feature = "automation-cli")]
fn automation_config_validate(args: &Args) -> Result<String> {
    let config = fairypam_agent::config::load_config(&args.config_path)?;
    fairypam_agent::core_facade::validate_config(&config)?;
    Ok("config valid".to_string())
}

#[cfg(feature = "automation-cli")]
fn automation_runtime_status(args: &Args) -> Result<String> {
    let pid_path = automation_runtime_pid_path(&args.log_path);
    let managed_pid = read_automation_runtime_pid(&pid_path).ok();
    let managed_running = managed_pid.is_some_and(process_running);
    let facade = fairypam_agent::core_facade::CoreFacade::new(
        &args.config_path,
        &args.log_path,
        |_spec, _, _| anyhow::bail!("automation CLI does not start runtime from status"),
    );
    if has_flag(&args.automation_args, "--json") {
        return Ok(serde_json::to_string_pretty(&serde_json::json!({
            "phase": facade.runtime_phase().label(),
            "status": facade.runtime_status(),
            "managed_runtime": {
                "pid_file": pid_path.display().to_string(),
                "pid": managed_pid,
                "running": managed_running,
                "scope": "cli-managed-only",
            }
        }))?);
    }
    Ok(format!(
        "{}: {}; cli_managed_pid={}; cli_managed_running={}",
        facade.runtime_phase().label(),
        facade.runtime_status(),
        managed_pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "none".to_string()),
        managed_running
    ))
}

#[cfg(feature = "automation-cli")]
fn automation_runtime_start(args: &Args) -> Result<String> {
    require_flag(&args.automation_args, "--test-only", "runtime start")?;
    let config = fairypam_agent::config::load_config(&args.config_path)?;
    fairypam_agent::core_facade::validate_config(&config)?;

    let pid_path = automation_runtime_pid_path(&args.log_path);
    let stop_path = automation_runtime_stop_path(&args.log_path);
    if let Ok(pid) = read_automation_runtime_pid(&pid_path) {
        if process_running(pid) {
            return automation_runtime_start_output(
                args,
                pid,
                &pid_path,
                &stop_path,
                "already_running",
            );
        }
        let _ = std::fs::remove_file(&pid_path);
    }
    let _ = std::fs::remove_file(&stop_path);

    if let Some(parent) = args.log_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let executable = std::env::current_exe().context("failed to locate current executable")?;
    let mut child = std::process::Command::new(&executable)
        .arg("--run")
        .arg("--config")
        .arg(&args.config_path)
        .arg("--log-file")
        .arg(&args.log_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .env("FAIRYPAM_AUTOMATION_STOP_FILE", &stop_path)
        .spawn()
        .with_context(|| format!("failed to start runtime: {}", executable.display()))?;
    let pid = child.id();
    let probe = probe_automation_runtime_start(
        &mut child,
        &args.log_path,
        AUTOMATION_START_PROBE_ATTEMPTS,
        AUTOMATION_START_PROBE_DELAY,
    )?;
    if let AutomationRuntimeStartProbe::Exited { status, log_state } = probe {
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(&stop_path);
        anyhow::bail!("runtime exited during startup: status={status}; log_state={log_state}");
    }
    write_automation_runtime_pid(&pid_path, &stop_path, pid, &executable, args)?;
    let status = match probe {
        AutomationRuntimeStartProbe::Ready { .. } => "started",
        AutomationRuntimeStartProbe::Alive { .. } => "starting",
        AutomationRuntimeStartProbe::Exited { .. } => unreachable!("handled above"),
    };
    automation_runtime_start_output(args, pid, &pid_path, &stop_path, status)
}

#[cfg(feature = "automation-cli")]
fn automation_runtime_start_output(
    args: &Args,
    pid: u32,
    pid_path: &Path,
    stop_path: &Path,
    status: &str,
) -> Result<String> {
    if has_flag(&args.automation_args, "--json") {
        return Ok(serde_json::to_string_pretty(&serde_json::json!({
            "status": status,
            "pid": pid,
            "pid_file": pid_path.display().to_string(),
            "stop_file": stop_path.display().to_string(),
            "scope": "cli-managed-only",
        }))?);
    }
    Ok(format!(
        "runtime {status}: pid={pid} pid_file={} stop_file={} scope=cli-managed-only",
        pid_path.display(),
        stop_path.display()
    ))
}

#[cfg(feature = "automation-cli")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum AutomationRuntimeStartProbe {
    Ready { log_state: String },
    Alive { log_state: String },
    Exited { status: String, log_state: String },
}

#[cfg(feature = "automation-cli")]
fn probe_automation_runtime_start(
    child: &mut std::process::Child,
    log_path: &Path,
    attempts: usize,
    delay: Duration,
) -> Result<AutomationRuntimeStartProbe> {
    for _ in 0..attempts.max(1) {
        if let Some(status) = child.try_wait()? {
            return Ok(AutomationRuntimeStartProbe::Exited {
                status: status.to_string(),
                log_state: automation_runtime_log_state(log_path),
            });
        }

        let log_state = automation_runtime_log_state(log_path);
        if log_state == "ready" {
            return Ok(AutomationRuntimeStartProbe::Ready { log_state });
        }
        std::thread::sleep(delay);
    }

    Ok(AutomationRuntimeStartProbe::Alive {
        log_state: automation_runtime_log_state(log_path),
    })
}

#[cfg(feature = "automation-cli")]
fn automation_runtime_log_state(log_path: &Path) -> String {
    let Ok(text) = fairypam_agent::core_facade::read_redacted_log_tail(log_path) else {
        return "no_log".to_string();
    };
    if text.contains("Handshake complete") || text.contains("Agent ready; waiting for commands") {
        "ready".to_string()
    } else if text.contains("WebSocket connected") {
        "websocket_connected".to_string()
    } else if text.contains("Connecting to Hub") {
        "connecting".to_string()
    } else if text.trim().is_empty() {
        "no_log".to_string()
    } else {
        "log_present_without_ready".to_string()
    }
}

#[cfg(feature = "automation-cli")]
fn automation_runtime_stop(args: &Args) -> Result<String> {
    require_flag(&args.automation_args, "--test-only", "runtime stop")?;
    let pid_path = automation_runtime_pid_path(&args.log_path);
    let Ok(pid) = read_automation_runtime_pid(&pid_path) else {
        return automation_runtime_stop_output(args, None, false, false, &pid_path, "not_running");
    };

    let stop_path = read_automation_runtime_field(&pid_path, "stop_file")
        .map(PathBuf::from)
        .unwrap_or_else(|_| automation_runtime_stop_path(&args.log_path));
    let was_running = process_running(pid);
    let mut forced = false;
    if was_running {
        if let Some(parent) = stop_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(&stop_path, "stop\n").with_context(|| {
            format!("failed to write runtime stop file: {}", stop_path.display())
        })?;
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(250));
            if !process_running(pid) {
                break;
            }
        }
        if process_running(pid) {
            stop_process(pid)?;
            forced = true;
        }
    }
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(&stop_path);
    automation_runtime_stop_output(args, Some(pid), was_running, forced, &pid_path, "stopped")
}

#[cfg(feature = "automation-cli")]
fn automation_runtime_stop_output(
    args: &Args,
    pid: Option<u32>,
    stopped: bool,
    forced: bool,
    pid_path: &Path,
    status: &str,
) -> Result<String> {
    if has_flag(&args.automation_args, "--json") {
        return Ok(serde_json::to_string_pretty(&serde_json::json!({
            "status": status,
            "pid": pid,
            "stopped": stopped,
            "forced": forced,
            "reconnect": false,
            "pid_file": pid_path.display().to_string(),
            "scope": "cli-managed-only",
        }))?);
    }
    Ok(format!(
        "runtime {status}: pid={} stopped={stopped} forced={forced} reconnect=false pid_file={} scope=cli-managed-only",
        pid.map(|pid| pid.to_string()).unwrap_or_else(|| "none".to_string()),
        pid_path.display()
    ))
}

#[cfg(feature = "automation-cli")]
fn automation_runtime_pid_path(log_path: &Path) -> PathBuf {
    log_path.with_extension("automation-runtime.pid")
}

#[cfg(feature = "automation-cli")]
fn automation_runtime_stop_path(log_path: &Path) -> PathBuf {
    log_path.with_extension("automation-runtime.stop")
}

#[cfg(feature = "automation-cli")]
fn write_automation_runtime_pid(
    pid_path: &Path,
    stop_path: &Path,
    pid: u32,
    executable: &Path,
    args: &Args,
) -> Result<()> {
    if let Some(parent) = pid_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let body = format!(
        "pid={pid}\nstop_file={}\nexe={}\nconfig={}\nlog={}\nstarted_at={}\n",
        stop_path.display(),
        executable.display(),
        args.config_path.display(),
        args.log_path.display(),
        chrono::Local::now().to_rfc3339()
    );
    std::fs::write(pid_path, body)
        .with_context(|| format!("failed to write runtime pid file: {}", pid_path.display()))
}

#[cfg(feature = "automation-cli")]
fn read_automation_runtime_pid(pid_path: &Path) -> Result<u32> {
    read_automation_runtime_field(pid_path, "pid")?
        .parse::<u32>()
        .context("runtime pid file has invalid pid")
}

#[cfg(feature = "automation-cli")]
fn read_automation_runtime_field(pid_path: &Path, key: &str) -> Result<String> {
    let text = std::fs::read_to_string(pid_path)
        .with_context(|| format!("failed to read runtime pid file: {}", pid_path.display()))?;
    let prefix = format!("{key}=");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .with_context(|| format!("runtime pid file missing {key}"))
        .map(str::trim)
        .map(str::to_string)
}

#[cfg(all(feature = "automation-cli", target_os = "windows"))]
fn process_running(pid: u32) -> bool {
    let filter = format!("PID eq {pid}");
    let Ok(output) = std::process::Command::new("tasklist")
        .arg("/FI")
        .arg(&filter)
        .arg("/FO")
        .arg("CSV")
        .arg("/NH")
        .output()
    else {
        return false;
    };
    String::from_utf8_lossy(&output.stdout).contains(&format!("\"{pid}\""))
}

#[cfg(all(feature = "automation-cli", not(target_os = "windows")))]
fn process_running(pid: u32) -> bool {
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(all(feature = "automation-cli", target_os = "windows"))]
fn stop_process(pid: u32) -> Result<()> {
    let pid = pid.to_string();
    let status = std::process::Command::new("taskkill")
        .args(["/PID", &pid, "/T", "/F"])
        .status()
        .with_context(|| format!("failed to stop runtime process {pid}"))?;
    if !status.success() {
        anyhow::bail!("failed to stop runtime process {pid}: {status}");
    }
    Ok(())
}

#[cfg(all(feature = "automation-cli", not(target_os = "windows")))]
fn stop_process(pid: u32) -> Result<()> {
    let status = std::process::Command::new("kill")
        .arg(pid.to_string())
        .status()
        .with_context(|| format!("failed to stop runtime process {pid}"))?;
    if !status.success() {
        anyhow::bail!("failed to stop runtime process {pid}: {status}");
    }
    Ok(())
}

#[cfg(feature = "automation-cli")]
fn automation_logs(args: &Args) -> Result<String> {
    match arg_at(&args.automation_args, 1) {
        Some("tail") => {
            let text = fairypam_agent::core_facade::read_redacted_log_tail(&args.log_path)?;
            let lines = value_after(&args.automation_args, "--lines")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(80);
            Ok(last_lines(&text, lines))
        }
        Some("export") => {
            require_flag(&args.automation_args, "--test-only", "logs export")?;
            let output = value_after(&args.automation_args, "--output")
                .map(PathBuf::from)
                .context("logs export requires --output PATH")?;
            let text = fairypam_agent::core_facade::read_redacted_log_tail(&args.log_path)?;
            if let Some(parent) = output.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            std::fs::write(&output, text)?;
            Ok(format!(
                "exported redacted log tail to {}",
                output.display()
            ))
        }
        _ => anyhow::bail!("usage: fairypam-agent automation logs tail|export"),
    }
}

#[cfg(feature = "automation-cli")]
fn automation_metrics(args: &Args) -> Result<String> {
    let config = fairypam_agent::config::load_config(&args.config_path).ok();
    let text = fairypam_agent::core_facade::read_redacted_log_tail(&args.log_path)?;
    let metrics = automation_metrics_from_log(config.as_ref(), &text);
    if has_flag(&args.automation_args, "--json") {
        return Ok(serde_json::to_string_pretty(&metrics)?);
    }
    Ok(format!(
        "configured_fps={} cpu_usage_latest={} reconnect_count={} video_frame_log_count={} dropped_video_frames_latest={} control_messages={} max_control_total_elapsed_ms={}",
        metrics["configured_fps"]
            .as_u64()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        metrics["cpu_usage_latest"]
            .as_f64()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unavailable".to_string()),
        metrics["reconnect_count"].as_u64().unwrap_or(0),
        metrics["video_frame_log_count"].as_u64().unwrap_or(0),
        metrics["dropped_video_frames_latest"]
            .as_u64()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        metrics["control_latency"]["message_count"].as_u64().unwrap_or(0),
        metrics["control_latency"]["max_total_elapsed_ms"]
            .as_u64()
            .unwrap_or(0)
    ))
}

#[cfg(feature = "automation-cli")]
fn automation_metrics_from_log(
    config: Option<&fairypam_agent::config::AppConfig>,
    text: &str,
) -> serde_json::Value {
    let mut reconnect_count = 0_u64;
    let mut video_frame_log_count = 0_u64;
    let mut dropped_video_frames_latest = None;
    let mut control_message_count = 0_u64;
    let mut max_control_queue_wait_ms = 0_u64;
    let mut max_control_total_elapsed_ms = 0_u64;
    let mut last_control_message_type = None::<String>;

    for line in text.lines() {
        if line.contains("agent connection will reconnect") {
            reconnect_count += 1;
        }
        if line.contains("video frame queued") {
            video_frame_log_count += 1;
            if let Some(value) = parse_log_u64(line, "dropped") {
                dropped_video_frames_latest = Some(value);
            }
        }
        if line.contains("outbound control message sent") {
            control_message_count += 1;
            if let Some(value) = parse_log_u64(line, "queue_wait_ms") {
                max_control_queue_wait_ms = max_control_queue_wait_ms.max(value);
            }
            if let Some(value) = parse_log_u64(line, "total_elapsed_ms") {
                max_control_total_elapsed_ms = max_control_total_elapsed_ms.max(value);
            }
            if let Some(value) = parse_log_string(line, "message_type") {
                last_control_message_type = Some(value);
            }
        }
    }

    serde_json::json!({
        "configured_fps": config.map(|config| config.capture.fps),
        "cpu_usage_latest": serde_json::Value::Null,
        "reconnect_count": reconnect_count,
        "video_frame_log_count": video_frame_log_count,
        "dropped_video_frames_latest": dropped_video_frames_latest,
        "control_latency": {
            "message_count": control_message_count,
            "max_queue_wait_ms": max_control_queue_wait_ms,
            "max_total_elapsed_ms": max_control_total_elapsed_ms,
            "last_message_type": last_control_message_type,
        },
    })
}

#[cfg(feature = "automation-cli")]
fn parse_log_u64(line: &str, key: &str) -> Option<u64> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
        if let Some(number) = value.get(key).and_then(serde_json::Value::as_u64) {
            return Some(number);
        }
        if let Some(number) = value
            .get("fields")
            .and_then(|fields| fields.get(key))
            .and_then(serde_json::Value::as_u64)
        {
            return Some(number);
        }
    }
    let marker = format!("{key}=");
    let value = line.split(&marker).nth(1)?;
    value
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()
}

#[cfg(feature = "automation-cli")]
fn parse_log_string(line: &str, key: &str) -> Option<String> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
        if let Some(text) = value.get(key).and_then(serde_json::Value::as_str) {
            return Some(text.to_string());
        }
        if let Some(text) = value
            .get("fields")
            .and_then(|fields| fields.get(key))
            .and_then(serde_json::Value::as_str)
        {
            return Some(text.to_string());
        }
    }
    let marker = format!("{key}=");
    let value = line.split(&marker).nth(1)?;
    Some(
        value
            .chars()
            .take_while(|ch| !ch.is_whitespace() && *ch != ',')
            .collect(),
    )
}

#[cfg(feature = "automation-cli")]
fn automation_self_test(args: &Args) -> Result<String> {
    require_flag(&args.automation_args, "--test-only", "self-test run")?;
    let suite = value_after(&args.automation_args, "--suite").unwrap_or("basic");
    let profile = value_after(&args.automation_args, "--profile").unwrap_or("genshin");
    match suite {
        "basic" => {}
        "capture" => require_flag(
            &args.automation_args,
            "--allow-capture",
            "capture self-test",
        )?,
        "input" => require_flag(&args.automation_args, "--allow-input", "input self-test")?,
        _ => anyhow::bail!("--suite must be basic, capture, or input"),
    }
    let config = fairypam_agent::config::load_config(&args.config_path)?;
    let games = fairypam_agent::mihoyo_discovery::discover_mihoyo_games()?;
    let game = games
        .iter()
        .find(|game| game.profile_id.as_deref() == Some(profile))
        .with_context(|| format!("supported discovered game not found: {profile}"))?;
    let target = fairypam_agent::core_facade::discovery_self_test_target(game)
        .with_context(|| format!("discovered game is not self-test ready: {profile}"))?;

    if suite == "basic" {
        return Ok(serde_json::to_string_pretty(&serde_json::json!({
            "suite": suite,
            "profile_id": target.profile_id,
            "executable": target.executable,
            "working_dir": target.working_dir,
            "ready": true,
        }))?);
    }

    let mut session = fairypam_agent::core_facade::SelfTestSession::new(&config.game_profiles)?;
    let launch = session.launch(&target, &[])?;
    let result = match suite {
        "capture" => {
            let frame = session.capture(&config.capture)?;
            serde_json::json!({
                "suite": suite,
                "pid": launch.pid,
                "window_title": launch.window.title,
                "jpeg_bytes": frame.jpeg.len(),
            })
        }
        "input" => {
            let binding = session.send_input(fairypam_agent::protocol::InputFrame {
                session_id: "automation-self-test".to_string(),
                game_id: profile.to_string(),
                seq: 0,
                keyboard: std::collections::HashMap::new(),
                mouse: fairypam_agent::protocol::MouseState::default(),
                gamepad: None,
            })?;
            serde_json::json!({
                "suite": suite,
                "pid": launch.pid,
                "window_title": binding.title,
            })
        }
        _ => unreachable!("suite was validated before launch"),
    };
    let _ = session.release_input();
    let _ = session.close(false);
    Ok(serde_json::to_string_pretty(&result)?)
}

#[cfg(feature = "automation-cli")]
fn arg_at(args: &[String], index: usize) -> Option<&str> {
    args.get(index).map(String::as_str)
}

#[cfg(feature = "automation-cli")]
fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

#[cfg(feature = "automation-cli")]
fn value_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].as_str())
}

#[cfg(feature = "automation-cli")]
fn require_flag(args: &[String], flag: &str, command: &str) -> Result<()> {
    if has_flag(args, flag) {
        Ok(())
    } else {
        anyhow::bail!("{command} requires {flag}")
    }
}

#[cfg(feature = "automation-cli")]
fn last_lines(text: &str, lines: usize) -> String {
    let mut tail = text.lines().rev().take(lines).collect::<Vec<_>>();
    tail.reverse();
    tail.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_command_line_preserves_mode_and_paths() {
        let args = Args {
            config_path: PathBuf::from(r"C:\FairyPam\config.yaml"),
            log_path: PathBuf::from(r"C:\FairyPam\logs\agent.log"),
            mode: Mode::Run,
            automation_args: Vec::new(),
        };

        let command_line = build_startup_command_line(&args);

        assert!(command_line.contains("--run"));
        assert!(command_line.contains("--config \"C:\\FairyPam\\config.yaml\""));
        assert!(command_line.contains("--log-file \"C:\\FairyPam\\logs\\agent.log\""));
    }

    #[test]
    fn automation_mode_flag_is_not_a_startup_mode() {
        assert_eq!(Mode::Automation.flag(), "automation");
    }

    #[cfg(feature = "automation-cli")]
    #[test]
    fn automation_requires_test_only_for_self_test() {
        let args = Args {
            config_path: PathBuf::from("config.yaml"),
            log_path: PathBuf::from("logs/agent.log"),
            mode: Mode::Automation,
            automation_args: vec![
                "self-test".into(),
                "run".into(),
                "--suite".into(),
                "capture".into(),
            ],
        };

        let err = automation_cli_output(&args).unwrap_err().to_string();
        assert!(err.contains("--test-only"));
    }

    #[cfg(feature = "automation-cli")]
    #[test]
    fn automation_capture_requires_allow_capture_before_loading_config() {
        let args = Args {
            config_path: PathBuf::from("missing-config.yaml"),
            log_path: PathBuf::from("logs/agent.log"),
            mode: Mode::Automation,
            automation_args: vec![
                "self-test".into(),
                "run".into(),
                "--suite".into(),
                "capture".into(),
                "--test-only".into(),
            ],
        };

        let err = automation_cli_output(&args).unwrap_err().to_string();
        assert!(err.contains("--allow-capture"));
        assert!(!err.contains("missing-config"));
    }

    #[cfg(feature = "automation-cli")]
    #[test]
    fn automation_help_lists_runtime_and_metrics_commands() {
        let args = Args {
            config_path: PathBuf::from("config.yaml"),
            log_path: PathBuf::from("logs/agent.log"),
            mode: Mode::Automation,
            automation_args: vec!["--help".into()],
        };

        let output = automation_cli_output(&args).unwrap();

        assert!(output.contains("runtime status|start|stop"));
        assert!(output.contains("metrics --json"));
    }

    #[cfg(feature = "automation-cli")]
    #[test]
    fn automation_runtime_start_requires_test_only_before_loading_config() {
        let args = Args {
            config_path: PathBuf::from("missing-config.yaml"),
            log_path: PathBuf::from("logs/agent.log"),
            mode: Mode::Automation,
            automation_args: vec!["runtime".into(), "start".into()],
        };

        let err = automation_cli_output(&args).unwrap_err().to_string();

        assert!(err.contains("--test-only"));
        assert!(!err.contains("missing-config"));
    }

    #[cfg(feature = "automation-cli")]
    #[test]
    fn automation_runtime_start_probe_reports_immediate_exit() {
        let dir = std::env::temp_dir().join(format!(
            "fairypam-agent-runtime-start-probe-test-{}",
            std::process::id()
        ));
        let log_path = dir.join("agent.log");
        std::fs::create_dir_all(&dir).unwrap();
        let mut child = immediate_exit_command();

        let probe =
            probe_automation_runtime_start(&mut child, &log_path, 20, Duration::from_millis(10))
                .unwrap();

        assert!(matches!(
            probe,
            AutomationRuntimeStartProbe::Exited { ref log_state, .. } if log_state == "no_log"
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(all(feature = "automation-cli", target_os = "windows"))]
    fn immediate_exit_command() -> std::process::Child {
        std::process::Command::new("cmd")
            .args(["/C", "exit", "/B", "7"])
            .spawn()
            .unwrap()
    }

    #[cfg(all(feature = "automation-cli", not(target_os = "windows")))]
    fn immediate_exit_command() -> std::process::Child {
        std::process::Command::new("sh")
            .args(["-c", "exit 7"])
            .spawn()
            .unwrap()
    }

    #[cfg(feature = "automation-cli")]
    #[test]
    fn automation_runtime_stop_missing_pid_is_cli_managed_no_reconnect() {
        let dir = std::env::temp_dir().join(format!(
            "fairypam-agent-runtime-stop-test-{}",
            std::process::id()
        ));
        let args = Args {
            config_path: dir.join("config.yaml"),
            log_path: dir.join("agent.log"),
            mode: Mode::Automation,
            automation_args: vec![
                "runtime".into(),
                "stop".into(),
                "--test-only".into(),
                "--json".into(),
            ],
        };

        let output = automation_cli_output(&args).unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(value["status"], "not_running");
        assert_eq!(value["reconnect"], false);
        assert_eq!(value["scope"], "cli-managed-only");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(feature = "automation-cli")]
    #[test]
    fn automation_logs_tail_redacts_sensitive_text() {
        let dir = std::env::temp_dir().join(format!(
            "fairypam-agent-automation-log-test-{}",
            std::process::id()
        ));
        let log_path = dir.join("agent.log");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&log_path, "ok=true\napi_key=fp_secret\n").unwrap();
        let args = Args {
            config_path: dir.join("config.yaml"),
            log_path,
            mode: Mode::Automation,
            automation_args: vec!["logs".into(), "tail".into()],
        };

        let output = automation_cli_output(&args).unwrap();
        assert!(output.contains("api_key=***"));
        assert!(!output.contains("fp_secret"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(feature = "automation-cli")]
    #[test]
    fn automation_metrics_summarizes_redacted_log_without_secrets() {
        let dir = std::env::temp_dir().join(format!(
            "fairypam-agent-automation-metrics-test-{}",
            std::process::id()
        ));
        let config_path = dir.join("config.yaml");
        let log_path = dir.join("agent.log");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &config_path,
            "hub:\n  ws_url: \"ws://127.0.0.1:8000/ws\"\n  api_key: \"fp_secret\"\nagent:\n  name: \"Agent\"\n  log_level: \"info\"\ncapture:\n  fps: 30\n  target_display: 0\n  jpeg_quality: 90\n  encoder: \"media_foundation\"\n",
        )
        .unwrap();
        std::fs::write(
            &log_path,
            "{\"message\":\"outbound control message sent\",\"message_type\":\"heartbeat\",\"queue_wait_ms\":7,\"total_elapsed_ms\":9,\"api_key\":\"fp_secret\"}\nagent connection will reconnect\nvideo frame queued: pid=42 process_name=game.exe bytes=10 count=1 dropped=3\n",
        )
        .unwrap();
        let args = Args {
            config_path,
            log_path,
            mode: Mode::Automation,
            automation_args: vec!["metrics".into(), "--json".into()],
        };

        let output = automation_cli_output(&args).unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(value["configured_fps"], 30);
        assert_eq!(value["reconnect_count"], 1);
        assert_eq!(value["video_frame_log_count"], 1);
        assert_eq!(value["dropped_video_frames_latest"], 3);
        assert_eq!(value["control_latency"]["message_count"], 1);
        assert_eq!(value["control_latency"]["max_total_elapsed_ms"], 9);
        assert!(!output.contains("fp_secret"));
        assert!(!output.contains("api_key"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(feature = "automation-cli")]
    #[test]
    fn automation_status_json_omits_api_key() {
        let dir = std::env::temp_dir().join(format!(
            "fairypam-agent-automation-status-test-{}",
            std::process::id()
        ));
        let config_path = dir.join("config.yaml");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &config_path,
            "hub:\n  ws_url: \"ws://127.0.0.1:8000/ws\"\n  api_key: \"fp_secret\"\nagent:\n  name: \"Agent\"\n  log_level: \"info\"\ncapture:\n  fps: 30\n  target_display: 0\n  jpeg_quality: 90\n  encoder: \"media_foundation\"\n",
        )
        .unwrap();
        let args = Args {
            config_path,
            log_path: dir.join("agent.log"),
            mode: Mode::Automation,
            automation_args: vec!["status".into(), "--json".into()],
        };

        let output = automation_cli_output(&args).unwrap();
        assert!(output.contains("\"agent_name\""));
        assert!(output.contains("\"process_privilege\""));
        assert!(!output.contains("api_key"));
        assert!(!output.contains("fp_secret"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn compact_log_file_retains_tail_when_log_is_too_large() {
        let dir =
            std::env::temp_dir().join(format!("fairypam-agent-log-compact-{}", std::process::id()));
        let path = dir.join("agent.log");
        std::fs::create_dir_all(&dir).unwrap();

        let mut original = vec![b'a'; (MAX_LOG_BYTES + 1024) as usize];
        original.extend_from_slice(b"\ntail-line\n");
        std::fs::write(&path, original).unwrap();

        compact_log_file(&path).unwrap();

        let compacted = std::fs::read_to_string(&path).unwrap();
        assert!(compacted.contains("log compacted"));
        assert!(compacted.contains("tail-line"));
        assert!(!compacted.starts_with('a'));
        assert!(std::fs::metadata(&path).unwrap().len() < MAX_LOG_BYTES);

        let _ = std::fs::remove_dir_all(dir);
    }
}
