#[cfg(windows)]
use std::{
    os::windows::ffi::OsStrExt,
    path::PathBuf,
    time::{Duration, Instant},
};

use tauri::State;
#[cfg(windows)]
use windows::{
    core::{HSTRING, PCWSTR},
    Win32::{
        Foundation::{CloseHandle, HWND, WAIT_OBJECT_0},
        Security::WinTrust::{
            WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
            WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
            WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
            WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        },
        System::Threading::{
            GetExitCodeProcess, OpenMutexW, WaitForSingleObject, SYNCHRONIZATION_SYNCHRONIZE,
        },
        UI::{
            Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
            WindowsAndMessaging::SW_HIDE,
        },
    },
};

#[cfg(windows)]
use crate::foreground_broker::foreground_broker;
use crate::{
    dto::{
        ConnectionStatusDto, EnvironmentCheckDto, InstalledGamesDto, LogTailDto, OverviewDto,
        RegistrationStatusDto, SupportStatusDto,
    },
    local_gateway::{ProductionGateway, UiCommandError},
};

type CommandResult<T> = Result<T, UiCommandError>;

#[cfg(windows)]
const PIPE_STARTUP_LIMIT: Duration = Duration::from_secs(20);
#[cfg(windows)]
const PIPE_SHUTDOWN_LIMIT: Duration = Duration::from_secs(10);
#[cfg(windows)]
const HUB_OBSERVATION_LIMIT: Duration = Duration::from_secs(20);
#[cfg(windows)]
const HUB_OBSERVATION_ATTEMPTS: u8 = 20;
#[cfg(windows)]
const HUB_OBSERVATION_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(windows)]
const PIPE_DELAYS_MS: [u64; 5] = [300, 600, 1_200, 2_400, 4_800];
#[cfg(windows)]
const REPAIR_TASK_ARGUMENT: &str = "--repair-tasks";
#[cfg(windows)]
const AGENT_INSTANCE_MUTEX: &str = r"Global\FairyPam.Agent.v1";

#[tauri::command]
pub async fn get_overview(state: State<'_, ProductionGateway>) -> CommandResult<OverviewDto> {
    state.overview().await
}

#[tauri::command]
pub async fn get_connection_status(
    state: State<'_, ProductionGateway>,
) -> CommandResult<ConnectionStatusDto> {
    state.connection_status().await
}

#[tauri::command]
pub async fn run_environment_check(
    state: State<'_, ProductionGateway>,
) -> CommandResult<EnvironmentCheckDto> {
    state.environment_check().await
}

#[tauri::command]
pub async fn get_log_tail(
    lines: u16,
    level: String,
    state: State<'_, ProductionGateway>,
) -> CommandResult<LogTailDto> {
    let level = match level.as_str() {
        "error" => fairypam_agent_local_protocol::LogLevel::Error,
        "warn" => fairypam_agent_local_protocol::LogLevel::Warn,
        "info" => fairypam_agent_local_protocol::LogLevel::Info,
        _ => {
            return Err(UiCommandError::unavailable(
                "local.command.invalid_argument",
                "level must be error, warn, or info",
            ))
        }
    };
    if !(1..=200).contains(&lines) {
        return Err(UiCommandError::unavailable(
            "local.command.invalid_argument",
            "lines must be within 1..=200",
        ));
    }
    state.log_tail(lines, level).await
}

#[tauri::command]
pub async fn scan_installed_games(
    state: State<'_, ProductionGateway>,
) -> CommandResult<InstalledGamesDto> {
    state.installed_games().await
}

#[tauri::command]
pub async fn register_hub(
    hub_address: String,
    registration_code: String,
    state: State<'_, ProductionGateway>,
) -> CommandResult<RegistrationStatusDto> {
    state.register_hub(hub_address, registration_code).await
}

#[tauri::command]
pub async fn ensure_local_agent(
    state: State<'_, ProductionGateway>,
) -> CommandResult<SupportStatusDto> {
    ensure_local_agent_owned(&state).await
}

pub(crate) async fn ensure_local_agent_owned(
    state: &ProductionGateway,
) -> CommandResult<SupportStatusDto> {
    #[cfg(windows)]
    {
        let _lifecycle = state.acquire_lifecycle()?;
        if state.interactive_owner_ready() {
            match state.status_with_timeout(Duration::from_secs(1)).await {
                Ok(_) => return observe_hub(state).await,
                Err(error) if error.code == "local.transport.pipe_not_found" => {
                    state.clear_interactive_owner();
                }
                Err(error) => return Err(error),
            }
        }
        replace_with_interactive_agent(state).await
    }
    #[cfg(not(windows))]
    {
        let _ = state;
        Err(UiCommandError::unavailable(
            "local.transport.platform_unsupported",
            "FairyPam Agent startup requires Windows",
        ))
    }
}

#[tauri::command]
pub async fn restart_local_agent(
    state: State<'_, ProductionGateway>,
) -> CommandResult<SupportStatusDto> {
    #[cfg(windows)]
    {
        let _lifecycle = state.acquire_lifecycle()?;
        replace_with_interactive_agent(&state).await
    }
    #[cfg(not(windows))]
    {
        let _ = state;
        Err(platform_unsupported())
    }
}

#[tauri::command]
pub async fn repair_agent_tasks(
    state: State<'_, ProductionGateway>,
) -> CommandResult<SupportStatusDto> {
    #[cfg(windows)]
    {
        let _lifecycle = state.acquire_lifecycle()?;
        stop_existing_agent(&state).await?;
        run_repair_helper()?;
        replace_with_interactive_agent(&state).await
    }
    #[cfg(not(windows))]
    {
        let _ = state;
        Err(platform_unsupported())
    }
}

#[cfg(not(windows))]
fn platform_unsupported() -> UiCommandError {
    UiCommandError::unavailable(
        "local.transport.platform_unsupported",
        "FairyPam Agent startup requires Windows",
    )
}

#[cfg(windows)]
async fn replace_with_interactive_agent(
    state: &ProductionGateway,
) -> CommandResult<SupportStatusDto> {
    stop_existing_agent(state).await?;
    launch_fixed_agent()?;
    match wait_for_agent(state).await {
        Ok(status) => Ok(status),
        Err(error) => {
            foreground_broker()?.clear();
            Err(error)
        }
    }
}

pub(crate) async fn shutdown_local_agent_for_exit(state: &ProductionGateway) -> CommandResult<()> {
    #[cfg(windows)]
    {
        let _lifecycle = state.acquire_lifecycle()?;
        stop_existing_agent(state).await
    }
    #[cfg(not(windows))]
    {
        let _ = state;
        Ok(())
    }
}

#[cfg(windows)]
async fn stop_existing_agent(state: &ProductionGateway) -> CommandResult<()> {
    foreground_broker()?.clear();
    state.clear_interactive_owner();
    match state.shutdown_agent().await {
        Ok(()) => {}
        Err(error) if error.code == "local.transport.pipe_not_found" => {}
        // The Agent cancels its Pipe server while completing safe shutdown.
        Err(error) if error.code == "local.transport.disconnected" => {}
        Err(error) => return Err(error),
    }
    let deadline = Instant::now() + PIPE_SHUTDOWN_LIMIT;
    loop {
        if !agent_instance_running()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(UiCommandError::unavailable(
                "startup.agent_shutdown_timeout",
                "The previous FairyPam Agent did not stop within 10 seconds",
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[cfg(windows)]
fn agent_instance_running() -> CommandResult<bool> {
    match unsafe {
        OpenMutexW(
            SYNCHRONIZATION_SYNCHRONIZE,
            false,
            &HSTRING::from(AGENT_INSTANCE_MUTEX),
        )
    } {
        Ok(handle) => {
            let _ = unsafe { CloseHandle(handle) };
            Ok(true)
        }
        Err(error) if error.code().0 as u32 == 0x8007_0002 => Ok(false),
        Err(_) => Err(UiCommandError::unavailable(
            "startup.agent_instance_unavailable",
            "FairyPam could not verify the previous Agent process",
        )),
    }
}

#[cfg(windows)]
async fn wait_for_agent(state: &ProductionGateway) -> CommandResult<SupportStatusDto> {
    let deadline = Instant::now() + PIPE_STARTUP_LIMIT;
    for delay in PIPE_DELAYS_MS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(delay).min(remaining)).await;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match state
            .status_with_timeout(remaining.min(Duration::from_secs(1)))
            .await
        {
            Ok(_) => {
                state.mark_interactive_owner_ready();
                return observe_hub(state).await;
            }
            Err(error) if error.code == "local.transport.pipe_not_found" => {}
            Err(error) => return Err(error),
        }
    }
    Err(UiCommandError::unavailable(
        "startup.pipe_timeout",
        "FairyPam Agent did not become ready within 20 seconds",
    ))
}

#[cfg(windows)]
async fn observe_hub(state: &ProductionGateway) -> CommandResult<SupportStatusDto> {
    let deadline = Instant::now() + HUB_OBSERVATION_LIMIT;
    for attempt in 0..HUB_OBSERVATION_ATTEMPTS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let status = match state
            .connection_status_with_timeout(remaining.min(Duration::from_secs(1)))
            .await
        {
            Ok(status) => status,
            Err(error) => return Err(error),
        };
        if status.control.eq_ignore_ascii_case("connected")
            && status.frame.eq_ignore_ascii_case("connected")
        {
            return Ok(SupportStatusDto {
                status: "ready".into(),
            });
        }
        if status.recovery_code == "runtime.not_registered" {
            return Ok(SupportStatusDto {
                status: "agent_ready".into(),
            });
        }
        if attempt + 1 < HUB_OBSERVATION_ATTEMPTS {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            tokio::time::sleep(HUB_OBSERVATION_INTERVAL.min(remaining)).await;
        }
    }
    Ok(SupportStatusDto {
        status: "hub_wait_timeout".into(),
    })
}

#[cfg(windows)]
fn launch_fixed_agent() -> CommandResult<()> {
    let (agent, directory) = fixed_agent_path()?;
    let broker = foreground_broker()?;
    let verb = HSTRING::from("runas");
    let file = HSTRING::from(agent.to_string_lossy().as_ref());
    let parameters = HSTRING::from(format!(
        "--ui-owner-pid {} --foreground-broker-hwnd {}",
        std::process::id(),
        broker.hwnd() as usize
    ));
    let working_directory = HSTRING::from(directory.to_string_lossy().as_ref());
    let mut execution = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        lpDirectory: PCWSTR(working_directory.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe { ShellExecuteExW(&mut execution) }.map_err(|_| {
        UiCommandError::unavailable(
            "startup.elevation_denied",
            "Windows did not authorize starting the FairyPam Agent",
        )
    })?;
    if execution.hProcess.is_invalid() {
        return Err(UiCommandError::unavailable(
            "startup.agent_start_failed",
            "FairyPam could not bind the elevated Agent process",
        ));
    }
    broker.bind_core(execution.hProcess)?;
    Ok(())
}

#[cfg(windows)]
fn run_repair_helper() -> CommandResult<()> {
    let (helper, directory) = fixed_helper_path()?;
    verify_repair_helper_signature(&helper)?;
    let verb = HSTRING::from("runas");
    let file = HSTRING::from(helper.to_string_lossy().as_ref());
    let parameters = HSTRING::from(format!(
        "\"{REPAIR_TASK_ARGUMENT}\" \"{}\"",
        directory.to_string_lossy()
    ));
    let working_directory = HSTRING::from(directory.to_string_lossy().as_ref());
    let mut execution = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        lpDirectory: PCWSTR(working_directory.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe { ShellExecuteExW(&mut execution) }.map_err(|_| {
        UiCommandError::unavailable(
            "startup.elevation_denied",
            "Windows did not authorize repairing the FairyPam Agent tasks",
        )
    })?;
    if execution.hProcess.is_invalid() {
        return Err(UiCommandError::unavailable(
            "startup.agent_repair_failed",
            "FairyPam could not observe the task repair process",
        ));
    }
    let wait = unsafe { WaitForSingleObject(execution.hProcess, 120_000) };
    let mut exit_code = u32::MAX;
    let exited = wait == WAIT_OBJECT_0
        && unsafe { GetExitCodeProcess(execution.hProcess, &mut exit_code) }.is_ok();
    let _ = unsafe { CloseHandle(execution.hProcess) };
    if !exited || exit_code != 0 {
        return Err(UiCommandError::unavailable(
            "startup.agent_repair_failed",
            "FairyPam could not repair the Agent tasks",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn verify_repair_helper_signature(helper: &std::path::Path) -> CommandResult<()> {
    // ponytail: public CI artifacts are explicitly non-promotable and unsigned.
    if option_env!("FAIRYPAM_ALLOW_UNSIGNED_CANDIDATE_REPAIR") == Some("1") {
        return Ok(());
    }

    let path: Vec<u16> = helper.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(path.as_ptr()),
        ..Default::default()
    };
    let mut trust = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            (&mut trust as *mut WINTRUST_DATA).cast(),
        )
    };
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            (&mut trust as *mut WINTRUST_DATA).cast(),
        )
    };
    if status != 0 {
        return Err(UiCommandError::unavailable(
            "startup.agent_repair_untrusted",
            "FairyPam could not verify the installed repair helper",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn fixed_helper_path() -> CommandResult<(PathBuf, PathBuf)> {
    let gui = std::env::current_exe().map_err(|_| {
        UiCommandError::unavailable("startup.agent_unavailable", "FairyPam Agent is unavailable")
    })?;
    let version_root = gui.parent().map(|path| path.to_path_buf()).ok_or_else(|| {
        UiCommandError::unavailable("startup.agent_unavailable", "FairyPam Agent is unavailable")
    })?;
    let versions = version_root.parent().ok_or_else(untrusted_install_root)?;
    if versions.file_name().and_then(|name| name.to_str()) != Some("versions") {
        return Err(untrusted_install_root());
    }
    let install_root = versions.parent().ok_or_else(untrusted_install_root)?;
    let helper = install_root
        .join("resources")
        .join("runtime")
        .join("fairypam-agent-installer.exe");
    for path in [&gui, &helper] {
        fairypam_agent_local_client::verify_protected_program_files_path(path)
            .map_err(|_| untrusted_install_root())?;
    }
    Ok((helper, install_root.to_path_buf()))
}

#[cfg(windows)]
fn fixed_agent_path() -> CommandResult<(PathBuf, PathBuf)> {
    let (gui, directory) = active_gui_paths()?;
    let agent = directory.join("fairypam-agent.exe");
    for path in [&gui, &agent] {
        fairypam_agent_local_client::verify_protected_program_files_path(path)
            .map_err(|_| untrusted_install_root())?;
    }
    Ok((agent, directory))
}

#[cfg(windows)]
pub(crate) fn verify_active_gui() -> CommandResult<()> {
    active_gui_paths().map(|_| ())
}

#[cfg(windows)]
fn active_gui_paths() -> CommandResult<(PathBuf, PathBuf)> {
    let gui = std::env::current_exe().map_err(|_| {
        UiCommandError::unavailable("startup.agent_unavailable", "FairyPam Agent is unavailable")
    })?;
    let version_root = gui.parent().map(|path| path.to_path_buf()).ok_or_else(|| {
        UiCommandError::unavailable("startup.agent_unavailable", "FairyPam Agent is unavailable")
    })?;
    let versions = version_root.parent().ok_or_else(untrusted_install_root)?;
    if versions.file_name().and_then(|name| name.to_str()) != Some("versions") {
        return Err(untrusted_install_root());
    }
    let install_root = versions.parent().ok_or_else(untrusted_install_root)?;
    let pointer = install_root.join(fairypam_agent_suite::CURRENT_POINTER_FILE);
    for path in [&gui, &pointer] {
        fairypam_agent_local_client::verify_protected_program_files_path(path)
            .map_err(|_| untrusted_install_root())?;
    }
    let active = fairypam_agent_suite::resolve_active_suite(install_root)
        .map_err(|_| untrusted_install_root())?;
    let actual = std::fs::canonicalize(&version_root).map_err(|_| untrusted_install_root())?;
    let expected =
        std::fs::canonicalize(&active.version_root).map_err(|_| untrusted_install_root())?;
    if !actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
    {
        return Err(UiCommandError::unavailable(
            "startup.inactive_suite",
            "FairyPam must be started from the active installed version",
        ));
    }
    Ok((gui, version_root))
}

#[cfg(windows)]
fn untrusted_install_root() -> UiCommandError {
    UiCommandError::unavailable(
        "startup.install_root_untrusted",
        "FairyPam must be installed under Program Files before requesting administrator access",
    )
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use std::time::Duration;

    #[cfg(windows)]
    use super::{
        AGENT_INSTANCE_MUTEX, HUB_OBSERVATION_ATTEMPTS, HUB_OBSERVATION_INTERVAL,
        HUB_OBSERVATION_LIMIT, PIPE_DELAYS_MS, PIPE_SHUTDOWN_LIMIT, PIPE_STARTUP_LIMIT,
    };

    #[cfg(windows)]
    #[test]
    fn startup_retry_budget_is_bounded() {
        assert_eq!(PIPE_DELAYS_MS.len(), 5);
        assert!(PIPE_DELAYS_MS.iter().sum::<u64>() < PIPE_STARTUP_LIMIT.as_millis() as u64);
        assert_eq!(PIPE_SHUTDOWN_LIMIT, Duration::from_secs(10));
        assert_eq!(AGENT_INSTANCE_MUTEX, r"Global\FairyPam.Agent.v1");
        assert_eq!(HUB_OBSERVATION_ATTEMPTS, 20);
        assert_eq!(HUB_OBSERVATION_INTERVAL, Duration::from_secs(1));
        assert_eq!(HUB_OBSERVATION_LIMIT, Duration::from_secs(20));
    }
}
