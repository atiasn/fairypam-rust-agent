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
            WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA,
            WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
            WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN,
            WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        },
        System::Threading::{GetExitCodeProcess, WaitForSingleObject},
        UI::{
            Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
            WindowsAndMessaging::SW_HIDE,
        },
    },
};

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
const HUB_OBSERVATION_LIMIT: Duration = Duration::from_secs(20);
#[cfg(windows)]
const HUB_OBSERVATION_ATTEMPTS: u8 = 20;
#[cfg(windows)]
const HUB_OBSERVATION_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(windows)]
const PIPE_DELAYS_MS: [u64; 5] = [300, 600, 1_200, 2_400, 4_800];
#[cfg(windows)]
const REPAIR_TASK_ARGUMENT: &str = "--repair-tasks";

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
    #[cfg(windows)]
    {
        match state.status_with_timeout(Duration::from_secs(1)).await {
            Ok(_) => return observe_hub(&state).await,
            Err(error) if error.code == "local.transport.pipe_not_found" => {
                run_fixed_helper("--run-agent-task")?;
            }
            Err(error) => return Err(error),
        }
        wait_for_agent(&state).await
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
        run_fixed_helper("--restart-agent-task")?;
        wait_for_agent(&state).await
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
        run_repair_helper()?;
        run_fixed_helper("--run-agent-task")?;
        wait_for_agent(&state).await
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
            Ok(_) => return observe_hub(state).await,
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
fn run_fixed_helper(argument: &'static str) -> CommandResult<()> {
    if !matches!(argument, "--run-agent-task" | "--restart-agent-task") {
        return Err(UiCommandError::unavailable(
            "startup.agent_task_failed",
            "FairyPam rejected an unsupported Agent task operation",
        ));
    }
    let (helper, directory) = fixed_helper_path()?;
    let status = std::process::Command::new(helper)
        .arg(argument)
        .arg(&directory)
        .current_dir(&directory)
        .status()
        .map_err(|_| agent_task_failed())?;
    match status.code() {
        Some(0) => Ok(()),
        Some(12) => Err(UiCommandError::unavailable(
            "startup.agent_task_missing",
            "The FairyPam Agent task is missing; repair the installation",
        )),
        Some(13) => Err(UiCommandError::unavailable(
            "startup.agent_repair_required",
            "The FairyPam Agent task is invalid; repair the installation",
        )),
        _ => Err(agent_task_failed()),
    }
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
    let directory = gui.parent().map(|path| path.to_path_buf()).ok_or_else(|| {
        UiCommandError::unavailable("startup.agent_unavailable", "FairyPam Agent is unavailable")
    })?;
    let helper = directory
        .join("resources")
        .join("runtime")
        .join("fairypam-agent-installer.exe");
    for path in [&gui, &helper] {
        fairypam_agent_local_client::verify_protected_program_files_path(path)
            .map_err(|_| untrusted_install_root())?;
    }
    Ok((helper, directory))
}

#[cfg(windows)]
fn agent_task_failed() -> UiCommandError {
    UiCommandError::unavailable(
        "startup.agent_task_failed",
        "Windows could not run the FairyPam Agent task",
    )
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
        HUB_OBSERVATION_ATTEMPTS, HUB_OBSERVATION_INTERVAL, HUB_OBSERVATION_LIMIT, PIPE_DELAYS_MS,
        PIPE_STARTUP_LIMIT,
    };

    #[cfg(windows)]
    #[test]
    fn startup_retry_budget_is_bounded() {
        assert_eq!(PIPE_DELAYS_MS.len(), 5);
        assert!(PIPE_DELAYS_MS.iter().sum::<u64>() < PIPE_STARTUP_LIMIT.as_millis() as u64);
        assert_eq!(HUB_OBSERVATION_ATTEMPTS, 20);
        assert_eq!(HUB_OBSERVATION_INTERVAL, Duration::from_secs(1));
        assert_eq!(HUB_OBSERVATION_LIMIT, Duration::from_secs(20));
    }
}
