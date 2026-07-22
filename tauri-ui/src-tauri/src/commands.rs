#[cfg(windows)]
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use tauri::State;
#[cfg(windows)]
use windows::{
    core::HSTRING,
    Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_HIDE},
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
        let deadline = Instant::now() + PIPE_STARTUP_LIMIT;
        match state.status_with_timeout(Duration::from_secs(1)).await {
            Ok(_) => return bind_and_observe_hub(&state).await,
            Err(error) if error.code == "local.transport.pipe_not_found" => {
                state.clear_ui_lifetime_binding();
            }
            Err(error) => return Err(error),
        }

        launch_fixed_agent()?;
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
                Ok(_) => return bind_and_observe_hub(&state).await,
                Err(error) if error.code == "local.transport.pipe_not_found" => {}
                Err(error) => return Err(error),
            }
        }
        Err(UiCommandError::unavailable(
            "startup.pipe_timeout",
            "FairyPam Agent did not become ready within 20 seconds",
        ))
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

#[cfg(windows)]
async fn bind_and_observe_hub(state: &ProductionGateway) -> CommandResult<SupportStatusDto> {
    state.bind_ui_lifetime().await?;
    observe_hub(state).await
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
        if status.hub_address.trim().is_empty() {
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
    let result = unsafe {
        ShellExecuteW(
            None,
            &HSTRING::from("runas"),
            &HSTRING::from(agent.to_string_lossy().as_ref()),
            &HSTRING::new(),
            &HSTRING::from(directory.to_string_lossy().as_ref()),
            SW_HIDE,
        )
    };
    if result.0 as usize <= 32 {
        return Err(UiCommandError::unavailable(
            "startup.elevation_denied",
            "Windows did not authorize starting the FairyPam Agent",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn fixed_agent_path() -> CommandResult<(PathBuf, PathBuf)> {
    let gui = std::env::current_exe().map_err(|_| {
        UiCommandError::unavailable("startup.agent_unavailable", "FairyPam Agent is unavailable")
    })?;
    let directory = gui.parent().map(|path| path.to_path_buf()).ok_or_else(|| {
        UiCommandError::unavailable("startup.agent_unavailable", "FairyPam Agent is unavailable")
    })?;
    let agent = directory.join("fairypam-agent.exe");
    for path in [&gui, &agent] {
        fairypam_agent_local_client::verify_protected_program_files_path(path)
            .map_err(|_| untrusted_install_root())?;
    }
    Ok((agent, directory))
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
