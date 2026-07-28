#[cfg(windows)]
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use crate::{
    dto::{
        ConnectionStatusDto, EnvironmentCheckDto, InstalledGamesDto, LogTailDto, OverviewDto,
        RegistrationStatusDto, SupportStatusDto,
    },
    local_gateway::{ProductionGateway, UiCommandError},
};
use tauri::State;

type CommandResult<T> = Result<T, UiCommandError>;

#[cfg(windows)]
const HUB_OBSERVATION_LIMIT: Duration = Duration::from_secs(20);
#[cfg(windows)]
const HUB_OBSERVATION_ATTEMPTS: u8 = 20;
#[cfg(windows)]
const HUB_OBSERVATION_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(windows)]
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
        observe_hub(state).await
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

pub(crate) async fn shutdown_local_agent_for_exit(state: &ProductionGateway) -> CommandResult<()> {
    #[cfg(windows)]
    {
        let _lifecycle = state.acquire_lifecycle()?;
        state.shutdown_agent().await
    }
    #[cfg(not(windows))]
    {
        let _ = state;
        Ok(())
    }
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
    use super::{HUB_OBSERVATION_ATTEMPTS, HUB_OBSERVATION_INTERVAL, HUB_OBSERVATION_LIMIT};

    #[cfg(windows)]
    #[test]
    fn hub_observation_budget_is_bounded() {
        assert_eq!(HUB_OBSERVATION_ATTEMPTS, 20);
        assert_eq!(HUB_OBSERVATION_INTERVAL, Duration::from_secs(1));
        assert_eq!(HUB_OBSERVATION_LIMIT, Duration::from_secs(20));
    }
}
