#[cfg(windows)]
use std::time::{Duration, Instant};

use tauri::State;

use crate::{
    dto::{
        ConnectionStatusDto, EnvironmentCheckDto, InstalledGamesDto, LogTailDto, OverviewDto,
        SupportStatusDto,
    },
    local_gateway::{ProductionGateway, UiCommandError},
};

type CommandResult<T> = Result<T, UiCommandError>;

#[cfg(windows)]
const PIPE_CHECK_LIMIT: u8 = 6;
#[cfg(windows)]
const PIPE_STARTUP_LIMIT: Duration = Duration::from_secs(20);
#[cfg(windows)]
const HUB_OBSERVATION_LIMIT: Duration = Duration::from_secs(20);
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
pub fn get_enrollment_mode() -> SupportStatusDto {
    #[cfg(windows)]
    let status = if fairypam_agentctl::enrollment::is_elevated_ui_invocation(
        &std::env::args().skip(1).collect::<Vec<_>>(),
    ) {
        "elevated"
    } else {
        "standard"
    };
    #[cfg(not(windows))]
    let status = "unsupported";
    SupportStatusDto {
        status: status.into(),
    }
}

#[tauri::command]
pub fn start_enrollment() -> CommandResult<SupportStatusDto> {
    #[cfg(windows)]
    {
        fairypam_agentctl::enrollment::launch_elevated_gui().map_err(enrollment_error)?;
        Ok(SupportStatusDto {
            status: "elevation_requested".into(),
        })
    }
    #[cfg(not(windows))]
    Err(UiCommandError::unavailable(
        "local.transport.platform_unsupported",
        "FairyPam Agent enrollment requires Windows",
    ))
}

#[tauri::command]
#[cfg_attr(not(windows), allow(dead_code))]
pub fn complete_enrollment(hub: String, code: String) -> CommandResult<SupportStatusDto> {
    #[cfg(windows)]
    {
        let arguments = std::env::args().skip(1).collect::<Vec<_>>();
        if !fairypam_agentctl::enrollment::is_elevated_ui_invocation(&arguments) {
            return Err(UiCommandError::unavailable(
                "enrollment.elevation_required",
                "registration must be completed in the elevated FairyPam window",
            ));
        }
        fairypam_agentctl::enrollment::enroll(&hub, &code).map_err(enrollment_error)?;
        Ok(SupportStatusDto {
            status: "completed".into(),
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (hub, code);
        Err(UiCommandError::unavailable(
            "local.transport.platform_unsupported",
            "FairyPam Agent enrollment requires Windows",
        ))
    }
}

#[tauri::command]
pub async fn ensure_local_agent(
    state: State<'_, ProductionGateway>,
) -> CommandResult<SupportStatusDto> {
    #[cfg(windows)]
    {
        let deadline = Instant::now() + PIPE_STARTUP_LIMIT;
        for attempt in 1..=PIPE_CHECK_LIMIT {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if state
                .overview_with_timeout(remaining.min(Duration::from_secs(1)))
                .await
                .is_ok()
            {
                return observe_hub(&state).await;
            }
            if attempt == 1 {
                fairypam_agentctl::enrollment::start_fixed_agent_task()
                    .map_err(enrollment_error)?;
            }
            if let Some(delay) = PIPE_DELAYS_MS.get((attempt - 1) as usize) {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(*delay).min(remaining)).await;
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
async fn observe_hub(state: &ProductionGateway) -> CommandResult<SupportStatusDto> {
    let deadline = Instant::now() + HUB_OBSERVATION_LIMIT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(SupportStatusDto {
                status: "hub_wait_timeout".into(),
            });
        }
        if let Ok(status) = state
            .connection_status_with_timeout(remaining.min(Duration::from_secs(1)))
            .await
        {
            if status.control.eq_ignore_ascii_case("connected")
                && status.frame.eq_ignore_ascii_case("connected")
            {
                return Ok(SupportStatusDto {
                    status: "ready".into(),
                });
            }
        }
        tokio::time::sleep(Duration::from_secs(1).min(remaining)).await;
    }
}

#[cfg(windows)]
fn enrollment_error(error: fairypam_agentctl::CliError) -> UiCommandError {
    match error {
        fairypam_agentctl::CliError::Client(error) => {
            UiCommandError::unavailable(error.code(), error.to_string())
        }
        fairypam_agentctl::CliError::Usage(message) => {
            UiCommandError::unavailable("enrollment.invalid", message)
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::{PIPE_CHECK_LIMIT, PIPE_DELAYS_MS, PIPE_STARTUP_LIMIT};

    #[cfg(windows)]
    #[test]
    fn startup_retry_budget_is_bounded() {
        assert_eq!(PIPE_CHECK_LIMIT, 6);
        assert_eq!(PIPE_DELAYS_MS.len(), (PIPE_CHECK_LIMIT - 1) as usize);
        assert!(PIPE_DELAYS_MS.iter().sum::<u64>() < PIPE_STARTUP_LIMIT.as_millis() as u64);
    }
}
