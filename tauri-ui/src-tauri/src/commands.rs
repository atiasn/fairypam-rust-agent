use tauri::State;

use crate::{
    dto::{
        CaptureStateDto, ConnectionStatusDto, DoctorDto, EnvironmentCheckDto, ExportResultDto,
        FocusedTargetDto, InstalledGamesDto, LockedTargetDto, LogTailDto, OverviewDto, ProfilesDto,
        ReleaseAllDto, SupportStatusDto, TargetsDto,
    },
    local_gateway::{ProductionGateway, UiCommandError},
};

type CommandResult<T> = Result<T, UiCommandError>;

fn identifier(value: String, field: &str) -> Result<String, UiCommandError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    valid.then_some(value).ok_or_else(|| {
        UiCommandError::unavailable(
            "local.command.invalid_argument",
            format!("{field} must be a 1..128 character identifier"),
        )
    })
}

#[tauri::command]
pub async fn get_overview(state: State<'_, ProductionGateway>) -> CommandResult<OverviewDto> {
    state.overview().await
}

#[tauri::command]
pub async fn get_doctor(state: State<'_, ProductionGateway>) -> CommandResult<DoctorDto> {
    state.doctor().await
}

#[tauri::command]
pub async fn list_profiles(state: State<'_, ProductionGateway>) -> CommandResult<ProfilesDto> {
    state.profiles().await
}

#[tauri::command]
pub async fn list_targets(
    profile_id: String,
    state: State<'_, ProductionGateway>,
) -> CommandResult<TargetsDto> {
    state.targets(identifier(profile_id, "profile_id")?).await
}

#[tauri::command]
pub async fn lock_target(
    profile_id: String,
    candidate_id: String,
    state: State<'_, ProductionGateway>,
) -> CommandResult<LockedTargetDto> {
    state
        .lock_target(
            identifier(profile_id, "profile_id")?,
            identifier(candidate_id, "candidate_id")?,
        )
        .await
}

#[tauri::command]
pub async fn focus_target(state: State<'_, ProductionGateway>) -> CommandResult<FocusedTargetDto> {
    state.focus_target().await
}

#[tauri::command]
pub async fn stop_capture(
    source_id: String,
    state: State<'_, ProductionGateway>,
) -> CommandResult<CaptureStateDto> {
    state
        .stop_capture(identifier(source_id, "source_id")?)
        .await
}

#[tauri::command]
pub async fn release_all(state: State<'_, ProductionGateway>) -> CommandResult<ReleaseAllDto> {
    state.release_all().await
}

#[tauri::command]
pub async fn get_update_status(
    state: State<'_, ProductionGateway>,
) -> CommandResult<SupportStatusDto> {
    state.update_status().await
}

#[tauri::command]
pub async fn get_startup_status(
    state: State<'_, ProductionGateway>,
) -> CommandResult<SupportStatusDto> {
    state.startup_status().await
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
pub fn export_diagnostics() -> CommandResult<ExportResultDto> {
    Ok(ExportResultDto {
        saved: false,
        reason_code: Some("diagnostics.export_unavailable".into()),
    })
}

#[tauri::command]
pub fn stop_agent_after_confirmation(confirmation: String) -> CommandResult<SupportStatusDto> {
    if confirmation != "STOP_AGENT" {
        return Err(UiCommandError::unavailable(
            "local.command.confirmation_required",
            "stopping the Agent requires the explicit STOP_AGENT confirmation",
        ));
    }
    Err(UiCommandError::unavailable(
        "local.command.agent_stop_unavailable",
        "the local protocol does not expose an Agent stop command",
    ))
}

#[tauri::command]
pub fn start_enrollment() -> CommandResult<SupportStatusDto> {
    #[cfg(windows)]
    {
        let ui_executable = std::env::current_exe().map_err(|_| {
            UiCommandError::unavailable(
                "enrollment.helper_unavailable",
                "the enrolled Agent helper is unavailable",
            )
        })?;
        let helper = ui_executable
            .parent()
            .map(|directory| directory.join("fairypam-agentctl.exe"))
            .ok_or_else(|| {
                UiCommandError::unavailable(
                    "enrollment.helper_unavailable",
                    "the enrolled Agent helper is unavailable",
                )
            })?;
        let metadata = std::fs::symlink_metadata(&helper).map_err(|_| {
            UiCommandError::unavailable(
                "enrollment.helper_unavailable",
                "the enrolled Agent helper is unavailable",
            )
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(UiCommandError::unavailable(
                "enrollment.helper_unavailable",
                "the enrolled Agent helper is unavailable",
            ));
        }
        let status = std::process::Command::new(helper)
            .arg("enroll")
            .status()
            .map_err(|_| {
                UiCommandError::unavailable(
                    "enrollment.launch_failed",
                    "the enrollment helper could not be started",
                )
            })?;
        if !status.success() {
            return Err(UiCommandError::unavailable(
                "enrollment.launch_failed",
                "the enrollment helper could not be started",
            ));
        }
        return Ok(SupportStatusDto {
            status: "elevation_requested".into(),
        });
    }
    #[cfg(not(windows))]
    Err(UiCommandError::unavailable(
        "local.transport.platform_unsupported",
        "FairyPam Agent enrollment requires Windows",
    ))
}
