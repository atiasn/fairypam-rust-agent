use tauri::State;

use crate::{
    dto::{
        CaptureStateDto, DoctorDto, ExportResultDto, FocusedTargetDto, LockedTargetDto,
        OverviewDto, ProfilesDto, ReleaseAllDto, SupportStatusDto, TargetsDto,
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
