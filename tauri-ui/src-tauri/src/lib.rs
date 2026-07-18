use std::time::Duration;

use fairypam_agent_local_client::{LocalClient, LocalClientError};
use fairypam_agent_local_protocol::{
    AgentLifecycle, AutostartState, CheckStatus, ControlMode, GuardianState, InstallationState,
    LocalCommand, LocalErrorCode, LocalPayload, TargetSummary, UpdateState,
};
use serde::Serialize;
use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager,
};
use tokio_util::sync::CancellationToken;

const CLIENT_NAME: &str = "fairypam-agent-ui";
const STATE_EVENT: &str = "agent-state";

#[derive(Clone)]
struct AppState {
    client: Option<LocalClient>,
    startup_error: Option<CommandError>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandError {
    code: String,
    message: String,
    retryable: bool,
}

impl CommandError {
    fn protocol(message: impl Into<String>) -> Self {
        Self {
            code: "protocol_error".into(),
            message: message.into(),
            retryable: false,
        }
    }
}

impl From<LocalClientError> for CommandError {
    fn from(error: LocalClientError) -> Self {
        let retryable = matches!(
            &error,
            LocalClientError::Unavailable
                | LocalClientError::Timeout
                | LocalClientError::Io(_)
                | LocalClientError::Remote {
                    retryable: true,
                    ..
                }
        );
        let code = match &error {
            LocalClientError::Remote { code, .. } => local_error_code(*code),
            _ => error.category(),
        };
        Self {
            code: code.into(),
            message: error.to_string(),
            retryable,
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentStatusDto {
    lifecycle: String,
    active_profile_id: Option<String>,
    target_locked: bool,
    capture_active: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsDto {
    agent_version: String,
    build_commit: String,
    protocol: String,
    control_connected: bool,
    audit_enabled: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DoctorCheckDto {
    component: String,
    status: String,
    summary: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TargetDto {
    target_id: String,
    title: String,
    process_name: String,
    foreground: Option<bool>,
    capturable: Option<bool>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseDto {
    holds: u32,
    state: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SuiteStatusDto {
    installation: String,
    guardian: String,
    control_mode: String,
    update: String,
    autostart: String,
    can_request_update: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PreviewDto {
    mime_type: String,
    data_base64: String,
    width: u32,
    height: u32,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceDto {
    action: String,
    accepted: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum AgentStateEvent {
    Status { status: AgentStatusDto },
    Offline { error: CommandError },
    Emergency { release: ReleaseDto },
    StopRequested {},
}

pub fn run() -> tauri::Result<()> {
    let (client, startup_error) = match LocalClient::production(CLIENT_NAME) {
        Ok(client) => (Some(client), None),
        Err(error) => (None, Some(error.into())),
    };
    let state = AppState {
        client,
        startup_error,
    };

    tauri::Builder::default()
        .manage(state)
        .setup(|app| {
            install_tray(app)?;
            start_state_monitor(app);
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            query_agent_status,
            query_diagnostics,
            query_suite_status,
            run_doctor,
            list_profiles,
            list_targets,
            select_target,
            focus_target,
            close_target,
            capture_preview,
            request_update,
            set_autostart,
            emergency_release_all,
        ])
        .run(tauri::generate_context!())
}

fn install_tray(app: &mut tauri::App) -> tauri::Result<()> {
    let show = MenuItemBuilder::with_id("show", "显示主窗口").build(app)?;
    let stop = MenuItemBuilder::with_id("stop", "停止 Agent…").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "退出界面").build(app)?;
    let menu = MenuBuilder::new(app)
        .items(&[&show, &stop, &quit])
        .build()?;
    let mut tray = TrayIconBuilder::new()
        .menu(&menu)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_main_window(app),
            "stop" => {
                show_main_window(app);
                let _ = app.emit(STATE_EVENT, AgentStateEvent::StopRequested {});
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn start_state_monitor(app: &tauri::App) {
    let app_handle = app.handle().clone();
    let state = app.state::<AppState>();
    let Some(client) = state.client.clone() else {
        if let Some(error) = state.startup_error.clone() {
            let _ = app_handle.emit(STATE_EVENT, AgentStateEvent::Offline { error });
        }
        return;
    };

    tauri::async_runtime::spawn(async move {
        loop {
            let event = match request(&client, LocalCommand::Status {}).await {
                Ok(payload) => match status_from_payload(payload) {
                    Ok(status) => AgentStateEvent::Status { status },
                    Err(error) => AgentStateEvent::Offline { error },
                },
                Err(error) => AgentStateEvent::Offline { error },
            };
            let _ = app_handle.emit(STATE_EVENT, event);
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

async fn request(
    client: &LocalClient,
    command: LocalCommand,
) -> Result<LocalPayload, CommandError> {
    client
        .request(command, CancellationToken::new())
        .await
        .map_err(Into::into)
}

async fn state_client(state: &tauri::State<'_, AppState>) -> Result<LocalClient, CommandError> {
    state.client.clone().ok_or_else(|| {
        state
            .startup_error
            .clone()
            .unwrap_or_else(|| CommandError::protocol("local client unavailable"))
    })
}

#[tauri::command]
async fn query_agent_status(
    state: tauri::State<'_, AppState>,
) -> Result<AgentStatusDto, CommandError> {
    let client = state_client(&state).await?;
    status_from_payload(request(&client, LocalCommand::Status {}).await?)
}

#[tauri::command]
async fn query_diagnostics(
    state: tauri::State<'_, AppState>,
) -> Result<DiagnosticsDto, CommandError> {
    let client = state_client(&state).await?;
    diagnostics_from_payload(request(&client, LocalCommand::Diagnostics {}).await?)
}

#[tauri::command]
async fn query_suite_status(
    state: tauri::State<'_, AppState>,
) -> Result<SuiteStatusDto, CommandError> {
    let client = state_client(&state).await?;
    suite_status_from_payload(request(&client, LocalCommand::SuiteStatus {}).await?)
}

#[tauri::command]
async fn run_doctor(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<DoctorCheckDto>, CommandError> {
    let client = state_client(&state).await?;
    match request(&client, LocalCommand::Doctor {}).await? {
        LocalPayload::Doctor { checks } => Ok(checks
            .into_iter()
            .map(|check| DoctorCheckDto {
                component: check.component,
                status: check_status(check.status).into(),
                summary: check.summary,
            })
            .collect()),
        payload => Err(unexpected("doctor", &payload)),
    }
}

#[tauri::command]
async fn list_profiles(state: tauri::State<'_, AppState>) -> Result<Vec<String>, CommandError> {
    let client = state_client(&state).await?;
    match request(&client, LocalCommand::ListProfiles {}).await? {
        LocalPayload::Profiles { profile_ids } => Ok(profile_ids),
        payload => Err(unexpected("profiles", &payload)),
    }
}

#[tauri::command]
async fn list_targets(
    state: tauri::State<'_, AppState>,
    profile_id: String,
) -> Result<Vec<TargetDto>, CommandError> {
    let client = state_client(&state).await?;
    match request(&client, LocalCommand::ListTargets { profile_id }).await? {
        LocalPayload::Targets { targets, .. } => {
            Ok(targets.into_iter().map(target_summary).collect())
        }
        payload => Err(unexpected("targets", &payload)),
    }
}

#[tauri::command]
async fn select_target(
    state: tauri::State<'_, AppState>,
    profile_id: String,
    target_id: String,
) -> Result<TargetDto, CommandError> {
    let client = state_client(&state).await?;
    target_from_payload(
        request(
            &client,
            LocalCommand::SelectTarget {
                profile_id,
                target_id,
            },
        )
        .await?,
    )
}

#[tauri::command]
async fn focus_target(state: tauri::State<'_, AppState>) -> Result<TargetDto, CommandError> {
    let client = state_client(&state).await?;
    target_from_payload(request(&client, LocalCommand::FocusTarget {}).await?)
}

#[tauri::command]
async fn close_target(
    state: tauri::State<'_, AppState>,
    timeout_ms: u32,
) -> Result<TargetDto, CommandError> {
    let client = state_client(&state).await?;
    target_from_payload(request(&client, LocalCommand::CloseTarget { timeout_ms }).await?)
}

#[tauri::command]
async fn capture_preview(
    state: tauri::State<'_, AppState>,
    quality: u8,
) -> Result<PreviewDto, CommandError> {
    let client = state_client(&state).await?;
    match request(&client, LocalCommand::CapturePreview { quality }).await? {
        LocalPayload::Preview {
            mime_type,
            data_base64,
            width,
            height,
        } => Ok(PreviewDto {
            mime_type,
            data_base64,
            width,
            height,
        }),
        payload => Err(unexpected("preview", &payload)),
    }
}

#[tauri::command]
async fn request_update(state: tauri::State<'_, AppState>) -> Result<MaintenanceDto, CommandError> {
    let client = state_client(&state).await?;
    maintenance_from_payload(request(&client, LocalCommand::RequestUpdate {}).await?)
}

#[tauri::command]
async fn set_autostart(
    state: tauri::State<'_, AppState>,
    enabled: bool,
) -> Result<MaintenanceDto, CommandError> {
    let client = state_client(&state).await?;
    maintenance_from_payload(request(&client, LocalCommand::SetAutostart { enabled }).await?)
}

#[tauri::command]
async fn emergency_release_all(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<ReleaseDto, CommandError> {
    let client = state_client(&state).await?;
    let release = match request(&client, LocalCommand::ReleaseAll {}).await? {
        LocalPayload::Released { holds, state } => ReleaseDto { holds, state },
        payload => return Err(unexpected("released", &payload)),
    };
    let _ = app.emit(
        STATE_EVENT,
        AgentStateEvent::Emergency {
            release: release.clone(),
        },
    );
    Ok(release)
}

#[doc(hidden)]
pub fn status_from_payload(payload: LocalPayload) -> Result<AgentStatusDto, CommandError> {
    match payload {
        LocalPayload::Status {
            lifecycle,
            active_profile_id,
            target_locked,
            capture_active,
        } => Ok(AgentStatusDto {
            lifecycle: lifecycle_name(lifecycle).into(),
            active_profile_id,
            target_locked,
            capture_active,
        }),
        payload => Err(unexpected("status", &payload)),
    }
}

#[doc(hidden)]
pub fn diagnostics_from_payload(payload: LocalPayload) -> Result<DiagnosticsDto, CommandError> {
    match payload {
        LocalPayload::Diagnostics {
            agent_version,
            build_commit,
            protocol,
            control_connected,
            audit_enabled,
        } => Ok(DiagnosticsDto {
            agent_version,
            build_commit,
            protocol,
            control_connected,
            audit_enabled,
        }),
        payload => Err(unexpected("diagnostics", &payload)),
    }
}

#[doc(hidden)]
pub fn suite_status_from_payload(payload: LocalPayload) -> Result<SuiteStatusDto, CommandError> {
    match payload {
        LocalPayload::SuiteStatus {
            installation,
            guardian,
            control_mode,
            update,
            autostart,
            can_request_update,
        } => Ok(SuiteStatusDto {
            installation: installation_name(installation).into(),
            guardian: guardian_name(guardian).into(),
            control_mode: control_mode_name(control_mode).into(),
            update: update_name(update).into(),
            autostart: autostart_name(autostart).into(),
            can_request_update,
        }),
        payload => Err(unexpected("suite_status", &payload)),
    }
}

fn maintenance_from_payload(payload: LocalPayload) -> Result<MaintenanceDto, CommandError> {
    match payload {
        LocalPayload::Maintenance { action, accepted } => Ok(MaintenanceDto { action, accepted }),
        payload => Err(unexpected("maintenance", &payload)),
    }
}

fn target_from_payload(payload: LocalPayload) -> Result<TargetDto, CommandError> {
    match payload {
        LocalPayload::Target {
            target_id,
            title,
            process_name,
            foreground,
            capturable,
            ..
        } => Ok(TargetDto {
            target_id,
            title,
            process_name,
            foreground,
            capturable,
        }),
        payload => Err(unexpected("target", &payload)),
    }
}

fn target_summary(target: TargetSummary) -> TargetDto {
    TargetDto {
        target_id: target.target_id,
        title: target.title,
        process_name: target.process_name,
        foreground: None,
        capturable: None,
    }
}

fn unexpected(expected: &str, payload: &LocalPayload) -> CommandError {
    CommandError::protocol(format!(
        "local Agent returned {} payload for {expected}",
        payload_name(payload)
    ))
}

fn payload_name(payload: &LocalPayload) -> &'static str {
    match payload {
        LocalPayload::Hello { .. } => "hello",
        LocalPayload::Status { .. } => "status",
        LocalPayload::Doctor { .. } => "doctor",
        LocalPayload::Profiles { .. } => "profiles",
        LocalPayload::Targets { .. } => "targets",
        LocalPayload::Target { .. } => "target",
        LocalPayload::Diagnostics { .. } => "diagnostics",
        LocalPayload::SuiteStatus { .. } => "suite_status",
        LocalPayload::Preview { .. } => "preview",
        LocalPayload::Maintenance { .. } => "maintenance",
        LocalPayload::Released { .. } => "released",
    }
}

fn lifecycle_name(lifecycle: AgentLifecycle) -> &'static str {
    match lifecycle {
        AgentLifecycle::Starting => "starting",
        AgentLifecycle::Connected => "connected",
        AgentLifecycle::Disconnected => "disconnected",
    }
}

fn check_status(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Ok => "ok",
        CheckStatus::Warning => "warning",
        CheckStatus::Error => "error",
    }
}

fn installation_name(state: InstallationState) -> &'static str {
    match state {
        InstallationState::Healthy => "healthy",
        InstallationState::Incomplete => "incomplete",
    }
}

fn guardian_name(state: GuardianState) -> &'static str {
    match state {
        GuardianState::Installed => "installed",
        GuardianState::Missing => "missing",
    }
}

fn control_mode_name(state: ControlMode) -> &'static str {
    match state {
        ControlMode::Unknown => "unknown",
        ControlMode::DryRun => "dry_run",
    }
}

fn update_name(state: UpdateState) -> &'static str {
    match state {
        UpdateState::Idle => "idle",
        UpdateState::Quiesced => "quiesced",
    }
}

fn autostart_name(state: AutostartState) -> &'static str {
    match state {
        AutostartState::Enabled => "enabled",
        AutostartState::Disabled => "disabled",
        AutostartState::Missing => "missing",
    }
}

fn local_error_code(code: LocalErrorCode) -> &'static str {
    match code {
        LocalErrorCode::InvalidArgument => "invalid_argument",
        LocalErrorCode::ProtocolViolation => "protocol_error",
        LocalErrorCode::ProtocolVersionMismatch => "protocol_version_mismatch",
        LocalErrorCode::MessageTooLarge => "message_too_large",
        LocalErrorCode::ReplayDetected => "replay_detected",
        LocalErrorCode::PermissionDenied => "permission_denied",
        LocalErrorCode::AgentUnavailable => "agent_unavailable",
        LocalErrorCode::TargetUnavailable => "target_unavailable",
        LocalErrorCode::OperationFailed => "operation_failed",
        LocalErrorCode::UnsupportedCapability => "unsupported_capability",
    }
}
