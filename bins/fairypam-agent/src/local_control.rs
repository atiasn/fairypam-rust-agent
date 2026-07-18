use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
#[cfg(feature = "dev-automation")]
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use fairypam_agent_core::AgentError;
use fairypam_agent_local_client::{CallerIdentity, ClientIntegrity, LocalRequestHandler};
use fairypam_agent_local_protocol::{
    AgentLifecycle, AutostartState, CheckStatus, DoctorCheck, GuardianState, InstallationState,
    LocalCommand, LocalErrorCode, LocalPayload, LocalRequest, LocalResponse, ProtocolError,
    TargetSummary, UpdateState,
};
use fairypam_agent_suite::SuiteManifest;

#[cfg(feature = "dev-automation")]
use fairypam_agent_dev_automation::AutomationManager;
#[cfg(feature = "dev-automation")]
use fairypam_agent_local_protocol::AutomationCapability;

use crate::execution::CommandExecutor;
use crate::profile_store::ProfileStore;
use crate::runtime::RuntimeState;

pub(crate) struct AgentLocalControl {
    state: Arc<Mutex<RuntimeState>>,
    execution: Arc<Mutex<CommandExecutor>>,
    profiles: ProfileStore,
    agent_version: String,
    build_commit: String,
    #[cfg(feature = "dev-automation")]
    automation: Mutex<AutomationManager>,
    #[cfg(feature = "dev-automation")]
    dev_input: Arc<Mutex<crate::dev_input::DevInputController>>,
}

impl AgentLocalControl {
    pub(crate) fn new(
        state: Arc<Mutex<RuntimeState>>,
        execution: Arc<Mutex<CommandExecutor>>,
        profiles: ProfileStore,
        agent_version: String,
        build_commit: String,
        #[cfg(feature = "dev-automation")] provisioned_build_id: String,
        #[cfg(feature = "dev-automation")] dev_input: Arc<
            Mutex<crate::dev_input::DevInputController>,
        >,
    ) -> Self {
        #[cfg(feature = "dev-automation")]
        let mut automation = AutomationManager::default();
        #[cfg(feature = "dev-automation")]
        automation.set_provisioned_build_id(provisioned_build_id);
        Self {
            state,
            execution,
            profiles,
            agent_version,
            build_commit,
            #[cfg(feature = "dev-automation")]
            automation: Mutex::new(automation),
            #[cfg(feature = "dev-automation")]
            dev_input,
        }
    }

    fn dispatch(
        &self,
        caller: &CallerIdentity,
        request: &LocalRequest,
    ) -> Result<LocalPayload, ProtocolError> {
        #[cfg(not(feature = "dev-automation"))]
        let _ = caller;
        #[cfg(feature = "dev-automation")]
        self.expire_automation()?;
        // Cargo feature unification can expose dependency-only dev variants to a
        // production package selected in a broad workspace command. Keep that
        // accidental surface fail-closed without making the normal production
        // graph warn about an otherwise unreachable catch-all arm.
        #[allow(unreachable_patterns)]
        match &request.command {
            LocalCommand::Hello { .. } => Err(ProtocolError::new(
                LocalErrorCode::ProtocolViolation,
                "hello is handled by the local transport",
            )),
            LocalCommand::Status {} => {
                let connected = self.state()?.session.is_some();
                let execution = self.execution()?;
                let status = execution.local_status();
                Ok(LocalPayload::Status {
                    lifecycle: if connected {
                        AgentLifecycle::Connected
                    } else {
                        AgentLifecycle::Disconnected
                    },
                    active_profile_id: status.active_profile_id,
                    target_locked: status.target_locked,
                    capture_active: status.capture_active,
                })
            }
            LocalCommand::Doctor {} => {
                let connected = self.state()?.session.is_some();
                let status = self.execution()?.local_status();
                let guardian_installed = guardian_path().is_ok();
                Ok(LocalPayload::Doctor {
                    checks: vec![
                        DoctorCheck {
                            component: "core_control".into(),
                            status: if connected {
                                CheckStatus::Ok
                            } else {
                                CheckStatus::Warning
                            },
                            summary: if connected {
                                "verified Core control session is connected"
                            } else {
                                "Core control session is disconnected"
                            }
                            .into(),
                        },
                        DoctorCheck {
                            component: "target_runtime".into(),
                            status: CheckStatus::Ok,
                            summary: format!(
                                "signed Profile target runtime ready; locked={}",
                                status.target_locked
                            ),
                        },
                        DoctorCheck {
                            component: "guardian".into(),
                            status: if guardian_installed {
                                CheckStatus::Warning
                            } else {
                                CheckStatus::Error
                            },
                            summary: if guardian_installed {
                                "suite Guardian member is present; runtime health is not exposed"
                            } else {
                                "Guardian executable is missing from the active suite"
                            }
                            .into(),
                        },
                    ],
                })
            }
            LocalCommand::ListProfiles {} => Ok(LocalPayload::Profiles {
                profile_ids: self.profiles.ids(),
            }),
            LocalCommand::ListTargets { profile_id } => {
                let targets = self
                    .execution()?
                    .local_list_targets(profile_id)
                    .map_err(map_agent)?
                    .into_iter()
                    .map(|target| TargetSummary {
                        target_id: target.target_id,
                        title: target.title,
                        process_name: target.process_name,
                    })
                    .collect();
                Ok(LocalPayload::Targets {
                    profile_id: profile_id.clone(),
                    targets,
                })
            }
            LocalCommand::SelectTarget {
                profile_id,
                target_id,
            } => {
                let target = self
                    .execution()?
                    .local_select_target(profile_id, target_id)
                    .map_err(map_agent)?;
                Ok(target_payload(target))
            }
            LocalCommand::FocusTarget {} => {
                let target = self.execution()?.local_focus_target().map_err(map_agent)?;
                Ok(target_payload(target))
            }
            LocalCommand::CloseTarget { timeout_ms } => {
                let target = self
                    .execution()?
                    .local_close_target(*timeout_ms)
                    .map_err(map_agent)?;
                Ok(target_payload(target))
            }
            LocalCommand::Diagnostics {} => Ok(LocalPayload::Diagnostics {
                agent_version: self.agent_version.clone(),
                build_commit: self.build_commit.clone(),
                protocol: "fairypam-local-v1".into(),
                control_connected: self.state()?.session.is_some(),
                audit_enabled: true,
            }),
            LocalCommand::SuiteStatus {} => self.suite_status(),
            LocalCommand::CapturePreview { quality } => {
                let preview = self
                    .execution()?
                    .local_capture_preview(*quality)
                    .map_err(map_agent)?;
                Ok(LocalPayload::Preview {
                    mime_type: preview.mime_type.into(),
                    data_base64: STANDARD.encode(preview.bytes),
                    width: preview.width,
                    height: preview.height,
                })
            }
            LocalCommand::RequestUpdate {} => {
                run_update_task()?;
                Ok(LocalPayload::Maintenance {
                    action: "update_task_started".into(),
                    accepted: true,
                })
            }
            LocalCommand::SetAutostart { enabled } => {
                set_agent_autostart(*enabled)?;
                Ok(LocalPayload::Maintenance {
                    action: if *enabled {
                        "autostart_enabled"
                    } else {
                        "autostart_disabled"
                    }
                    .into(),
                    accepted: true,
                })
            }
            LocalCommand::ReleaseAll {} => {
                #[cfg(feature = "dev-automation")]
                self.release_dev_input()?;
                let holds = self.execution()?.local_release_all().map_err(map_agent)?;
                Ok(LocalPayload::Released {
                    holds,
                    state: "safe".into(),
                })
            }
            LocalCommand::PrepareUpdate { .. } => {
                require_high_integrity(caller)?;
                self.state()?.accepting_commands = false;
                #[cfg(feature = "dev-automation")]
                self.release_dev_input()?;
                let holds = self.execution()?.local_release_all().map_err(map_agent)?;
                Ok(LocalPayload::Released {
                    holds,
                    state: "update_quiesced".into(),
                })
            }
            LocalCommand::ResumeAfterUpdateFailure {} => {
                require_high_integrity(caller)?;
                self.state()?.accepting_commands = true;
                Ok(LocalPayload::Released {
                    holds: 0,
                    state: "accepting".into(),
                })
            }
            #[cfg(feature = "dev-automation")]
            LocalCommand::DevStatus {} => {
                let automation = self.automation()?;
                Ok(LocalPayload::DevStatus {
                    provisioned_build_id: automation.provisioned_build_id().map(str::to_owned),
                    active_session_id: automation.active().map(|value| value.session_id.clone()),
                    expires_at_unix_ms: automation.active().map(|value| value.expires_at_unix_ms),
                })
            }
            #[cfg(feature = "dev-automation")]
            LocalCommand::DevStartAutomation {
                target,
                capabilities,
                ttl_ms,
            } => {
                let mut automation = self.automation()?;
                let session = automation.start(
                    caller,
                    target.clone(),
                    capabilities.clone(),
                    Duration::from_millis(u64::from(*ttl_ms)),
                    request.request_id.clone(),
                    Instant::now(),
                )?;
                Ok(LocalPayload::AutomationSession {
                    session_id: session.session_id.clone(),
                    expires_at_unix_ms: session.expires_at_unix_ms,
                })
            }
            #[cfg(feature = "dev-automation")]
            LocalCommand::DevPulseTestbed { session_id } => {
                let (target, expires_at) = {
                    let mut automation = self.automation()?;
                    let session = automation.authorize_testbed_action(
                        caller,
                        session_id,
                        AutomationCapability::PulseTestAction,
                        Instant::now(),
                    )?;
                    (session.target.clone(), session.expires_at)
                };
                self.dev_input()?
                    .pulse(
                        &self.profiles,
                        &target,
                        session_id,
                        expires_at,
                        guardian_path()?,
                    )
                    .map_err(map_agent)?;
                Ok(LocalPayload::TestbedAction {
                    session_id: session_id.clone(),
                    action: "pulse".into(),
                    accepted: true,
                })
            }
            #[cfg(feature = "dev-automation")]
            LocalCommand::DevHoldTestbed {
                session_id,
                duration_ms,
            } => {
                let (target, expires_at) = {
                    let mut automation = self.automation()?;
                    let session = automation.authorize_testbed_action(
                        caller,
                        session_id,
                        AutomationCapability::HoldTestAction,
                        Instant::now(),
                    )?;
                    (session.target.clone(), session.expires_at)
                };
                let hold_until = Instant::now()
                    .checked_add(Duration::from_millis(u64::from(*duration_ms)))
                    .ok_or_else(|| {
                        ProtocolError::new(
                            LocalErrorCode::InvalidArgument,
                            "testbed hold deadline overflowed",
                        )
                    })?;
                if hold_until > expires_at {
                    return Err(ProtocolError::new(
                        LocalErrorCode::InvalidArgument,
                        "testbed hold exceeds the automation session deadline",
                    ));
                }
                self.dev_input()?
                    .hold(
                        &self.profiles,
                        &target,
                        session_id,
                        expires_at,
                        hold_until,
                        guardian_path()?,
                    )
                    .map_err(map_agent)?;
                Ok(LocalPayload::TestbedAction {
                    session_id: session_id.clone(),
                    action: "hold".into(),
                    accepted: true,
                })
            }
            #[cfg(feature = "dev-automation")]
            LocalCommand::DevStopAutomation {} | LocalCommand::DevEmergencyStop {} => {
                self.automation()?.emergency_stop();
                self.release_dev_input()?;
                let holds = self.execution()?.local_release_all().map_err(map_agent)?;
                Ok(LocalPayload::Released {
                    holds,
                    state: "automation_revoked".into(),
                })
            }
            #[cfg(not(feature = "dev-automation"))]
            _ => Err(ProtocolError::new(
                LocalErrorCode::UnsupportedCapability,
                "UNSUPPORTED_CAPABILITY",
            )),
        }
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, RuntimeState>, ProtocolError> {
        self.state.lock().map_err(|_| poisoned("runtime state"))
    }

    fn suite_status(&self) -> Result<LocalPayload, ProtocolError> {
        let executable = std::env::current_exe().map_err(operation_failed)?;
        let root = executable.parent().ok_or_else(|| {
            ProtocolError::new(
                LocalErrorCode::OperationFailed,
                "cannot locate the active suite directory",
            )
        })?;
        let installation = if SuiteManifest::load_and_verify(root).is_ok() {
            InstallationState::Healthy
        } else {
            InstallationState::Incomplete
        };
        let guardian = if installation == InstallationState::Healthy
            && root.join("fairypam-agent-guardian.exe").is_file()
        {
            GuardianState::Installed
        } else {
            GuardianState::Missing
        };
        let autostart = agent_task_state()?;
        let can_request_update = matches!(update_task_state()?, AutostartState::Enabled);
        let update = if self.state()?.accepting_commands {
            UpdateState::Idle
        } else {
            UpdateState::Quiesced
        };
        let control_mode = self.execution()?.local_status().control_mode;
        Ok(LocalPayload::SuiteStatus {
            installation,
            guardian,
            control_mode,
            update,
            autostart,
            can_request_update,
        })
    }

    fn execution(&self) -> Result<std::sync::MutexGuard<'_, CommandExecutor>, ProtocolError> {
        self.execution
            .lock()
            .map_err(|_| poisoned("execution state"))
    }

    #[cfg(feature = "dev-automation")]
    fn automation(&self) -> Result<std::sync::MutexGuard<'_, AutomationManager>, ProtocolError> {
        self.automation
            .lock()
            .map_err(|_| poisoned("automation state"))
    }

    #[cfg(feature = "dev-automation")]
    fn dev_input(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, crate::dev_input::DevInputController>, ProtocolError>
    {
        self.dev_input
            .lock()
            .map_err(|_| poisoned("dev input state"))
    }

    #[cfg(feature = "dev-automation")]
    fn release_dev_input(&self) -> Result<(), ProtocolError> {
        self.dev_input()?.release_all();
        Ok(())
    }

    #[cfg(feature = "dev-automation")]
    fn expire_automation(&self) -> Result<(), ProtocolError> {
        let now = Instant::now();
        let expired_audit = {
            let mut automation = self.automation()?;
            let audit_id = automation
                .active()
                .filter(|session| now >= session.expires_at)
                .map(|session| session.audit_id.clone());
            automation.expire(now).then_some(audit_id).flatten()
        };
        if let Some(audit_id) = expired_audit {
            self.release_dev_input()?;
            self.execution()?.local_release_all().map_err(map_agent)?;
            tracing::info!(
                audit_event = "automation_session_expired",
                request_id = %audit_id,
                result = "released",
                "automation TTL expired and input was released"
            );
        }
        Ok(())
    }

    #[cfg(feature = "dev-automation")]
    pub(crate) fn tick_automation(&self) -> Result<(), ProtocolError> {
        self.expire_automation()
    }
}

fn require_high_integrity(caller: &CallerIdentity) -> Result<(), ProtocolError> {
    if caller.integrity != ClientIntegrity::High {
        return Err(ProtocolError::new(
            LocalErrorCode::PermissionDenied,
            "suite maintenance commands require the fixed high-integrity updater entrypoint",
        ));
    }
    Ok(())
}

impl LocalRequestHandler for AgentLocalControl {
    fn server_version(&self) -> &str {
        &self.agent_version
    }

    fn handle(&self, caller: &CallerIdentity, request: &LocalRequest) -> LocalResponse {
        let command = request.command.name();
        let mutating = request.command.mutates_state();
        let result = self.dispatch(caller, request);
        let result_code = match &result {
            Ok(_) => "OK".to_owned(),
            Err(error) => format!("{:?}", error.code),
        };
        if mutating {
            tracing::info!(
                audit_event = "local_state_change",
                request_id = %request.request_id,
                command,
                caller_pid = caller.process_id,
                caller_user = %caller.user_sid_hash,
                caller_logon = %caller.logon_sid_hash,
                result = %result_code,
                "local Agent domain request"
            );
        }
        match result {
            Ok(payload) => LocalResponse::ok(request.request_id.clone(), payload),
            Err(error) => LocalResponse::error(request.request_id.clone(), error),
        }
    }

    fn client_disconnected(&self, _caller: &CallerIdentity) {
        #[cfg(feature = "dev-automation")]
        if self
            .automation()
            .is_ok_and(|mut manager| manager.client_disconnected(_caller.process_id))
        {
            let _ = self.release_dev_input();
            let result = self
                .execution()
                .and_then(|mut execution| execution.local_release_all().map_err(map_agent));
            tracing::info!(
                audit_event = "automation_client_disconnected",
                caller_pid = _caller.process_id,
                caller_user = %_caller.user_sid_hash,
                release_succeeded = result.is_ok(),
                "automation session revoked on client exit"
            );
        }
    }
}

fn guardian_path() -> Result<std::path::PathBuf, ProtocolError> {
    let current = std::env::current_exe()
        .map_err(|error| ProtocolError::new(LocalErrorCode::OperationFailed, error.to_string()))?;
    let directory = current.parent().ok_or_else(|| {
        ProtocolError::new(
            LocalErrorCode::OperationFailed,
            "cannot locate provisioned Agent slot",
        )
    })?;
    let guardian = directory.join("fairypam-agent-guardian.exe");
    if !guardian.is_file() {
        return Err(ProtocolError::new(
            LocalErrorCode::OperationFailed,
            "provisioned Guardian is missing",
        ));
    }
    Ok(guardian)
}

fn active_suite_root() -> Result<std::path::PathBuf, ProtocolError> {
    let current = std::env::current_exe().map_err(operation_failed)?;
    current
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| {
            ProtocolError::new(
                LocalErrorCode::OperationFailed,
                "cannot locate the active suite directory",
            )
        })
}

fn active_suite_member(name: &str) -> Result<std::path::PathBuf, ProtocolError> {
    Ok(active_suite_root()?.join(name))
}

fn verify_active_suite() -> Result<(), ProtocolError> {
    SuiteManifest::load_and_verify(&active_suite_root()?)
        .map(|_| ())
        .map_err(operation_failed)
}

fn agent_task_state() -> Result<AutostartState, ProtocolError> {
    fixed_task_state(
        "FairyPam Agent",
        &active_suite_member("fairypam-agent.exe")?,
        "HighestAvailable",
        None,
    )
}

fn update_task_state() -> Result<AutostartState, ProtocolError> {
    let program_data = std::env::var_os("ProgramData")
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            ProtocolError::new(
                LocalErrorCode::OperationFailed,
                "ProgramData is unavailable or not absolute",
            )
        })?;
    let policy = program_data.join("FairyPam/Agent/security-policy.json");
    if !policy.is_file() {
        return Ok(AutostartState::Missing);
    }
    let arguments = format!("apply --security-policy \"{}\"", policy.display());
    fixed_task_state(
        "FairyPam Agent Update",
        &active_suite_member("fairypam-agent-updater.exe")?,
        "HighestAvailable",
        Some(&arguments),
    )
}

fn fixed_task_state(
    name: &str,
    executable: &std::path::Path,
    run_level: &str,
    arguments: Option<&str>,
) -> Result<AutostartState, ProtocolError> {
    let output = Command::new("schtasks.exe")
        .args(["/Query", "/TN", name, "/XML"])
        .stdin(Stdio::null())
        .output()
        .map_err(operation_failed)?;
    if !output.status.success() {
        return Ok(AutostartState::Missing);
    }
    let xml = decode_windows_text(&output.stdout);
    task_state_from_xml(&xml, executable, run_level, arguments)
}

fn task_state_from_xml(
    xml: &str,
    executable: &std::path::Path,
    run_level: &str,
    arguments: Option<&str>,
) -> Result<AutostartState, ProtocolError> {
    let executable = executable.to_str().ok_or_else(|| {
        ProtocolError::new(
            LocalErrorCode::OperationFailed,
            "fixed task executable path is not Unicode",
        )
    })?;
    let expected_command = format!("<Command>{}</Command>", xml_text(executable));
    let exact_arguments = match arguments {
        Some(arguments) => {
            let expected = format!("<Arguments>{}</Arguments>", xml_text(arguments));
            xml.matches("<Arguments>").count() == 1 && xml.matches(&expected).count() == 1
        }
        None => !xml.contains("<Arguments>"),
    };
    if xml.matches("<Exec>").count() != 1
        || xml.matches("</Exec>").count() != 1
        || xml.matches("<Command>").count() != 1
        || xml.matches(&expected_command).count() != 1
        || xml.matches("<RunLevel>").count() != 1
        || xml
            .matches(&format!("<RunLevel>{run_level}</RunLevel>"))
            .count()
            != 1
        || !exact_arguments
        || ["<ComHandler>", "<SendEmail>", "<ShowMessage>"]
            .iter()
            .any(|tag| xml.contains(tag))
    {
        return Err(ProtocolError::new(
            LocalErrorCode::OperationFailed,
            "fixed task action does not match the protected suite entrypoint",
        ));
    }
    if xml.contains("<Enabled>false</Enabled>") {
        Ok(AutostartState::Disabled)
    } else if xml.contains("<Enabled>true</Enabled>") {
        Ok(AutostartState::Enabled)
    } else {
        Err(ProtocolError::new(
            LocalErrorCode::OperationFailed,
            "fixed task XML omitted its enabled state",
        ))
    }
}

fn run_update_task() -> Result<(), ProtocolError> {
    const TASK: &str = "FairyPam Agent Update";
    if !matches!(update_task_state()?, AutostartState::Enabled) {
        return Err(ProtocolError::new(
            LocalErrorCode::OperationFailed,
            "fixed update task is unavailable, disabled, or has drifted",
        ));
    }
    verify_active_suite()?;
    let status = Command::new("schtasks.exe")
        .args(["/Run", "/TN", TASK])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(operation_failed)?;
    if !status.success() {
        return Err(ProtocolError::new(
            LocalErrorCode::OperationFailed,
            "fixed update task could not be started",
        ));
    }
    Ok(())
}

fn set_agent_autostart(enabled: bool) -> Result<(), ProtocolError> {
    if matches!(agent_task_state()?, AutostartState::Missing) {
        return Err(ProtocolError::new(
            LocalErrorCode::OperationFailed,
            "fixed Agent task is missing",
        ));
    }
    if enabled {
        verify_active_suite()?;
    }
    let mode = if enabled { "/ENABLE" } else { "/DISABLE" };
    let status = Command::new("schtasks.exe")
        .args(["/Change", "/TN", "FairyPam Agent", mode])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(operation_failed)?;
    if !status.success() {
        return Err(ProtocolError::new(
            LocalErrorCode::OperationFailed,
            "fixed Agent task autostart state could not be changed",
        ));
    }
    let expected = if enabled {
        AutostartState::Enabled
    } else {
        AutostartState::Disabled
    };
    if agent_task_state()? != expected {
        return Err(ProtocolError::new(
            LocalErrorCode::OperationFailed,
            "fixed Agent task did not confirm the requested autostart state",
        ));
    }
    Ok(())
}

fn decode_windows_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.get(1).is_some_and(|byte| *byte == 0) {
        let words = bytes
            .chunks_exact(2)
            .skip(usize::from(bytes.starts_with(&[0xff, 0xfe])))
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        String::from_utf16_lossy(&words)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn operation_failed(error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::new(LocalErrorCode::OperationFailed, error.to_string())
}

fn target_payload(target: crate::execution::LocalTarget) -> LocalPayload {
    LocalPayload::Target {
        profile_id: target.profile_id,
        target_id: target.target_id,
        title: target.title,
        process_name: target.process_name,
        foreground: target.foreground,
        capturable: target.capturable,
    }
}

fn map_agent(error: AgentError) -> ProtocolError {
    let code = if error.code().starts_with("target.") {
        LocalErrorCode::TargetUnavailable
    } else if error.code().starts_with("profile.") {
        LocalErrorCode::InvalidArgument
    } else {
        LocalErrorCode::OperationFailed
    };
    ProtocolError::new(code, error.to_string())
}

fn poisoned(component: &str) -> ProtocolError {
    ProtocolError::new(
        LocalErrorCode::OperationFailed,
        format!("{component} is unavailable"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_task_parser_rejects_action_drift() {
        let executable = std::path::Path::new(
            r"C:\Program Files\FairyPam\Agent\active\fairypam-agent-updater.exe",
        );
        let arguments =
            r#"apply --security-policy "C:\ProgramData\FairyPam\Agent\security-policy.json""#;
        let xml = format!(
            "<Task><Principals><RunLevel>HighestAvailable</RunLevel></Principals><Settings><Enabled>true</Enabled></Settings><Actions><Exec><Command>{}</Command><Arguments>{}</Arguments></Exec></Actions></Task>",
            xml_text(executable.to_str().unwrap()),
            xml_text(arguments),
        );
        assert_eq!(
            task_state_from_xml(&xml, executable, "HighestAvailable", Some(arguments)).unwrap(),
            AutostartState::Enabled
        );
        assert!(task_state_from_xml(
            &xml.replace("fairypam-agent-updater.exe", "other.exe"),
            executable,
            "HighestAvailable",
            Some(arguments),
        )
        .is_err());
        let extra_action = xml.replace(
            "</Actions>",
            "<Exec><Command>C:\\Windows\\System32\\cmd.exe</Command></Exec></Actions>",
        );
        assert!(task_state_from_xml(
            &extra_action,
            executable,
            "HighestAvailable",
            Some(arguments),
        )
        .is_err());
    }
}
