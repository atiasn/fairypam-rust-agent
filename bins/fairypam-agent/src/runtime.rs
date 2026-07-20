#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::VecDeque;
use std::env;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicBool, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fairypam_agent_core::profile::Ed25519SignatureVerifier;
use fairypam_agent_core::supervisor::{SessionDriver, SessionSupervisor, SupervisorHooks};
use fairypam_agent_core::AgentError;
use fairypam_agent_protocol::v1::{
    agent_control_event, hub_control_command, AgentControlEvent, AgentHello, AgentStatus,
    CommandAck, CommandNack, CommandRef, Heartbeat, SessionRef,
};
#[cfg(windows)]
use fairypam_agent_transport::validate_transport_config;
use fairypam_agent_transport::{
    connect_control, connect_frame, control_queue, open_control_tunnel, open_frame_tunnel,
    receive_hub_hello, CappedBackoff, ControlSender, ControlSession, SessionFrameSlot,
    TransportConfig, TransportError, VerifiedSession,
};
use http::Uri;
#[cfg(any(windows, test))]
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio_util::sync::CancellationToken;

use crate::execution::{CommandExecutor, CommandOutcome, ExecutionSession, FrameSink};
#[cfg(any(windows, test))]
use crate::observability;
use crate::observability::AgentLogRecord;
use crate::profile_store::ProfileStore;

#[cfg(windows)]
const PRODUCTION_AUDIT_STATE_DIR: &str = r"C:\ProgramData\FairyPam\Agent\audit";
#[cfg(windows)]
const LOCAL_CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(any(windows, test))]
use crate::local_control::LocalControlRuntime;
#[cfg(windows)]
use crate::local_control::{AuditEvent, AuditSink, LocalControlAdapter};
#[cfg(all(windows, feature = "dev-automation"))]
use fairypam_agent_core::state::Effect;
#[cfg(all(windows, feature = "dev-automation"))]
use fairypam_agent_dev_automation::{
    AutomationCapability, AutomationTarget, DevSessionManager, DevSessionRequest,
    DevSessionRevocationReason,
};
#[cfg(any(windows, test))]
use fairypam_agent_local_protocol::LocalCommand;
use fairypam_agent_local_protocol::LogLevel;
#[cfg(windows)]
use fairypam_agent_local_protocol::{decode_request_or_error_response, encode_frame};
#[cfg(all(windows, feature = "dev-automation"))]
use fairypam_agent_local_protocol::{LocalError, RequestEnvelope, ResponseEnvelope};
#[cfg(windows)]
use fairypam_agent_windows::{
    current_process_pipe_owner, default_production_pipe_name, IntegrityLevel, PipeOwner,
    WindowsNamedPipeServer,
};

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub transport: TransportConfig,
    pub agent_version: String,
    pub build_commit: String,
    pub profiles: ProfileStore,
    enrollment_generation: Option<String>,
    awaiting_enrollment: bool,
}

impl RuntimeConfig {
    /// Production Agent instances are deliberately able to serve the local,
    /// authenticated enrollment pipe before any Hub credentials exist.
    #[cfg(windows)]
    pub fn from_production() -> Result<Self, AgentError> {
        if enrollment_state_exists() {
            match Self::from_enrollment_state() {
                Ok(config) => Ok(config),
                Err(error) => {
                    tracing::warn!(
                        code = error.code(),
                        "invalid enrollment state ignored; local registration remains available"
                    );
                    Ok(Self::unregistered())
                }
            }
        } else if [
            "FAIRYPAM_PROFILE_ROOT_PUBLIC_KEY_HEX",
            "FAIRYPAM_PROFILE_DIR",
            "FAIRYPAM_CONTROL_ENDPOINT",
            "FAIRYPAM_FRAME_ENDPOINT",
            "FAIRYPAM_HUB_SERVER_NAME",
            "FAIRYPAM_AGENT_ID",
            "FAIRYPAM_CA_PEM",
            "FAIRYPAM_AGENT_CERT_PEM",
            "FAIRYPAM_AGENT_KEY_PEM",
        ]
        .into_iter()
        .any(|name| env::var_os(name).is_some())
        {
            // Preserve the explicitly configured developer/test runtime; an
            // unregistered production package has no such endpoint.
            Self::from_env()
        } else {
            Ok(Self::unregistered())
        }
    }

    #[cfg(not(windows))]
    pub fn from_production() -> Result<Self, AgentError> {
        Self::from_env()
    }

    #[cfg(any(windows, test))]
    fn unregistered() -> Self {
        Self {
            transport: TransportConfig {
                control_endpoint: "https://unregistered.invalid"
                    .parse()
                    .expect("fixed unregistered URI"),
                frame_endpoint: "https://unregistered.invalid"
                    .parse()
                    .expect("fixed unregistered URI"),
                server_name: "unregistered".to_owned(),
                agent_id: "unregistered".to_owned(),
                ca_pem: PathBuf::new(),
                identity_cert_pem: PathBuf::new(),
                identity_key_pem: PathBuf::new(),
                connect_timeout: Duration::from_secs(10),
            },
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            build_commit: option_env!("FAIRYPAM_BUILD_COMMIT")
                .unwrap_or("unknown")
                .to_owned(),
            profiles: ProfileStore::default(),
            enrollment_generation: None,
            awaiting_enrollment: true,
        }
    }

    pub fn from_env() -> Result<Self, AgentError> {
        #[cfg(windows)]
        if enrollment_state_exists() {
            return Self::from_enrollment_state();
        }
        let verifier = Ed25519SignatureVerifier::from_public_key_hex(&required(
            "FAIRYPAM_PROFILE_ROOT_PUBLIC_KEY_HEX",
        )?)?;
        let profiles = ProfileStore::load(&required_path("FAIRYPAM_PROFILE_DIR")?, &verifier)?;
        Ok(Self {
            transport: TransportConfig {
                control_endpoint: required_uri("FAIRYPAM_CONTROL_ENDPOINT")?,
                frame_endpoint: required_uri("FAIRYPAM_FRAME_ENDPOINT")?,
                server_name: required("FAIRYPAM_HUB_SERVER_NAME")?,
                agent_id: required("FAIRYPAM_AGENT_ID")?,
                ca_pem: required_path("FAIRYPAM_CA_PEM")?,
                identity_cert_pem: required_path("FAIRYPAM_AGENT_CERT_PEM")?,
                identity_key_pem: required_path("FAIRYPAM_AGENT_KEY_PEM")?,
                connect_timeout: Duration::from_secs(10),
            },
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            build_commit: option_env!("FAIRYPAM_BUILD_COMMIT")
                .unwrap_or("unknown")
                .to_owned(),
            profiles,
            enrollment_generation: None,
            awaiting_enrollment: false,
        })
    }

    #[cfg(windows)]
    fn from_enrollment_state() -> Result<Self, AgentError> {
        let root = PathBuf::from(r"C:\ProgramData\FairyPam\Agent\enrollment");
        crate::enrollment::ensure_private_directory(&root)?;
        let pointer = load_private_json(&root.join("current.json"))?;
        let generation = enrollment_field(&pointer, "generation")?;
        Self::from_enrollment_candidate(&root, generation)
    }

    #[cfg(windows)]
    fn from_enrollment_candidate(root: &Path, generation: String) -> Result<Self, AgentError> {
        if !generation.starts_with("g-")
            || generation.len() > 80
            || generation
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-'))
        {
            return Err(AgentError::new(
                "runtime.enrollment_invalid",
                "invalid enrollment generation",
            ));
        }
        let directory = root.join(&generation);
        let document = load_private_json(&directory.join("runtime.json"))?;
        validate_enrollment_expiry(&enrollment_field(&document, "expires_at")?)?;
        let verifier = Ed25519SignatureVerifier::from_public_key_hex(&enrollment_field(
            &document,
            "profile_root_public_key_hex",
        )?)?;
        let profiles = ProfileStore::load_optional(&enrollment_profile_directory()?, &verifier)?;
        Ok(Self {
            transport: TransportConfig {
                control_endpoint: enrollment_field(&document, "control_endpoint")?
                    .parse()
                    .map_err(|error| {
                        AgentError::new(
                            "runtime.enrollment_invalid",
                            format!("invalid control endpoint: {error}"),
                        )
                    })?,
                frame_endpoint: enrollment_field(&document, "frame_endpoint")?
                    .parse()
                    .map_err(|error| {
                        AgentError::new(
                            "runtime.enrollment_invalid",
                            format!("invalid frame endpoint: {error}"),
                        )
                    })?,
                server_name: enrollment_field(&document, "hub_server_name")?,
                agent_id: enrollment_field(&document, "agent_id")?,
                ca_pem: private_file(&directory, "ca.pem")?,
                identity_cert_pem: private_file(&directory, "client-cert.pem")?,
                identity_key_pem: private_file(&directory, "client-key.pem")?,
                connect_timeout: Duration::from_secs(10),
            },
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            build_commit: option_env!("FAIRYPAM_BUILD_COMMIT")
                .unwrap_or("unknown")
                .to_owned(),
            profiles,
            enrollment_generation: Some(generation),
            awaiting_enrollment: false,
        })
    }
}

#[cfg(any(windows, test))]
fn validate_enrollment_expiry(value: &str) -> Result<(), AgentError> {
    let expires_at = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
        AgentError::new(
            "runtime.enrollment_invalid",
            "invalid enrollment expiration",
        )
    })?;
    (expires_at > OffsetDateTime::now_utc())
        .then_some(())
        .ok_or_else(|| {
            AgentError::new(
                "runtime.enrollment_invalid",
                "enrollment credential has expired",
            )
        })
}

#[cfg(windows)]
pub(crate) fn validate_enrollment_candidate(
    root: &Path,
    generation: &str,
) -> Result<(), AgentError> {
    crate::enrollment::ensure_private_directory(root)?;
    let candidate = RuntimeConfig::from_enrollment_candidate(root, generation.to_owned())?;
    validate_transport_config(&candidate.transport).map_err(|_| {
        AgentError::new(
            "runtime.enrollment_invalid",
            "enrollment transport identity is invalid",
        )
    })
}

#[cfg(windows)]
fn enrollment_state_exists() -> bool {
    let root = Path::new(r"C:\ProgramData\FairyPam\Agent\enrollment");
    crate::enrollment::ensure_private_directory(root).is_ok()
        && root
            .join("current.json")
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

#[cfg(windows)]
fn enrollment_profile_directory() -> Result<PathBuf, AgentError> {
    if let Some(path) = env::var_os("FAIRYPAM_PROFILE_DIR").filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    let executable = env::current_exe().map_err(|_| {
        AgentError::new(
            "runtime.profile_directory_unavailable",
            "cannot determine the enrolled Agent directory",
        )
    })?;
    let directory = executable.parent().ok_or_else(|| {
        AgentError::new(
            "runtime.profile_directory_unavailable",
            "the enrolled Agent executable has no parent directory",
        )
    })?;
    Ok(directory.join("profiles"))
}

#[cfg(windows)]
fn load_private_json(path: &Path) -> Result<serde_json::Value, AgentError> {
    let metadata = path.symlink_metadata().map_err(|_| {
        AgentError::new(
            "runtime.enrollment_invalid",
            "enrollment state is unavailable",
        )
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(AgentError::new(
            "runtime.enrollment_invalid",
            "enrollment state is not a regular file",
        ));
    }
    serde_json::from_slice(&std::fs::read(path).map_err(|_| {
        AgentError::new(
            "runtime.enrollment_invalid",
            "enrollment state cannot be read",
        )
    })?)
    .map_err(|_| {
        AgentError::new(
            "runtime.enrollment_invalid",
            "enrollment state is malformed",
        )
    })
}

#[cfg(windows)]
fn enrollment_field(
    document: &serde_json::Value,
    name: &'static str,
) -> Result<String, AgentError> {
    document
        .get(name)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            AgentError::new(
                "runtime.enrollment_invalid",
                format!("enrollment field {name} is missing"),
            )
        })
}

#[cfg(windows)]
fn private_file(directory: &Path, name: &'static str) -> Result<PathBuf, AgentError> {
    let path = directory.join(name);
    let metadata = path.symlink_metadata().map_err(|_| {
        AgentError::new(
            "runtime.enrollment_invalid",
            "enrollment credential is unavailable",
        )
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(AgentError::new(
            "runtime.enrollment_invalid",
            "enrollment credential is unsafe",
        ));
    }
    Ok(path)
}

struct RuntimeState {
    control: Option<ControlSession>,
    sender: Option<ControlSender>,
    session: Option<VerifiedSession>,
    frames: Option<SessionFrameSlot>,
    control_state: ConnectionState,
    frame_state: ConnectionState,
    last_error_code: String,
    logs: VecDeque<AgentLogRecord>,
}

#[derive(Clone, Copy)]
enum ConnectionState {
    Offline,
    Connecting,
    Connected,
    Reconnecting,
}

impl ConnectionState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Reconnecting => "reconnecting",
        }
    }
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            control: None,
            sender: None,
            session: None,
            frames: None,
            control_state: ConnectionState::Offline,
            frame_state: ConnectionState::Offline,
            last_error_code: "runtime.offline".to_owned(),
            logs: VecDeque::new(),
        }
    }
}

impl RuntimeState {
    fn record(&mut self, level: LogLevel, message: &'static str) {
        if self.logs.len() == 200 {
            self.logs.pop_front();
        }
        self.logs.push_back(AgentLogRecord::new(level, message));
    }
}

pub struct GrpcSessionDriver {
    config: Arc<Mutex<RuntimeConfig>>,
    state: Arc<Mutex<RuntimeState>>,
    execution: Arc<Mutex<CommandExecutor>>,
    enrollment_ready: Arc<tokio::sync::Notify>,
    reconnect_requested: Arc<tokio::sync::Notify>,
    registration_in_progress: Arc<AtomicBool>,
}

impl GrpcSessionDriver {
    pub fn new(config: RuntimeConfig) -> Self {
        let execution = CommandExecutor::production(config.profiles.clone());
        let state = if config.awaiting_enrollment {
            let mut state = RuntimeState {
                last_error_code: "runtime.not_registered".to_owned(),
                ..RuntimeState::default()
            };
            state.record(
                LogLevel::Info,
                "Agent is awaiting authenticated Hub registration",
            );
            state
        } else {
            RuntimeState::default()
        };
        Self {
            config: Arc::new(Mutex::new(config)),
            state: Arc::new(Mutex::new(state)),
            execution: Arc::new(Mutex::new(execution)),
            enrollment_ready: Arc::new(tokio::sync::Notify::new()),
            reconnect_requested: Arc::new(tokio::sync::Notify::new()),
            registration_in_progress: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(any(windows, test))]
    fn local_runtime(&self) -> SharedRuntime {
        SharedRuntime {
            execution: Arc::clone(&self.execution),
            state: Arc::clone(&self.state),
            config: Arc::clone(&self.config),
            enrollment_ready: Arc::clone(&self.enrollment_ready),
            reconnect_requested: Arc::clone(&self.reconnect_requested),
            registration_in_progress: Arc::clone(&self.registration_in_progress),
        }
    }

    fn is_registered(&self) -> Result<bool, AgentError> {
        Ok(!self.config.lock().map_err(lock_error)?.awaiting_enrollment)
    }

    #[cfg(any(windows, test))]
    async fn wait_until_registered(&self) -> Result<(), AgentError> {
        while !self.is_registered()? {
            self.wait_for_enrollment_ready().await;
        }
        Ok(())
    }

    async fn wait_for_enrollment_ready(&self) {
        self.enrollment_ready.notified().await;
    }

    async fn wait_for_reconnect(&self) {
        self.reconnect_requested.notified().await;
    }

    fn session_parts(
        &self,
    ) -> Result<(VerifiedSession, SessionFrameSlot, ControlSender), AgentError> {
        let state = self.state.lock().map_err(lock_error)?;
        Ok((
            state.session.clone().ok_or_else(session_missing)?,
            state.frames.clone().ok_or_else(session_missing)?,
            state.sender.clone().ok_or_else(session_missing)?,
        ))
    }

    fn enrollment_changed(&self) -> Result<bool, AgentError> {
        #[cfg(windows)]
        {
            let expected = self
                .config
                .lock()
                .map_err(lock_error)?
                .enrollment_generation
                .clone();
            let Some(expected) = expected else {
                return Ok(false);
            };
            let root = Path::new(r"C:\ProgramData\FairyPam\Agent\enrollment");
            crate::enrollment::ensure_private_directory(root)?;
            let pointer = load_private_json(&root.join("current.json"))?;
            Ok(enrollment_field(&pointer, "generation")? != expected)
        }
        #[cfg(not(windows))]
        Ok(false)
    }
}

impl SessionDriver for GrpcSessionDriver {
    async fn establish_session(&self, cancellation: CancellationToken) -> Result<(), AgentError> {
        let config = self.config.lock().map_err(lock_error)?.clone();
        #[cfg(windows)]
        if config.awaiting_enrollment {
            return Err(AgentError::new(
                "runtime.not_registered",
                "Agent is awaiting authenticated Hub registration",
            ));
        }
        if let Ok(mut state) = self.state.lock() {
            state.control_state = ConnectionState::Connecting;
            state.frame_state = ConnectionState::Connecting;
            state.last_error_code = "runtime.connecting".to_owned();
            state.record(LogLevel::Info, "Agent Control connection is starting");
        }
        let connection = tokio::select! {
            _ = cancellation.cancelled() => return Err(cancelled()),
            result = connect_control(&config.transport) => result.map_err(map_transport)?,
        };
        let (sender, receiver) = control_queue();
        sender
            .send(AgentControlEvent {
                payload: Some(agent_control_event::Payload::Hello(AgentHello {
                    agent_id: config.transport.agent_id.clone(),
                    agent_version: config.agent_version.clone(),
                    protocol_major: 1,
                    protocol_minor: 0,
                    build_commit: config.build_commit.clone(),
                    installed_profile_ids: config.profiles.ids(),
                })),
            })
            .await
            .map_err(map_transport)?;
        let pending = tokio::select! {
            _ = cancellation.cancelled() => return Err(cancelled()),
            result = open_control_tunnel(&connection, receiver) => result.map_err(map_transport)?,
        };
        let control = tokio::select! {
            _ = cancellation.cancelled() => return Err(cancelled()),
            result = receive_hub_hello(pending) => result.map_err(map_transport)?,
        };
        let session = control.verified_session().clone();
        let frames = session.frame_slot();
        sender
            .try_send(status_event(&session, "ConnectedIdle"))
            .map_err(map_transport)?;
        let mut state = self.state.lock().map_err(lock_error)?;
        let logs = std::mem::take(&mut state.logs);
        *state = RuntimeState {
            control: Some(control),
            sender: Some(sender),
            session: Some(session),
            frames: Some(frames),
            control_state: ConnectionState::Connected,
            frame_state: ConnectionState::Connecting,
            last_error_code: "runtime.frame_connecting".to_owned(),
            logs,
        };
        state.record(LogLevel::Info, "Agent Control connection is established");
        Ok(())
    }

    async fn run_control_session(&self, cancellation: CancellationToken) -> Result<(), AgentError> {
        let (mut control, sender, session) = {
            let mut state = self.state.lock().map_err(lock_error)?;
            (
                state.control.take().ok_or_else(session_missing)?,
                state.sender.clone().ok_or_else(session_missing)?,
                state.session.clone().ok_or_else(session_missing)?,
            )
        };
        let mut heartbeat = tokio::time::interval(Duration::from_millis(u64::from(
            session.heartbeat_interval_ms(),
        )));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        heartbeat.tick().await;
        let mut enrollment_watch = tokio::time::interval(Duration::from_secs(1));
        enrollment_watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        enrollment_watch.tick().await;
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(cancelled()),
                _ = self.wait_for_reconnect() => {
                    return Err(AgentError::new(
                        "runtime.enrollment_changed",
                        "enrollment changed; reconnecting with current credentials",
                    ));
                }
                _ = enrollment_watch.tick() => {
                    if self.enrollment_changed()? {
                        return Err(AgentError::new(
                            "runtime.enrollment_changed",
                            "enrollment generation changed; reconnecting with current credentials",
                        ));
                    }
                }
                _ = heartbeat.tick() => {
                    sender.try_send(heartbeat_event(&session)).map_err(map_transport)?;
                }
                command = control.message() => {
                    let command = command.map_err(map_transport)?.ok_or_else(|| {
                        AgentError::new("runtime.control_closed", "Hub closed the Control stream")
                    })?.into_inner();
                    let reference = command_reference(&command).ok_or_else(|| {
                        AgentError::new("runtime.command_invalid", "verified command lost CommandRef")
                    })?;
                    let frames = {
                        let state = self.state.lock().map_err(lock_error)?;
                        state.frames.clone().ok_or_else(session_missing)?
                    };
                    let outcome = self
                        .execution
                        .lock()
                        .map_err(lock_error)?
                        .execute(
                            &command,
                            &ExecutionSession::from_verified(&session),
                            Arc::new(frames) as Arc<dyn FrameSink>,
                        );
                    let event = match outcome {
                        CommandOutcome::Ack(result) => ack_event(reference, &result),
                        CommandOutcome::Nack { code, message } => {
                            nack_event(reference, &code, &message)
                        }
                    };
                    sender.try_send(event).map_err(map_transport)?;
                }
            }
        }
    }

    async fn run_frame_session(&self, cancellation: CancellationToken) -> Result<(), AgentError> {
        let config = self.config.lock().map_err(lock_error)?.clone();
        let (_session, frames, _sender) = self.session_parts()?;
        let connection = tokio::select! {
            _ = cancellation.cancelled() => return Err(cancelled()),
            result = connect_frame(&config.transport) => result.map_err(map_transport)?,
        };
        let mut frame = tokio::select! {
            _ = cancellation.cancelled() => return Err(cancelled()),
            result = open_frame_tunnel(&connection, &frames) => result.map_err(map_transport)?,
        };
        if let Ok(mut state) = self.state.lock() {
            state.frame_state = ConnectionState::Connected;
            state.last_error_code = "runtime.connected".to_owned();
            state.record(LogLevel::Info, "Agent Frame connection is established");
        }
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                directive = frame.message() => {
                    let Some(directive) = directive.map_err(map_transport)? else {
                        return Err(AgentError::new(
                            "runtime.frame_closed",
                            "Hub closed the Frame stream",
                        ));
                    };
                    let directive = directive.into_inner();
                    if directive.capture_source_id.is_empty() {
                        continue;
                    }
                    if !directive.enabled {
                        self.execution
                            .lock()
                            .map_err(lock_error)?
                            .stop_capture(Some(&directive.capture_source_id))?;
                    }
                }
            }
        }
    }
}

pub struct RuntimeSafetyHooks {
    config: Arc<Mutex<RuntimeConfig>>,
    state: Arc<Mutex<RuntimeState>>,
    execution: Arc<Mutex<CommandExecutor>>,
}

impl RuntimeSafetyHooks {
    pub fn for_driver(driver: &GrpcSessionDriver) -> Self {
        Self {
            config: Arc::clone(&driver.config),
            state: Arc::clone(&driver.state),
            execution: Arc::clone(&driver.execution),
        }
    }
}

impl SupervisorHooks for RuntimeSafetyHooks {
    fn close_input_gate(&mut self) -> Result<(), String> {
        tracing::info!(effect = "close_input_gate", "fail-closed cleanup effect");
        Ok(())
    }

    fn guardian_release_all(&mut self) -> Result<(), String> {
        // The production binary never arms without a separate local authority.
        // Thus no physical holds can exist in this DryRun runtime. The hook is
        // still explicit so the full Windows input owner can replace it in the
        // Task 9 harness without changing supervisor ordering.
        tracing::info!(effect = "guardian_release_all", state = "dry_run_no_holds");
        Ok(())
    }

    fn cancel_all_tasks(&mut self) {
        tracing::info!(effect = "cancel_all_tasks");
    }

    fn join_all_tasks(&mut self) -> Result<(), String> {
        tracing::info!(effect = "join_all_tasks", result = "joined");
        Ok(())
    }

    fn clear_target_session(&mut self) {
        #[cfg(windows)]
        if enrollment_state_exists() {
            match RuntimeConfig::from_enrollment_state() {
                Ok(config) => {
                    if let Ok(mut execution) = self.execution.lock() {
                        *execution = CommandExecutor::production(config.profiles.clone());
                    }
                    if let Ok(mut current) = self.config.lock() {
                        *current = config;
                    }
                }
                Err(error) => {
                    if let Ok(mut state) = self.state.lock() {
                        state.last_error_code = "runtime.enrollment_refresh_failed".to_owned();
                        state.record(
                            LogLevel::Warn,
                            "Enrollment refresh failed; reconnect remains fail-closed",
                        );
                    }
                    tracing::warn!(code = error.code(), "enrollment refresh failed");
                }
            }
        }
        if let Ok(mut execution) = self.execution.lock() {
            let _ = execution.reset();
        }
        if let Ok(mut state) = self.state.lock() {
            let logs = std::mem::take(&mut state.logs);
            *state = RuntimeState {
                control_state: ConnectionState::Reconnecting,
                frame_state: ConnectionState::Reconnecting,
                last_error_code: "runtime.reconnecting".to_owned(),
                logs,
                ..RuntimeState::default()
            };
            state.record(
                LogLevel::Warn,
                "Agent session was cleared and will reconnect",
            );
        }
        tracing::info!(effect = "clear_target_session");
    }

    fn cancel_frame_pipeline(&mut self) {
        if let Ok(mut execution) = self.execution.lock() {
            let _ = execution.stop_capture(None);
        }
        tracing::info!(effect = "cancel_frame_pipeline");
    }

    fn join_frame_pipeline(&mut self) -> Result<(), String> {
        tracing::info!(effect = "join_frame_pipeline", result = "joined");
        Ok(())
    }
}

pub async fn run(config: RuntimeConfig) -> Result<(), AgentError> {
    #[cfg(windows)]
    let _instance = AgentInstance::acquire()?;
    let driver = GrpcSessionDriver::new(config);
    let hooks = RuntimeSafetyHooks::for_driver(&driver);
    let backoff = CappedBackoff::new(Duration::from_millis(250), Duration::from_secs(30))
        .map_err(map_transport)?;
    let mut supervisor = SessionSupervisor::new(hooks, backoff);
    #[cfg(windows)]
    let mut local_control = tokio::spawn(run_local_control(
        driver.local_runtime(),
        production_local_control_config()?,
    ));
    #[cfg(windows)]
    if !driver.is_registered()? {
        tokio::select! {
            result = driver.wait_until_registered() => result?,
            result = &mut local_control => return match result {
                Ok(never) => match never {},
                Err(error) => Err(AgentError::new("local.runtime_join_failed", error.to_string())),
            },
        }
    }
    #[cfg(windows)]
    let result = tokio::select! {
        result = supervisor.run(&driver) => result,
        result = local_control => match result {
            Ok(never) => match never {},
            Err(error) => Err(AgentError::new("local.runtime_join_failed", error.to_string())),
        },
    };
    #[cfg(not(windows))]
    let result = supervisor.run(&driver).await;
    match result {
        Ok(never) => match never {},
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
struct AgentInstance(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl AgentInstance {
    fn acquire() -> Result<Self, AgentError> {
        use windows::{
            core::HSTRING,
            Win32::{
                Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS},
                System::Threading::CreateMutexW,
            },
        };

        let handle =
            unsafe { CreateMutexW(None, false, &HSTRING::from(r"Local\FairyPam.Agent.v1")) }
                .map_err(|error| {
                    AgentError::new("runtime.instance_unavailable", error.to_string())
                })?;
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            let _ = unsafe { CloseHandle(handle) };
            return Err(AgentError::new(
                "runtime.instance_already_running",
                "another FairyPam Agent instance is already running",
            ));
        }
        Ok(Self(handle))
    }
}

#[cfg(windows)]
impl Drop for AgentInstance {
    fn drop(&mut self) {
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[cfg(any(windows, test))]
#[derive(Clone)]
struct SharedRuntime {
    execution: Arc<Mutex<CommandExecutor>>,
    state: Arc<Mutex<RuntimeState>>,
    config: Arc<Mutex<RuntimeConfig>>,
    enrollment_ready: Arc<tokio::sync::Notify>,
    reconnect_requested: Arc<tokio::sync::Notify>,
    registration_in_progress: Arc<AtomicBool>,
}

#[cfg(any(windows, test))]
impl LocalControlRuntime for SharedRuntime {
    fn execute(&mut self, command: &LocalCommand) -> Result<serde_json::Value, AgentError> {
        match command {
            LocalCommand::GetConnectionStatus => self.connection_status(),
            LocalCommand::RunEnvironmentCheck => self.environment_check(),
            LocalCommand::GetLogTail { lines, level } => self.log_tail(*lines, level),
            LocalCommand::ScanInstalledGames => observability::scan_installed_games(),
            #[cfg(windows)]
            LocalCommand::RegisterHub {
                hub_address,
                registration_code,
            } => self.register_hub(hub_address, registration_code),
            #[cfg(all(test, not(windows)))]
            LocalCommand::RegisterHub { .. } => Err(AgentError::new(
                "enrollment.platform_unsupported",
                "Hub registration requires Windows",
            )),
            _ => self
                .execution
                .lock()
                .map_err(lock_error)?
                .execute_local(command),
        }
    }
}

#[cfg(any(windows, test))]
impl SharedRuntime {
    #[cfg(windows)]
    fn register_hub(
        &self,
        hub_address: &str,
        registration_code: &str,
    ) -> Result<serde_json::Value, AgentError> {
        // Return before the elevated Agent dialogue is shown. This one pipe
        // remains available for status and retry requests during the bounded
        // human-confirmation window.
        if self.registration_in_progress.swap(true, Ordering::AcqRel) {
            return Err(AgentError::new(
                "enrollment.registration_pending",
                "a Hub registration confirmation is already pending",
            ));
        }
        self.mark_registration_pending();
        let runtime = self.clone();
        let hub_address = hub_address.to_owned();
        let registration_code = registration_code.to_owned();
        if std::thread::Builder::new()
            .name("fairypam-enrollment".to_owned())
            .spawn(move || runtime.finish_registration(hub_address, registration_code))
            .is_err()
        {
            self.registration_in_progress
                .store(false, Ordering::Release);
            return Err(AgentError::new(
                "enrollment.unavailable",
                "Hub registration could not be started",
            ));
        }
        Ok(registration_pending())
    }

    #[cfg(windows)]
    fn finish_registration(&self, hub_address: String, registration_code: String) {
        let was_waiting = self
            .config
            .lock()
            .map(|config| config.awaiting_enrollment)
            .unwrap_or(true);
        let result = crate::enrollment::register_with_confirmation(
            &hub_address,
            &registration_code,
            !was_waiting,
        )
        .and_then(|_| RuntimeConfig::from_enrollment_state())
        .and_then(|config| self.activate_enrollment(config))
        .map(|_| {
            if !was_waiting {
                self.request_reconnect();
            }
        });
        if let Err(error) = result {
            if let Ok(mut state) = self.state.lock() {
                state.last_error_code = error.code().to_owned();
                state.record(LogLevel::Warn, "Hub registration was not completed");
            }
            tracing::warn!(code = error.code(), "Hub registration was not completed");
        }
        self.registration_in_progress
            .store(false, Ordering::Release);
    }

    #[cfg(windows)]
    fn mark_registration_pending(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.last_error_code = "runtime.enrollment_confirmation_pending".to_owned();
            state.record(
                LogLevel::Info,
                "Hub registration is awaiting elevated Agent confirmation",
            );
        }
    }

    fn request_reconnect(&self) {
        if let Ok(mut state) = self.state.lock() {
            // Leave the active generation in place; supervisor cleanup reloads
            // the persisted replacement before reconnecting.
            state.last_error_code = "runtime.enrollment_changed".to_owned();
            state.record(
                LogLevel::Info,
                "Hub registration changed; reconnecting safely",
            );
        }
        self.reconnect_requested.notify_one();
    }

    fn activate_enrollment(&self, config: RuntimeConfig) -> Result<(), AgentError> {
        let mut execution = self.execution.lock().map_err(lock_error)?;
        let mut state = self.state.lock().map_err(lock_error)?;
        let mut current = self.config.lock().map_err(lock_error)?;
        *execution = CommandExecutor::production(config.profiles.clone());
        *current = config;
        state.control_state = ConnectionState::Reconnecting;
        state.frame_state = ConnectionState::Reconnecting;
        state.last_error_code = "runtime.enrollment_registered".to_owned();
        state.record(
            LogLevel::Info,
            "Hub registration completed; reconnecting safely",
        );
        drop((execution, state, current));
        self.enrollment_ready.notify_one();
        Ok(())
    }

    fn connection_status(&self) -> Result<serde_json::Value, AgentError> {
        let capture_active = self
            .execution
            .lock()
            .map_err(lock_error)?
            .execute_local(&LocalCommand::Status)?["capture_active"]
            .as_bool()
            .unwrap_or(false);
        let state = self.state.lock().map_err(lock_error)?;
        let config = self.config.lock().map_err(lock_error)?;
        Ok(serde_json::json!({
            "hub_address": if config.awaiting_enrollment { String::new() } else { display_hub_address(&config.transport.control_endpoint) },
            "control": state.control_state.as_str(),
            "frame": state.frame_state.as_str(),
            "capture_active": capture_active,
            "recovery_code": state.last_error_code,
        }))
    }

    fn environment_check(&self) -> Result<serde_json::Value, AgentError> {
        let (control_state, frame_state) = {
            let state = self.state.lock().map_err(lock_error)?;
            (state.control_state, state.frame_state)
        };
        let (profiles_configured, certificate_ready) = {
            let config = self.config.lock().map_err(lock_error)?;
            let certificate_paths = [
                config.transport.ca_pem.clone(),
                config.transport.identity_cert_pem.clone(),
                config.transport.identity_key_pem.clone(),
            ];
            (
                !config.profiles.ids().is_empty(),
                certificate_paths
                    .into_iter()
                    .all(|path| regular_nonempty_file(&path)),
            )
        };
        let binary_ready = std::env::current_exe()
            .ok()
            .is_some_and(|path| regular_nonempty_file(&path));
        let guardian_ready = std::env::current_exe().ok().is_some_and(|path| {
            path.parent().is_some_and(|directory| {
                regular_nonempty_file(&directory.join("fairypam-agent-guardian.exe"))
            })
        });
        let (game_status, game_code) = if observability::scan_installed_games().is_ok() {
            ("available", "game.discovery_ready")
        } else {
            ("unavailable", "game.discovery_unavailable")
        };
        let check = |id: &str, status: ConnectionState| {
            serde_json::json!({
                "id": id,
                "status": status.as_str(),
                "code": if matches!(status, ConnectionState::Connected) { "runtime.connected" } else { "runtime.connection_unavailable" },
                "recovery": "Check Agent registration and Hub reachability",
            })
        };
        Ok(serde_json::json!({"checks": [
            {"id": "binary_or_task", "status": if binary_ready { "available" } else { "unavailable" }, "code": if binary_ready { "agent.binary_available" } else { "agent.binary_unavailable" }, "recovery": "Repair the Agent installation if the production binary is unavailable"},
            {"id": "agent", "status": "available", "code": "agent.running", "recovery": "No action required"},
            {"id": "certificate", "status": if certificate_ready { "available" } else { "unavailable" }, "code": if certificate_ready { "runtime.certificate_files_available" } else { "runtime.certificate_unavailable" }, "recovery": "Re-enroll if the Agent cannot connect"},
            check("control", control_state),
            check("frame", frame_state),
            {"id": "guardian", "status": if guardian_ready { "available" } else { "unavailable" }, "code": if guardian_ready { "guardian.binary_available" } else { "guardian.binary_unavailable" }, "recovery": "Repair the Agent installation if the Guardian binary is unavailable"},
            {"id": "profiles", "status": if profiles_configured { "available" } else { "unavailable" }, "code": if profiles_configured { "profile.available" } else { "profile.unavailable" }, "recovery": "Install a signed Profile before selecting a target"},
            {"id": "game_discovery", "status": game_status, "code": game_code, "recovery": "Rescan installed games if the launcher was updated"}
        ]}))
    }

    fn log_tail(&self, lines: u16, level: &LogLevel) -> Result<serde_json::Value, AgentError> {
        let mut state = self.state.lock().map_err(lock_error)?;
        Ok(observability::log_tail_json(
            state.logs.make_contiguous(),
            lines,
            level,
        ))
    }
}

#[cfg(any(windows, test))]
fn registration_pending() -> serde_json::Value {
    serde_json::json!({"status": "pending"})
}

#[cfg(any(windows, test))]
async fn before_local_request_deadline<T>(
    deadline: tokio::time::Instant,
    operation: impl std::future::Future<Output = T>,
) -> Option<T> {
    tokio::time::timeout_at(deadline, operation).await.ok()
}

fn regular_nonempty_file(path: &Path) -> bool {
    path.symlink_metadata().is_ok_and(|metadata| {
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() > 0
    })
}

#[cfg(windows)]
struct RuntimeAudit {
    state_dir: Option<PathBuf>,
}

#[cfg(windows)]
impl RuntimeAudit {
    fn new(state_dir: Option<PathBuf>) -> Self {
        Self { state_dir }
    }
}

#[cfg(windows)]
impl AuditSink for RuntimeAudit {
    fn record(&mut self, event: AuditEvent) -> Result<(), AgentError> {
        tracing::info!(request_id = %event.request_id, caller_sid_hash = %event.caller_sid_hash, command = %event.command, result_code = %event.result_code, build_id = %event.build_id, "local control mutation audited");
        let Some(state_dir) = &self.state_dir else {
            return Ok(());
        };
        let path = state_dir.join("local-control-audit.jsonl");
        let line = format!("{}\n", event.to_json());
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut file| {
                crate::enrollment::restrict_path(&path).map_err(|error| {
                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, error.to_string())
                })?;
                std::io::Write::write_all(&mut file, line.as_bytes())
            })
            .map_err(|_| {
                AgentError::new(
                    "local.audit_failed",
                    "local control mutation audit could not be persisted",
                )
            })
    }
}

#[cfg(windows)]
struct LocalControlConfig {
    owner: PipeOwner,
    pipe_name: String,
    audit_state_dir: Option<PathBuf>,
    single_request_connections: bool,
    #[cfg(all(windows, feature = "dev-automation"))]
    dev_session_state_dir: Option<PathBuf>,
}

#[cfg(windows)]
fn production_local_control_config() -> Result<LocalControlConfig, AgentError> {
    let owner = current_process_pipe_owner(IntegrityLevel::Medium)
        .map_err(|error| AgentError::new(error.code(), error.to_string()))?;
    let audit_state_dir = PathBuf::from(PRODUCTION_AUDIT_STATE_DIR);
    crate::enrollment::ensure_private_directory(&audit_state_dir)?;
    Ok(LocalControlConfig {
        owner,
        pipe_name: default_production_pipe_name().to_owned(),
        audit_state_dir: Some(audit_state_dir),
        single_request_connections: true,
        #[cfg(all(windows, feature = "dev-automation"))]
        dev_session_state_dir: None,
    })
}

#[cfg(windows)]
async fn run_local_control(
    runtime: SharedRuntime,
    config: LocalControlConfig,
) -> std::convert::Infallible {
    #[cfg(all(windows, feature = "dev-automation"))]
    let execution = Arc::clone(&runtime.execution);
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let single_request_connections = config.single_request_connections;
    #[cfg(all(windows, feature = "dev-automation"))]
    let mut dev_session = config
        .dev_session_state_dir
        .as_ref()
        .map(|state_dir| DevConnectionSession::new(state_dir.clone()));
    let mut adapter = LocalControlAdapter::new(
        config.owner.clone(),
        runtime,
        RuntimeAudit::new(config.audit_state_dir),
        option_env!("FAIRYPAM_BUILD_ID").unwrap_or("unknown"),
    );
    loop {
        let mut server = match WindowsNamedPipeServer::create(
            &config.pipe_name,
            config.owner.clone(),
        ) {
            Ok(server) => server,
            Err(error) => {
                tracing::warn!(code = error.code(), error = %error, "local control pipe creation failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let (caller, first_prefix_byte) = match server.connect_and_verify().await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(code = error.code(), error = %error, "local control client rejected");
                #[cfg(all(windows, feature = "dev-automation"))]
                if let Some(session) = &dev_session {
                    session.record_connection_rejection(error.code());
                }
                continue;
            }
        };
        let pipe = server.pipe_mut();
        let mut first_prefix_byte = Some(first_prefix_byte);
        loop {
            #[cfg(all(windows, feature = "dev-automation"))]
            if let Some(session) = &mut dev_session {
                apply_dev_effects(&execution, session.expire());
            }
            let mut prefix = [0_u8; 4];
            let prefix_start = match first_prefix_byte.take() {
                Some(byte) => {
                    prefix[0] = byte;
                    1
                }
                None => 0,
            };
            let request_deadline = tokio::time::Instant::now() + LOCAL_CONTROL_REQUEST_TIMEOUT;
            #[cfg(all(windows, feature = "dev-automation"))]
            let request_deadline = dev_session
                .as_ref()
                .and_then(DevConnectionSession::expires_at)
                .map(tokio::time::Instant::from_std)
                .map_or(request_deadline, |deadline| request_deadline.min(deadline));
            match before_local_request_deadline(
                request_deadline,
                pipe.read_exact(&mut prefix[prefix_start..]),
            )
            .await
            {
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    tracing::debug!(%error, "local control client disconnected");
                    break;
                }
                None => {
                    tracing::warn!("local control request prefix exceeded deadline");
                    #[cfg(all(windows, feature = "dev-automation"))]
                    if let Some(session) = &mut dev_session {
                        apply_dev_effects(&execution, session.expire());
                    }
                    break;
                }
            }
            let length = u32::from_le_bytes(prefix) as usize;
            if length > fairypam_agent_local_protocol::MAX_FRAME_BYTES {
                tracing::warn!(length, "local control frame exceeded protocol limit");
                break;
            }
            let mut frame = prefix.to_vec();
            frame.resize(4 + length, 0);
            match before_local_request_deadline(request_deadline, pipe.read_exact(&mut frame[4..]))
                .await
            {
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    tracing::debug!(%error, "local control client disconnected before request completed");
                    break;
                }
                None => {
                    tracing::warn!("local control request body exceeded deadline");
                    #[cfg(all(windows, feature = "dev-automation"))]
                    if let Some(session) = &mut dev_session {
                        apply_dev_effects(&execution, session.expire());
                    }
                    break;
                }
            }
            let response = match decode_request_or_error_response(&frame) {
                Ok(request) => {
                    #[cfg(all(windows, feature = "dev-automation"))]
                    let (dev_effects, dev_authorization) = dev_session
                        .as_mut()
                        .map(|session| session.authorize(&caller, &request))
                        .unwrap_or_else(|| (Vec::new(), Ok(())));
                    #[cfg(all(windows, feature = "dev-automation"))]
                    {
                        apply_dev_effects(&execution, dev_effects);
                        match dev_authorization {
                            Err(error) => ResponseEnvelope {
                                request_id: request.request_id,
                                result: Err(LocalError {
                                    code: error.code().to_owned(),
                                    message: error.to_string(),
                                }),
                            },
                            Ok(()) => {
                                let is_emergency_stop =
                                    matches!(&request.command, LocalCommand::ReleaseAll);
                                let response = match adapter.handle(&caller, request) {
                                    Ok(response) => response,
                                    Err(error) => {
                                        tracing::warn!(code = error.code(), error = %error, "local control identity changed after connection");
                                        break;
                                    }
                                };
                                if is_emergency_stop {
                                    if let Some(session) = &mut dev_session {
                                        apply_dev_effects(&execution, session.emergency_stop());
                                    }
                                }
                                response
                            }
                        }
                    }
                    #[cfg(not(all(windows, feature = "dev-automation")))]
                    match adapter.handle(&caller, request) {
                        Ok(response) => response,
                        Err(error) => {
                            tracing::warn!(code = error.code(), error = %error, "local control identity changed after connection");
                            break;
                        }
                    }
                }
                Err(response) => response,
            };
            let frame = match encode_frame(&response) {
                Ok(frame) => frame,
                Err(error) => {
                    tracing::warn!(code = error.code(), error = %error, "local control response encoding failed");
                    break;
                }
            };
            let response_deadline = tokio::time::Instant::now() + LOCAL_CONTROL_REQUEST_TIMEOUT;
            match before_local_request_deadline(response_deadline, pipe.write_all(&frame)).await {
                Some(Ok(())) => {}
                Some(Err(error)) => {
                    tracing::debug!(%error, "local control response could not be delivered");
                    break;
                }
                None => {
                    tracing::warn!("local control response write exceeded deadline");
                    break;
                }
            }
            if single_request_connections {
                break;
            }
        }
        #[cfg(all(windows, feature = "dev-automation"))]
        if let Some(session) = &mut dev_session {
            apply_dev_effects(&execution, session.client_disconnected());
        }
    }
}

#[cfg(all(windows, feature = "dev-automation"))]
struct DevConnectionSession {
    sessions: DevSessionManager,
    state_dir: PathBuf,
    build_id: String,
    requires_reconnect: bool,
}

#[cfg(all(windows, feature = "dev-automation"))]
impl DevConnectionSession {
    fn new(state_dir: PathBuf) -> Self {
        Self {
            sessions: DevSessionManager::default(),
            state_dir,
            build_id: option_env!("FAIRYPAM_BUILD_ID")
                .unwrap_or("unknown")
                .to_owned(),
            requires_reconnect: false,
        }
    }

    fn authorize(
        &mut self,
        caller: &fairypam_agent_windows::VerifiedPipeCaller,
        request: &RequestEnvelope,
    ) -> (
        Vec<Effect>,
        Result<(), fairypam_agent_dev_automation::DevSessionError>,
    ) {
        self.authorize_at(caller, request, std::time::Instant::now())
    }

    fn authorize_at(
        &mut self,
        caller: &fairypam_agent_windows::VerifiedPipeCaller,
        request: &RequestEnvelope,
        now: std::time::Instant,
    ) -> (
        Vec<Effect>,
        Result<(), fairypam_agent_dev_automation::DevSessionError>,
    ) {
        let Some(capability) = dev_capability(&request.command) else {
            return (Vec::new(), Ok(()));
        };
        let had_active = self.sessions.active_nonce().is_some();
        let expired = self.sessions.expire_active(now);
        self.record_revocation(had_active);
        if had_active && self.sessions.active_nonce().is_none() {
            self.requires_reconnect = true;
        }
        if self.requires_reconnect {
            return (
                expired,
                Err(fairypam_agent_dev_automation::DevSessionError::expired()),
            );
        }
        let session = self.sessions.create_with_nonce(
            request.nonce,
            DevSessionRequest {
                caller_sid: caller.user_sid.clone(),
                target: AutomationTarget::Testbed,
                capabilities: std::collections::BTreeSet::from([capability]),
                expires_at: now + Duration::from_secs(10),
                build_id: self.build_id.clone(),
            },
            now,
        );
        let result =
            session.and_then(|session| self.sessions.authorize(session.nonce, capability, now));
        (expired, result)
    }

    fn expire(&mut self) -> Vec<Effect> {
        let had_active = self.sessions.active_nonce().is_some();
        let effects = self.sessions.expire_active(std::time::Instant::now());
        self.record_revocation(had_active);
        if had_active && self.sessions.active_nonce().is_none() {
            self.requires_reconnect = true;
        }
        effects
    }

    fn expires_at(&self) -> Option<std::time::Instant> {
        self.sessions.active_expires_at()
    }

    fn client_disconnected(&mut self) -> Vec<Effect> {
        let had_active = self.sessions.active_nonce().is_some();
        let effects = self
            .sessions
            .active_nonce()
            .map(|nonce| self.sessions.on_client_disconnect(nonce))
            .unwrap_or_default();
        self.record_revocation(had_active);
        self.requires_reconnect = false;
        effects
    }

    fn emergency_stop(&mut self) -> Vec<Effect> {
        let had_active = self.sessions.active_nonce().is_some();
        let effects = self.sessions.emergency_stop();
        self.record_revocation(had_active);
        if had_active {
            self.requires_reconnect = true;
        }
        effects
    }

    fn record_revocation(&self, revoked: bool) {
        if !revoked {
            return;
        }
        let Some(revocation) = self.sessions.last_revocation() else {
            return;
        };
        let reason = match revocation.reason {
            DevSessionRevocationReason::ClientDisconnected => "client_disconnected",
            DevSessionRevocationReason::Expired => "expired",
            DevSessionRevocationReason::EmergencyStop => "emergency_stop",
        };
        let audit_id = revocation
            .audit_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let line = serde_json::json!({
            "event": "dev_session_revoked",
            "audit_id": audit_id,
            "reason": reason,
            "build_id": self.build_id,
        })
        .to_string();
        let path = self.state_dir.join("dev-session-audit.jsonl");
        if let Err(error) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut file| {
                std::io::Write::write_all(&mut file, format!("{line}\n").as_bytes())
            })
        {
            tracing::warn!(path = %path.display(), %error, "Dev session audit persistence failed");
        }
    }

    fn record_connection_rejection(&self, code: &str) {
        let line = serde_json::json!({
            "event": "local_control_rejected",
            "stage": "connect_and_verify",
            "code": code,
            "build_id": self.build_id,
        })
        .to_string();
        let path = self.state_dir.join("dev-local-control-diagnostics.jsonl");
        if let Err(error) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut file| {
                std::io::Write::write_all(&mut file, format!("{line}\n").as_bytes())
            })
        {
            tracing::warn!(path = %path.display(), %error, "Dev local control diagnostics persistence failed");
        }
    }
}

#[cfg(all(windows, feature = "dev-automation"))]
fn dev_capability(command: &LocalCommand) -> Option<AutomationCapability> {
    match command {
        LocalCommand::StartCapture { .. } | LocalCommand::StopCapture { .. } => {
            Some(AutomationCapability::Capture)
        }
        LocalCommand::TestbedPulse => Some(AutomationCapability::Input),
        _ => None,
    }
}

#[cfg(all(windows, feature = "dev-automation"))]
fn apply_dev_effects(execution: &Arc<Mutex<CommandExecutor>>, effects: Vec<Effect>) {
    if !effects.contains(&Effect::ReleaseAll) {
        return;
    }
    match execution
        .lock()
        .map_err(lock_error)
        .and_then(|mut execution| {
            execution
                .execute_local(&LocalCommand::ReleaseAll)
                .map(|_| ())
        }) {
        Ok(()) => tracing::info!(
            effect = "release_all",
            "Dev session revocation released input"
        ),
        Err(error) => tracing::error!(%error, "Dev session release-all failed"),
    }
}

#[cfg(all(windows, feature = "dev-automation"))]
pub async fn run_dev_local() -> Result<(), AgentError> {
    let root = std::env::current_dir()
        .map_err(|error| AgentError::new("local.config_missing", error.to_string()))?;
    let key = std::fs::read_to_string(root.join("test-profile-root-public-key.hex"))
        .map_err(|error| AgentError::new("local.config_missing", error.to_string()))?;
    let verifier = Ed25519SignatureVerifier::from_public_key_hex(key.trim())?;
    let profiles = ProfileStore::load(&root.join("profiles"), &verifier)?;
    let config = dev_local_control_config()?;
    let execution = Arc::new(Mutex::new(CommandExecutor::production(profiles.clone())));
    let never = run_local_control(
        SharedRuntime {
            execution,
            state: Arc::new(Mutex::new(RuntimeState::default())),
            config: Arc::new(Mutex::new(RuntimeConfig {
                transport: TransportConfig {
                    control_endpoint: "https://unavailable".parse().expect("fixed URI"),
                    frame_endpoint: "https://unavailable".parse().expect("fixed URI"),
                    server_name: "unavailable".to_owned(),
                    agent_id: "unavailable".to_owned(),
                    ca_pem: PathBuf::new(),
                    identity_cert_pem: PathBuf::new(),
                    identity_key_pem: PathBuf::new(),
                    connect_timeout: Duration::from_secs(10),
                },
                agent_version: "dev".to_owned(),
                build_commit: "unknown".to_owned(),
                profiles,
                enrollment_generation: None,
                awaiting_enrollment: false,
            })),
            enrollment_ready: Arc::new(tokio::sync::Notify::new()),
            reconnect_requested: Arc::new(tokio::sync::Notify::new()),
            registration_in_progress: Arc::new(AtomicBool::new(false)),
        },
        config,
    )
    .await;
    match never {}
}

#[cfg(all(windows, feature = "dev-automation"))]
fn dev_local_control_config() -> Result<LocalControlConfig, AgentError> {
    let local_app_data = env::var("LOCALAPPDATA").map_err(|_| {
        AgentError::new(
            "local.config_missing",
            "LOCALAPPDATA is required for Dev provision receipt",
        )
    })?;
    let receipt = std::fs::read_to_string(
        std::path::Path::new(&local_app_data).join("FairyPam/dev/provision.json"),
    )
    .map_err(|error| AgentError::new("local.config_missing", error.to_string()))?;
    let receipt: serde_json::Value = serde_json::from_str(&receipt)
        .map_err(|error| AgentError::new("local.config_invalid", error.to_string()))?;
    let owner = PipeOwner {
        user_sid: receipt["owner_sid"]
            .as_str()
            .ok_or_else(|| {
                AgentError::new("local.config_invalid", "provision owner_sid is missing")
            })?
            .to_owned(),
        logon_sid: receipt["logon_sid"]
            .as_str()
            .ok_or_else(|| {
                AgentError::new("local.config_invalid", "provision logon_sid is missing")
            })?
            .to_owned(),
        session_id: receipt["session_id"].as_u64().ok_or_else(|| {
            AgentError::new("local.config_invalid", "provision session_id is missing")
        })? as u32,
        minimum_integrity: IntegrityLevel::Medium,
    };
    let pipe_name = receipt["pipe_name"]
        .as_str()
        .ok_or_else(|| AgentError::new("local.config_invalid", "provision pipe_name is missing"))?
        .to_owned();
    let state_dir = receipt["state_dir"]
        .as_str()
        .ok_or_else(|| AgentError::new("local.config_invalid", "provision state_dir is missing"))?;
    Ok(LocalControlConfig {
        owner,
        pipe_name,
        audit_state_dir: Some(PathBuf::from(state_dir)),
        single_request_connections: false,
        dev_session_state_dir: Some(PathBuf::from(state_dir)),
    })
}

fn required(name: &'static str) -> Result<String, AgentError> {
    env::var(name).map_err(|_| {
        AgentError::new(
            "runtime.config_missing",
            format!("required environment variable {name} is missing"),
        )
    })
}

fn required_uri(name: &'static str) -> Result<Uri, AgentError> {
    required(name)?.parse().map_err(|error| {
        AgentError::new(
            "runtime.config_invalid",
            format!("{name} is not a valid URI: {error}"),
        )
    })
}

fn required_path(name: &'static str) -> Result<PathBuf, AgentError> {
    Ok(PathBuf::from(required(name)?))
}

#[cfg(any(windows, test))]
fn display_hub_address(uri: &Uri) -> String {
    let Some(host) = uri.host() else {
        return "unavailable".to_owned();
    };
    match uri.port_u16() {
        Some(port) => format!("https://{host}:{port}"),
        None => format!("https://{host}"),
    }
}

fn map_transport(error: TransportError) -> AgentError {
    AgentError::new(error.code(), error.to_string())
}

fn lock_error<T>(error: std::sync::PoisonError<T>) -> AgentError {
    AgentError::new("runtime.state_poisoned", error.to_string())
}

fn session_missing() -> AgentError {
    AgentError::new("runtime.session_missing", "verified session is unavailable")
}

fn cancelled() -> AgentError {
    AgentError::new("runtime.cancelled", "session task was cancelled")
}

fn session_ref(session: &VerifiedSession) -> SessionRef {
    SessionRef {
        agent_id: session.agent_id().to_owned(),
        session_id: session.session_id().to_owned(),
        generation: session.generation(),
    }
}

fn heartbeat_event(session: &VerifiedSession) -> AgentControlEvent {
    AgentControlEvent {
        payload: Some(agent_control_event::Payload::Heartbeat(Heartbeat {
            session: Some(session_ref(session)),
            sent_at_unix_ms: now_unix_ms(),
        })),
    }
}

fn status_event(session: &VerifiedSession, state: &str) -> AgentControlEvent {
    AgentControlEvent {
        payload: Some(agent_control_event::Payload::Status(AgentStatus {
            session: Some(session_ref(session)),
            state: state.to_owned(),
            profile_id: String::new(),
        })),
    }
}

fn ack_event(command: CommandRef, result_json: &str) -> AgentControlEvent {
    AgentControlEvent {
        payload: Some(agent_control_event::Payload::Ack(CommandAck {
            command: Some(command),
            result_json: result_json.to_owned(),
        })),
    }
}

fn nack_event(command: CommandRef, error_code: &str, message: &str) -> AgentControlEvent {
    AgentControlEvent {
        payload: Some(agent_control_event::Payload::Nack(CommandNack {
            command: Some(command),
            error_code: error_code.to_owned(),
            message: message.to_owned(),
        })),
    }
}

fn command_reference(
    command: &fairypam_agent_protocol::v1::HubControlCommand,
) -> Option<CommandRef> {
    use hub_control_command::Payload;
    match command.payload.as_ref()? {
        Payload::Hello(_) => None,
        Payload::EnumerateTargets(value) => value.command.clone(),
        Payload::LockTarget(value) => value.command.clone(),
        Payload::StartCapture(value) => value.command.clone(),
        Payload::StopCapture(value) => value.command.clone(),
        Payload::InputLease(value) => value.command.clone(),
        Payload::PulseAction(value) => value.command.clone(),
        Payload::MouseDeltaAction(value) => value.command.clone(),
        Payload::WindowPointClickAction(value) => value.command.clone(),
        Payload::ReleaseAll(value) => value.command.clone(),
        Payload::StopSession(value) => value.command.clone(),
        Payload::FocusTarget(value) => value.command.clone(),
        Payload::CloseTarget(value) => value.command.clone(),
    }
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use fairypam_agent_local_protocol::LocalCommand;
    use fairypam_agent_protocol::v1::{CloseTarget, FocusTarget, HubControlCommand};

    use super::*;

    #[test]
    fn production_runtime_is_explicitly_dry_run_for_remote_actions() {
        let command = CommandRef {
            command_id: "command-1".into(),
            ..CommandRef::default()
        };
        let event = nack_event(command, "agent.dry_run_only", "denied");

        let Some(agent_control_event::Payload::Nack(nack)) = event.payload else {
            panic!("remote action was not denied");
        };
        assert_eq!(nack.error_code, "agent.dry_run_only");
    }

    #[test]
    fn target_operation_command_refs_reach_ack_nack_correlation() {
        let reference = CommandRef {
            command_id: "target-operation".into(),
            ..CommandRef::default()
        };
        for payload in [
            hub_control_command::Payload::FocusTarget(FocusTarget {
                command: Some(reference.clone()),
            }),
            hub_control_command::Payload::CloseTarget(CloseTarget {
                command: Some(reference.clone()),
                timeout_ms: 500,
            }),
        ] {
            let command = HubControlCommand {
                payload: Some(payload),
            };
            assert_eq!(command_reference(&command), Some(reference.clone()));
        }
    }

    #[test]
    fn regular_nonempty_file_rejects_missing_and_empty_files() {
        let root =
            std::env::temp_dir().join(format!("fairypam-runtime-file-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let empty = root.join("empty");
        let populated = root.join("populated");
        std::fs::write(&empty, []).unwrap();
        std::fs::write(&populated, [1]).unwrap();

        assert!(!regular_nonempty_file(&root.join("missing")));
        assert!(!regular_nonempty_file(&empty));
        assert!(regular_nonempty_file(&populated));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn enrollment_expiration_must_be_valid_rfc3339_and_in_the_future() {
        assert!(validate_enrollment_expiry("2999-01-01T00:00:00Z").is_ok());
        assert_eq!(
            validate_enrollment_expiry("2000-01-01T00:00:00Z")
                .unwrap_err()
                .code(),
            "runtime.enrollment_invalid"
        );
        assert_eq!(
            validate_enrollment_expiry("not-a-timestamp")
                .unwrap_err()
                .code(),
            "runtime.enrollment_invalid"
        );
    }

    #[tokio::test]
    async fn unregistered_runtime_keeps_local_control_then_notifies_supervisor() {
        let driver = GrpcSessionDriver::new(RuntimeConfig::unregistered());
        let mut local = driver.local_runtime();

        assert!(!driver.is_registered().unwrap());
        assert_eq!(
            local.execute(&LocalCommand::GetConnectionStatus).unwrap()["hub_address"],
            ""
        );

        let mut enrolled = RuntimeConfig::unregistered();
        enrolled.transport.control_endpoint = "https://hub.example/control".parse().unwrap();
        enrolled.enrollment_generation = Some("g-test".to_owned());
        enrolled.awaiting_enrollment = false;
        let supervisor_gate = driver.wait_until_registered();
        tokio::pin!(supervisor_gate);
        local.activate_enrollment(enrolled).unwrap();

        tokio::time::timeout(Duration::from_millis(10), supervisor_gate)
            .await
            .expect("registration must wake the supervisor")
            .expect("registration state must remain readable");

        assert!(driver.is_registered().unwrap());
        assert_eq!(
            local.execute(&LocalCommand::GetConnectionStatus).unwrap()["hub_address"],
            "https://hub.example"
        );

        local.request_reconnect();
        tokio::time::timeout(Duration::from_millis(10), driver.wait_for_reconnect())
            .await
            .expect("re-registration must wake the active supervisor");
    }

    #[test]
    fn registration_pending_exposes_only_status() {
        let response = registration_pending();

        assert_eq!(response, serde_json::json!({"status": "pending"}));
        assert_eq!(response.as_object().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn local_request_deadline_expires_without_poisoning_the_next_read() {
        let expired = before_local_request_deadline(
            tokio::time::Instant::now(),
            std::future::pending::<()>(),
        )
        .await;
        let recovered = before_local_request_deadline(
            tokio::time::Instant::now() + Duration::from_millis(10),
            std::future::ready(7_u8),
        )
        .await;

        assert_eq!(expired, None);
        assert_eq!(recovered, Some(7));
    }

    #[cfg(all(windows, feature = "dev-automation"))]
    #[test]
    fn expired_dev_connection_requires_reconnect_and_releases_input() {
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

        use fairypam_agent_core::state::Effect;
        use fairypam_agent_local_protocol::{RequestEnvelope, PROTOCOL_VERSION};
        use fairypam_agent_windows::{IntegrityLevel, VerifiedPipeCaller};

        let state_dir = std::env::temp_dir().join(format!(
            "fairypam-dev-session-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time is after Unix epoch")
                .as_nanos(),
        ));
        std::fs::create_dir_all(&state_dir).expect("create Dev session state directory");
        let mut session = DevConnectionSession::new(state_dir.clone());
        let caller = VerifiedPipeCaller {
            pid: 42,
            user_sid: "S-1-5-21-owner".to_owned(),
            logon_sid: "S-1-5-5-owner".to_owned(),
            session_id: 1,
            integrity: IntegrityLevel::Medium,
        };
        let request = |nonce| RequestEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: format!("request-{nonce}"),
            nonce: [nonce; 32],
            command: LocalCommand::TestbedPulse,
        };
        let now = Instant::now();

        assert!(session.authorize_at(&caller, &request(1), now).1.is_ok());
        let (effects, error) =
            session.authorize_at(&caller, &request(2), now + Duration::from_secs(11));

        assert_eq!(effects, vec![Effect::ReleaseAll]);
        assert_eq!(error.unwrap_err().code(), "dev.session.expired");
        assert!(session.client_disconnected().is_empty());
        assert!(session
            .authorize_at(&caller, &request(3), now + Duration::from_secs(12))
            .1
            .is_ok());
        std::fs::remove_dir_all(state_dir).expect("remove Dev session state directory");
    }
}
