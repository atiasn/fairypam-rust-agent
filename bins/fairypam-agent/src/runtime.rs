#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::VecDeque;
use std::env;
use std::path::{Path, PathBuf};
#[cfg(any(windows, test))]
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicBool, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fairypam_agent_core::profile::Ed25519SignatureVerifier;
#[cfg(windows)]
use fairypam_agent_core::supervisor::SessionSupervisor;
use fairypam_agent_core::supervisor::{SessionDriver, SupervisorHooks};
use fairypam_agent_core::AgentError;
use fairypam_agent_protocol::v2::{
    agent_control_event, AgentControlEvent, AgentRuntimeState, AgentStatus, Heartbeat, SessionRef,
};
#[cfg(windows)]
use fairypam_agent_transport::validate_transport_config;
#[cfg(windows)]
use fairypam_agent_transport::CappedBackoff;
use fairypam_agent_transport::{
    connect_control, connect_frame, control_queue, open_control_tunnel, open_frame_tunnel,
    receive_hub_hello, ControlSender, ControlSession, SessionFrameSlot, TransportConfig,
    TransportError, VerifiedSession,
};
use http::Uri;
#[cfg(any(windows, test))]
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio_util::sync::CancellationToken;

use crate::execution::{CommandExecutor, CommandOutcome, ExecutionSession, FrameSink};
use crate::gui_lifecycle::GuiLifetime;
#[cfg(any(windows, test))]
use crate::observability;
use crate::observability::AgentLogRecord;
use crate::profile_store::ProfileStore;
use crate::v2_adapter;
const REGISTRATION_JOIN_TIMEOUT: Duration = Duration::from_secs(20);

use crate::runtime_api::LogLevel;
#[cfg(any(windows, test))]
use crate::runtime_api::RuntimeCommand as LocalCommand;

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub transport: TransportConfig,
    pub agent_version: String,
    pub build_commit: String,
    pub profiles: ProfileStore,
    enrollment_root: Option<PathBuf>,
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
            #[cfg(windows)]
            enrollment_root: Some(PathBuf::from(crate::enrollment::STATE_ROOT)),
            #[cfg(not(windows))]
            enrollment_root: None,
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
            enrollment_root: None,
            enrollment_generation: None,
            awaiting_enrollment: false,
        })
    }

    #[cfg(windows)]
    fn from_enrollment_state() -> Result<Self, AgentError> {
        let root = PathBuf::from(crate::enrollment::STATE_ROOT);
        Self::from_enrollment_state_at(&root)
    }

    #[cfg(windows)]
    fn from_enrollment_state_at(root: &Path) -> Result<Self, AgentError> {
        crate::enrollment::ensure_private_directory(root)?;
        let pointer = load_private_json(&root.join("current.json"))?;
        let generation = enrollment_field(&pointer, "generation")?;
        Self::from_enrollment_candidate(root, generation)
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
            enrollment_root: Some(root.to_path_buf()),
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
    enrollment_state_exists_at(Path::new(crate::enrollment::STATE_ROOT))
}

#[cfg(windows)]
fn enrollment_state_exists_at(root: &Path) -> bool {
    crate::enrollment::ensure_private_directory(root).is_ok()
        && crate::enrollment::verify_private_file(&root.join("current.json")).is_ok()
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
    let mut file = crate::enrollment::open_private_read(path).map_err(|_| {
        AgentError::new(
            "runtime.enrollment_invalid",
            "enrollment state is unavailable or unsafe",
        )
    })?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes).map_err(|_| {
        AgentError::new(
            "runtime.enrollment_invalid",
            "enrollment state cannot be read",
        )
    })?;
    crate::enrollment::verify_private_file(path).map_err(|_| {
        AgentError::new(
            "runtime.enrollment_invalid",
            "enrollment state changed during read",
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
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
    crate::enrollment::verify_private_file(&path).map_err(|_| {
        AgentError::new(
            "runtime.enrollment_invalid",
            "enrollment credential is unsafe",
        )
    })?;
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

#[derive(Clone, Copy)]
enum RuntimeLogMessage {
    AwaitingRegistration,
    Started,
    ControlConnectionStarting,
    ControlConnectionEstablished,
    FrameConnectionEstablished,
    EnrollmentRefreshFailed,
    SessionCleared,
    LocalShutdownRequested,
    LocalUiBound,
    LocalUiShutdownRequested,
    LocalEnvironmentCheckRequested,
    LocalGameScanRequested,
    LocalRegistrationRequested,
    RegistrationStarted,
    RegistrationChanged,
    RegistrationCompleted,
}

impl RuntimeLogMessage {
    #[cfg(test)]
    const ALL: &[Self] = &[
        Self::AwaitingRegistration,
        Self::Started,
        Self::ControlConnectionStarting,
        Self::ControlConnectionEstablished,
        Self::FrameConnectionEstablished,
        Self::EnrollmentRefreshFailed,
        Self::SessionCleared,
        Self::LocalShutdownRequested,
        Self::LocalUiBound,
        Self::LocalUiShutdownRequested,
        Self::LocalEnvironmentCheckRequested,
        Self::LocalGameScanRequested,
        Self::LocalRegistrationRequested,
        Self::RegistrationStarted,
        Self::RegistrationChanged,
        Self::RegistrationCompleted,
    ];

    const fn text(self) -> &'static str {
        match self {
            Self::AwaitingRegistration => "后台服务正在等待完成安全注册",
            Self::Started => "后台服务已启动，正在准备连接",
            Self::ControlConnectionStarting => "正在建立服务连接",
            Self::ControlConnectionEstablished => "服务连接已建立",
            Self::FrameConnectionEstablished => "画面服务已准备就绪",
            Self::EnrollmentRefreshFailed => "注册信息刷新失败，连接将保持安全关闭",
            Self::SessionCleared => "连接已重置，正在重新连接",
            Self::LocalShutdownRequested => "后台服务收到安全停止请求",
            Self::LocalUiBound => "界面已连接到后台服务",
            Self::LocalUiShutdownRequested => "界面请求安全停止后台服务",
            Self::LocalEnvironmentCheckRequested => "界面请求环境检查",
            Self::LocalGameScanRequested => "界面请求扫描已安装游戏",
            Self::LocalRegistrationRequested => "界面请求注册服务",
            Self::RegistrationStarted => "服务注册已开始，正在安全领取凭据",
            Self::RegistrationChanged => "服务注册信息已变更，正在安全重连",
            Self::RegistrationCompleted => "服务注册已完成，正在安全重连",
        }
    }
}

fn registration_failure_code(code: &str) -> &'static str {
    match code {
        "enrollment.elevation_required" => "enrollment.elevation_required",
        "enrollment.request_invalid" => "enrollment.request_invalid",
        "enrollment.network_failed" => "enrollment.network_failed",
        "enrollment.failed" => "enrollment.failed",
        "runtime.enrollment_invalid" => "runtime.enrollment_invalid",
        "runtime.state_poisoned" => "runtime.state_poisoned",
        _ => "enrollment.failed",
    }
}

impl RuntimeState {
    fn record(&mut self, level: LogLevel, message: RuntimeLogMessage) {
        self.record_text(level, message.text());
    }

    fn record_registration_failure(&mut self, code: &str) {
        self.record_text(
            LogLevel::Warn,
            &format!(
                "服务注册失败（错误码：{}）",
                registration_failure_code(code)
            ),
        );
    }

    fn record_text(&mut self, level: LogLevel, message: &str) {
        if self.logs.len() == 200 {
            self.logs.pop_front();
        }
        self.logs
            .push_back(AgentLogRecord::new(level.clone(), message));
        #[cfg(windows)]
        if let Err(error) =
            observability::production_log().and_then(|log| log.append(level, message))
        {
            tracing::warn!(code = error.code(), "protected Agent log write failed");
        }
    }
}

pub struct GrpcSessionDriver {
    config: Arc<Mutex<RuntimeConfig>>,
    state: Arc<Mutex<RuntimeState>>,
    execution: Arc<Mutex<CommandExecutor>>,
    enrollment_ready: Arc<tokio::sync::Notify>,
    reconnect_requested: Arc<tokio::sync::Notify>,
    registration_in_progress: Arc<AtomicBool>,
    registration_worker: Arc<Mutex<Option<JoinHandle<()>>>>,
    gui_shutdown: CancellationToken,
    gui_lifetime: GuiLifetime,
}

impl GrpcSessionDriver {
    pub fn new(config: RuntimeConfig) -> Self {
        let execution = CommandExecutor::production(config.profiles.clone());
        let mut state = if config.awaiting_enrollment {
            let mut state = RuntimeState {
                last_error_code: "runtime.not_registered".to_owned(),
                ..RuntimeState::default()
            };
            state.record(LogLevel::Info, RuntimeLogMessage::AwaitingRegistration);
            state
        } else {
            RuntimeState::default()
        };
        state.record(LogLevel::Info, RuntimeLogMessage::Started);
        let gui_shutdown = CancellationToken::new();
        Self {
            config: Arc::new(Mutex::new(config)),
            state: Arc::new(Mutex::new(state)),
            execution: Arc::new(Mutex::new(execution)),
            enrollment_ready: Arc::new(tokio::sync::Notify::new()),
            reconnect_requested: Arc::new(tokio::sync::Notify::new()),
            registration_in_progress: Arc::new(AtomicBool::new(false)),
            registration_worker: Arc::new(Mutex::new(None)),
            gui_lifetime: GuiLifetime::new(gui_shutdown.clone()),
            gui_shutdown,
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
            registration_worker: Arc::clone(&self.registration_worker),
            gui_lifetime: self.gui_lifetime.clone(),
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
            let (expected, root) = {
                let config = self.config.lock().map_err(lock_error)?;
                (
                    config.enrollment_generation.clone(),
                    config.enrollment_root.clone(),
                )
            };
            let Some(expected) = expected else {
                return Ok(false);
            };
            let root = root.ok_or_else(|| {
                AgentError::new(
                    "runtime.enrollment_invalid",
                    "enrollment state root is unavailable",
                )
            })?;
            crate::enrollment::ensure_private_directory(&root)?;
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
            state.record(LogLevel::Info, RuntimeLogMessage::ControlConnectionStarting);
        }
        let connection = tokio::select! {
            _ = cancellation.cancelled() => return Err(cancelled()),
            result = connect_control(&config.transport) => result.map_err(map_transport)?,
        };
        let (sender, receiver) = control_queue();
        sender
            .send(v2_adapter::hello(
                config.transport.agent_id.clone(),
                config.agent_version.clone(),
                config.build_commit.clone(),
                &config.profiles,
            ))
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
            .try_send(status_event(&session, AgentRuntimeState::ConnectedIdle))
            .map_err(map_transport)?;
        sender
            .try_send(v2_adapter::discovery_snapshot(
                fairypam_agent_protocol::v2::SessionRef {
                    agent_id: session.agent_id().to_owned(),
                    session_id: session.session_id().to_owned(),
                    generation: session.generation(),
                },
                &config.profiles,
            )?)
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
        state.record(
            LogLevel::Info,
            RuntimeLogMessage::ControlConnectionEstablished,
        );
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
        let mut capture_health = tokio::time::interval(Duration::from_millis(250));
        capture_health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        capture_health.tick().await;
        let mut translator = v2_adapter::Translator::new(session.max_input_lease_ms());
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
                _ = capture_health.tick() => {
                    let event = self
                        .execution
                        .lock()
                        .map_err(lock_error)?
                        .capture_failure_event(&ExecutionSession::from_verified(&session))?;
                    if let Some(event) = event {
                        sender.try_send(v2_adapter::safety_event(event)?).map_err(map_transport)?;
                    }
                }
                command = control.message() => {
                    let command = command.map_err(map_transport)?.ok_or_else(|| {
                        AgentError::new("runtime.control_closed", "Hub closed the Control stream")
                    })?.into_inner();
                    let identity = v2_adapter::identity(&command).ok_or_else(|| {
                        AgentError::new(
                            "runtime.command_invalid",
                            "verified command lost CommandRef",
                        )
                    })?;
                    let translated = match translator.translate(&command) {
                        Ok(command) => command,
                        Err(error) => {
                            let event = match v2_adapter::internal_task_identity(&identity) {
                                Ok(task) => {
                                    let mut execution = self.execution.lock().map_err(lock_error)?;
                                    let outcome = if error.code() == "command.payload_digest_conflict" {
                                        execution.v2_payload_digest_conflict(&task)
                                    } else {
                                        execution.reject_v2_task(&task, error.code())
                                    };
                                    v2_adapter::result(identity, outcome)
                                }
                                Err(_) => v2_adapter::error(identity, &error),
                            };
                            sender.try_send(event).map_err(map_transport)?;
                            continue;
                        }
                    };
                    let outcome = match translated {
                        v2_adapter::TranslatedCommand::Internal(internal) => {
                            let frames = {
                                let state = self.state.lock().map_err(lock_error)?;
                                state.frames.clone().ok_or_else(session_missing)?
                            };
                            self.execution.lock().map_err(lock_error)?.execute(
                                &internal,
                                &ExecutionSession::from_verified(&session),
                                Arc::new(frames) as Arc<dyn FrameSink>,
                            )
                        }
                        v2_adapter::TranslatedCommand::BeginAttempt {
                            task,
                            contract,
                            digest_key,
                            payload_digest,
                        } => {
                            let outcome = self.execution
                                .lock()
                                .map_err(lock_error)?
                                .execute_v2_begin(&task, &contract);
                            if matches!(&outcome, CommandOutcome::TaskAck { .. }) {
                                translator.accept_begin(contract, digest_key, payload_digest);
                            }
                            outcome
                        }
                        v2_adapter::TranslatedCommand::InputFrame { task, frame } => {
                            self.execution
                                .lock()
                                .map_err(lock_error)?
                                .execute_v2_input_frame(&task, &frame)
                        }
                    };
                    let event = v2_adapter::result(identity, outcome);
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
            state.record(
                LogLevel::Info,
                RuntimeLogMessage::FrameConnectionEstablished,
            );
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
                    frames.set_accept_frames(directive.accept_frames);
                }
            }
        }
    }
}

pub struct RuntimeSafetyHooks {
    config: Arc<Mutex<RuntimeConfig>>,
    state: Arc<Mutex<RuntimeState>>,
    execution: Arc<Mutex<CommandExecutor>>,
    registration_worker: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl RuntimeSafetyHooks {
    pub fn for_driver(driver: &GrpcSessionDriver) -> Self {
        Self {
            config: Arc::clone(&driver.config),
            state: Arc::clone(&driver.state),
            execution: Arc::clone(&driver.execution),
            registration_worker: Arc::clone(&driver.registration_worker),
        }
    }
}

fn join_registration_worker(
    worker: &Arc<Mutex<Option<JoinHandle<()>>>>,
    timeout: Duration,
) -> Result<(), String> {
    let Some(worker_handle) = worker.lock().map_err(|error| error.to_string())?.take() else {
        return Ok(());
    };
    let deadline = Instant::now() + timeout;
    while !worker_handle.is_finished() {
        if Instant::now() >= deadline {
            *worker.lock().map_err(|error| error.to_string())? = Some(worker_handle);
            return Err("registration worker did not finish before the deadline".to_owned());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    worker_handle
        .join()
        .map_err(|_| "registration worker panicked".to_owned())
}

impl SupervisorHooks for RuntimeSafetyHooks {
    fn close_input_gate(&mut self) -> Result<(), String> {
        tracing::info!(effect = "close_input_gate", "fail-closed cleanup effect");
        Ok(())
    }

    fn guardian_release_all(&mut self) -> Result<(), String> {
        self.execution
            .lock()
            .map_err(|error| error.to_string())?
            .emergency_release_input()
            .map_err(|error| error.to_string())?;
        tracing::info!(effect = "guardian_release_all", state = "released");
        Ok(())
    }

    fn cancel_all_tasks(&mut self) {
        tracing::info!(effect = "cancel_all_tasks");
    }

    fn join_all_tasks(&mut self) -> Result<(), String> {
        join_registration_worker(&self.registration_worker, REGISTRATION_JOIN_TIMEOUT)?;
        tracing::info!(effect = "join_all_tasks", result = "joined");
        Ok(())
    }

    fn clear_target_session(&mut self) {
        #[cfg(windows)]
        if let Some(root) = self
            .config
            .lock()
            .ok()
            .and_then(|config| config.enrollment_root.clone())
            .filter(|root| enrollment_state_exists_at(root))
        {
            match RuntimeConfig::from_enrollment_state_at(&root) {
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
                        state.record(LogLevel::Warn, RuntimeLogMessage::EnrollmentRefreshFailed);
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
            state.record(LogLevel::Warn, RuntimeLogMessage::SessionCleared);
        }
        tracing::info!(effect = "clear_target_session");
    }

    fn cancel_frame_pipeline(&mut self) {
        if let Ok(mut execution) = self.execution.lock() {
            let _ = execution.emergency_release_input();
            let _ = execution.stop_capture(None);
        }
        tracing::info!(effect = "cancel_frame_pipeline");
    }

    fn join_frame_pipeline(&mut self) -> Result<(), String> {
        tracing::info!(effect = "join_frame_pipeline", result = "joined");
        Ok(())
    }
}

#[cfg(any(windows, test))]
#[derive(Clone)]
pub struct EmbeddedRuntimeHandle {
    runtime: SharedRuntime,
    completion: Arc<EmbeddedRuntimeCompletion>,
}

#[cfg(any(windows, test))]
#[derive(Default)]
struct EmbeddedRuntimeCompletion {
    result: Mutex<Option<Result<(), String>>>,
    completed: tokio::sync::Notify,
}

#[cfg(any(windows, test))]
impl EmbeddedRuntimeCompletion {
    fn finish(&self, result: &Result<(), AgentError>) {
        let stored = result.as_ref().map(|_| ()).map_err(ToString::to_string);
        if let Ok(mut current) = self.result.lock() {
            *current = Some(stored);
        }
        self.completed.notify_waiters();
    }

    async fn wait(&self) -> Result<(), AgentError> {
        loop {
            let notified = self.completed.notified();
            if let Some(result) = self.result.lock().map_err(lock_error)?.clone() {
                return result
                    .map_err(|message| AgentError::new("runtime.embedded_failed", message));
            }
            notified.await;
        }
    }

    fn ensure_running(&self) -> Result<(), AgentError> {
        match self.result.lock().map_err(lock_error)?.as_ref() {
            None => Ok(()),
            Some(Ok(())) => Err(AgentError::new(
                "runtime.embedded_stopped",
                "embedded runtime has stopped",
            )),
            Some(Err(message)) => Err(AgentError::new("runtime.embedded_failed", message.clone())),
        }
    }
}

#[cfg(any(windows, test))]
impl EmbeddedRuntimeHandle {
    pub fn execute(&self, command: &LocalCommand) -> Result<serde_json::Value, AgentError> {
        self.completion.ensure_running()?;
        match command {
            LocalCommand::Status
            | LocalCommand::Doctor
            | LocalCommand::ListProfiles
            | LocalCommand::GetConnectionStatus
            | LocalCommand::RunEnvironmentCheck
            | LocalCommand::GetLogTail { .. }
            | LocalCommand::ScanInstalledGames
            | LocalCommand::RegisterHub { .. } => self.runtime.execute_embedded(command),
            LocalCommand::ShutdownAgent => {
                self.runtime.record_local_operation(command);
                self.runtime.execution.lock().map_err(lock_error)?.reset()?;
                self.runtime.gui_lifetime.request_maintenance_shutdown()?;
                Ok(serde_json::json!({"state": "shutting_down"}))
            }
            _ => Err(AgentError::new(
                "local.embedded_command_not_allowed",
                "the embedded GUI runtime does not expose device commands",
            )),
        }
    }

    pub async fn wait_for_shutdown(&self, timeout: Duration) -> Result<(), AgentError> {
        tokio::time::timeout(timeout, self.completion.wait())
            .await
            .map_err(|_| {
                AgentError::new(
                    "runtime.shutdown_timeout",
                    "embedded runtime did not finish cleanup before the deadline",
                )
            })?
    }
}

#[cfg(windows)]
pub fn start_embedded(
    config: RuntimeConfig,
) -> Result<
    (
        EmbeddedRuntimeHandle,
        impl std::future::Future<Output = Result<(), AgentError>>,
    ),
    AgentError,
> {
    verify_active_agent_suite()?;
    let instance = AgentInstance::acquire()?;
    let driver = GrpcSessionDriver::new(config);
    let completion = Arc::new(EmbeddedRuntimeCompletion::default());
    let handle = EmbeddedRuntimeHandle {
        runtime: driver.local_runtime(),
        completion: Arc::clone(&completion),
    };
    Ok((handle, async move {
        let _instance = instance;
        let result = run_embedded_driver(driver).await;
        completion.finish(&result);
        result
    }))
}

#[cfg(windows)]
async fn run_embedded_driver(driver: GrpcSessionDriver) -> Result<(), AgentError> {
    let hooks = RuntimeSafetyHooks::for_driver(&driver);
    let backoff = CappedBackoff::new(Duration::from_millis(250), Duration::from_secs(30))
        .map_err(map_transport)?;
    let mut supervisor = SessionSupervisor::new(hooks, backoff);
    if !driver.is_registered()? {
        tokio::select! {
            result = driver.wait_until_registered() => result?,
            _ = driver.gui_shutdown.cancelled() => {
                return shutdown_embedded(&driver, &mut supervisor);
            }
        }
    }
    let mut supervisor_run = Box::pin(supervisor.run(&driver));
    tokio::select! {
        result = &mut supervisor_run => match result {
            Ok(never) => match never {},
            Err(error) => Err(error),
        },
        _ = driver.gui_shutdown.cancelled() => {
            drop(supervisor_run);
            shutdown_embedded(&driver, &mut supervisor)
        }
    }
}

#[cfg(windows)]
fn shutdown_embedded(
    driver: &GrpcSessionDriver,
    supervisor: &mut SessionSupervisor<RuntimeSafetyHooks>,
) -> Result<(), AgentError> {
    if let Ok(mut state) = driver.state.lock() {
        state.record(LogLevel::Info, RuntimeLogMessage::LocalShutdownRequested);
    }
    let _ = supervisor.handle_control_failure()?;
    Ok(())
}

#[cfg(windows)]
fn verify_active_agent_suite() -> Result<(), AgentError> {
    let executable = std::env::current_exe().map_err(|_| {
        AgentError::new("runtime.inactive_suite", "Agent executable is unavailable")
    })?;
    let version_root = executable.parent().ok_or_else(|| {
        AgentError::new(
            "runtime.inactive_suite",
            "Agent version root is unavailable",
        )
    })?;
    let versions = version_root.parent().ok_or_else(|| {
        AgentError::new(
            "runtime.inactive_suite",
            "Agent versions root is unavailable",
        )
    })?;
    if versions.file_name().and_then(|name| name.to_str()) != Some("versions") {
        return Err(AgentError::new(
            "runtime.inactive_suite",
            "Agent is not running from a versioned product root",
        ));
    }
    let install_root = versions.parent().ok_or_else(|| {
        AgentError::new(
            "runtime.inactive_suite",
            "Agent install root is unavailable",
        )
    })?;
    let active = fairypam_agent_suite::resolve_active_suite(install_root)
        .map_err(|error| AgentError::new(error.code(), error.to_string()))?;
    let actual = std::fs::canonicalize(version_root)
        .map_err(|error| AgentError::new("runtime.inactive_suite", error.to_string()))?;
    let expected = std::fs::canonicalize(active.version_root)
        .map_err(|error| AgentError::new("runtime.inactive_suite", error.to_string()))?;
    if !actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
    {
        return Err(AgentError::new(
            "runtime.inactive_suite",
            "Agent executable does not belong to the active suite",
        ));
    }
    Ok(())
}

#[cfg(windows)]
struct AgentInstance(usize);

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
            unsafe { CreateMutexW(None, false, &HSTRING::from(r"Global\FairyPam.Agent.v1")) }
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
        Ok(Self(handle.0 as usize))
    }
}

#[cfg(windows)]
impl Drop for AgentInstance {
    fn drop(&mut self) {
        use windows::Win32::Foundation::HANDLE;

        let _ = unsafe { windows::Win32::Foundation::CloseHandle(HANDLE(self.0 as _)) };
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
    registration_worker: Arc<Mutex<Option<JoinHandle<()>>>>,
    gui_lifetime: GuiLifetime,
}

#[cfg(any(windows, test))]
impl SharedRuntime {
    fn execute_embedded(&self, command: &LocalCommand) -> Result<serde_json::Value, AgentError> {
        self.record_local_operation(command);
        match command {
            LocalCommand::GetConnectionStatus => self.connection_status(),
            LocalCommand::RunEnvironmentCheck => self.environment_check(),
            LocalCommand::GetLogTail { lines, level } => self.log_tail(*lines, level),
            LocalCommand::ScanInstalledGames => self.scan_installed_games(),
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

    fn record_local_operation(&self, command: &LocalCommand) {
        let message = match command {
            LocalCommand::BindUiLifetime => Some(RuntimeLogMessage::LocalUiBound),
            LocalCommand::ShutdownAgent => Some(RuntimeLogMessage::LocalUiShutdownRequested),
            LocalCommand::RunEnvironmentCheck => {
                Some(RuntimeLogMessage::LocalEnvironmentCheckRequested)
            }
            LocalCommand::ScanInstalledGames => Some(RuntimeLogMessage::LocalGameScanRequested),
            LocalCommand::RegisterHub { .. } => Some(RuntimeLogMessage::LocalRegistrationRequested),
            // The log page reads this same source; recording each tail request
            // would create a feedback loop during polling.
            LocalCommand::GetLogTail { .. } => None,
            _ => None,
        };
        if let Some(message) = message {
            if let Ok(mut state) = self.state.lock() {
                state.record(LogLevel::Info, message);
            }
        }
    }

    #[cfg(windows)]
    fn register_hub(
        &self,
        hub_address: &str,
        registration_code: &str,
    ) -> Result<serde_json::Value, AgentError> {
        // Return while the direct claim runs so the GUI remains responsive to
        // status and retry requests.
        if self.registration_in_progress.swap(true, Ordering::AcqRel) {
            return Err(AgentError::new(
                "enrollment.registration_pending",
                "a Hub registration is already pending",
            ));
        }
        if let Err(error) =
            join_registration_worker(&self.registration_worker, REGISTRATION_JOIN_TIMEOUT)
        {
            self.registration_in_progress
                .store(false, Ordering::Release);
            return Err(AgentError::new("enrollment.worker_join_failed", error));
        }
        self.mark_registration_started();
        let runtime = self.clone();
        let hub_address = hub_address.to_owned();
        let registration_code = registration_code.to_owned();
        let worker = std::thread::Builder::new()
            .name("fairypam-enrollment".to_owned())
            .spawn(move || runtime.finish_registration(hub_address, registration_code))
            .map_err(|_| {
                AgentError::new(
                    "enrollment.unavailable",
                    "Hub registration could not be started",
                )
            });
        let worker = match worker {
            Ok(worker) => worker,
            Err(error) => {
                self.registration_in_progress
                    .store(false, Ordering::Release);
                if let Ok(mut state) = self.state.lock() {
                    state.last_error_code = error.code().to_owned();
                    state.record_registration_failure(error.code());
                }
                return Err(error);
            }
        };
        if let Ok(mut current) = self.registration_worker.lock() {
            *current = Some(worker);
        } else {
            let _ = worker.join();
            return Err(AgentError::new(
                "enrollment.worker_state_unavailable",
                "registration worker state is unavailable",
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
        let root = self
            .config
            .lock()
            .ok()
            .and_then(|config| config.enrollment_root.clone());
        let result = root
            .ok_or_else(|| {
                AgentError::new(
                    "runtime.enrollment_invalid",
                    "enrollment state root is unavailable",
                )
            })
            .and_then(|root| {
                crate::enrollment::register_at(&root, &hub_address, &registration_code)?;
                RuntimeConfig::from_enrollment_state_at(&root)
            })
            .and_then(|config| self.activate_enrollment(config))
            .map(|_| {
                if !was_waiting {
                    self.request_reconnect();
                }
            });
        if let Err(error) = result {
            if let Ok(mut state) = self.state.lock() {
                state.last_error_code = error.code().to_owned();
                state.record_registration_failure(error.code());
            }
            tracing::warn!(code = error.code(), "Hub registration was not completed");
        }
        self.registration_in_progress
            .store(false, Ordering::Release);
    }

    #[cfg(windows)]
    fn mark_registration_started(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.last_error_code = "runtime.enrollment_registration_pending".to_owned();
            state.record(LogLevel::Info, RuntimeLogMessage::RegistrationStarted);
        }
    }

    fn request_reconnect(&self) {
        if let Ok(mut state) = self.state.lock() {
            // Leave the active generation in place; supervisor cleanup reloads
            // the persisted replacement before reconnecting.
            state.last_error_code = "runtime.enrollment_changed".to_owned();
            state.record(LogLevel::Info, RuntimeLogMessage::RegistrationChanged);
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
        state.record(LogLevel::Info, RuntimeLogMessage::RegistrationCompleted);
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
        Ok(serde_json::json!({
            "control": state.control_state.as_str(),
            "frame": state.frame_state.as_str(),
            "capture_active": capture_active,
            "recovery_code": state.last_error_code,
        }))
    }

    fn environment_check(&self) -> Result<serde_json::Value, AgentError> {
        let registration_pending = self.registration_in_progress.load(Ordering::Acquire);
        let (control_state, frame_state) = {
            let state = self.state.lock().map_err(lock_error)?;
            (state.control_state, state.frame_state)
        };
        let (awaiting_enrollment, profiles_configured, certificate_ready, games_available) = {
            let config = self.config.lock().map_err(lock_error)?;
            let certificate_paths = [
                config.transport.ca_pem.clone(),
                config.transport.identity_cert_pem.clone(),
                config.transport.identity_key_pem.clone(),
            ];
            let games_available = observability::scan_installed_games(&config.profiles).is_ok();
            (
                config.awaiting_enrollment,
                !config.profiles.ids().is_empty(),
                certificate_paths
                    .into_iter()
                    .all(|path| regular_nonempty_file(&path)),
                games_available,
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
        let (game_status, game_code) = if games_available {
            ("available", "game.discovery_ready")
        } else {
            ("unavailable", "game.discovery_unavailable")
        };
        let check = |id: &str, status: ConnectionState| {
            serde_json::json!({
                "id": id,
                "status": status.as_str(),
                "code": if matches!(status, ConnectionState::Connected) { "runtime.connected" } else { "runtime.connection_unavailable" },
                "recovery": "请检查本地服务注册状态和服务连接是否可用。",
            })
        };
        let registration_ready = binary_ready && guardian_ready;
        let enrollment_check = |id: &str, status: ConnectionState| {
            if awaiting_enrollment {
                serde_json::json!({"id": id, "status": "pending", "code": "enrollment.required", "recovery": "请先完成本地服务注册，再检查服务连接。"})
            } else {
                check(id, status)
            }
        };
        Ok(
            serde_json::json!({"registration_ready": registration_ready, "registration_pending": registration_pending, "checks": [
                {"id": "binary_or_task", "status": if binary_ready { "available" } else { "unavailable" }, "code": if binary_ready { "agent.binary_available" } else { "agent.binary_unavailable" }, "recovery": "本地服务安装不完整，请重新安装 FairyPam。"},
                {"id": "agent", "status": "available", "code": "agent.running", "recovery": "无需操作。"},
                {"id": "certificate", "status": if awaiting_enrollment { "pending" } else if certificate_ready { "available" } else { "unavailable" }, "code": if awaiting_enrollment { "enrollment.required" } else if certificate_ready { "runtime.certificate_files_available" } else { "runtime.certificate_unavailable" }, "recovery": "请完成注册或重新注册本地服务。"},
                enrollment_check("control", control_state),
                enrollment_check("frame", frame_state),
                {"id": "guardian", "status": if guardian_ready { "available" } else { "unavailable" }, "code": if guardian_ready { "guardian.binary_available" } else { "guardian.binary_unavailable" }, "recovery": "本地服务组件不完整，请重新安装 FairyPam。"},
                {"id": "profiles", "status": if profiles_configured { "available" } else { "unavailable" }, "code": if profiles_configured { "profile.available" } else { "profile.unavailable" }, "recovery": "请安装已签名配置文件后再选择游戏。"},
                {"id": "game_discovery", "status": game_status, "code": game_code, "recovery": "启动器更新后，请重新扫描已安装游戏。"}
            ]}),
        )
    }

    fn log_tail(&self, lines: u16, level: &LogLevel) -> Result<serde_json::Value, AgentError> {
        #[cfg(windows)]
        return observability::production_log()?.tail(lines, level);
        #[cfg(not(windows))]
        {
            let mut state = self.state.lock().map_err(lock_error)?;
            Ok(observability::log_tail_json(
                state.logs.make_contiguous(),
                lines,
                level,
            ))
        }
    }

    fn scan_installed_games(&self) -> Result<serde_json::Value, AgentError> {
        let config = self.config.lock().map_err(lock_error)?;
        observability::scan_installed_games(&config.profiles)
    }
}

#[cfg(any(windows, test))]
fn registration_pending() -> serde_json::Value {
    serde_json::json!({"status": "pending"})
}

fn regular_nonempty_file(path: &Path) -> bool {
    path.symlink_metadata().is_ok_and(|metadata| {
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() > 0
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

fn status_event(session: &VerifiedSession, state: AgentRuntimeState) -> AgentControlEvent {
    AgentControlEvent {
        payload: Some(agent_control_event::Payload::Status(AgentStatus {
            session: Some(session_ref(session)),
            state: state as i32,
            profile_id: String::new(),
            attempt: None,
        })),
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
    use crate::runtime_api::{LogLevel, RuntimeCommand as LocalCommand};

    use super::*;

    #[test]
    fn registration_failure_log_code_is_whitelisted() {
        assert_eq!(
            registration_failure_code("enrollment.network_failed"),
            "enrollment.network_failed"
        );
        assert_eq!(
            registration_failure_code("registration-code=not-for-log"),
            "enrollment.failed"
        );
    }

    #[test]
    fn registration_worker_is_rejoined_after_a_bounded_timeout() {
        let worker = Arc::new(Mutex::new(Some(std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(20));
        }))));

        assert!(join_registration_worker(&worker, Duration::ZERO).is_err());
        assert!(worker.lock().unwrap().is_some());
        join_registration_worker(&worker, Duration::from_secs(1)).unwrap();
        assert!(worker.lock().unwrap().is_none());
    }

    #[test]
    fn embedded_runtime_exposes_observability_but_not_device_commands() {
        let driver = GrpcSessionDriver::new(RuntimeConfig::unregistered());
        let completion = Arc::new(EmbeddedRuntimeCompletion::default());
        let handle = EmbeddedRuntimeHandle {
            runtime: driver.local_runtime(),
            completion: Arc::clone(&completion),
        };

        assert!(handle.execute(&LocalCommand::Status).is_ok());
        assert_eq!(
            handle
                .execute(&LocalCommand::ReleaseAll)
                .unwrap_err()
                .code(),
            "local.embedded_command_not_allowed"
        );
        completion.finish(&Err(AgentError::new("runtime.test_failure", "stopped")));
        assert_eq!(
            handle.execute(&LocalCommand::Status).unwrap_err().code(),
            "runtime.embedded_failed"
        );
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

    #[test]
    fn runtime_log_messages_are_localized_and_hide_internal_terms() {
        let mut state = RuntimeState::default();
        for message in RuntimeLogMessage::ALL {
            assert!(message
                .text()
                .chars()
                .any(|character| ('\u{4e00}'..='\u{9fff}').contains(&character)));
            state.record(LogLevel::Info, *message);
        }

        let output =
            observability::log_tail_json(state.logs.make_contiguous(), 200, &LogLevel::Info)
                .to_string()
                .to_ascii_lowercase();
        for forbidden in ["agent", "hub", "control", "frame", "grpc"] {
            assert!(!output.contains(forbidden), "log tail exposed {forbidden}");
        }
        assert_eq!(state.logs.len(), RuntimeLogMessage::ALL.len());
    }

    #[tokio::test]
    async fn unregistered_embedded_runtime_notifies_supervisor() {
        let driver = GrpcSessionDriver::new(RuntimeConfig::unregistered());
        let local = driver.local_runtime();

        assert!(!driver.is_registered().unwrap());
        assert!(local
            .execute_embedded(&LocalCommand::GetConnectionStatus)
            .unwrap()
            .get("hub_address")
            .is_none());
        let diagnostics = local
            .execute_embedded(&LocalCommand::RunEnvironmentCheck)
            .unwrap();
        assert_eq!(diagnostics["registration_pending"], false);
        for id in ["certificate", "control", "frame"] {
            assert_eq!(
                diagnostics["checks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|check| check["id"] == id)
                    .unwrap()["status"],
                "pending"
            );
        }
        assert!(diagnostics["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|check| {
                check["recovery"].as_str().is_some_and(|message| {
                    message
                        .chars()
                        .any(|character| ('\u{4e00}'..='\u{9fff}').contains(&character))
                })
            }));

        local
            .registration_in_progress
            .store(true, Ordering::Release);
        let pending_diagnostics = local
            .execute_embedded(&LocalCommand::RunEnvironmentCheck)
            .unwrap();
        assert_eq!(pending_diagnostics["registration_pending"], true);
        // Production log tailing requires installer-provisioned private paths.
        // This runtime test verifies the shared record boundary without depending
        // on Windows installer state.
        let messages = {
            let state = local.state.lock().unwrap();
            state
                .logs
                .iter()
                .map(|entry| entry.message.clone())
                .collect::<Vec<_>>()
        };
        assert!(messages
            .iter()
            .any(|message| message == "后台服务已启动，正在准备连接"));
        assert!(messages.iter().any(|message| message == "界面请求环境检查"));

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
        let status = local
            .execute_embedded(&LocalCommand::GetConnectionStatus)
            .unwrap();
        assert!(status.get("hub_address").is_none());
        assert!(!status.to_string().contains("hub.example"));

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
}
