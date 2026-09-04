#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::VecDeque;
use std::env;
use std::path::{Path, PathBuf};
#[cfg(any(windows, test))]
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicBool, Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fairypam_agent_core::profile::Ed25519SignatureVerifier;
#[cfg(windows)]
use fairypam_agent_core::supervisor::SessionSupervisor;
use fairypam_agent_core::supervisor::{SessionDriver, SupervisorHooks};
use fairypam_agent_core::AgentError;
#[cfg(any(windows, test))]
use fairypam_agent_protocol::local_v1::{
    local_control_request, local_control_response, DiagnosticsResult, EmergencyReleaseResult,
    EnvironmentCheck, EnvironmentResult, LocalCommandOutcome, LocalControlRequest,
    LocalControlResponse, RegistrationResult, StatusResult,
};
use fairypam_agent_protocol::v3::{
    self as v3, agent_control_event, hub_telemetry_command, AgentControlEvent, AgentRuntimeState,
    AgentStatus, Heartbeat, SessionRef,
};
#[cfg(any(windows, test))]
use fairypam_agent_transport::validate_transport_config;
#[cfg(windows)]
use fairypam_agent_transport::CappedBackoff;
use fairypam_agent_transport::{
    connect_control, connect_frame, connect_telemetry, control_queue, open_control_tunnel,
    open_frame_tunnel, open_telemetry_tunnel, receive_hub_hello, receive_telemetry_hello,
    telemetry_hello_event, telemetry_queue, ControlSender, ControlSession, SessionFrameSlot,
    TransportConfig, TransportError, VerifiedSession,
};
use http::Uri;
#[cfg(any(windows, test))]
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio_util::sync::CancellationToken;
#[cfg(any(windows, test))]
use zeroize::Zeroizing;

use crate::execution::{CommandExecutor, CommandOutcome, ExecutionSession, FrameSink};
use crate::managed_game::close_event_id;
#[cfg(any(windows, test))]
use crate::observability;
use crate::observability::AgentLogRecord;
use crate::profile_catalog::ProfileCatalogStore;
use crate::profile_store::ProfileStore;
use crate::v3_adapter;
const REGISTRATION_JOIN_TIMEOUT: Duration = Duration::from_secs(20);

use crate::runtime_api::LogLevel;
#[cfg(any(windows, test))]
use crate::runtime_api::RuntimeCommand as LocalCommand;
use crate::telemetry::{TelemetryState, MAX_LOG_CHUNK_BYTES};

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub transport: TransportConfig,
    pub agent_version: String,
    pub build_commit: String,
    pub profiles: ProfileStore,
    pub profile_root_public_key_hex: Option<String>,
    profile_catalog: Option<ProfileCatalogStore>,
    enrollment_root: Option<PathBuf>,
    enrollment_generation: Option<String>,
    awaiting_enrollment: bool,
}

impl RuntimeConfig {
    /// Production Agent instances are deliberately able to serve the local,
    /// authenticated enrollment pipe before any Hub credentials exist.
    #[cfg(windows)]
    pub fn from_production() -> Result<Self, AgentError> {
        let root = PathBuf::from(crate::enrollment::STATE_ROOT);
        crate::enrollment::ensure_private_directory(&root)?;
        crate::enrollment::cleanup_retired_generations(&root)?;
        if enrollment_state_exists_at(&root) {
            match Self::from_enrollment_state_at(&root) {
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

    #[cfg(any(windows, test, feature = "test-support"))]
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
            profile_root_public_key_hex: None,
            profile_catalog: None,
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
        let profile_root_public_key_hex = required("FAIRYPAM_PROFILE_ROOT_PUBLIC_KEY_HEX")?;
        let verifier = Ed25519SignatureVerifier::from_public_key_hex(&profile_root_public_key_hex)?;
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
            profile_root_public_key_hex: Some(profile_root_public_key_hex),
            profile_catalog: None,
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
        let pointer: EnrollmentPointer = load_private_json(&root.join("current.json"))?;
        let generation = pointer.generation;
        let config = Self::from_enrollment_candidate(root, generation)?;
        let _ = crate::enrollment::cleanup_retired_generations(root);
        Ok(config)
    }

    #[cfg(windows)]
    fn from_enrollment_candidate(root: &Path, generation: String) -> Result<Self, AgentError> {
        if !crate::enrollment::valid_generation(&generation) {
            return Err(AgentError::new(
                "runtime.enrollment_invalid",
                "invalid enrollment generation",
            ));
        }
        let directory = root.join(&generation);
        let document: crate::enrollment::EnrollmentRuntimeDocument =
            load_private_json(&directory.join("runtime.json"))?;
        validate_enrollment_expiry(&document.expires_at)?;
        let verifier =
            Ed25519SignatureVerifier::from_public_key_hex(&document.profile_root_public_key_hex)?;
        let profile_catalog = ProfileCatalogStore::open(
            PathBuf::from(crate::enrollment::PROFILE_CATALOG_ROOT),
            verifier,
        );
        let profiles = profile_catalog
            .active()
            .map_or_else(ProfileStore::default, |active| active.profiles.clone());
        Ok(Self {
            transport: TransportConfig {
                control_endpoint: document.control_endpoint.parse().map_err(|error| {
                    AgentError::new(
                        "runtime.enrollment_invalid",
                        format!("invalid control endpoint: {error}"),
                    )
                })?,
                frame_endpoint: document.frame_endpoint.parse().map_err(|error| {
                    AgentError::new(
                        "runtime.enrollment_invalid",
                        format!("invalid frame endpoint: {error}"),
                    )
                })?,
                server_name: document.hub_server_name,
                agent_id: document.agent_id,
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
            profile_root_public_key_hex: Some(document.profile_root_public_key_hex),
            profile_catalog: Some(profile_catalog),
            enrollment_root: Some(root.to_path_buf()),
            enrollment_generation: Some(generation),
            awaiting_enrollment: false,
        })
    }
}

#[cfg(any(windows, test))]
fn validate_enrollment_expiry(value: &str) -> Result<OffsetDateTime, AgentError> {
    let expires_at = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
        AgentError::new(
            "runtime.enrollment_invalid",
            "invalid enrollment expiration",
        )
    })?;
    (expires_at > OffsetDateTime::now_utc())
        .then_some(expires_at)
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
fn load_private_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, AgentError> {
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
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentPointer {
    generation: String,
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
    persist_logs: bool,
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
            persist_logs: true,
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
            Self::AwaitingRegistration => "本机 Core 正在等待完成安全注册",
            Self::Started => "本机 Core 已启动，正在准备远程连接",
            Self::ControlConnectionStarting => "正在建立服务连接",
            Self::ControlConnectionEstablished => "服务连接已建立",
            Self::FrameConnectionEstablished => "画面服务已准备就绪",
            Self::EnrollmentRefreshFailed => "注册信息刷新失败，连接将保持安全关闭",
            Self::SessionCleared => "连接已重置，正在重新连接",
            Self::LocalShutdownRequested => "本机 Core 收到安全停止请求",
            Self::LocalUiShutdownRequested => "界面请求安全停止本机 Core",
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

    fn record_command_diagnostic(&mut self, outcome: &CommandOutcome) {
        if let Some(message) = outcome.local_diagnostic() {
            self.record_text(LogLevel::Warn, message);
        }
    }

    fn record_text(&mut self, level: LogLevel, message: &str) {
        if self.logs.len() == 200 {
            self.logs.pop_front();
        }
        self.logs
            .push_back(AgentLogRecord::new(level.clone(), message));
        #[cfg(windows)]
        if self.persist_logs {
            if let Err(error) =
                observability::production_log().and_then(|log| log.append(level, message))
            {
                tracing::warn!(code = error.code(), "protected Agent log write failed");
            }
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
    shutdown: CancellationToken,
    agent_process_generation_id: String,
    telemetry: Arc<Mutex<TelemetryState>>,
}

impl GrpcSessionDriver {
    pub fn new(config: RuntimeConfig) -> Self {
        let mut execution = CommandExecutor::production(
            config.profiles.clone(),
            &config.transport.agent_id,
            config.profile_root_public_key_hex.as_deref(),
        );
        execution.set_profile_update_blocked(
            !config.awaiting_enrollment
                && config
                    .profile_catalog
                    .as_ref()
                    .is_some_and(|catalog| catalog.active().is_none()),
        );
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
        let shutdown = CancellationToken::new();
        let agent_process_generation_id = v3_adapter::process_generation_id();
        let telemetry = new_telemetry_state(agent_process_generation_id.clone());
        Self {
            config: Arc::new(Mutex::new(config)),
            state: Arc::new(Mutex::new(state)),
            execution: Arc::new(Mutex::new(execution)),
            enrollment_ready: Arc::new(tokio::sync::Notify::new()),
            reconnect_requested: Arc::new(tokio::sync::Notify::new()),
            registration_in_progress: Arc::new(AtomicBool::new(false)),
            registration_worker: Arc::new(Mutex::new(None)),
            shutdown,
            agent_process_generation_id,
            telemetry: Arc::new(Mutex::new(telemetry)),
        }
    }

    fn execution_for_session(
        &self,
        session: &VerifiedSession,
    ) -> Result<MutexGuard<'_, CommandExecutor>, AgentError> {
        self.execution_for_agent_identity(session.agent_id())
    }

    fn execution_for_agent_identity(
        &self,
        agent_id: &str,
    ) -> Result<MutexGuard<'_, CommandExecutor>, AgentError> {
        let execution = self.execution.lock().map_err(lock_error)?;
        execution.ensure_agent_identity(agent_id)?;
        Ok(execution)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn for_test() -> Self {
        let config = RuntimeConfig::unregistered();
        let mut execution = CommandExecutor::without_devices_for_test();
        execution.rebind_managed_game_identity(&config.transport.agent_id);
        let agent_process_generation_id = "11111111-1111-4111-8111-111111111111".to_owned();
        Self {
            config: Arc::new(Mutex::new(config)),
            state: Arc::new(Mutex::new(RuntimeState {
                last_error_code: "runtime.not_registered".to_owned(),
                persist_logs: false,
                ..RuntimeState::default()
            })),
            execution: Arc::new(Mutex::new(execution)),
            enrollment_ready: Arc::new(tokio::sync::Notify::new()),
            reconnect_requested: Arc::new(tokio::sync::Notify::new()),
            registration_in_progress: Arc::new(AtomicBool::new(false)),
            registration_worker: Arc::new(Mutex::new(None)),
            shutdown: CancellationToken::new(),
            agent_process_generation_id: agent_process_generation_id.clone(),
            telemetry: Arc::new(Mutex::new(TelemetryState::memory(
                agent_process_generation_id,
            ))),
        }
    }

    #[cfg(any(windows, test))]
    pub(crate) fn local_control(&self) -> LocalControlRuntime {
        LocalControlRuntime {
            execution: Arc::clone(&self.execution),
            state: Arc::clone(&self.state),
            config: Arc::clone(&self.config),
            enrollment_ready: Arc::clone(&self.enrollment_ready),
            reconnect_requested: Arc::clone(&self.reconnect_requested),
            registration_in_progress: Arc::clone(&self.registration_in_progress),
            registration_worker: Arc::clone(&self.registration_worker),
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
            let pointer: EnrollmentPointer = load_private_json(&root.join("current.json"))?;
            Ok(pointer.generation != expected)
        }
        #[cfg(not(windows))]
        Ok(false)
    }

    fn receive_profile_catalog(
        &self,
        catalog: &v3::ProfileCatalog,
        sender: &ControlSender,
        session: &VerifiedSession,
    ) -> Result<(), AgentError> {
        let mut execution = self.execution_for_session(session)?;
        execution.set_profile_update_blocked(true);
        let staged = {
            let mut config = self.config.lock().map_err(lock_error)?;
            let store = config.profile_catalog.as_mut().ok_or_else(|| {
                AgentError::new(
                    "profile_catalog.unavailable",
                    "Profile Catalog storage is unavailable",
                )
            })?;
            store.stage(catalog)
        };
        match staged {
            Ok(true) => {
                sender
                    .try_send(self.profile_catalog_event(
                        session,
                        catalog.catalog_version,
                        &catalog.catalog_digest,
                        v3::ProfileCatalogApplyState::Pending,
                        None,
                    )?)
                    .map_err(map_transport)?;
                self.activate_profile_catalog_if_ready_locked(sender, session, &mut execution)
            }
            Ok(false) => {
                execution.set_profile_update_blocked(false);
                sender
                    .try_send(self.profile_catalog_event(
                        session,
                        catalog.catalog_version,
                        &catalog.catalog_digest,
                        v3::ProfileCatalogApplyState::Applied,
                        None,
                    )?)
                    .map_err(map_transport)
            }
            Err(error) => sender
                .try_send(self.profile_catalog_event(
                    session,
                    catalog.catalog_version,
                    &catalog.catalog_digest,
                    v3::ProfileCatalogApplyState::Rejected,
                    Some(error.code().to_owned()),
                )?)
                .map_err(map_transport),
        }
    }

    fn activate_profile_catalog_if_ready(
        &self,
        sender: &ControlSender,
        session: &VerifiedSession,
    ) -> Result<(), AgentError> {
        let mut execution = self.execution_for_session(session)?;
        self.activate_profile_catalog_if_ready_locked(sender, session, &mut execution)
    }

    fn activate_profile_catalog_if_ready_locked(
        &self,
        sender: &ControlSender,
        session: &VerifiedSession,
        execution: &mut CommandExecutor,
    ) -> Result<(), AgentError> {
        if !execution.profile_activation_ready()? {
            return Ok(());
        }
        let pending = self
            .config
            .lock()
            .map_err(lock_error)?
            .profile_catalog
            .as_ref()
            .and_then(ProfileCatalogStore::pending_identity)
            .map(|(version, digest)| (version, digest.to_owned()));
        let Some((version, digest)) = pending else {
            return Ok(());
        };
        let activated = {
            let mut config = self.config.lock().map_err(lock_error)?;
            let result = config
                .profile_catalog
                .as_mut()
                .ok_or_else(|| {
                    AgentError::new(
                        "profile_catalog.unavailable",
                        "Profile Catalog storage is unavailable",
                    )
                })?
                .activate();
            if let Ok(active) = &result {
                config.profiles = active.profiles.clone();
            }
            result
        };
        match activated {
            Ok(active) => {
                execution.emergency_release_input()?;
                sender
                    .try_send(self.profile_catalog_event(
                        session,
                        active.version,
                        &active.digest,
                        v3::ProfileCatalogApplyState::Applied,
                        None,
                    )?)
                    .map_err(map_transport)?;
                sender
                    .try_send(v3_adapter::discovery_snapshot(
                        session_ref(session),
                        &active.profiles,
                    )?)
                    .map_err(map_transport)?;
                // Guardian must rebuild its fixed emergency-release set from the
                // newly active signed Catalog before this Agent accepts input.
                self.shutdown.cancel();
                Ok(())
            }
            Err(error) => sender
                .try_send(self.profile_catalog_event(
                    session,
                    version,
                    &digest,
                    v3::ProfileCatalogApplyState::Rejected,
                    Some(error.code().to_owned()),
                )?)
                .map_err(map_transport),
        }
    }

    fn profile_catalog_event(
        &self,
        session: &VerifiedSession,
        desired_version: u64,
        desired_digest: &str,
        state: v3::ProfileCatalogApplyState,
        error_code: Option<String>,
    ) -> Result<AgentControlEvent, AgentError> {
        let active = self
            .config
            .lock()
            .map_err(lock_error)?
            .profile_catalog
            .as_ref()
            .and_then(|catalog| {
                catalog
                    .active()
                    .map(|active| (active.version, active.digest.clone()))
            });
        Ok(v3_adapter::profile_catalog_status(
            session_ref(session),
            desired_version,
            desired_digest.to_owned(),
            state,
            active
                .as_ref()
                .map(|(version, digest)| (*version, digest.as_str())),
            error_code,
        ))
    }

    async fn run_telemetry_forever(
        &self,
        cancellation: CancellationToken,
        session: VerifiedSession,
    ) -> Result<(), AgentError> {
        loop {
            if cancellation.is_cancelled() {
                return Ok(());
            }
            if let Err(error) = self
                .run_telemetry_once(cancellation.child_token(), &session)
                .await
            {
                if let Ok(mut telemetry) = self.telemetry.lock() {
                    telemetry.cancel_detail_on_disconnect();
                }
                tracing::warn!(code = error.code(), "Telemetry channel reconnecting");
            }
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
        }
    }

    async fn run_telemetry_once(
        &self,
        cancellation: CancellationToken,
        control_session: &VerifiedSession,
    ) -> Result<(), AgentError> {
        let config = self.config.lock().map_err(lock_error)?.clone();
        let connection = tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            result = connect_telemetry(&config.transport) => result.map_err(map_transport)?,
        };
        let (sender, receiver) = telemetry_queue();
        sender
            .send(telemetry_hello_event(
                control_session,
                self.agent_process_generation_id.clone(),
            ))
            .await
            .map_err(map_transport)?;
        let pending = open_telemetry_tunnel(&connection, receiver)
            .await
            .map_err(map_transport)?;
        let mut commands = receive_telemetry_hello(pending)
            .await
            .map_err(map_transport)?;
        let hello = *commands.hello();
        let lease_receipts = self.telemetry.lock().map_err(lock_error)?.lease_receipts();
        for receipt in lease_receipts {
            sender
                .send(crate::telemetry::lease_receipt_event(receipt))
                .await
                .map_err(map_transport)?;
        }
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut log_tick = tokio::time::interval(transfer_interval(
            MAX_LOG_CHUNK_BYTES,
            hello.total_bytes_per_second,
        ));
        log_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut pending_log_chunks = VecDeque::new();
        let mut active_log_request = None;
        let mut inflight_batch = None;
        let mut next_backfill = Instant::now();
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                command = commands.message() => {
                    let command = command.map_err(map_transport)?.ok_or_else(|| {
                        AgentError::new("runtime.telemetry_closed", "Hub closed the Telemetry stream")
                    })?;
                    match command.payload.as_ref() {
                        Some(hub_telemetry_command::Payload::Receipt(receipt)) => {
                            if inflight_batch == Some(receipt.batch_sequence) {
                                self.telemetry
                                    .lock()
                                    .map_err(lock_error)?
                                    .apply_receipts(&receipt.records)?;
                                inflight_batch = None;
                            }
                        }
                        Some(hub_telemetry_command::Payload::DiagnosticLease(lease)) => {
                            let receipt = self.telemetry.lock().map_err(lock_error)?.handle_lease(
                                lease,
                                &config.transport.agent_id,
                                control_session.generation(),
                            )?;
                            sender
                                .send(crate::telemetry::lease_receipt_event(receipt))
                                .await
                                .map_err(map_transport)?;
                        }
                        Some(hub_telemetry_command::Payload::RevokeDiagnosticLease(revoke)) => {
                            let receipt = self
                                .telemetry
                                .lock()
                                .map_err(lock_error)?
                                .handle_revoke(revoke)?;
                            cancel_agent_log_reads_for_terminal(
                                &mut pending_log_chunks,
                                &receipt,
                            );
                            if receipt.target_type == v3::DiagnosticTargetType::Agent as i32 {
                                active_log_request = None;
                            }
                            sender
                                .send(crate::telemetry::lease_receipt_event(receipt))
                                .await
                                .map_err(map_transport)?;
                        }
                        Some(hub_telemetry_command::Payload::LogRead(request)) => {
                            if active_log_request.is_some() {
                                sender
                                    .try_send(crate::telemetry::log_read_error(
                                        request,
                                        "diagnostic.log_read_busy",
                                    ))
                                    .map_err(map_transport)?;
                                continue;
                            }
                            let chunks = {
                                let telemetry = self.telemetry.lock().map_err(lock_error)?;
                                crate::telemetry::log_chunks(
                                    request,
                                    &telemetry,
                                    &config.transport.agent_id,
                                    diagnostic_log(),
                                )
                            };
                            active_log_request = Some(request.request_id.clone());
                            pending_log_chunks.extend(chunks);
                        }
                        Some(hub_telemetry_command::Payload::CancelLogRead(cancel)) => {
                            cancel_log_read(&mut pending_log_chunks, &cancel.request_id);
                            if active_log_request.as_deref() == Some(cancel.request_id.as_str()) {
                                active_log_request = None;
                            }
                        }
                        Some(hub_telemetry_command::Payload::Hello(_)) | None => {
                            return Err(AgentError::new(
                                "runtime.telemetry_command_invalid",
                                "Hub sent an invalid Telemetry command",
                            ));
                        }
                    }
                }
                _ = log_tick.tick(), if !pending_log_chunks.is_empty() => {
                    let chunk = pending_log_chunks
                        .pop_front()
                        .expect("log chunk queue is not empty");
                    let completed_request = match chunk.payload.as_ref() {
                        Some(v3::agent_telemetry_event::Payload::LogChunk(value)) if value.eof => {
                            Some(value.request_id.clone())
                        }
                        _ => None,
                    };
                    sender.send(chunk).await.map_err(map_transport)?;
                    if completed_request.as_deref() == active_log_request.as_deref() {
                        active_log_request = None;
                    }
                    next_backfill = Instant::now() + Duration::from_secs(1);
                }
                _ = tick.tick() => {
                    let expired = self.telemetry.lock().map_err(lock_error)?.expire_leases()?;
                    for receipt in &expired {
                        cancel_agent_log_reads_for_terminal(
                            &mut pending_log_chunks,
                            receipt,
                        );
                        if receipt.target_type == v3::DiagnosticTargetType::Agent as i32 {
                            active_log_request = None;
                        }
                    }
                    for receipt in expired {
                        sender
                            .try_send(crate::telemetry::lease_receipt_event(receipt))
                            .map_err(map_transport)?;
                    }
                    if !pending_log_chunks.is_empty()
                        || inflight_batch.is_some()
                        || Instant::now() < next_backfill
                    {
                        continue;
                    }
                    let event = {
                        let mut telemetry = self.telemetry.lock().map_err(lock_error)?;
                        telemetry.refresh_queue_metrics()?;
                        telemetry.next_batch(
                            hello.max_batch_records.min(64) as usize,
                            hello
                                .max_batch_bytes
                                .min(hello.backfill_bytes_per_second)
                                .min(hello.total_bytes_per_second)
                                .min(128 * 1024) as usize,
                        )?
                    };
                    let Some(event) = event else { continue };
                    let Some(v3::agent_telemetry_event::Payload::Batch(batch)) = event.payload.as_ref() else {
                        return Err(AgentError::new(
                            "runtime.telemetry_batch_invalid",
                            "local Telemetry queue produced an invalid batch",
                        ));
                    };
                    inflight_batch = Some(batch.batch_sequence);
                    sender.send(event).await.map_err(map_transport)?;
                    next_backfill = Instant::now() + Duration::from_secs(1);
                }
            }
        }
    }
}

fn cancel_log_read(chunks: &mut VecDeque<v3::AgentTelemetryEvent>, request_id: &str) {
    chunks.retain(|event| {
        !matches!(
            event.payload.as_ref(),
            Some(v3::agent_telemetry_event::Payload::LogChunk(chunk))
                if chunk.request_id == request_id
        )
    });
}

fn cancel_agent_log_reads_for_terminal(
    chunks: &mut VecDeque<v3::AgentTelemetryEvent>,
    receipt: &v3::DiagnosticLeaseReceipt,
) {
    if receipt.target_type == v3::DiagnosticTargetType::Agent as i32
        && matches!(
            v3::DiagnosticLeaseDisposition::try_from(receipt.disposition),
            Ok(v3::DiagnosticLeaseDisposition::Revoked | v3::DiagnosticLeaseDisposition::Expired)
        )
    {
        chunks.clear();
    }
}

fn transfer_interval(bytes: usize, bytes_per_second: u32) -> Duration {
    Duration::from_secs_f64(bytes as f64 / bytes_per_second.max(1) as f64)
}

#[cfg(windows)]
fn new_telemetry_state(process_generation_id: String) -> TelemetryState {
    TelemetryState::production(process_generation_id.clone()).unwrap_or_else(|error| {
        tracing::warn!(
            code = error.code(),
            "protected telemetry buffer is unavailable"
        );
        TelemetryState::memory(process_generation_id)
    })
}

#[cfg(windows)]
fn diagnostic_log() -> Result<crate::observability::FixedLog, AgentError> {
    crate::observability::production_log()
}

#[cfg(not(windows))]
fn diagnostic_log() -> Result<crate::observability::FixedLog, AgentError> {
    Err(AgentError::new(
        "diagnostic.log_read_unavailable",
        "production Agent log is Windows-only",
    ))
}

#[cfg(not(windows))]
fn new_telemetry_state(process_generation_id: String) -> TelemetryState {
    TelemetryState::memory(process_generation_id)
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
            .send(v3_adapter::hello(
                config.transport.agent_id.clone(),
                config.agent_version.clone(),
                config.build_commit.clone(),
                self.agent_process_generation_id.clone(),
                &config.profiles,
                config.profile_catalog.as_ref().and_then(|catalog| {
                    catalog
                        .active()
                        .map(|active| (active.version, active.digest.as_str()))
                }),
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
        let runtime_state = self.execution.lock().map_err(lock_error)?.runtime_state()?;
        sender
            .try_send(status_event(&session, runtime_state))
            .map_err(map_transport)?;
        sender
            .try_send(v3_adapter::discovery_snapshot(
                session_ref(&session),
                &config.profiles,
            )?)
            .map_err(map_transport)?;
        let mut state = self.state.lock().map_err(lock_error)?;
        let logs = std::mem::take(&mut state.logs);
        let persist_logs = state.persist_logs;
        *state = RuntimeState {
            control: Some(control),
            sender: Some(sender),
            session: Some(session),
            frames: Some(frames),
            control_state: ConnectionState::Connected,
            frame_state: ConnectionState::Connecting,
            last_error_code: "runtime.frame_connecting".to_owned(),
            logs,
            persist_logs,
        };
        state.record(
            LogLevel::Info,
            RuntimeLogMessage::ControlConnectionEstablished,
        );
        drop(state);
        if let Ok(mut telemetry) = self.telemetry.lock() {
            let _ = telemetry.record_event(
                "agent.control.connected",
                v3::TelemetrySeverity::Info,
                None,
                None,
                None,
                None,
            );
        }
        self.execution
            .lock()
            .map_err(lock_error)?
            .prepare_managed_game_close_replay();
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
        let mut translator = v3_adapter::Translator::new(session.max_input_lease_ms());
        let telemetry_cancellation = cancellation.child_token();
        let mut telemetry =
            Box::pin(self.run_telemetry_forever(telemetry_cancellation.clone(), session.clone()));
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(cancelled()),
                result = &mut telemetry => {
                    if let Err(error) = result {
                        tracing::warn!(code = error.code(), "Telemetry task stopped unexpectedly");
                    }
                    telemetry = Box::pin(
                        self.run_telemetry_forever(
                            telemetry_cancellation.clone(),
                            session.clone(),
                        ),
                    );
                }
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
                    let mut execution = self.execution_for_session(&session)?;
                    self.activate_profile_catalog_if_ready_locked(
                        &sender,
                        &session,
                        &mut execution,
                    )?;
                    sender.try_send(heartbeat_event(&session)).map_err(map_transport)?;
                    let runtime_state = execution.runtime_state()?;
                    sender.try_send(status_event(&session, runtime_state)).map_err(map_transport)?;
                    if let Some(status) = execution.managed_game_status() {
                        sender.try_send(managed_game_idle_event(&session, status)).map_err(map_transport)?;
                    }
                }
                _ = capture_health.tick() => {
                    let mut execution = self.execution_for_session(&session)?;
                    for event in execution.tick_safety(&ExecutionSession::from_verified(&session))? {
                        sender.try_send(v3_adapter::safety_event(event)?).map_err(map_transport)?;
                    }
                    let event = execution.capture_failure_event(&ExecutionSession::from_verified(&session))?;
                    if let Some(event) = event {
                        sender.try_send(v3_adapter::safety_event(event)?).map_err(map_transport)?;
                    }
                    match execution.realtime_program_events(&ExecutionSession::from_verified(&session)) {
                        Ok(events) => {
                            for event in events {
                                sender.try_send(event).map_err(map_transport)?;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(code = error.code(), "Realtime Program Worker became uncertain");
                            sender.try_send(realtime_failure_event(&session, error.code()))
                                .map_err(map_transport)?;
                        }
                    }
                }
                command = control.message() => {
                    let command = command.map_err(map_transport)?.ok_or_else(|| {
                        AgentError::new("runtime.control_closed", "Hub closed the Control stream")
                    })?.into_inner();
                    if let Some(v3::hub_control_command::Payload::AcknowledgeManagedGameClose(value)) =
                        command.payload.as_ref()
                    {
                        self.execution_for_session(&session)?
                            .acknowledge_managed_game_close(value)?;
                        continue;
                    }
                    if let Some(v3::hub_control_command::Payload::ProfileCatalog(value)) =
                        command.payload.as_ref()
                    {
                        self.receive_profile_catalog(value, &sender, &session)?;
                        continue;
                    }
                    let identity = v3_adapter::identity(&command).ok_or_else(|| {
                        AgentError::new(
                            "runtime.command_invalid",
                            "verified command lost CommandRef",
                        )
                    })?;
                    let command_name = v3_adapter::command_name(&command);
                    let command_started_at = telemetry_unix_nano();
                    let translated = match translator.translate(&command) {
                        Ok(command) => command,
                        Err(error) => {
                            let event = match v3_adapter::internal_task_identity(&identity) {
                                Ok(task) => {
                                    let mut execution = self.execution_for_session(&session)?;
                                    let mut outcome = if error.code() == "command.payload_digest_conflict" {
                                        execution.v3_payload_digest_conflict(&task)
                                    } else {
                                        execution.reject_v3_task(&task, error.code())
                                    };
                                    execution.stamp_target_generation(&mut outcome);
                                    v3_adapter::result(identity.clone(), outcome)
                                }
                                Err(_) => v3_adapter::error(identity.clone(), &error),
                            };
                            let send_result =
                                send_command_result(&sender, event, &cancellation).await;
                            let telemetry_error_code = send_result
                                .as_ref()
                                .err()
                                .map_or(error.code(), |send_error| send_error.code());
                            if let Ok(mut telemetry) = self.telemetry.lock() {
                                let _ = telemetry.record_command_span(
                                    command_name,
                                    &identity,
                                    command_started_at,
                                    telemetry_unix_nano(),
                                    Some(telemetry_error_code),
                                    &[],
                                );
                            }
                            send_result?;
                            continue;
                        }
                    };
                    let mut execution = self.execution_for_session(&session)?;
                    let mut outcome = match translated {
                        v3_adapter::TranslatedCommand::Internal(internal) => {
                            let frames = {
                                let state = self.state.lock().map_err(lock_error)?;
                                state.frames.clone().ok_or_else(session_missing)?
                            };
                            execution.execute(
                                &internal,
                                &ExecutionSession::from_verified(&session),
                                Arc::new(frames) as Arc<dyn FrameSink>,
                            )
                        }
                        v3_adapter::TranslatedCommand::CloseTarget { value } => {
                            let mut report = |phase| {
                                let event = managed_game_close_progress_event(
                                    &session,
                                    &value.game_session_id,
                                    value.state_version,
                                    phase,
                                );
                                if let Err(error) = sender.try_send(event) {
                                    tracing::warn!(
                                        code = error.code(),
                                        "managed game close progress event was not sent"
                                    );
                                }
                            };
                            execution.execute_v3_close_target_with_progress(
                                &value,
                                &mut report,
                            )
                        }
                        v3_adapter::TranslatedCommand::ConfigureIdleClose { value } => {
                            execution.execute_v3_configure_idle_close(&value)
                        }
                        v3_adapter::TranslatedCommand::BeginAttempt {
                            task,
                            contract,
                            digest_key,
                            payload_digest,
                        } => {
                            let outcome = execution.execute_v3_begin(&task, &contract);
                            if matches!(&outcome, CommandOutcome::TaskAck { .. }) {
                                translator.accept_begin(contract, digest_key, payload_digest);
                            }
                            outcome
                        }
                        v3_adapter::TranslatedCommand::InputFrame { task, frame } => {
                            execution.execute_v3_input_frame(&task, &frame, None, None)
                        }
                        v3_adapter::TranslatedCommand::ClientPointClick { task, value } => {
                            execution.execute_v3_input_frame(
                                &task,
                                &v3::InputFrame {
                                    input_sequence: value.input_sequence,
                                    lease_ms: value.lease_ms,
                                    source_frame_sequence: Some(value.source_frame_sequence),
                                    target_generation: value.target_generation,
                                    ..v3::InputFrame::default()
                                },
                                Some((&value.action_id, value.x_ppm, value.y_ppm)),
                                None,
                            )
                        }
                        v3_adapter::TranslatedCommand::ClientPointSwipe { task, value } => {
                            execution.execute_v3_input_frame(
                                &task,
                                &v3::InputFrame {
                                    input_sequence: value.input_sequence,
                                    lease_ms: value.lease_ms,
                                    source_frame_sequence: Some(value.source_frame_sequence),
                                    target_generation: value.target_generation,
                                    ..v3::InputFrame::default()
                                },
                                None,
                                Some((
                                    &value.action_id,
                                    value.start_x_ppm,
                                    value.start_y_ppm,
                                    value.end_x_ppm,
                                    value.end_y_ppm,
                                    value.duration_ms,
                                )),
                            )
                        }
                        v3_adapter::TranslatedCommand::StartRealtimeProgram { task, value } => {
                            execution.execute_v3_start_realtime_program(&task, &value)
                        }
                        v3_adapter::TranslatedCommand::RenewRealtimeProgram { task, value } => {
                            execution.execute_v3_renew_realtime_program(&task, &value)
                        }
                        v3_adapter::TranslatedCommand::StopRealtimeProgram { task, value } => {
                            execution.execute_v3_stop_realtime_program(&task, &value)
                        }
                    };
                    execution.stamp_target_generation(&mut outcome);
                    let command_telemetry_attributes =
                        execution.take_command_telemetry_attributes();
                    drop(execution);
                    if let Ok(mut state) = self.state.lock() {
                        state.record_command_diagnostic(&outcome);
                    }
                    let outcome_error_code =
                        outcome.telemetry_error_code().map(str::to_owned);
                    let event = v3_adapter::result(identity.clone(), outcome);
                    let send_result = send_command_result(&sender, event, &cancellation).await;
                    let telemetry_error_code = send_result
                        .as_ref()
                        .err()
                        .map(|error| error.code())
                        .or(outcome_error_code.as_deref());
                    if let Ok(mut telemetry) = self.telemetry.lock() {
                        let _ = telemetry.record_command_span(
                            command_name,
                            &identity,
                            command_started_at,
                            telemetry_unix_nano(),
                            telemetry_error_code,
                            &command_telemetry_attributes,
                        );
                    }
                    send_result?;
                    self.activate_profile_catalog_if_ready(&sender, &session)?;
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

impl GrpcSessionDriver {
    fn tick_managed_game_close(&self) -> Result<(), AgentError> {
        let connection = {
            let state = self.state.lock().map_err(lock_error)?;
            state.sender.clone().zip(state.session.clone())
        };
        let agent_id = match connection.as_ref() {
            Some((_, session)) => session.agent_id().to_owned(),
            None => self
                .config
                .lock()
                .map_err(lock_error)?
                .transport
                .agent_id
                .clone(),
        };
        self.tick_managed_game_close_for_identity(&agent_id, connection.as_ref())
    }

    fn tick_managed_game_close_for_identity(
        &self,
        agent_id: &str,
        connection: Option<&(ControlSender, VerifiedSession)>,
    ) -> Result<(), AgentError> {
        let mut execution = self.execution_for_agent_identity(agent_id)?;
        let mut report = |game_session_id: &str, state_version, phase| {
            let Some((sender, session)) = connection else {
                return;
            };
            let event =
                managed_game_close_progress_event(session, game_session_id, state_version, phase);
            if let Err(error) = sender.try_send(event) {
                tracing::warn!(
                    code = error.code(),
                    "managed game close progress event was not sent"
                );
            }
        };
        let _ = execution.close_idle_game_if_due_with_progress(&mut report)?;
        let receipt = execution.pending_managed_game_close();
        let Some(receipt) = receipt else {
            return Ok(());
        };
        let Some((sender, session)) = connection else {
            return Ok(());
        };
        sender
            .try_send(managed_game_close_event(session, receipt))
            .map_err(map_transport)?;
        execution.mark_managed_game_close_reported();
        Ok(())
    }
}

fn install_runtime_config(
    execution: &Arc<Mutex<CommandExecutor>>,
    current: &Arc<Mutex<RuntimeConfig>>,
    config: RuntimeConfig,
) -> Result<(), AgentError> {
    let mut execution = execution.lock().map_err(lock_error)?;
    let mut current = current.lock().map_err(lock_error)?;
    if let Err(error) = execution.ensure_agent_identity(&config.transport.agent_id) {
        if error.code() != "runtime.enrollment_changed" {
            return Err(error);
        }
        execution.rebind_managed_game_identity(&config.transport.agent_id)
    }
    execution.reload_profiles_with_key(
        config.profiles.clone(),
        config.profile_root_public_key_hex.as_deref(),
    )?;
    execution.set_profile_update_blocked(
        config
            .profile_catalog
            .as_ref()
            .is_some_and(|catalog| catalog.active().is_none()),
    );
    *current = config;
    Ok(())
}

pub struct RuntimeSafetyHooks {
    config: Arc<Mutex<RuntimeConfig>>,
    state: Arc<Mutex<RuntimeState>>,
    execution: Arc<Mutex<CommandExecutor>>,
    registration_worker: Arc<Mutex<Option<JoinHandle<()>>>>,
    telemetry: Arc<Mutex<TelemetryState>>,
}

impl RuntimeSafetyHooks {
    pub fn for_driver(driver: &GrpcSessionDriver) -> Self {
        Self {
            config: Arc::clone(&driver.config),
            state: Arc::clone(&driver.state),
            execution: Arc::clone(&driver.execution),
            registration_worker: Arc::clone(&driver.registration_worker),
            telemetry: Arc::clone(&driver.telemetry),
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
        if let Ok(mut telemetry) = self.telemetry.lock() {
            telemetry.cancel_detail_on_disconnect();
        }
        #[cfg(windows)]
        if let Some(root) = self
            .config
            .lock()
            .ok()
            .and_then(|config| config.enrollment_root.clone())
            .filter(|root| enrollment_state_exists_at(root))
        {
            match RuntimeConfig::from_enrollment_state_at(&root)
                .and_then(|config| install_runtime_config(&self.execution, &self.config, config))
            {
                Ok(()) => {}
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
            let _ = execution.reset_session();
        }
        if let Ok(mut state) = self.state.lock() {
            let logs = std::mem::take(&mut state.logs);
            let persist_logs = state.persist_logs;
            *state = RuntimeState {
                control_state: ConnectionState::Reconnecting,
                frame_state: ConnectionState::Reconnecting,
                last_error_code: "runtime.reconnecting".to_owned(),
                logs,
                persist_logs,
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

#[cfg(windows)]
pub async fn run_production(
    config: RuntimeConfig,
    guardian_pipe: String,
) -> Result<(), AgentError> {
    verify_active_agent_suite()?;
    run_standalone(config, Some(guardian_pipe)).await
}

#[cfg(windows)]
pub async fn run_development(config: RuntimeConfig) -> Result<(), AgentError> {
    run_standalone(config, None).await
}

#[cfg(windows)]
async fn run_standalone(
    config: RuntimeConfig,
    guardian_pipe: Option<String>,
) -> Result<(), AgentError> {
    let _instance = AgentInstance::acquire()?;
    let driver = GrpcSessionDriver::new(config);
    let guardian = guardian_pipe
        .map(|pipe_name| {
            crate::guardian_channel::GuardianChannel::start(
                &driver.config.lock().map_err(lock_error)?.profiles,
                driver.shutdown.clone(),
                pipe_name,
                Arc::clone(&driver.execution),
            )
        })
        .transpose();
    let guardian = match guardian {
        Ok(guardian) => guardian,
        Err(error) => return Err(error),
    };
    let worker_info = match driver
        .execution
        .lock()
        .map_err(lock_error)?
        .ensure_worker_ready()
    {
        Ok(info) => info,
        Err(error) => {
            let _ = guardian.map(|guardian| guardian.stop());
            return Err(error);
        }
    };
    if let Some(info) = worker_info {
        let attributes = [
            ("maa.runtime.version", info.maa_runtime_version.as_str()),
            ("windows.capture.backend", info.capture_backend.as_str()),
            ("windows.input.backend", info.input_backend.as_str()),
        ]
        .into_iter()
        .map(|(key, value)| v3::TelemetryAttribute {
            key: key.to_owned(),
            value: Some(v3::telemetry_attribute::Value::StringValue(
                value.to_owned(),
            )),
        })
        .collect();
        driver
            .telemetry
            .lock()
            .map_err(lock_error)?
            .record_event_with_attributes(
                "agent.windows_io.ready",
                v3::TelemetrySeverity::Info,
                None,
                None,
                None,
                None,
                attributes,
            )?;
        tracing::info!(
            maa_runtime_version = info.maa_runtime_version,
            capture_backend = info.capture_backend,
            input_backend = info.input_backend,
            "Win32 Worker ready"
        );
    }
    let local_control = match crate::local_control::LocalControlServer::start(
        driver.local_control(),
        driver.shutdown.clone(),
    ) {
        Ok(server) => server,
        Err(error) => {
            let _ = guardian.map(|guardian| guardian.stop());
            return Err(error);
        }
    };
    let shutdown = driver.shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown.cancel();
        }
    });
    let runtime_result = run_driver(driver).await;
    let local_control_result = local_control.stop();
    let guardian_result = guardian.map_or(Ok(()), |guardian| guardian.stop());
    let cleanup_result = match (local_control_result, guardian_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(local), Err(guardian)) => Err(AgentError::new(
            "runtime.cleanup_failed",
            format!("{local}; {guardian}"),
        )),
    };
    match (runtime_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(runtime), Err(guardian)) => Err(AgentError::new(
            "runtime.cleanup_failed",
            format!("{runtime}; {guardian}"),
        )),
    }
}

#[cfg(windows)]
async fn run_driver(driver: GrpcSessionDriver) -> Result<(), AgentError> {
    let hooks = RuntimeSafetyHooks::for_driver(&driver);
    let backoff = CappedBackoff::new(Duration::from_millis(250), Duration::from_secs(30))
        .map_err(map_transport)?;
    let mut supervisor = SessionSupervisor::new(hooks, backoff);
    if !driver.is_registered()? {
        tokio::select! {
            result = driver.wait_until_registered() => result?,
            _ = driver.shutdown.cancelled() => {
                return shutdown_runtime(&driver, &mut supervisor);
            }
        }
    }
    let mut supervisor_run = Box::pin(supervisor.run(&driver));
    let mut idle_close = tokio::time::interval(Duration::from_millis(250));
    idle_close.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    idle_close.tick().await;
    loop {
        tokio::select! {
            result = &mut supervisor_run => return match result {
                Ok(never) => match never {},
                Err(error) => Err(error),
            },
            _ = idle_close.tick() => {
                if let Err(error) = driver.tick_managed_game_close() {
                    tracing::warn!(code = error.code(), "managed game idle-close tick paused");
                }
            },
            _ = driver.shutdown.cancelled() => {
                drop(supervisor_run);
                return shutdown_runtime(&driver, &mut supervisor);
            }
        }
    }
}

#[cfg(windows)]
fn shutdown_runtime(
    driver: &GrpcSessionDriver,
    supervisor: &mut SessionSupervisor<RuntimeSafetyHooks>,
) -> Result<(), AgentError> {
    if let Ok(mut state) = driver.state.lock() {
        state.record(LogLevel::Info, RuntimeLogMessage::LocalShutdownRequested);
    }
    let _ = supervisor.handle_control_failure()?;
    driver
        .telemetry
        .lock()
        .map_err(lock_error)?
        .mark_clean_shutdown()?;
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
pub(crate) struct LocalControlRuntime {
    execution: Arc<Mutex<CommandExecutor>>,
    state: Arc<Mutex<RuntimeState>>,
    config: Arc<Mutex<RuntimeConfig>>,
    enrollment_ready: Arc<tokio::sync::Notify>,
    reconnect_requested: Arc<tokio::sync::Notify>,
    registration_in_progress: Arc<AtomicBool>,
    registration_worker: Arc<Mutex<Option<JoinHandle<()>>>>,
}

#[cfg(any(windows, test))]
impl LocalControlRuntime {
    #[cfg(any(windows, test))]
    pub(crate) fn handle_local_request(
        &self,
        mut request: LocalControlRequest,
    ) -> LocalControlResponse {
        let request_id = std::mem::take(&mut request.request_id);
        let command = request.command.take();
        if matches!(
            command,
            Some(local_control_request::Command::EmergencyRelease(_))
        ) {
            return match self.execute_local(&LocalCommand::ReleaseAll) {
                Ok(value) => {
                    let cleanup_complete = value["cleanup_complete"].as_bool().unwrap_or(false);
                    LocalControlResponse {
                        request_id,
                        outcome: if cleanup_complete {
                            LocalCommandOutcome::Applied
                        } else {
                            LocalCommandOutcome::Uncertain
                        } as i32,
                        error_code: value["error_code"].as_str().map(str::to_owned),
                        result: Some(local_control_response::Result::EmergencyRelease(
                            EmergencyReleaseResult {
                                cleanup_complete,
                                holds: value["holds"].as_u64().unwrap_or_default() as u32,
                            },
                        )),
                    }
                }
                Err(error) => LocalControlResponse {
                    request_id,
                    outcome: LocalCommandOutcome::Uncertain as i32,
                    error_code: Some(error.code().to_owned()),
                    result: None,
                },
            };
        }
        let result = match command {
            Some(local_control_request::Command::GetStatus(_)) => self
                .local_status()
                .map(local_control_response::Result::Status),
            Some(local_control_request::Command::GetEnvironment(_)) => self
                .local_environment()
                .map(local_control_response::Result::Environment),
            Some(local_control_request::Command::RegisterHub(mut value)) => {
                let code = Zeroizing::new(std::mem::take(&mut value.registration_code));
                self.execute_local(&LocalCommand::RegisterHub {
                    registration_code: code,
                })
                .map(|_| {
                    local_control_response::Result::Registration(RegistrationResult {
                        pending: true,
                    })
                })
            }
            Some(local_control_request::Command::EmergencyRelease(_)) => unreachable!(),
            Some(local_control_request::Command::ExportDiagnostics(_)) => {
                #[cfg(windows)]
                let bundle = self.diagnostic_bundle();
                #[cfg(all(test, not(windows)))]
                let bundle = Err(AgentError::new(
                    "diagnostic.platform_unsupported",
                    "diagnostic export requires Windows",
                ));
                bundle.map(|bundle| {
                    local_control_response::Result::Diagnostics(DiagnosticsResult {
                        bundle,
                        suggested_file_name: format!("fairypam-diagnostics-{}.json", now_unix_ms()),
                    })
                })
            }
            None => Err(AgentError::new(
                "local.command_missing",
                "local control request has no command",
            )),
        };
        match result {
            Ok(result) => LocalControlResponse {
                request_id,
                outcome: LocalCommandOutcome::Applied as i32,
                error_code: None,
                result: Some(result),
            },
            Err(error) => LocalControlResponse {
                request_id,
                outcome: LocalCommandOutcome::NotApplied as i32,
                error_code: Some(error.code().to_owned()),
                result: None,
            },
        }
    }

    #[cfg(any(windows, test))]
    fn local_status(&self) -> Result<StatusResult, AgentError> {
        let status = self.execute_local(&LocalCommand::Status)?;
        let connection = self.connection_status()?;
        let registered = !self.config.lock().map_err(lock_error)?.awaiting_enrollment;
        Ok(StatusResult {
            runtime_state: json_string(&status, "state"),
            control_state: json_string(&connection, "control"),
            frame_state: json_string(&connection, "frame"),
            task_active: status["task_active"].as_bool().unwrap_or(false),
            capture_active: status["capture_active"].as_bool().unwrap_or(false),
            registered,
            recovery_code: json_string(&connection, "recovery_code"),
        })
    }

    #[cfg(any(windows, test))]
    fn local_environment(&self) -> Result<EnvironmentResult, AgentError> {
        let value = self.environment_check()?;
        let checks = value["checks"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|check| EnvironmentCheck {
                id: json_string(check, "id"),
                status: json_string(check, "status"),
                code: json_string(check, "code"),
                recovery: json_string(check, "recovery"),
            })
            .collect();
        Ok(EnvironmentResult {
            registration_ready: value["registration_ready"].as_bool().unwrap_or(false),
            registration_pending: value["registration_pending"].as_bool().unwrap_or(false),
            checks,
        })
    }

    #[cfg(windows)]
    fn diagnostic_bundle(&self) -> Result<Vec<u8>, AgentError> {
        const MAX_EXPORTED_LOG_BYTES: usize = 48 * 1024;

        let status = self.execute_local(&LocalCommand::Status)?;
        let connection = self.connection_status()?;
        let environment = self.environment_check()?;
        let logs = observability::production_log()?.snapshot(MAX_EXPORTED_LOG_BYTES)?;
        let bundle = serde_json::json!({
            "schema_version": 1,
            "generated_at_unix_ms": now_unix_ms(),
            "status": status,
            "connection": connection,
            "environment": environment,
            "logs_ndjson": String::from_utf8_lossy(&logs),
        });
        serde_json::to_vec_pretty(&bundle)
            .map_err(|error| AgentError::new("diagnostic.export_failed", error.to_string()))
    }

    fn execute_local(&self, command: &LocalCommand) -> Result<serde_json::Value, AgentError> {
        self.record_local_operation(command);
        match command {
            LocalCommand::GetConnectionStatus => self.connection_status(),
            LocalCommand::RunEnvironmentCheck => self.environment_check(),
            LocalCommand::GetLogTail { lines, level } => self.log_tail(*lines, level),
            LocalCommand::ScanInstalledGames => self.scan_installed_games(),
            #[cfg(windows)]
            LocalCommand::RegisterHub { registration_code } => {
                self.register_hub(registration_code.clone())
            }
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
        registration_code: Zeroizing<String>,
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
        let worker = std::thread::Builder::new()
            .name("fairypam-enrollment".to_owned())
            .spawn(move || runtime.finish_registration(registration_code))
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
    fn finish_registration(&self, registration_code: Zeroizing<String>) {
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
                crate::enrollment::register_at_signed(&root, registration_code.as_str())?;
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
        install_runtime_config(&self.execution, &self.config, config)?;
        let mut state = self.state.lock().map_err(lock_error)?;
        state.control_state = ConnectionState::Reconnecting;
        state.frame_state = ConnectionState::Reconnecting;
        state.last_error_code = "runtime.enrollment_registered".to_owned();
        state.record(LogLevel::Info, RuntimeLogMessage::RegistrationCompleted);
        drop(state);
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
            let certificate_ready = validate_transport_config(&config.transport).is_ok();
            let games_available = observability::scan_installed_games(&config.profiles).is_ok();
            (
                config.awaiting_enrollment,
                !config.profiles.ids().is_empty(),
                certificate_ready,
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
                {"id": "profiles", "status": if profiles_configured { "available" } else { "unavailable" }, "code": if profiles_configured { "profile.available" } else { "profile.unavailable" }, "recovery": "请保持服务连接，等待 Hub 自动下发已签名 Profile Catalog。"},
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

#[cfg(any(windows, test))]
fn json_string(value: &serde_json::Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_owned()
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

async fn send_command_result(
    sender: &ControlSender,
    event: AgentControlEvent,
    cancellation: &CancellationToken,
) -> Result<(), AgentError> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(cancelled()),
        result = sender.send(event) => result.map_err(map_transport),
    }
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

fn managed_game_idle_event(
    session: &VerifiedSession,
    mut status: v3::ManagedGameIdleStatus,
) -> AgentControlEvent {
    status.session = Some(session_ref(session));
    AgentControlEvent {
        payload: Some(agent_control_event::Payload::ManagedGameIdleStatus(status)),
    }
}

fn managed_game_close_event(
    session: &VerifiedSession,
    receipt: v3::ManagedGameCloseReceipt,
) -> AgentControlEvent {
    let event_id = close_event_id(&receipt);
    AgentControlEvent {
        payload: Some(agent_control_event::Payload::ManagedGameCloseEvent(
            v3::ManagedGameCloseEvent {
                session: Some(session_ref(session)),
                event_id,
                receipt: Some(receipt),
            },
        )),
    }
}

fn managed_game_close_progress_event(
    session: &VerifiedSession,
    game_session_id: &str,
    state_version: u64,
    phase: v3::ManagedGameClosePhase,
) -> AgentControlEvent {
    AgentControlEvent {
        payload: Some(agent_control_event::Payload::ManagedGameCloseProgress(
            v3::ManagedGameCloseProgress {
                session: Some(session_ref(session)),
                game_session_id: game_session_id.to_owned(),
                state_version,
                phase: phase as i32,
                occurred_at_unix_ms: now_unix_ms(),
            },
        )),
    }
}

fn realtime_failure_event(session: &VerifiedSession, reason_code: &str) -> AgentControlEvent {
    AgentControlEvent {
        payload: Some(agent_control_event::Payload::SafetyEvent(v3::SafetyEvent {
            session: Some(session_ref(session)),
            reason_code: reason_code.to_owned(),
            state: AgentRuntimeState::RecoveryBlocked as i32,
            attempt: None,
            attempt_receipt: None,
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

fn telemetry_unix_nano() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use crate::runtime_api::{LogLevel, RuntimeCommand as LocalCommand};

    use super::*;

    #[tokio::test]
    async fn command_result_waits_for_control_queue_capacity() {
        let (sender, mut receiver) = control_queue();
        for _ in 0..fairypam_agent_transport::CONTROL_QUEUE_CAPACITY {
            sender.try_send(AgentControlEvent::default()).unwrap();
        }
        let cancellation = CancellationToken::new();
        let waiting = tokio::spawn({
            let sender = sender.clone();
            let cancellation = cancellation.clone();
            async move {
                send_command_result(&sender, AgentControlEvent::default(), &cancellation).await
            }
        });

        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        receiver.recv().await.unwrap();
        tokio::time::timeout(Duration::from_millis(100), waiting)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

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
    fn local_control_exposes_typed_status_and_confirmed_release() {
        let local = GrpcSessionDriver::for_test().local_control();
        let request = |command| LocalControlRequest {
            request_id: "shell-test".into(),
            deadline_unix_ms: now_unix_ms() + 1_000,
            command: Some(command),
        };
        let status =
            local.handle_local_request(request(local_control_request::Command::GetStatus(
                fairypam_agent_protocol::local_v1::GetStatus {},
            )));
        assert_eq!(status.outcome, LocalCommandOutcome::Applied as i32);
        assert!(matches!(
            status.result,
            Some(local_control_response::Result::Status(StatusResult {
                registered: false,
                ..
            }))
        ));

        let released =
            local.handle_local_request(request(local_control_request::Command::EmergencyRelease(
                fairypam_agent_protocol::local_v1::EmergencyRelease {},
            )));
        assert_eq!(released.outcome, LocalCommandOutcome::Applied as i32);
        assert!(matches!(
            released.result,
            Some(local_control_response::Result::EmergencyRelease(
                EmergencyReleaseResult {
                    cleanup_complete: true,
                    holds: 0,
                }
            ))
        ));
    }

    #[test]
    fn cancelled_log_read_drops_only_matching_chunks() {
        let chunk = |request_id: &str| v3::AgentTelemetryEvent {
            payload: Some(v3::agent_telemetry_event::Payload::LogChunk(
                v3::AgentLogChunk {
                    request_id: request_id.to_owned(),
                    ..v3::AgentLogChunk::default()
                },
            )),
        };
        let mut chunks = VecDeque::from([chunk("cancelled"), chunk("kept")]);

        cancel_log_read(&mut chunks, "cancelled");

        assert_eq!(chunks.len(), 1);
        assert!(matches!(
            chunks.front().and_then(|event| event.payload.as_ref()),
            Some(v3::agent_telemetry_event::Payload::LogChunk(chunk))
                if chunk.request_id == "kept"
        ));
    }

    #[test]
    fn only_terminal_agent_lease_drops_pending_log_chunks() {
        let mut chunks = VecDeque::from([v3::AgentTelemetryEvent::default()]);
        let mut receipt = v3::DiagnosticLeaseReceipt {
            target_type: v3::DiagnosticTargetType::TaskRun as i32,
            disposition: v3::DiagnosticLeaseDisposition::Revoked as i32,
            ..v3::DiagnosticLeaseReceipt::default()
        };

        cancel_agent_log_reads_for_terminal(&mut chunks, &receipt);
        assert_eq!(chunks.len(), 1);

        receipt.target_type = v3::DiagnosticTargetType::Agent as i32;
        cancel_agent_log_reads_for_terminal(&mut chunks, &receipt);

        assert!(chunks.is_empty());
    }

    #[test]
    fn telemetry_rate_uses_the_hub_advertised_limit() {
        assert_eq!(
            transfer_interval(32 * 1024, 256 * 1024),
            Duration::from_millis(125)
        );
        assert_eq!(
            transfer_interval(32 * 1024, 64 * 1024),
            Duration::from_millis(500)
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

    #[test]
    fn capture_frame_diagnostic_is_recorded_locally() {
        let mut state = RuntimeState {
            persist_logs: false,
            ..RuntimeState::default()
        };
        state.record_command_diagnostic(&CommandOutcome::TaskAck {
            result: "{}".into(),
            outcome: None,
            receipt: Box::default(),
            local_diagnostic: Some(
                "target.focus_failed: request_accepted=false, foreground_pid=42, target_pid=84"
                    .into(),
            ),
        });

        assert_eq!(state.logs.len(), 1);
        assert_eq!(
            state.logs.front().unwrap().message,
            "target.focus_failed: request_accepted=false, foreground_pid=42, target_pid=84"
        );
    }

    #[tokio::test]
    async fn unregistered_embedded_runtime_notifies_supervisor() {
        let driver = GrpcSessionDriver::new(RuntimeConfig::unregistered());
        let local = driver.local_control();

        assert!(!driver.is_registered().unwrap());
        assert!(local
            .execute_local(&LocalCommand::GetConnectionStatus)
            .unwrap()
            .get("hub_address")
            .is_none());
        let diagnostics = local
            .execute_local(&LocalCommand::RunEnvironmentCheck)
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
            .execute_local(&LocalCommand::RunEnvironmentCheck)
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
            .any(|message| message == "本机 Core 已启动，正在准备远程连接"));
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
            .execute_local(&LocalCommand::GetConnectionStatus)
            .unwrap();
        assert!(status.get("hub_address").is_none());
        assert!(!status.to_string().contains("hub.example"));

        local.request_reconnect();
        tokio::time::timeout(Duration::from_millis(10), driver.wait_for_reconnect())
            .await
            .expect("re-registration must wake the active supervisor");
    }

    #[test]
    fn enrollment_identity_change_resets_only_managed_game_namespace() {
        let driver = GrpcSessionDriver::for_test();
        let local = driver.local_control();
        let old_agent_id = driver.config.lock().unwrap().transport.agent_id.clone();
        let policy = |state_version| v3::ConfigureIdleClose {
            game_id: "game-1".to_owned(),
            game_session_id: "session-1".to_owned(),
            profile_id: "genshin-impact".to_owned(),
            state_version,
            enabled: false,
            idle_timeout_ms: 0,
            occupied: true,
            ..v3::ConfigureIdleClose::default()
        };
        assert!(matches!(
            driver
                .execution
                .lock()
                .unwrap()
                .execute_v3_configure_idle_close(&policy(2)),
            CommandOutcome::Ack(_)
        ));

        let mut same_identity = RuntimeConfig::unregistered();
        same_identity.enrollment_generation = Some("generation-2".to_owned());
        local.activate_enrollment(same_identity).unwrap();
        assert!(matches!(
            driver
                .execution
                .lock()
                .unwrap()
                .execute_v3_configure_idle_close(&policy(1)),
            CommandOutcome::Nack { ref code, .. } if code == "idle_close.state_stale"
        ));

        let mut new_identity = RuntimeConfig::unregistered();
        new_identity.transport.agent_id = "agent-b".to_owned();
        new_identity.enrollment_generation = Some("generation-3".to_owned());
        install_runtime_config(&driver.execution, &driver.config, new_identity.clone()).unwrap();
        assert!(driver.execution_for_agent_identity("agent-b").is_ok());
        let cleanup_identity_error = match driver.execution_for_agent_identity(&old_agent_id) {
            Err(error) => error,
            Ok(_) => panic!("cleanup refresh must reject the old agent identity"),
        };
        assert_eq!(cleanup_identity_error.code(), "runtime.enrollment_changed");
        local.activate_enrollment(new_identity).unwrap();
        let identity_error = match driver.execution_for_agent_identity(&old_agent_id) {
            Err(error) => error,
            Ok(_) => panic!("old agent identity must be rejected"),
        };
        assert_eq!(identity_error.code(), "runtime.enrollment_changed");
        assert_eq!(
            driver
                .tick_managed_game_close_for_identity(&old_agent_id, None)
                .unwrap_err()
                .code(),
            "runtime.enrollment_changed"
        );
        let mut execution = driver.execution.lock().unwrap();
        execution.ensure_agent_identity("agent-b").unwrap();
        assert!(matches!(
            execution.execute_v3_configure_idle_close(&policy(1)),
            CommandOutcome::Ack(_)
        ));
    }

    #[test]
    fn registration_pending_exposes_only_status() {
        let response = registration_pending();

        assert_eq!(response, serde_json::json!({"status": "pending"}));
        assert_eq!(response.as_object().unwrap().len(), 1);
    }
}
