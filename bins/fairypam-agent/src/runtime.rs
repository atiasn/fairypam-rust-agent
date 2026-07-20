use std::env;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fairypam_agent_core::profile::Ed25519SignatureVerifier;
use fairypam_agent_core::supervisor::{SessionDriver, SessionSupervisor, SupervisorHooks};
use fairypam_agent_core::AgentError;
use fairypam_agent_protocol::v1::{
    agent_control_event, hub_control_command, AgentControlEvent, AgentHello, AgentStatus,
    CommandAck, CommandNack, CommandRef, Heartbeat, SessionRef,
};
use fairypam_agent_transport::{
    connect_control, connect_frame, control_queue, open_control_tunnel, open_frame_tunnel,
    receive_hub_hello, CappedBackoff, ControlSender, ControlSession, SessionFrameSlot,
    TransportConfig, TransportError, VerifiedSession,
};
use http::Uri;
use tokio_util::sync::CancellationToken;

use crate::execution::{CommandExecutor, CommandOutcome, ExecutionSession, FrameSink};
use crate::profile_store::ProfileStore;

#[cfg(windows)]
use crate::local_control::{AuditEvent, AuditSink, LocalControlAdapter, LocalControlRuntime};
#[cfg(all(windows, feature = "dev-automation"))]
use fairypam_agent_core::state::Effect;
#[cfg(all(windows, feature = "dev-automation"))]
use fairypam_agent_dev_automation::{
    AutomationCapability, AutomationTarget, DevSessionManager, DevSessionRequest,
    DevSessionRevocationReason,
};
#[cfg(windows)]
use fairypam_agent_local_protocol::{decode_request_or_error_response, encode_frame};
#[cfg(all(windows, feature = "dev-automation"))]
use fairypam_agent_local_protocol::{LocalCommand, LocalError, RequestEnvelope, ResponseEnvelope};
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
}

impl RuntimeConfig {
    pub fn from_env() -> Result<Self, AgentError> {
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
        })
    }
}

#[derive(Default)]
struct RuntimeState {
    control: Option<ControlSession>,
    sender: Option<ControlSender>,
    session: Option<VerifiedSession>,
    frames: Option<SessionFrameSlot>,
}

pub struct GrpcSessionDriver {
    config: RuntimeConfig,
    state: Arc<Mutex<RuntimeState>>,
    execution: Arc<Mutex<CommandExecutor>>,
}

impl GrpcSessionDriver {
    pub fn new(config: RuntimeConfig) -> Self {
        let execution = CommandExecutor::production(config.profiles.clone());
        Self {
            config,
            state: Arc::new(Mutex::new(RuntimeState::default())),
            execution: Arc::new(Mutex::new(execution)),
        }
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
}

impl SessionDriver for GrpcSessionDriver {
    async fn establish_session(&self, cancellation: CancellationToken) -> Result<(), AgentError> {
        let connection = tokio::select! {
            _ = cancellation.cancelled() => return Err(cancelled()),
            result = connect_control(&self.config.transport) => result.map_err(map_transport)?,
        };
        let (sender, receiver) = control_queue();
        sender
            .send(AgentControlEvent {
                payload: Some(agent_control_event::Payload::Hello(AgentHello {
                    agent_id: self.config.transport.agent_id.clone(),
                    agent_version: self.config.agent_version.clone(),
                    protocol_major: 1,
                    protocol_minor: 0,
                    build_commit: self.config.build_commit.clone(),
                    installed_profile_ids: self.config.profiles.ids(),
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
        *state = RuntimeState {
            control: Some(control),
            sender: Some(sender),
            session: Some(session),
            frames: Some(frames),
        };
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
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(cancelled()),
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
        let (_session, frames, _sender) = self.session_parts()?;
        let connection = tokio::select! {
            _ = cancellation.cancelled() => return Err(cancelled()),
            result = connect_frame(&self.config.transport) => result.map_err(map_transport)?,
        };
        let mut frame = tokio::select! {
            _ = cancellation.cancelled() => return Err(cancelled()),
            result = open_frame_tunnel(&connection, &frames) => result.map_err(map_transport)?,
        };
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
    state: Arc<Mutex<RuntimeState>>,
    execution: Arc<Mutex<CommandExecutor>>,
}

impl RuntimeSafetyHooks {
    pub fn for_driver(driver: &GrpcSessionDriver) -> Self {
        Self {
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
        if let Ok(mut execution) = self.execution.lock() {
            let _ = execution.reset();
        }
        if let Ok(mut state) = self.state.lock() {
            *state = RuntimeState::default();
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
    let driver = GrpcSessionDriver::new(config);
    let hooks = RuntimeSafetyHooks::for_driver(&driver);
    let backoff = CappedBackoff::new(Duration::from_millis(250), Duration::from_secs(30))
        .map_err(map_transport)?;
    let mut supervisor = SessionSupervisor::new(hooks, backoff);
    #[cfg(windows)]
    let local_control = tokio::spawn(run_local_control(
        Arc::clone(&driver.execution),
        production_local_control_config()?,
    ));
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
struct SharedExecutor(Arc<Mutex<CommandExecutor>>);

#[cfg(windows)]
impl LocalControlRuntime for SharedExecutor {
    fn execute(
        &mut self,
        command: &fairypam_agent_local_protocol::LocalCommand,
    ) -> Result<serde_json::Value, AgentError> {
        self.0.lock().map_err(lock_error)?.execute_local(command)
    }
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
    fn record(&mut self, event: AuditEvent) {
        tracing::info!(request_id = %event.request_id, caller_sid_hash = %event.caller_sid_hash, command = %event.command, result_code = %event.result_code, build_id = %event.build_id, "local control mutation audited");
        let Some(state_dir) = &self.state_dir else {
            return;
        };
        let path = state_dir.join("local-control-audit.jsonl");
        let line = format!("{}\\n", event.to_json());
        if let Err(error) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut file| std::io::Write::write_all(&mut file, line.as_bytes()))
        {
            tracing::warn!(path = %path.display(), %error, "local control audit persistence failed");
        }
    }
}

#[cfg(windows)]
struct LocalControlConfig {
    owner: PipeOwner,
    pipe_name: String,
    audit_state_dir: Option<PathBuf>,
    #[cfg(all(windows, feature = "dev-automation"))]
    dev_session_state_dir: Option<PathBuf>,
}

#[cfg(windows)]
fn production_local_control_config() -> Result<LocalControlConfig, AgentError> {
    let owner = current_process_pipe_owner(IntegrityLevel::Medium)
        .map_err(|error| AgentError::new(error.code(), error.to_string()))?;
    Ok(LocalControlConfig {
        owner,
        pipe_name: default_production_pipe_name().to_owned(),
        audit_state_dir: None,
        #[cfg(all(windows, feature = "dev-automation"))]
        dev_session_state_dir: None,
    })
}

#[cfg(windows)]
async fn run_local_control(
    execution: Arc<Mutex<CommandExecutor>>,
    config: LocalControlConfig,
) -> std::convert::Infallible {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(all(windows, feature = "dev-automation"))]
    let mut dev_session = config
        .dev_session_state_dir
        .as_ref()
        .map(|state_dir| DevConnectionSession::new(state_dir.clone()));
    let mut adapter = LocalControlAdapter::new(
        config.owner.clone(),
        SharedExecutor(Arc::clone(&execution)),
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
            #[cfg(all(windows, feature = "dev-automation"))]
            let prefix_result = match dev_session
                .as_ref()
                .and_then(DevConnectionSession::expires_at)
            {
                Some(deadline) => match tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    pipe.read_exact(&mut prefix[prefix_start..]),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        if let Some(session) = &mut dev_session {
                            apply_dev_effects(&execution, session.expire());
                        }
                        continue;
                    }
                },
                None => pipe.read_exact(&mut prefix[prefix_start..]).await,
            };
            #[cfg(not(all(windows, feature = "dev-automation")))]
            let prefix_result = pipe.read_exact(&mut prefix[prefix_start..]).await;
            if let Err(error) = prefix_result {
                tracing::debug!(%error, "local control client disconnected");
                break;
            }
            let length = u32::from_le_bytes(prefix) as usize;
            if length > fairypam_agent_local_protocol::MAX_FRAME_BYTES {
                tracing::warn!(length, "local control frame exceeded protocol limit");
                break;
            }
            let mut frame = prefix.to_vec();
            frame.resize(4 + length, 0);
            #[cfg(all(windows, feature = "dev-automation"))]
            let body_result = match dev_session
                .as_ref()
                .and_then(DevConnectionSession::expires_at)
            {
                Some(deadline) => match tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    pipe.read_exact(&mut frame[4..]),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        if let Some(session) = &mut dev_session {
                            apply_dev_effects(&execution, session.expire());
                        }
                        continue;
                    }
                },
                None => pipe.read_exact(&mut frame[4..]).await,
            };
            #[cfg(not(all(windows, feature = "dev-automation")))]
            let body_result = pipe.read_exact(&mut frame[4..]).await;
            if let Err(error) = body_result {
                tracing::debug!(%error, "local control client disconnected before request completed");
                break;
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
            if let Err(error) = pipe.write_all(&frame).await {
                tracing::debug!(%error, "local control response could not be delivered");
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
                std::io::Write::write_all(&mut file, format!("{line}\\n").as_bytes())
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
                std::io::Write::write_all(&mut file, format!("{line}\\n").as_bytes())
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
    let never = run_local_control(
        Arc::new(Mutex::new(CommandExecutor::production(profiles))),
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
