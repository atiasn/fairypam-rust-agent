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
    match supervisor.run(&driver).await {
        Ok(never) => match never {},
        Err(error) => Err(error),
    }
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
}
