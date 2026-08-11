use fairypam_agent_protocol::v2::agent_control_service_client::AgentControlServiceClient;
use fairypam_agent_protocol::v2::{
    command_identity, hub_control_command, AgentControlEvent, CommandIdentity, CommandRef,
    HubControlCommand, HubHello,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Streaming};

use crate::{ControlChannel, TransportError};

pub const CONTROL_QUEUE_CAPACITY: usize = 64;

#[derive(Clone, Debug)]
pub struct ControlSender {
    sender: mpsc::Sender<AgentControlEvent>,
}

impl ControlSender {
    pub fn try_send(&self, event: AgentControlEvent) -> Result<(), TransportError> {
        self.sender.try_send(event).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => TransportError::new(
                "transport.control_queue_full",
                "Control outbound queue reached its declared capacity",
            ),
            mpsc::error::TrySendError::Closed(_) => TransportError::new(
                "transport.control_queue_closed",
                "Control outbound queue is closed",
            ),
        })
    }

    pub async fn send(&self, event: AgentControlEvent) -> Result<(), TransportError> {
        self.sender.send(event).await.map_err(|_| {
            TransportError::new(
                "transport.control_queue_closed",
                "Control outbound queue is closed",
            )
        })
    }
}

pub fn control_queue() -> (ControlSender, ControlReceiver) {
    let (sender, receiver) = mpsc::channel(CONTROL_QUEUE_CAPACITY);
    (ControlSender { sender }, ControlReceiver(receiver))
}

pub struct ControlReceiver(mpsc::Receiver<AgentControlEvent>);

impl ControlReceiver {
    pub async fn recv(&mut self) -> Option<AgentControlEvent> {
        self.0.recv().await
    }
}

pub struct PendingControlTunnel {
    agent_id: String,
    commands: Streaming<HubControlCommand>,
}

pub async fn open_control_tunnel(
    connection: &ControlChannel,
    receiver: ControlReceiver,
) -> Result<PendingControlTunnel, TransportError> {
    let mut client = AgentControlServiceClient::new(connection.channel.clone());
    let commands = client
        .control_tunnel(Request::new(ReceiverStream::new(receiver.0)))
        .await
        .map(tonic::Response::into_inner)
        .map_err(|error| TransportError::new("transport.control_open_failed", error.to_string()))?;
    Ok(PendingControlTunnel {
        agent_id: connection.agent_id.clone(),
        commands,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSession {
    agent_id: String,
    session_id: String,
    generation: u64,
    heartbeat_interval_ms: u32,
    max_input_lease_ms: u32,
    max_frame_bytes: u32,
}

impl VerifiedSession {
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn heartbeat_interval_ms(&self) -> u32 {
        self.heartbeat_interval_ms
    }

    pub const fn max_input_lease_ms(&self) -> u32 {
        self.max_input_lease_ms
    }

    pub const fn max_frame_bytes(&self) -> u32 {
        self.max_frame_bytes
    }
}

#[derive(Debug)]
pub struct VerifiedControlCommand(HubControlCommand);

impl VerifiedControlCommand {
    pub fn into_inner(self) -> HubControlCommand {
        self.0
    }
}

pub struct ControlSession {
    session: VerifiedSession,
    commands: Streaming<HubControlCommand>,
    last_sequence: u64,
}

impl ControlSession {
    pub const fn verified_session(&self) -> &VerifiedSession {
        &self.session
    }

    pub async fn message(&mut self) -> Result<Option<VerifiedControlCommand>, TransportError> {
        let command = self.commands.message().await.map_err(|error| {
            TransportError::new("transport.control_read_failed", error.to_string())
        })?;
        let Some(command) = command else {
            return Ok(None);
        };
        let verified = verify_control_command(&self.session, command)?;
        let Some(reference) = command_ref(&verified.0) else {
            return Ok(Some(verified));
        };
        let now_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64;
        verify_command_freshness(
            reference,
            self.last_sequence,
            now_unix_ms,
            task_identity(&verified.0),
        )?;
        self.last_sequence = reference.sequence;
        Ok(Some(verified))
    }
}

pub async fn receive_hub_hello(
    mut pending: PendingControlTunnel,
) -> Result<ControlSession, TransportError> {
    let command = pending
        .commands
        .message()
        .await
        .map_err(|error| TransportError::new("transport.control_read_failed", error.to_string()))?
        .ok_or_else(|| {
            TransportError::new(
                "transport.hub_hello_missing",
                "Control tunnel closed before HubHello",
            )
        })?;
    let Some(hub_control_command::Payload::Hello(hello)) = command.payload else {
        return Err(TransportError::new(
            "transport.hub_hello_missing",
            "HubHello must be the first Control command",
        ));
    };
    let session = verify_hub_hello(hello, &pending.agent_id)?;
    Ok(ControlSession {
        session,
        commands: pending.commands,
        last_sequence: 0,
    })
}

pub(crate) fn verify_hub_hello(
    hello: HubHello,
    expected_agent_id: &str,
) -> Result<VerifiedSession, TransportError> {
    let session = hello.session.ok_or_else(|| {
        TransportError::new("transport.session_invalid", "HubHello session is missing")
    })?;
    if session.agent_id != expected_agent_id
        || session.session_id.is_empty()
        || session.generation == 0
        || hello.heartbeat_interval_ms == 0
        || hello.max_input_lease_ms == 0
        || hello.max_frame_bytes == 0
        || hello.accepted_protocol_minor != 6
    {
        return Err(TransportError::new(
            "transport.session_invalid",
            "HubHello does not match the authenticated Agent session",
        ));
    }
    Ok(VerifiedSession {
        agent_id: session.agent_id,
        session_id: session.session_id,
        generation: session.generation,
        heartbeat_interval_ms: hello.heartbeat_interval_ms,
        max_input_lease_ms: hello.max_input_lease_ms,
        max_frame_bytes: hello.max_frame_bytes,
    })
}

pub(crate) fn verify_control_command(
    session: &VerifiedSession,
    command: HubControlCommand,
) -> Result<VerifiedControlCommand, TransportError> {
    if matches!(
        command.payload.as_ref(),
        Some(
            hub_control_command::Payload::AcknowledgeManagedGameClose(_)
                | hub_control_command::Payload::ProfileCatalog(_)
        )
    ) {
        return Ok(VerifiedControlCommand(command));
    }
    let reference = command_ref(&command).ok_or_else(|| {
        TransportError::new(
            "transport.command_session_invalid",
            "Control command is missing its CommandRef",
        )
    })?;
    let command_session = reference.session.as_ref().ok_or_else(|| {
        TransportError::new(
            "transport.command_session_invalid",
            "Control command is missing its SessionRef",
        )
    })?;
    if command_session.agent_id != session.agent_id
        || command_session.session_id != session.session_id
        || command_session.generation != session.generation
        || reference.command_id.is_empty()
        || reference.sequence == 0
    {
        return Err(TransportError::new(
            "transport.command_session_invalid",
            "Control command does not match the verified session generation",
        ));
    }
    Ok(VerifiedControlCommand(command))
}

fn command_ref(command: &HubControlCommand) -> Option<&CommandRef> {
    use hub_control_command::Payload;
    match command.payload.as_ref()? {
        Payload::Hello(_) => None,
        Payload::LaunchTarget(value) => session_ref(value.reference.as_ref()),
        Payload::CloseTarget(value) => session_ref(value.reference.as_ref()),
        Payload::ConfigureIdleClose(value) => session_ref(value.reference.as_ref()),
        Payload::AcknowledgeManagedGameClose(_) | Payload::ProfileCatalog(_) => None,
        Payload::BeginAttempt(value) => task_ref(value.reference.as_ref()),
        Payload::StartAttemptTarget(value) => task_ref(value.reference.as_ref()),
        Payload::StartCapture(value) => task_ref(value.reference.as_ref()),
        Payload::CaptureFrame(value) => task_ref(value.reference.as_ref()),
        Payload::StopCapture(value) => task_ref(value.reference.as_ref()),
        Payload::StartMusicAutoplay(value) => task_ref(value.reference.as_ref()),
        Payload::StopMusicAutoplay(value) => task_ref(value.reference.as_ref()),
        Payload::InputFrame(value) => task_ref(value.reference.as_ref()),
        Payload::ClientPointClick(value) => task_ref(value.reference.as_ref()),
        Payload::ReleaseAll(value) => identity_ref(value.reference.as_ref()),
        Payload::FinishAttempt(value) => task_ref(value.reference.as_ref()),
        Payload::InspectAttempt(value) => task_ref(value.reference.as_ref()),
        Payload::StopSession(value) => session_ref(value.reference.as_ref()),
    }
}

fn session_ref(identity: Option<&CommandIdentity>) -> Option<&CommandRef> {
    match identity?.value.as_ref()? {
        command_identity::Value::Command(command) => Some(command),
        command_identity::Value::Task(_) => None,
    }
}

fn task_ref(identity: Option<&CommandIdentity>) -> Option<&CommandRef> {
    match identity?.value.as_ref()? {
        command_identity::Value::Task(task) => task.command.as_ref(),
        command_identity::Value::Command(_) => None,
    }
}

fn identity_ref(identity: Option<&CommandIdentity>) -> Option<&CommandRef> {
    match identity?.value.as_ref()? {
        command_identity::Value::Command(command) => Some(command),
        command_identity::Value::Task(task) => task.command.as_ref(),
    }
}

fn task_identity(command: &HubControlCommand) -> bool {
    use hub_control_command::Payload;
    let identity = match command.payload.as_ref() {
        Some(Payload::BeginAttempt(value)) => value.reference.as_ref(),
        Some(Payload::StartAttemptTarget(value)) => value.reference.as_ref(),
        Some(Payload::StartCapture(value)) => value.reference.as_ref(),
        Some(Payload::CaptureFrame(value)) => value.reference.as_ref(),
        Some(Payload::StopCapture(value)) => value.reference.as_ref(),
        Some(Payload::StartMusicAutoplay(value)) => value.reference.as_ref(),
        Some(Payload::StopMusicAutoplay(value)) => value.reference.as_ref(),
        Some(Payload::InputFrame(value)) => value.reference.as_ref(),
        Some(Payload::ClientPointClick(value)) => value.reference.as_ref(),
        Some(Payload::ReleaseAll(value)) => value.reference.as_ref(),
        Some(Payload::FinishAttempt(value)) => value.reference.as_ref(),
        Some(Payload::InspectAttempt(value)) => value.reference.as_ref(),
        _ => None,
    };
    matches!(
        identity.and_then(|identity| identity.value.as_ref()),
        Some(command_identity::Value::Task(_))
    )
}

fn verify_command_freshness(
    reference: &CommandRef,
    last_sequence: u64,
    now_unix_ms: i64,
    allow_exact_task_replay: bool,
) -> Result<(), TransportError> {
    if reference.sequence < last_sequence
        || (reference.sequence == last_sequence && !allow_exact_task_replay)
    {
        return Err(TransportError::new(
            "transport.command_replayed",
            "Control command sequence is not strictly monotonic",
        ));
    }
    if reference.expires_at_unix_ms <= now_unix_ms {
        return Err(TransportError::new(
            "transport.command_expired",
            "Control command expired before execution",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod v2_tests {
    use fairypam_agent_protocol::v2::{
        command_identity, hub_control_command, AcknowledgeManagedGameClose, CommandIdentity,
        CommandRef, HubControlCommand, HubHello, InputFrame, SessionRef, TaskCommandRef,
    };

    use super::*;

    fn session(generation: u64) -> VerifiedSession {
        verify_hub_hello(
            HubHello {
                session: Some(SessionRef {
                    agent_id: "agent-a".into(),
                    session_id: "session-1".into(),
                    generation,
                }),
                heartbeat_interval_ms: 1_000,
                max_input_lease_ms: 500,
                max_frame_bytes: 1_024,
                accepted_protocol_minor: 6,
            },
            "agent-a",
        )
        .unwrap()
    }

    fn command(generation: u64, sequence: u64) -> CommandRef {
        CommandRef {
            session: Some(SessionRef {
                agent_id: "agent-a".into(),
                session_id: "session-1".into(),
                generation,
            }),
            command_id: "cmd-1".into(),
            sequence,
            expires_at_unix_ms: i64::MAX,
        }
    }

    #[test]
    fn hub_hello_requires_current_protocol_minor() {
        let hello = HubHello {
            session: Some(SessionRef {
                agent_id: "agent-a".into(),
                session_id: "session-1".into(),
                generation: 1,
            }),
            heartbeat_interval_ms: 1_000,
            max_input_lease_ms: 500,
            max_frame_bytes: 1_024,
            accepted_protocol_minor: 0,
        };

        assert_eq!(
            verify_hub_hello(hello, "agent-a").unwrap_err().code(),
            "transport.session_invalid"
        );
    }

    #[test]
    fn task_command_must_match_verified_generation() {
        let stale = HubControlCommand {
            payload: Some(hub_control_command::Payload::InputFrame(InputFrame {
                reference: Some(CommandIdentity {
                    value: Some(command_identity::Value::Task(TaskCommandRef {
                        command: Some(command(1, 1)),
                        payload_digest: "a".repeat(64),
                        ..TaskCommandRef::default()
                    })),
                }),
                input_sequence: 1,
                lease_ms: 100,
                ..InputFrame::default()
            })),
        };

        assert_eq!(
            verify_control_command(&session(2), stale)
                .unwrap_err()
                .code(),
            "transport.command_session_invalid"
        );
    }

    #[test]
    fn task_command_rejects_session_only_identity() {
        let invalid = HubControlCommand {
            payload: Some(hub_control_command::Payload::InputFrame(InputFrame {
                reference: Some(CommandIdentity {
                    value: Some(command_identity::Value::Command(command(2, 1))),
                }),
                input_sequence: 1,
                lease_ms: 100,
                ..InputFrame::default()
            })),
        };

        assert_eq!(
            verify_control_command(&session(2), invalid)
                .unwrap_err()
                .code(),
            "transport.command_session_invalid"
        );
    }

    #[test]
    fn managed_game_close_ack_uses_receipt_identity_without_command_ref() {
        let ack = HubControlCommand {
            payload: Some(hub_control_command::Payload::AcknowledgeManagedGameClose(
                AcknowledgeManagedGameClose {
                    event_id: "event-1".into(),
                    game_session_id: "session-1".into(),
                    state_version: 4,
                },
            )),
        };

        assert!(verify_control_command(&session(2), ack).is_ok());
    }

    #[test]
    fn command_freshness_is_monotonic_and_deadline_bound() {
        let reference = command(2, 7);
        assert_eq!(
            verify_command_freshness(&reference, 7, 0, false)
                .unwrap_err()
                .code(),
            "transport.command_replayed"
        );
        assert!(verify_command_freshness(&reference, 7, 0, true).is_ok());
        let mut expired = reference;
        expired.expires_at_unix_ms = 1;
        assert_eq!(
            verify_command_freshness(&expired, 6, 1, false)
                .unwrap_err()
                .code(),
            "transport.command_expired"
        );
    }
}
