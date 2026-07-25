use fairypam_agent_protocol::v1::agent_control_service_client::AgentControlServiceClient;
use fairypam_agent_protocol::v1::{
    hub_control_command, AgentControlEvent, CommandRef, HubControlCommand, HubHello,
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
        let reference = command_ref(&verified.0).expect("verified command has CommandRef");
        let now_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64;
        verify_command_freshness(reference, self.last_sequence, now_unix_ms)?;
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
        Payload::EnumerateTargets(value) => value.command.as_ref(),
        Payload::LockTarget(value) => value.command.as_ref(),
        Payload::StartCapture(value) => value.command.as_ref(),
        Payload::StopCapture(value) => value.command.as_ref(),
        Payload::InputLease(value) => value.command.as_ref(),
        Payload::PulseAction(value) => value.command.as_ref(),
        Payload::MouseDeltaAction(value) => value.command.as_ref(),
        Payload::WindowPointClickAction(value) => value.command.as_ref(),
        Payload::ReleaseAll(value) => value.command.as_ref(),
        Payload::StopSession(value) => value.command.as_ref(),
        Payload::FocusTarget(value) => value.command.as_ref(),
        Payload::CloseTarget(value) => value.command.as_ref(),
        Payload::UpdateDirective(value) => value.command.as_ref(),
    }
}

fn verify_command_freshness(
    reference: &CommandRef,
    last_sequence: u64,
    now_unix_ms: i64,
) -> Result<(), TransportError> {
    if reference.sequence <= last_sequence {
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
mod tests {
    use fairypam_agent_protocol::v1::{
        CloseTarget, CommandRef, FocusTarget, PulseAction, SessionRef,
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
                accepted_protocol_minor: 0,
            },
            "agent-a",
        )
        .unwrap()
    }

    #[test]
    fn hub_hello_must_match_authenticated_agent() {
        let hello = HubHello {
            session: Some(SessionRef {
                agent_id: "agent-b".into(),
                session_id: "session-1".into(),
                generation: 1,
            }),
            heartbeat_interval_ms: 1_000,
            max_input_lease_ms: 500,
            max_frame_bytes: 1_024,
            accepted_protocol_minor: 0,
        };

        let error = verify_hub_hello(hello, "agent-a").unwrap_err();

        assert_eq!(error.code(), "transport.session_invalid");
    }

    #[test]
    fn every_control_command_must_match_verified_generation() {
        let stale = HubControlCommand {
            payload: Some(hub_control_command::Payload::PulseAction(PulseAction {
                command: Some(CommandRef {
                    session: Some(SessionRef {
                        agent_id: "agent-a".into(),
                        session_id: "session-1".into(),
                        generation: 1,
                    }),
                    command_id: "cmd-1".into(),
                    sequence: 1,
                    expires_at_unix_ms: i64::MAX,
                }),
                action_id: "jump".into(),
            })),
        };

        let error = verify_control_command(&session(2), stale).unwrap_err();

        assert_eq!(error.code(), "transport.command_session_invalid");
    }

    #[test]
    fn sequence_replay_and_expiry_are_rejected_before_runtime() {
        let reference = CommandRef {
            session: Some(SessionRef {
                agent_id: "agent-a".into(),
                session_id: "session-1".into(),
                generation: 2,
            }),
            command_id: "cmd-1".into(),
            sequence: 7,
            expires_at_unix_ms: 1_001,
        };

        assert_eq!(
            verify_command_freshness(&reference, 7, 1_000)
                .unwrap_err()
                .code(),
            "transport.command_replayed"
        );
        assert_eq!(
            verify_command_freshness(&reference, 6, 1_001)
                .unwrap_err()
                .code(),
            "transport.command_expired"
        );
    }

    #[test]
    fn focus_and_close_commands_preserve_verified_command_refs() {
        let reference = CommandRef {
            session: Some(SessionRef {
                agent_id: "agent-a".into(),
                session_id: "session-1".into(),
                generation: 2,
            }),
            command_id: "target-operation".into(),
            sequence: 1,
            expires_at_unix_ms: i64::MAX,
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
            let verified = verify_control_command(
                &session(2),
                HubControlCommand {
                    payload: Some(payload),
                },
            )
            .unwrap();
            let command = verified.into_inner();
            assert_eq!(command_ref(&command).unwrap(), &reference);
        }
    }
}
