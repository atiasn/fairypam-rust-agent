use fairypam_agent_protocol::v2::{
    agent_telemetry_event, hub_telemetry_command, AgentTelemetryEvent, AgentTelemetryHello,
    HubTelemetryCommand, HubTelemetryHello, SessionRef,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Streaming};

use crate::{TelemetryChannel, TransportError, VerifiedSession};

pub const TELEMETRY_QUEUE_CAPACITY: usize = 64;

#[derive(Clone, Debug)]
pub struct TelemetrySender(mpsc::Sender<AgentTelemetryEvent>);

impl TelemetrySender {
    pub async fn send(&self, event: AgentTelemetryEvent) -> Result<(), TransportError> {
        self.0.send(event).await.map_err(|_| {
            TransportError::new(
                "transport.telemetry_queue_closed",
                "Telemetry outbound queue is closed",
            )
        })
    }

    pub fn try_send(&self, event: AgentTelemetryEvent) -> Result<(), TransportError> {
        self.0.try_send(event).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => TransportError::new(
                "transport.telemetry_queue_full",
                "Telemetry outbound queue reached its declared capacity",
            ),
            mpsc::error::TrySendError::Closed(_) => TransportError::new(
                "transport.telemetry_queue_closed",
                "Telemetry outbound queue is closed",
            ),
        })
    }
}

pub struct TelemetryReceiver(mpsc::Receiver<AgentTelemetryEvent>);

pub fn telemetry_queue() -> (TelemetrySender, TelemetryReceiver) {
    let (sender, receiver) = mpsc::channel(TELEMETRY_QUEUE_CAPACITY);
    (TelemetrySender(sender), TelemetryReceiver(receiver))
}

pub struct PendingTelemetryTunnel {
    commands: Streaming<HubTelemetryCommand>,
}

pub async fn open_telemetry_tunnel(
    connection: &TelemetryChannel,
    receiver: TelemetryReceiver,
) -> Result<PendingTelemetryTunnel, TransportError> {
    let mut client = fairypam_agent_protocol::v2::agent_telemetry_service_client::AgentTelemetryServiceClient::new(
        connection.channel.clone(),
    );
    let commands = client
        .telemetry_tunnel(Request::new(ReceiverStream::new(receiver.0)))
        .await
        .map(tonic::Response::into_inner)
        .map_err(|error| {
            TransportError::new("transport.telemetry_open_failed", error.to_string())
        })?;
    Ok(PendingTelemetryTunnel { commands })
}

pub struct TelemetrySession {
    hello: HubTelemetryHello,
    commands: Streaming<HubTelemetryCommand>,
}

impl TelemetrySession {
    pub const fn hello(&self) -> &HubTelemetryHello {
        &self.hello
    }

    pub async fn message(&mut self) -> Result<Option<HubTelemetryCommand>, TransportError> {
        self.commands.message().await.map_err(|error| {
            TransportError::new("transport.telemetry_read_failed", error.to_string())
        })
    }
}

pub async fn receive_telemetry_hello(
    mut pending: PendingTelemetryTunnel,
) -> Result<TelemetrySession, TransportError> {
    let command = pending
        .commands
        .message()
        .await
        .map_err(|error| TransportError::new("transport.telemetry_read_failed", error.to_string()))?
        .ok_or_else(|| {
            TransportError::new(
                "transport.telemetry_hello_missing",
                "Telemetry tunnel closed before HubTelemetryHello",
            )
        })?;
    let Some(hub_telemetry_command::Payload::Hello(hello)) = command.payload else {
        return Err(TransportError::new(
            "transport.telemetry_hello_missing",
            "HubTelemetryHello must be the first Telemetry command",
        ));
    };
    if hello.accepted_schema_version != 1
        || hello.max_record_bytes == 0
        || hello.max_record_bytes > 16 * 1024
        || hello.max_batch_records == 0
        || hello.max_batch_records > 64
        || hello.max_batch_bytes == 0
        || hello.max_batch_bytes > 256 * 1024
        || hello.backfill_bytes_per_second == 0
        || hello.backfill_bytes_per_second > 128 * 1024
        || hello.total_bytes_per_second == 0
        || hello.total_bytes_per_second > 256 * 1024
    {
        return Err(TransportError::new(
            "transport.telemetry_hello_invalid",
            "HubTelemetryHello exceeds the Agent transport limits",
        ));
    }
    Ok(TelemetrySession {
        hello,
        commands: pending.commands,
    })
}

pub fn hello_event(
    session: &VerifiedSession,
    process_generation_id: String,
) -> AgentTelemetryEvent {
    AgentTelemetryEvent {
        payload: Some(agent_telemetry_event::Payload::Hello(AgentTelemetryHello {
            control_session: Some(SessionRef {
                agent_id: session.agent_id().to_owned(),
                session_id: session.session_id().to_owned(),
                generation: session.generation(),
            }),
            agent_process_generation_id: process_generation_id,
            protocol_minor: 8,
            telemetry_schema_versions: vec![1],
        })),
    }
}
