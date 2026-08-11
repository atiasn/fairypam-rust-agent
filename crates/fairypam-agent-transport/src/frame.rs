use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use fairypam_agent_protocol::v2::agent_frame_service_client::AgentFrameServiceClient;
use fairypam_agent_protocol::v2::{FrameDirective, FramePacket};
use tokio::sync::watch;
use tokio_stream::wrappers::WatchStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Streaming};

use crate::{FrameChannel, TransportError, VerifiedSession};

#[derive(Clone, Debug)]
struct VersionedFrame {
    version: u64,
    frame: FramePacket,
}

#[derive(Clone, Debug)]
pub struct LatestFrameSlot {
    sender: watch::Sender<Option<VersionedFrame>>,
    next_version: Arc<AtomicU64>,
    delivered_version: Arc<AtomicU64>,
    overwritten: Arc<AtomicU64>,
}

#[derive(Clone, Debug)]
pub struct SessionFrameSlot {
    session: VerifiedSession,
    frames: LatestFrameSlot,
    accept_frames: Arc<std::sync::atomic::AtomicBool>,
}

impl Default for LatestFrameSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl LatestFrameSlot {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(None);
        Self {
            sender,
            next_version: Arc::new(AtomicU64::new(0)),
            delivered_version: Arc::new(AtomicU64::new(0)),
            overwritten: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn publish(&self, frame: FramePacket) {
        let version = self.next_version.fetch_add(1, Ordering::Relaxed) + 1;
        if version > 1 && self.delivered_version.load(Ordering::Acquire) < version - 1 {
            self.overwritten.fetch_add(1, Ordering::Relaxed);
        }
        self.sender
            .send_replace(Some(VersionedFrame { version, frame }));
    }

    pub fn latest(&self) -> Option<FramePacket> {
        self.sender
            .borrow()
            .as_ref()
            .map(|versioned| versioned.frame.clone())
    }

    pub fn overwritten_frames(&self) -> u64 {
        self.overwritten.load(Ordering::Relaxed)
    }

    pub fn stream(&self) -> impl Stream<Item = FramePacket> + Send + use<> {
        let delivered_version = Arc::clone(&self.delivered_version);
        WatchStream::new(self.sender.subscribe()).filter_map(move |versioned| {
            versioned.map(|versioned| {
                delivered_version.fetch_max(versioned.version, Ordering::Release);
                versioned.frame
            })
        })
    }
}

impl VerifiedSession {
    pub fn frame_slot(&self) -> SessionFrameSlot {
        SessionFrameSlot {
            session: self.clone(),
            frames: LatestFrameSlot::new(),
            accept_frames: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }
}

impl SessionFrameSlot {
    pub fn publish(&self, frame: FramePacket) -> Result<(), TransportError> {
        self.publish_if_accepting(frame).map(drop)
    }

    pub fn publish_if_accepting(&self, frame: FramePacket) -> Result<bool, TransportError> {
        let session = frame.session.as_ref().ok_or_else(|| {
            TransportError::new(
                "transport.frame_session_invalid",
                "FramePacket session is missing",
            )
        })?;
        if session.agent_id != self.session.agent_id()
            || session.session_id != self.session.session_id()
            || session.generation != self.session.generation()
            || frame.payload.len() > self.session.max_frame_bytes() as usize
        {
            return Err(TransportError::new(
                "transport.frame_session_invalid",
                "FramePacket does not match the verified Control generation or size limit",
            ));
        }
        if self.accept_frames.load(Ordering::Acquire) {
            self.frames.publish(frame);
            return Ok(true);
        }
        Ok(false)
    }

    pub fn set_accept_frames(&self, accept: bool) {
        self.accept_frames.store(accept, Ordering::Release);
    }

    pub fn overwritten_frames(&self) -> u64 {
        self.frames.overwritten_frames()
    }

    fn stream(&self) -> impl Stream<Item = FramePacket> + Send + use<> {
        let attach = FramePacket {
            session: Some(fairypam_agent_protocol::v2::SessionRef {
                agent_id: self.session.agent_id().to_owned(),
                session_id: self.session.session_id().to_owned(),
                generation: self.session.generation(),
            }),
            ..FramePacket::default()
        };
        tokio_stream::once(attach).chain(self.frames.stream())
    }
}

#[derive(Debug)]
pub struct VerifiedFrameDirective(FrameDirective);

impl VerifiedFrameDirective {
    pub fn into_inner(self) -> FrameDirective {
        self.0
    }
}

pub struct FrameSession {
    session: VerifiedSession,
    directives: Streaming<FrameDirective>,
}

impl FrameSession {
    pub async fn message(&mut self) -> Result<Option<VerifiedFrameDirective>, TransportError> {
        let directive = self.directives.message().await.map_err(|error| {
            TransportError::new("transport.frame_read_failed", error.to_string())
        })?;
        directive
            .map(|directive| verify_frame_directive(&self.session, directive))
            .transpose()
    }
}

pub async fn open_frame_tunnel(
    connection: &FrameChannel,
    frames: &SessionFrameSlot,
) -> Result<FrameSession, TransportError> {
    if connection.agent_id != frames.session.agent_id() {
        return Err(TransportError::new(
            "transport.frame_identity_mismatch",
            "Frame connection identity does not match Control session",
        ));
    }
    let mut client = AgentFrameServiceClient::new(connection.channel.clone());
    let directives = client
        .frame_tunnel(Request::new(frames.stream()))
        .await
        .map(tonic::Response::into_inner)
        .map_err(|error| TransportError::new("transport.frame_open_failed", error.to_string()))?;
    Ok(FrameSession {
        session: frames.session.clone(),
        directives,
    })
}

pub(crate) fn verify_frame_directive(
    session: &VerifiedSession,
    directive: FrameDirective,
) -> Result<VerifiedFrameDirective, TransportError> {
    let directive_session = directive.session.as_ref().ok_or_else(|| {
        TransportError::new(
            "transport.frame_directive_session_invalid",
            "Frame directive is missing its SessionRef",
        )
    })?;
    if directive_session.agent_id != session.agent_id()
        || directive_session.session_id != session.session_id()
        || directive_session.generation != session.generation()
    {
        return Err(TransportError::new(
            "transport.frame_directive_session_invalid",
            "Frame directive does not match the verified Control generation",
        ));
    }
    Ok(VerifiedFrameDirective(directive))
}

#[cfg(test)]
mod tests {
    use fairypam_agent_protocol::v2::{HubHello, SessionRef};

    use super::*;
    use crate::control::verify_hub_hello;

    fn session() -> VerifiedSession {
        verify_hub_hello(
            HubHello {
                session: Some(SessionRef {
                    agent_id: "agent-a".into(),
                    session_id: "session-1".into(),
                    generation: 2,
                }),
                heartbeat_interval_ms: 1_000,
                max_input_lease_ms: 500,
                max_frame_bytes: 4,
                accepted_protocol_minor: 6,
            },
            "agent-a",
        )
        .unwrap()
    }

    #[test]
    fn frame_slot_rejects_stale_generation_and_oversized_payload() {
        let frames = session().frame_slot();
        let stale = frames
            .publish(FramePacket {
                session: Some(SessionRef {
                    agent_id: "agent-a".into(),
                    session_id: "session-1".into(),
                    generation: 1,
                }),
                payload: vec![1],
                ..FramePacket::default()
            })
            .unwrap_err();
        assert_eq!(stale.code(), "transport.frame_session_invalid");

        let oversized = frames
            .publish(FramePacket {
                session: Some(SessionRef {
                    agent_id: "agent-a".into(),
                    session_id: "session-1".into(),
                    generation: 2,
                }),
                payload: vec![0; 5],
                ..FramePacket::default()
            })
            .unwrap_err();
        assert_eq!(oversized.code(), "transport.frame_session_invalid");
    }

    #[test]
    fn frame_directive_must_match_verified_generation() {
        let error = verify_frame_directive(
            &session(),
            FrameDirective {
                session: Some(SessionRef {
                    agent_id: "agent-a".into(),
                    session_id: "session-1".into(),
                    generation: 1,
                }),
                ..FrameDirective::default()
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "transport.frame_directive_session_invalid");
    }

    #[tokio::test]
    async fn frame_directive_pauses_and_resumes_transport_without_stopping_capture() {
        let frames = session().frame_slot();
        let stream = frames.stream();
        tokio::pin!(stream);
        assert_eq!(stream.next().await.unwrap().frame_sequence, 0);

        frames.set_accept_frames(false);
        assert!(!frames
            .publish_if_accepting(FramePacket {
                session: Some(SessionRef {
                    agent_id: "agent-a".into(),
                    session_id: "session-1".into(),
                    generation: 2,
                }),
                frame_sequence: 1,
                payload: vec![1],
                ..FramePacket::default()
            })
            .unwrap());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), stream.next())
                .await
                .is_err()
        );

        frames.set_accept_frames(true);
        frames
            .publish(FramePacket {
                session: Some(SessionRef {
                    agent_id: "agent-a".into(),
                    session_id: "session-1".into(),
                    generation: 2,
                }),
                frame_sequence: 2,
                payload: vec![2],
                ..FramePacket::default()
            })
            .unwrap();
        assert_eq!(stream.next().await.unwrap().frame_sequence, 2);
    }
}
