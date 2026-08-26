//! Versioned protobuf IPC shared by the Agent and Guardian processes.

use std::io::Read;

use fairypam_agent_protocol::guardian_v1 as wire;
use prost::Message;
use thiserror::Error;

pub const GUARDIAN_PROTOCOL_MAJOR: u32 = 1;
pub const GUARDIAN_PROTOCOL_MINOR: u32 = 1;
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionId(String);

impl ActionId {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            });
        if !valid {
            return Err(ProtocolError::InvalidActionId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    X1,
    X2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PhysicalHold {
    ScanCode {
        action_id: ActionId,
        scan_code: u16,
        extended: bool,
    },
    MouseButton {
        action_id: ActionId,
        button: MouseButton,
    },
}

impl PhysicalHold {
    pub const fn action_id(&self) -> &ActionId {
        match self {
            Self::ScanCode { action_id, .. } | Self::MouseButton { action_id, .. } => action_id,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseReason {
    LeaseExpired,
    FocusLost,
    SessionChanged,
    EmergencyStop,
    GuardianFailure,
    AgentExited,
    HeartbeatExpired,
    AgentDisconnected,
    PlatformFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardianRequest {
    RegisterAgent {
        agent_pid: u32,
        agent_process_handle: u64,
        heartbeat_timeout_ms: u32,
        isolation_key_name: Option<String>,
    },
    Heartbeat {
        sequence: u64,
    },
    WorkerHealth {
        ready: bool,
    },
    RegisterIntent {
        sequence: u64,
        holds: Vec<PhysicalHold>,
    },
    CommitHolds {
        sequence: u64,
    },
    ReleaseAll {
        reason: ReleaseReason,
    },
    Status {},
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardianResponse {
    Ack {
        isolation_status: Option<i32>,
        activation_pending: bool,
    },
    Status {
        agent_pid: Option<u32>,
        committed_hold_count: usize,
        last_sequence: u64,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("guardian.invalid_action_id")]
    InvalidActionId,
    #[error("guardian.message_too_large")]
    MessageTooLarge,
    #[error("guardian.protocol_incompatible")]
    ProtocolIncompatible,
    #[error("guardian.invalid_message: {0}")]
    InvalidMessage(String),
    #[error("guardian.io_failed: {0}")]
    Io(String),
}

pub fn read_bounded_frame<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut length = [0_u8; 4];
    let mut offset = 0;
    while offset < length.len() {
        let read = reader
            .read(&mut length[offset..])
            .map_err(|error| ProtocolError::Io(error.to_string()))?;
        if read == 0 {
            return if offset == 0 {
                Ok(None)
            } else {
                Err(ProtocolError::InvalidMessage(
                    "truncated frame header".into(),
                ))
            };
        }
        offset += read;
    }
    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge);
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| ProtocolError::InvalidMessage(error.to_string()))?;
    Ok(Some(payload))
}

pub fn encode_request(message: &GuardianRequest) -> Result<Vec<u8>, ProtocolError> {
    encode_envelope(wire::guardian_envelope::Payload::Request(request_to_wire(
        message,
    )))
}

pub fn encode_response(message: &GuardianResponse) -> Result<Vec<u8>, ProtocolError> {
    encode_envelope(wire::guardian_envelope::Payload::Response(
        response_to_wire(message)?,
    ))
}

pub fn decode_request(bytes: &[u8]) -> Result<GuardianRequest, ProtocolError> {
    match decode_envelope(bytes)? {
        wire::guardian_envelope::Payload::Request(request) => request_from_wire(request),
        wire::guardian_envelope::Payload::Response(_) => Err(ProtocolError::InvalidMessage(
            "expected Guardian request".into(),
        )),
    }
}

pub fn decode_response(bytes: &[u8]) -> Result<GuardianResponse, ProtocolError> {
    match decode_envelope(bytes)? {
        wire::guardian_envelope::Payload::Response(response) => response_from_wire(response),
        wire::guardian_envelope::Payload::Request(_) => Err(ProtocolError::InvalidMessage(
            "expected Guardian response".into(),
        )),
    }
}

fn encode_envelope(payload: wire::guardian_envelope::Payload) -> Result<Vec<u8>, ProtocolError> {
    let payload = wire::GuardianEnvelope {
        protocol_major: GUARDIAN_PROTOCOL_MAJOR,
        protocol_minor: GUARDIAN_PROTOCOL_MINOR,
        payload: Some(payload),
    }
    .encode_to_vec();
    if payload.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge);
    }
    let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::MessageTooLarge)?;
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn decode_envelope(bytes: &[u8]) -> Result<wire::guardian_envelope::Payload, ProtocolError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge);
    }
    let envelope = wire::GuardianEnvelope::decode(bytes)
        .map_err(|error| ProtocolError::InvalidMessage(error.to_string()))?;
    if envelope.protocol_major != GUARDIAN_PROTOCOL_MAJOR
        || envelope.protocol_minor > GUARDIAN_PROTOCOL_MINOR
    {
        return Err(ProtocolError::ProtocolIncompatible);
    }
    envelope.payload.ok_or(ProtocolError::ProtocolIncompatible)
}

fn request_to_wire(request: &GuardianRequest) -> wire::GuardianRequest {
    use wire::guardian_request::Payload;
    let payload = match request {
        GuardianRequest::RegisterAgent {
            agent_pid,
            agent_process_handle,
            heartbeat_timeout_ms,
            isolation_key_name,
        } => Payload::RegisterAgent(wire::RegisterAgent {
            agent_pid: *agent_pid,
            agent_process_handle: *agent_process_handle,
            heartbeat_timeout_ms: *heartbeat_timeout_ms,
            isolation_key_name: isolation_key_name.clone(),
        }),
        GuardianRequest::Heartbeat { sequence } => Payload::Heartbeat(wire::Heartbeat {
            sequence: *sequence,
        }),
        GuardianRequest::WorkerHealth { ready } => {
            Payload::WorkerHealth(wire::WorkerHealth { ready: *ready })
        }
        GuardianRequest::RegisterIntent { sequence, holds } => {
            Payload::RegisterIntent(wire::RegisterIntent {
                sequence: *sequence,
                holds: holds.iter().map(hold_to_wire).collect(),
            })
        }
        GuardianRequest::CommitHolds { sequence } => Payload::CommitHolds(wire::CommitHolds {
            sequence: *sequence,
        }),
        GuardianRequest::ReleaseAll { reason } => Payload::ReleaseAll(wire::ReleaseAll {
            reason: reason_to_wire(*reason) as i32,
        }),
        GuardianRequest::Status {} => Payload::Status(wire::Status {}),
    };
    wire::GuardianRequest {
        payload: Some(payload),
    }
}

fn request_from_wire(request: wire::GuardianRequest) -> Result<GuardianRequest, ProtocolError> {
    use wire::guardian_request::Payload;
    match request.payload.ok_or_else(invalid_payload)? {
        Payload::RegisterAgent(value) => Ok(GuardianRequest::RegisterAgent {
            agent_pid: value.agent_pid,
            agent_process_handle: value.agent_process_handle,
            heartbeat_timeout_ms: value.heartbeat_timeout_ms,
            isolation_key_name: value.isolation_key_name,
        }),
        Payload::Heartbeat(value) => Ok(GuardianRequest::Heartbeat {
            sequence: value.sequence,
        }),
        Payload::WorkerHealth(value) => Ok(GuardianRequest::WorkerHealth { ready: value.ready }),
        Payload::RegisterIntent(value) => Ok(GuardianRequest::RegisterIntent {
            sequence: value.sequence,
            holds: value
                .holds
                .into_iter()
                .map(hold_from_wire)
                .collect::<Result<_, _>>()?,
        }),
        Payload::CommitHolds(value) => Ok(GuardianRequest::CommitHolds {
            sequence: value.sequence,
        }),
        Payload::ReleaseAll(value) => Ok(GuardianRequest::ReleaseAll {
            reason: reason_from_wire(value.reason)?,
        }),
        Payload::Status(_) => Ok(GuardianRequest::Status {}),
    }
}

fn response_to_wire(response: &GuardianResponse) -> Result<wire::GuardianResponse, ProtocolError> {
    use wire::guardian_response::Payload;
    let payload = match response {
        GuardianResponse::Ack {
            isolation_status,
            activation_pending,
        } => Payload::Ack(wire::Ack {
            isolation_status: *isolation_status,
            activation_pending: *activation_pending,
        }),
        GuardianResponse::Status {
            agent_pid,
            committed_hold_count,
            last_sequence,
        } => Payload::Status(wire::GuardianStatus {
            agent_pid: *agent_pid,
            committed_hold_count: (*committed_hold_count)
                .try_into()
                .map_err(|_| invalid_payload())?,
            last_sequence: *last_sequence,
        }),
        GuardianResponse::Error { code, message } => Payload::Error(wire::GuardianError {
            code: code.clone(),
            message: message.clone(),
        }),
    };
    Ok(wire::GuardianResponse {
        payload: Some(payload),
    })
}

fn response_from_wire(response: wire::GuardianResponse) -> Result<GuardianResponse, ProtocolError> {
    use wire::guardian_response::Payload;
    match response.payload.ok_or_else(invalid_payload)? {
        Payload::Ack(value) => Ok(GuardianResponse::Ack {
            isolation_status: value.isolation_status,
            activation_pending: value.activation_pending,
        }),
        Payload::Status(value) => Ok(GuardianResponse::Status {
            agent_pid: value.agent_pid,
            committed_hold_count: value
                .committed_hold_count
                .try_into()
                .map_err(|_| invalid_payload())?,
            last_sequence: value.last_sequence,
        }),
        Payload::Error(value) => Ok(GuardianResponse::Error {
            code: value.code,
            message: value.message,
        }),
    }
}

fn hold_to_wire(hold: &PhysicalHold) -> wire::PhysicalHold {
    use wire::physical_hold::Kind;
    match hold {
        PhysicalHold::ScanCode {
            action_id,
            scan_code,
            extended,
        } => wire::PhysicalHold {
            action_id: action_id.as_str().to_owned(),
            kind: Some(Kind::ScanCode(wire::ScanCodeHold {
                scan_code: u32::from(*scan_code),
                extended: *extended,
            })),
        },
        PhysicalHold::MouseButton { action_id, button } => wire::PhysicalHold {
            action_id: action_id.as_str().to_owned(),
            kind: Some(Kind::MouseButton(wire::MouseButtonHold {
                button: button_to_wire(*button) as i32,
            })),
        },
    }
}

fn hold_from_wire(hold: wire::PhysicalHold) -> Result<PhysicalHold, ProtocolError> {
    use wire::physical_hold::Kind;
    let action_id = ActionId::new(hold.action_id)?;
    match hold.kind.ok_or_else(invalid_payload)? {
        Kind::ScanCode(value) => Ok(PhysicalHold::ScanCode {
            action_id,
            scan_code: value.scan_code.try_into().map_err(|_| invalid_payload())?,
            extended: value.extended,
        }),
        Kind::MouseButton(value) => Ok(PhysicalHold::MouseButton {
            action_id,
            button: button_from_wire(value.button)?,
        }),
    }
}

const fn button_to_wire(button: MouseButton) -> wire::MouseButton {
    match button {
        MouseButton::Left => wire::MouseButton::Left,
        MouseButton::Right => wire::MouseButton::Right,
        MouseButton::Middle => wire::MouseButton::Middle,
        MouseButton::X1 => wire::MouseButton::X1,
        MouseButton::X2 => wire::MouseButton::X2,
    }
}

fn button_from_wire(button: i32) -> Result<MouseButton, ProtocolError> {
    match wire::MouseButton::try_from(button).map_err(|_| invalid_payload())? {
        wire::MouseButton::Left => Ok(MouseButton::Left),
        wire::MouseButton::Right => Ok(MouseButton::Right),
        wire::MouseButton::Middle => Ok(MouseButton::Middle),
        wire::MouseButton::X1 => Ok(MouseButton::X1),
        wire::MouseButton::X2 => Ok(MouseButton::X2),
        wire::MouseButton::Unspecified => Err(invalid_payload()),
    }
}

const fn reason_to_wire(reason: ReleaseReason) -> wire::ReleaseReason {
    match reason {
        ReleaseReason::LeaseExpired => wire::ReleaseReason::LeaseExpired,
        ReleaseReason::FocusLost => wire::ReleaseReason::FocusLost,
        ReleaseReason::SessionChanged => wire::ReleaseReason::SessionChanged,
        ReleaseReason::EmergencyStop => wire::ReleaseReason::EmergencyStop,
        ReleaseReason::GuardianFailure => wire::ReleaseReason::GuardianFailure,
        ReleaseReason::AgentExited => wire::ReleaseReason::AgentExited,
        ReleaseReason::HeartbeatExpired => wire::ReleaseReason::HeartbeatExpired,
        ReleaseReason::AgentDisconnected => wire::ReleaseReason::AgentDisconnected,
        ReleaseReason::PlatformFailure => wire::ReleaseReason::PlatformFailure,
    }
}

fn reason_from_wire(reason: i32) -> Result<ReleaseReason, ProtocolError> {
    match wire::ReleaseReason::try_from(reason).map_err(|_| invalid_payload())? {
        wire::ReleaseReason::LeaseExpired => Ok(ReleaseReason::LeaseExpired),
        wire::ReleaseReason::FocusLost => Ok(ReleaseReason::FocusLost),
        wire::ReleaseReason::SessionChanged => Ok(ReleaseReason::SessionChanged),
        wire::ReleaseReason::EmergencyStop => Ok(ReleaseReason::EmergencyStop),
        wire::ReleaseReason::GuardianFailure => Ok(ReleaseReason::GuardianFailure),
        wire::ReleaseReason::AgentExited => Ok(ReleaseReason::AgentExited),
        wire::ReleaseReason::HeartbeatExpired => Ok(ReleaseReason::HeartbeatExpired),
        wire::ReleaseReason::AgentDisconnected => Ok(ReleaseReason::AgentDisconnected),
        wire::ReleaseReason::PlatformFailure => Ok(ReleaseReason::PlatformFailure),
        wire::ReleaseReason::Unspecified => Err(invalid_payload()),
    }
}

fn invalid_payload() -> ProtocolError {
    ProtocolError::InvalidMessage("Guardian payload is invalid".into())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn heartbeat() -> GuardianRequest {
        GuardianRequest::Heartbeat { sequence: 7 }
    }

    #[test]
    fn versioned_protobuf_round_trips() {
        let frame = encode_request(&heartbeat()).unwrap();
        let payload = read_bounded_frame(&mut Cursor::new(frame))
            .unwrap()
            .unwrap();
        assert_eq!(decode_request(&payload).unwrap(), heartbeat());
    }

    #[test]
    fn rejects_unknown_payload_and_newer_protocol() {
        let unknown_payload = [0x08, 0x01, 0x78, 0x00];
        assert_eq!(
            decode_request(&unknown_payload).unwrap_err(),
            ProtocolError::ProtocolIncompatible
        );
        let newer = wire::GuardianEnvelope {
            protocol_major: GUARDIAN_PROTOCOL_MAJOR,
            protocol_minor: GUARDIAN_PROTOCOL_MINOR + 1,
            payload: Some(wire::guardian_envelope::Payload::Request(request_to_wire(
                &heartbeat(),
            ))),
        }
        .encode_to_vec();
        assert_eq!(
            decode_request(&newer).unwrap_err(),
            ProtocolError::ProtocolIncompatible
        );
    }

    #[test]
    fn rejects_oversized_and_truncated_frames() {
        let oversized = ((MAX_MESSAGE_BYTES + 1) as u32).to_le_bytes();
        assert_eq!(
            read_bounded_frame(&mut Cursor::new(oversized)).unwrap_err(),
            ProtocolError::MessageTooLarge
        );
        let mut truncated = 8_u32.to_le_bytes().to_vec();
        truncated.extend_from_slice(&[1, 2]);
        assert!(matches!(
            read_bounded_frame(&mut Cursor::new(truncated)),
            Err(ProtocolError::InvalidMessage(_))
        ));
    }
}
