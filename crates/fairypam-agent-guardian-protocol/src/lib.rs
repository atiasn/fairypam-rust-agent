//! Strict IPC protocol shared by the Agent and Guardian processes.

use std::io::{BufRead, Read};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    X1,
    X2,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PhysicalHold {
    ScanCode {
        action_id: ActionId,
        scan_code: u16,
        #[serde(default)]
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuardianRequest {
    RegisterAgent {
        agent_pid: u32,
        agent_process_handle: u64,
        heartbeat_timeout_ms: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        isolation_key_name: Option<String>,
    },
    Heartbeat {
        sequence: u64,
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuardianResponse {
    Ack {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        isolation_status: Option<i32>,
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
    #[error("guardian.invalid_message: {0}")]
    InvalidMessage(String),
    #[error("guardian.io_failed: {0}")]
    Io(String),
}

pub fn read_bounded_line<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut line = Vec::new();
    let read = Read::by_ref(reader)
        .take((MAX_MESSAGE_BYTES + 1) as u64)
        .read_until(b'\n', &mut line)
        .map_err(|error| ProtocolError::Io(error.to_string()))?;
    if read == 0 {
        return Ok(None);
    }
    if line.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge);
    }
    Ok(Some(line))
}

pub fn encode_line<T: Serialize>(message: &T) -> Result<Vec<u8>, ProtocolError> {
    let mut encoded = serde_json::to_vec(message)
        .map_err(|error| ProtocolError::InvalidMessage(error.to_string()))?;
    if encoded.len() >= MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge);
    }
    encoded.push(b'\n');
    Ok(encoded)
}

pub fn decode_request(bytes: &[u8]) -> Result<GuardianRequest, ProtocolError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|error| ProtocolError::InvalidMessage(error.to_string()))
}

pub fn decode_response(bytes: &[u8]) -> Result<GuardianResponse, ProtocolError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|error| ProtocolError::InvalidMessage(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn unknown_message_tag_is_rejected() {
        let error =
            decode_request(br#"{"type":"execute_arbitrary","command":"calc.exe"}"#).unwrap_err();
        assert!(matches!(error, ProtocolError::InvalidMessage(_)));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let error = decode_request(br#"{"type":"status","extra":true}"#).unwrap_err();
        assert!(matches!(error, ProtocolError::InvalidMessage(_)));
    }

    #[test]
    fn oversized_line_is_rejected_before_unbounded_buffering() {
        let mut bytes = vec![b'x'; MAX_MESSAGE_BYTES + 1];
        bytes.push(b'\n');

        let error = read_bounded_line(&mut Cursor::new(bytes)).unwrap_err();

        assert_eq!(error, ProtocolError::MessageTooLarge);
    }
}
