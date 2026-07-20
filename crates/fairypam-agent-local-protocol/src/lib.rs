//! Strict, framed local-control protocol shared by privileged Agent callers.

use std::{collections::VecDeque, fmt};

use serde::{
    de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::{Map, Value};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "encoding", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureEncoding {
    Jpeg { quality: u8 },
    Png,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalCommand {
    Status,
    Doctor,
    ListProfiles,
    EnumerateTargets {
        profile_id: String,
    },
    LockTarget {
        profile_id: String,
        candidate_id: String,
    },
    FocusTarget,
    StartCapture {
        source_id: String,
        fps: u8,
        encoding: CaptureEncoding,
    },
    StopCapture {
        source_id: String,
    },
    #[cfg(feature = "dev-automation")]
    TestbedPulse,
    ReleaseAll,
    UpdateStatus,
    StartupStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEnvelope {
    pub protocol_version: u16,
    pub request_id: String,
    pub nonce: [u8; 32],
    pub command: LocalCommand,
}

#[derive(Serialize)]
struct RequestWire<'a> {
    protocol_version: u16,
    request_id: &'a str,
    nonce: [u8; 32],
    #[serde(flatten)]
    command: &'a LocalCommand,
}

impl Serialize for RequestEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        RequestWire {
            protocol_version: self.protocol_version,
            request_id: &self.request_id,
            nonce: self.nonce,
            command: &self.command,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RequestEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        request_from_value(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalResponse {
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    pub request_id: String,
    pub result: Result<LocalResponse, LocalError>,
}

#[derive(Debug, Error)]
pub enum LocalProtocolError {
    #[error("local.protocol.frame_too_large")]
    FrameTooLarge,
    #[error("local.protocol.invalid: {0}")]
    Invalid(String),
    #[error("local.protocol.unsupported_capability")]
    UnsupportedCapability,
    #[error("local.protocol.unsupported_version")]
    UnsupportedVersion,
    #[error("local.protocol.nonce_replayed")]
    NonceReplayed,
}

impl LocalProtocolError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::FrameTooLarge => "local.protocol.frame_too_large",
            Self::Invalid(_) => "local.protocol.invalid",
            Self::UnsupportedCapability => "local.protocol.unsupported_capability",
            Self::UnsupportedVersion => "local.protocol.unsupported_version",
            Self::NonceReplayed => "local.protocol.nonce_replayed",
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, LocalProtocolError> {
    let json = serde_json::to_vec(value)
        .map_err(|error| LocalProtocolError::invalid(error.to_string()))?;
    if json.len() > MAX_FRAME_BYTES {
        return Err(LocalProtocolError::FrameTooLarge);
    }

    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(&(json.len() as u32).to_le_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

pub fn decode_request(frame: &[u8]) -> Result<RequestEnvelope, LocalProtocolError> {
    request_from_value(decode_frame_value(frame)?)
}

/// Decodes a request while preserving the caller correlation id for a stable
/// protocol error response.  A server uses this at its framing boundary so an
/// unknown (including Dev-only) command is rejected without terminating the
/// privileged pipe listener or reaching a domain handler.
pub fn decode_request_or_error_response(frame: &[u8]) -> Result<RequestEnvelope, ResponseEnvelope> {
    let value = match decode_frame_value(frame) {
        Ok(value) => value,
        Err(error) => return Err(protocol_error_response("invalid".to_owned(), error)),
    };
    let request_id = value
        .as_object()
        .and_then(|object| object.get("request_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("invalid")
        .to_owned();
    request_from_value(value).map_err(|error| protocol_error_response(request_id, error))
}

pub fn decode_response(frame: &[u8]) -> Result<ResponseEnvelope, LocalProtocolError> {
    serde_json::from_value(decode_frame_value(frame)?)
        .map_err(|error| LocalProtocolError::invalid(error.to_string()))
}

fn decode_frame_value(frame: &[u8]) -> Result<Value, LocalProtocolError> {
    if frame.len() > MAX_FRAME_BYTES + 4 {
        return Err(LocalProtocolError::FrameTooLarge);
    }
    if frame.len() < 4 {
        return Err(LocalProtocolError::invalid("missing frame length prefix"));
    }

    let payload_length =
        u32::from_le_bytes(frame[..4].try_into().expect("prefix length checked")) as usize;
    if payload_length > MAX_FRAME_BYTES {
        return Err(LocalProtocolError::FrameTooLarge);
    }
    if frame.len() != payload_length + 4 {
        return Err(LocalProtocolError::invalid(
            "frame length does not match prefix",
        ));
    }

    parse_unique_json(&frame[4..])
}

fn protocol_error_response(request_id: String, error: LocalProtocolError) -> ResponseEnvelope {
    ResponseEnvelope {
        request_id,
        result: Err(LocalError {
            code: error.code().to_owned(),
            message: error.to_string(),
        }),
    }
}

fn parse_unique_json(payload: &[u8]) -> Result<Value, LocalProtocolError> {
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let value = UniqueJson::deserialize(&mut deserializer)
        .map_err(|error| LocalProtocolError::invalid(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| LocalProtocolError::invalid(error.to_string()))?;
    Ok(value.0)
}

struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| E::custom("JSON numbers must be finite"))?;
        Ok(UniqueJson(Value::Number(number)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(value)))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJson>()? {
            values.push(value.0);
        }
        Ok(UniqueJson(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
            }
            let value = map.next_value::<UniqueJson>()?;
            object.insert(key, value.0);
        }
        Ok(UniqueJson(Value::Object(object)))
    }
}

fn request_from_value(value: Value) -> Result<RequestEnvelope, LocalProtocolError> {
    let object = value
        .as_object()
        .ok_or_else(|| LocalProtocolError::invalid("request must be an object"))?;
    let protocol_version = required_field(object, "protocol_version")?;
    let request_id = required_field(object, "request_id")?;
    let nonce = required_field(object, "nonce")?;
    let command_name: String = required_field(object, "command")?;

    if !is_supported_command(&command_name) {
        return Err(LocalProtocolError::UnsupportedCapability);
    }
    if object
        .keys()
        .filter(|key| !matches!(key.as_str(), "protocol_version" | "request_id" | "nonce"))
        .any(|key| !is_allowed_command_field(&command_name, key))
    {
        return Err(LocalProtocolError::invalid("unknown command field"));
    }

    let command = serde_json::from_value(Value::Object(
        object
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "protocol_version" | "request_id" | "nonce"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    ))
    .map_err(|error| LocalProtocolError::invalid(error.to_string()))?;

    if protocol_version != PROTOCOL_VERSION {
        return Err(LocalProtocolError::UnsupportedVersion);
    }

    Ok(RequestEnvelope {
        protocol_version,
        request_id,
        nonce,
        command,
    })
}

fn required_field<T>(object: &Map<String, Value>, name: &str) -> Result<T, LocalProtocolError>
where
    T: DeserializeOwned,
{
    let value = object
        .get(name)
        .cloned()
        .ok_or_else(|| LocalProtocolError::invalid(format!("missing {name}")))?;
    serde_json::from_value(value).map_err(|error| LocalProtocolError::invalid(error.to_string()))
}

fn is_supported_command(command: &str) -> bool {
    match command {
        "status" | "doctor" | "list_profiles" | "enumerate_targets" | "lock_target"
        | "focus_target" | "start_capture" | "stop_capture" | "release_all" | "update_status"
        | "startup_status" => true,
        #[cfg(feature = "dev-automation")]
        "testbed_pulse" => true,
        _ => false,
    }
}

fn is_allowed_command_field(command: &str, field: &str) -> bool {
    matches!(
        (command, field),
        (_, "command")
            | ("enumerate_targets", "profile_id")
            | ("lock_target", "profile_id" | "candidate_id")
            | ("start_capture", "source_id" | "fps" | "encoding")
            | ("stop_capture", "source_id")
    )
}

#[derive(Debug)]
pub struct NonceReplayGuard {
    capacity: usize,
    accepted: VecDeque<[u8; 32]>,
}

impl NonceReplayGuard {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            accepted: VecDeque::with_capacity(capacity.max(1)),
        }
    }

    pub fn accept(&mut self, nonce: [u8; 32]) -> Result<(), LocalProtocolError> {
        if self.accepted.contains(&nonce) {
            return Err(LocalProtocolError::NonceReplayed);
        }
        if self.accepted.len() == self.capacity {
            self.accepted.pop_front();
        }
        self.accepted.push_back(nonce);
        Ok(())
    }
}
