//! Shared, fail-closed client for the privileged Agent local control plane.
//!
//! This crate owns framing, request correlation, bounded connection setup and
//! stable error categories. It deliberately contains no Agent input, capture,
//! GUI or process-launching implementation.

use std::{collections::BTreeSet, pin::Pin, time::Duration};

use fairypam_agent_local_protocol::{
    decode_response, encode_frame, LocalCommand, LocalError, LocalProtocolError, LocalResponse,
    RequestEnvelope, PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio_stream::Stream;

#[cfg(windows)]
mod windows_named_pipe;

#[cfg(windows)]
pub use windows_named_pipe::{
    verify_protected_program_files_path, WindowsNamedPipeClientTransport,
};

const CONNECT_ATTEMPTS: usize = 3;
const INITIAL_CONNECT_BACKOFF: Duration = Duration::from_millis(10);

#[cfg(any(windows, test))]
fn normalize_windows_path(path: &str) -> Option<String> {
    let path = path.trim().trim_matches('"').replace('/', "\\");
    let path = path
        .strip_prefix(r"\\?\UNC\")
        .map(|suffix| format!(r"\\{suffix}"))
        .or_else(|| path.strip_prefix(r"\\?\").map(str::to_owned))
        .unwrap_or(path);
    (!path.is_empty() && path.contains('\\')).then(|| path.trim_end_matches('\\').to_lowercase())
}

#[cfg(any(windows, test))]
fn windows_path_is_within(path: &str, root: &str) -> bool {
    let (Some(path), Some(root)) = (normalize_windows_path(path), normalize_windows_path(root))
    else {
        return false;
    };
    path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|suffix| suffix.starts_with('\\'))
}

/// The errors exposed by every local-control caller, including the GUI and CLI.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LocalClientError {
    #[error("{code}: {message}")]
    Identity { code: String, message: String },
    #[error("{code}: {message}")]
    Protocol { code: String, message: String },
    #[error("{code}: {message}")]
    Transport { code: String, message: String },
    #[error("{code}: {message}")]
    Domain { code: String, message: String },
    #[error("local.transport.timeout: request exceeded its deadline")]
    Timeout,
    #[error("local.transport.cancelled: request was cancelled before dispatch")]
    Cancelled,
}

impl LocalClientError {
    pub fn code(&self) -> &str {
        match self {
            Self::Identity { code, .. }
            | Self::Protocol { code, .. }
            | Self::Transport { code, .. }
            | Self::Domain { code, .. } => code,
            Self::Timeout => "local.transport.timeout",
            Self::Cancelled => "local.transport.cancelled",
        }
    }

    pub fn identity(reason: impl AsRef<str>) -> Self {
        let reason = reason.as_ref();
        let code = if reason.starts_with("local.identity.") {
            reason.to_owned()
        } else {
            format!("local.identity.{reason}")
        };
        Self::Identity {
            message: code.clone(),
            code,
        }
    }

    pub fn protocol(error: LocalProtocolError) -> Self {
        Self::Protocol {
            code: error.code().to_owned(),
            message: error.to_string(),
        }
    }

    pub fn protocol_message(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Protocol {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn transport(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Transport {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn domain(error: LocalError) -> Self {
        Self::Domain {
            code: error.code,
            message: error.message,
        }
    }

    pub fn pipe_not_found() -> Self {
        Self::transport(
            "local.transport.pipe_not_found",
            "the Agent local-control pipe is not available",
        )
    }

    pub fn disconnected() -> Self {
        Self::transport(
            "local.transport.disconnected",
            "the Agent local-control pipe disconnected",
        )
    }

    pub const fn timeout() -> Self {
        Self::Timeout
    }

    pub const fn cancelled() -> Self {
        Self::Cancelled
    }

    fn retryable_connect_failure(&self) -> bool {
        matches!(
            self.code(),
            "local.transport.pipe_not_found"
                | "local.transport.pipe_busy"
                | "local.transport.disconnected"
        )
    }
}

impl From<LocalProtocolError> for LocalClientError {
    fn from(error: LocalProtocolError) -> Self {
        Self::protocol(error)
    }
}

/// Minimal transport boundary used by both the CLI and GUI.
///
/// `connect` has a benign default so deterministic transports can model an
/// already-connected pipe. Only this phase is eligible for client retries.
#[allow(async_fn_in_trait)]
pub trait LocalTransport: Send {
    async fn connect(&mut self) -> Result<(), LocalClientError> {
        Ok(())
    }

    async fn send(&mut self, frame: Vec<u8>) -> Result<(), LocalClientError>;
    async fn receive(&mut self) -> Result<Vec<u8>, LocalClientError>;
    async fn close(&mut self);
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEvent {
    pub request_id: String,
    pub body: Value,
}

pub type LocalEventStream =
    Pin<Box<dyn Stream<Item = Result<LocalEvent, LocalClientError>> + Send>>;

/// A serial request client. The protocol currently has no event command, so
/// subscriptions return an explicit capability error until a later protocol
/// version defines an authenticated event vocabulary.
pub struct LocalClient<T> {
    transport: T,
    cancelled: BTreeSet<String>,
}

impl<T: LocalTransport> LocalClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            cancelled: BTreeSet::new(),
        }
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    pub fn cancel(&mut self, request_id: &str) {
        self.cancelled.insert(request_id.to_owned());
    }

    pub async fn request(
        &mut self,
        command: LocalCommand,
        timeout: Duration,
    ) -> Result<LocalResponse, LocalClientError> {
        let request = self.new_request(command)?;
        self.request_envelope(request, timeout).await
    }

    /// Dispatch a request with caller-owned correlation id.
    ///
    /// Callers that need to invoke [`Self::cancel`] should keep this id unique
    /// for the lifetime of the local-control connection.
    pub async fn request_with_id(
        &mut self,
        request_id: impl Into<String>,
        command: LocalCommand,
        timeout: Duration,
    ) -> Result<LocalResponse, LocalClientError> {
        let mut request = self.new_request(command)?;
        request.request_id = request_id.into();
        self.request_envelope(request, timeout).await
    }

    pub fn subscribe(&self) -> Result<LocalEventStream, LocalClientError> {
        Err(LocalClientError::protocol_message(
            "local.protocol.unsupported_capability",
            "the current local protocol does not define event subscriptions",
        ))
    }

    fn new_request(&self, command: LocalCommand) -> Result<RequestEnvelope, LocalClientError> {
        let mut material = [0_u8; 48];
        getrandom::fill(&mut material).map_err(|error| {
            LocalClientError::protocol_message(
                "local.protocol.nonce_unavailable",
                format!("operating-system random source failed: {error}"),
            )
        })?;

        let mut nonce = [0_u8; 32];
        nonce.copy_from_slice(&material[16..]);
        Ok(RequestEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: format!("request-{}", hex(&material[..16])),
            nonce,
            command,
        })
    }

    async fn request_envelope(
        &mut self,
        request: RequestEnvelope,
        timeout: Duration,
    ) -> Result<LocalResponse, LocalClientError> {
        let deadline = tokio::time::Instant::now() + timeout;
        if self.take_cancelled(&request.request_id) {
            return Err(LocalClientError::cancelled());
        }

        match tokio::time::timeout_at(deadline, self.establish_connection()).await {
            Ok(result) => result?,
            Err(_) => {
                self.transport.close().await;
                return Err(LocalClientError::timeout());
            }
        }

        if self.take_cancelled(&request.request_id) {
            self.transport.close().await;
            return Err(LocalClientError::cancelled());
        }

        let frame = encode_frame(&request).map_err(LocalClientError::from)?;
        match tokio::time::timeout_at(deadline, self.transport.send(frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.transport.close().await;
                return Err(error);
            }
            Err(_) => {
                self.transport.close().await;
                return Err(LocalClientError::timeout());
            }
        }

        let frame = match tokio::time::timeout_at(deadline, self.transport.receive()).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(error)) => {
                self.transport.close().await;
                return Err(error);
            }
            Err(_) => {
                self.transport.close().await;
                return Err(LocalClientError::timeout());
            }
        };
        let response = match decode_response(&frame) {
            Ok(response) => response,
            Err(error) => {
                self.transport.close().await;
                return Err(error.into());
            }
        };
        if response.request_id != request.request_id {
            self.transport.close().await;
            return Err(LocalClientError::protocol_message(
                "local.protocol.invalid",
                "response request_id does not match the dispatched request",
            ));
        }

        match response.result {
            Ok(response) => Ok(response),
            Err(error) => Err(LocalClientError::domain(error)),
        }
    }

    async fn establish_connection(&mut self) -> Result<(), LocalClientError> {
        let mut delay = INITIAL_CONNECT_BACKOFF;
        for attempt in 0..CONNECT_ATTEMPTS {
            match self.transport.connect().await {
                Ok(()) => return Ok(()),
                Err(error)
                    if error.retryable_connect_failure() && attempt + 1 < CONNECT_ATTEMPTS =>
                {
                    self.transport.close().await;
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2);
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("a bounded connect loop always returns")
    }

    fn take_cancelled(&mut self, request_id: &str) -> bool {
        self.cancelled.remove(request_id)
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod path_tests {
    use super::windows_path_is_within;

    #[test]
    fn protected_root_check_rejects_prefix_confusion_and_appdata() {
        let root = r"C:\Program Files";
        assert!(windows_path_is_within(
            r"\\?\C:\Program Files\FairyPam\fairypam-agent.exe",
            root
        ));
        assert!(!windows_path_is_within(
            r"C:\Program Files-Evil\FairyPam\fairypam-agent.exe",
            root
        ));
        assert!(!windows_path_is_within(
            r"C:\Users\clei\AppData\Local\FairyPam\fairypam-agent.exe",
            root
        ));
    }
}
