//! Independent Control and Frame gRPC transport primitives.

mod backoff;
mod control;
mod frame;
mod telemetry;
mod tls;

pub use backoff::CappedBackoff;
pub use control::{
    control_queue, open_control_tunnel, receive_hub_hello, ControlReceiver, ControlSender,
    ControlSession, PendingControlTunnel, VerifiedControlCommand, VerifiedSession,
    CONTROL_QUEUE_CAPACITY,
};
pub use frame::{
    open_frame_tunnel, FrameSession, LatestFrameSlot, SessionFrameSlot, VerifiedFrameDirective,
};
pub use telemetry::{
    hello_event as telemetry_hello_event, open_telemetry_tunnel, receive_telemetry_hello,
    telemetry_queue, TelemetryReceiver, TelemetrySender, TelemetrySession,
    TELEMETRY_QUEUE_CAPACITY,
};
pub use tls::{
    connect_control, connect_frame, connect_telemetry, validate_transport_config, ControlChannel,
    FrameChannel, TelemetryChannel, TransportConfig,
};

use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct TransportError {
    code: &'static str,
    message: String,
}

impl TransportError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }
}
