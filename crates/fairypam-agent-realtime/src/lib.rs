pub mod input_batch;
pub mod local_input_monitor;
pub mod metrics;
pub mod music_engine;
pub mod pixel_probe;
pub mod program;
pub mod scheduler;
pub mod spec;

use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct RealtimeError {
    code: &'static str,
    message: String,
}

impl RealtimeError {
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
