pub mod controller;
pub mod health;
pub mod runtime_discovery;
pub mod runtime_manifest;
pub mod runtime_switch;
pub mod runtime_verify;
pub mod worker_client;

use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct MaaRuntimeError {
    code: &'static str,
    message: String,
}

impl MaaRuntimeError {
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

impl From<std::io::Error> for MaaRuntimeError {
    fn from(error: std::io::Error) -> Self {
        Self::new("maa.runtime_io_failed", error.to_string())
    }
}
