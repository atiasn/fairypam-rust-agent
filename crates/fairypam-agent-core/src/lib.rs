pub mod platform;
pub mod profile;
pub mod state;
#[cfg(feature = "supervisor")]
pub mod supervisor;
pub mod target;

use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct AgentError {
    code: &'static str,
    message: String,
}

impl AgentError {
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
