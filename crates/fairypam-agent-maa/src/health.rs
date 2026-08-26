use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RuntimeHealth {
    pub runtime_version: String,
    pub backend: String,
    pub connected: bool,
    pub last_error_code: Option<String>,
    pub event_count: u64,
    pub last_event: Option<String>,
}
