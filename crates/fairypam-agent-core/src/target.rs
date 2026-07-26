use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetSelector {
    pub candidate_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetCandidate {
    pub selector: TargetSelector,
    pub window_handle: u64,
    pub process_id: u32,
    pub process_name: String,
    pub process_path_sha256: String,
    pub window_title: String,
    pub window_class: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetBinding {
    pub profile_id: String,
    pub profile_version: String,
    pub process_id: u32,
    pub process_name: String,
    pub process_started_at_unix_ms: u64,
    pub process_path_sha256: String,
    pub window_handle: u64,
    pub window_title: String,
    pub window_class: String,
    pub client_rect: ClientRect,
    pub dpi: u32,
    pub integrity: IntegrityLevel,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetSnapshot {
    pub binding: TargetBinding,
    pub foreground: bool,
    pub minimized: bool,
    pub capturable: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientRect {
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityLevel {
    Unknown,
    Low,
    Medium,
    High,
    System,
}
