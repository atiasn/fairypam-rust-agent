#[cfg(feature = "dev-automation")]
use std::collections::BTreeSet;
use std::collections::HashMap;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 0;
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_NONCE_ENTRIES: usize = 1_024;
pub const REPLAY_WINDOW: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalRequest {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub request_id: String,
    pub nonce: String,
    pub command: LocalCommand,
}

impl LocalRequest {
    pub fn new(request_id: String, nonce: String, command: LocalCommand) -> Self {
        Self {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            request_id,
            nonce,
            command,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_major != PROTOCOL_MAJOR || self.protocol_minor > PROTOCOL_MINOR {
            return Err(ProtocolError::new(
                LocalErrorCode::ProtocolVersionMismatch,
                "local protocol version is unsupported",
            ));
        }
        validate_request_id(&self.request_id)?;
        validate_nonce(&self.nonce)?;
        self.command.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalCommand {
    Hello {
        client_name: String,
        client_version: String,
    },
    Status {},
    Doctor {},
    ListProfiles {},
    ListTargets {
        profile_id: String,
    },
    SelectTarget {
        profile_id: String,
        target_id: String,
    },
    FocusTarget {},
    CloseTarget {
        timeout_ms: u32,
    },
    Diagnostics {},
    SuiteStatus {},
    CapturePreview {
        quality: u8,
    },
    RequestUpdate {},
    SetAutostart {
        enabled: bool,
    },
    ReleaseAll {},
    PrepareUpdate {
        timeout_ms: u32,
    },
    ResumeAfterUpdateFailure {},
    #[cfg(feature = "dev-automation")]
    DevStatus {},
    #[cfg(feature = "dev-automation")]
    DevStartAutomation {
        target: AutomationTarget,
        capabilities: BTreeSet<AutomationCapability>,
        ttl_ms: u32,
    },
    #[cfg(feature = "dev-automation")]
    DevPulseTestbed {
        session_id: String,
    },
    #[cfg(feature = "dev-automation")]
    DevHoldTestbed {
        session_id: String,
        duration_ms: u32,
    },
    #[cfg(feature = "dev-automation")]
    DevStopAutomation {},
    #[cfg(feature = "dev-automation")]
    DevEmergencyStop {},
}

impl LocalCommand {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "hello",
            Self::Status {} => "status",
            Self::Doctor {} => "doctor",
            Self::ListProfiles {} => "list_profiles",
            Self::ListTargets { .. } => "list_targets",
            Self::SelectTarget { .. } => "select_target",
            Self::FocusTarget {} => "focus_target",
            Self::CloseTarget { .. } => "close_target",
            Self::Diagnostics {} => "diagnostics",
            Self::SuiteStatus {} => "suite_status",
            Self::CapturePreview { .. } => "capture_preview",
            Self::RequestUpdate {} => "request_update",
            Self::SetAutostart { .. } => "set_autostart",
            Self::ReleaseAll {} => "release_all",
            Self::PrepareUpdate { .. } => "prepare_update",
            Self::ResumeAfterUpdateFailure {} => "resume_after_update_failure",
            #[cfg(feature = "dev-automation")]
            Self::DevStatus {} => "dev_status",
            #[cfg(feature = "dev-automation")]
            Self::DevStartAutomation { .. } => "dev_start_automation",
            #[cfg(feature = "dev-automation")]
            Self::DevPulseTestbed { .. } => "dev_pulse_testbed",
            #[cfg(feature = "dev-automation")]
            Self::DevHoldTestbed { .. } => "dev_hold_testbed",
            #[cfg(feature = "dev-automation")]
            Self::DevStopAutomation {} => "dev_stop_automation",
            #[cfg(feature = "dev-automation")]
            Self::DevEmergencyStop {} => "dev_emergency_stop",
        }
    }

    pub const fn mutates_state(&self) -> bool {
        match self {
            Self::SelectTarget { .. }
            | Self::FocusTarget {}
            | Self::CloseTarget { .. }
            | Self::RequestUpdate {}
            | Self::SetAutostart { .. }
            | Self::ReleaseAll {} => true,
            Self::PrepareUpdate { .. } | Self::ResumeAfterUpdateFailure {} => true,
            #[cfg(feature = "dev-automation")]
            Self::DevStartAutomation { .. }
            | Self::DevPulseTestbed { .. }
            | Self::DevHoldTestbed { .. }
            | Self::DevStopAutomation {}
            | Self::DevEmergencyStop {} => true,
            _ => false,
        }
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Hello {
                client_name,
                client_version,
            } => {
                validate_label(client_name, "client name", 64)?;
                validate_label(client_version, "client version", 32)
            }
            Self::ListTargets { profile_id } | Self::SelectTarget { profile_id, .. } => {
                validate_profile_id(profile_id)?;
                if let Self::SelectTarget { target_id, .. } = self {
                    validate_opaque_id(target_id, "target id")?;
                }
                Ok(())
            }
            Self::CloseTarget { timeout_ms } if !(1..=5_000).contains(timeout_ms) => {
                Err(ProtocolError::new(
                    LocalErrorCode::InvalidArgument,
                    "close timeout must be between 1 and 5000 ms",
                ))
            }
            Self::PrepareUpdate { timeout_ms } if !(1..=30_000).contains(timeout_ms) => {
                Err(ProtocolError::new(
                    LocalErrorCode::InvalidArgument,
                    "update quiesce timeout must be between 1 and 30000 ms",
                ))
            }
            Self::CapturePreview { quality } if !(1..=100).contains(quality) => {
                Err(ProtocolError::new(
                    LocalErrorCode::InvalidArgument,
                    "preview quality must be between 1 and 100",
                ))
            }
            #[cfg(feature = "dev-automation")]
            Self::DevStartAutomation {
                target,
                capabilities,
                ttl_ms,
            } => {
                target.validate()?;
                if capabilities.is_empty() || capabilities.len() > 3 {
                    return Err(ProtocolError::new(
                        LocalErrorCode::InvalidArgument,
                        "automation capabilities must be a non-empty fixed set",
                    ));
                }
                if !(1_000..=30_000).contains(ttl_ms) {
                    return Err(ProtocolError::new(
                        LocalErrorCode::InvalidArgument,
                        "automation TTL must be between 1000 and 30000 ms",
                    ));
                }
                Ok(())
            }
            #[cfg(feature = "dev-automation")]
            Self::DevPulseTestbed { session_id } => {
                validate_opaque_id(session_id, "automation session id")
            }
            #[cfg(feature = "dev-automation")]
            Self::DevHoldTestbed {
                session_id,
                duration_ms,
            } => {
                validate_opaque_id(session_id, "automation session id")?;
                if !(1..=30_000).contains(duration_ms) {
                    return Err(ProtocolError::new(
                        LocalErrorCode::InvalidArgument,
                        "testbed hold duration must be between 1 and 30000 ms",
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[cfg(feature = "dev-automation")]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "target", rename_all = "snake_case", deny_unknown_fields)]
pub enum AutomationTarget {
    TestbedNormal {},
    TestbedHigh {},
    LiveGame { profile_id: String },
}

#[cfg(feature = "dev-automation")]
impl AutomationTarget {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::TestbedNormal {} | Self::TestbedHigh {} => Ok(()),
            Self::LiveGame { profile_id } => validate_profile_id(profile_id),
        }
    }
}

#[cfg(feature = "dev-automation")]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AutomationCapability {
    CaptureScreenshot,
    PulseTestAction,
    HoldTestAction,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalResponse {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub request_id: String,
    pub result: LocalResult,
}

impl LocalResponse {
    pub fn ok(request_id: impl Into<String>, payload: LocalPayload) -> Self {
        Self {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            request_id: request_id.into(),
            result: LocalResult::Ok { payload },
        }
    }

    pub fn error(request_id: impl Into<String>, error: ProtocolError) -> Self {
        Self {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            request_id: request_id.into(),
            result: LocalResult::Error {
                code: error.code,
                message: error.message,
                retryable: error.retryable,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalResult {
    Ok {
        payload: LocalPayload,
    },
    Error {
        code: LocalErrorCode,
        message: String,
        retryable: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalPayload {
    Hello {
        server_version: String,
        protocol_major: u16,
        protocol_minor: u16,
    },
    Status {
        lifecycle: AgentLifecycle,
        active_profile_id: Option<String>,
        target_locked: bool,
        capture_active: bool,
    },
    Doctor {
        checks: Vec<DoctorCheck>,
    },
    Profiles {
        profile_ids: Vec<String>,
    },
    Targets {
        profile_id: String,
        targets: Vec<TargetSummary>,
    },
    Target {
        profile_id: String,
        target_id: String,
        title: String,
        process_name: String,
        foreground: Option<bool>,
        capturable: Option<bool>,
    },
    Diagnostics {
        agent_version: String,
        build_commit: String,
        protocol: String,
        control_connected: bool,
        audit_enabled: bool,
    },
    SuiteStatus {
        installation: InstallationState,
        guardian: GuardianState,
        control_mode: ControlMode,
        update: UpdateState,
        autostart: AutostartState,
        can_request_update: bool,
    },
    Preview {
        mime_type: String,
        data_base64: String,
        width: u32,
        height: u32,
    },
    Maintenance {
        action: String,
        accepted: bool,
    },
    Released {
        holds: u32,
        state: String,
    },
    #[cfg(feature = "dev-automation")]
    DevStatus {
        provisioned_build_id: Option<String>,
        build_commit: String,
        active_session_id: Option<String>,
        expires_at_unix_ms: Option<u64>,
    },
    #[cfg(feature = "dev-automation")]
    AutomationSession {
        session_id: String,
        expires_at_unix_ms: u64,
    },
    #[cfg(feature = "dev-automation")]
    TestbedAction {
        session_id: String,
        action: String,
        accepted: bool,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentLifecycle {
    Starting,
    Connected,
    Disconnected,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallationState {
    Healthy,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuardianState {
    Installed,
    Missing,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlMode {
    Unknown,
    DryRun,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    Idle,
    Quiesced,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutostartState {
    Enabled,
    Disabled,
    Missing,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DoctorCheck {
    pub component: String,
    pub status: CheckStatus,
    pub summary: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Warning,
    Error,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetSummary {
    pub target_id: String,
    pub title: String,
    pub process_name: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LocalErrorCode {
    InvalidArgument,
    ProtocolViolation,
    ProtocolVersionMismatch,
    MessageTooLarge,
    ReplayDetected,
    PermissionDenied,
    AgentUnavailable,
    TargetUnavailable,
    OperationFailed,
    UnsupportedCapability,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{code:?}: {message}")]
pub struct ProtocolError {
    pub code: LocalErrorCode,
    pub message: String,
    pub retryable: bool,
    pub request_id: Option<String>,
}

impl ProtocolError {
    pub fn new(code: LocalErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: false,
            request_id: None,
        }
    }

    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    pub fn with_request_id(mut self, request_id: Option<String>) -> Self {
        self.request_id = request_id;
        self
    }
}

pub fn encode_request(request: &LocalRequest) -> Result<Vec<u8>, ProtocolError> {
    request.validate()?;
    encode(request, MAX_MESSAGE_BYTES)
}

pub fn decode_request(bytes: &[u8]) -> Result<LocalRequest, ProtocolError> {
    check_message_size(bytes)?;
    match serde_json::from_slice::<LocalRequest>(bytes) {
        Ok(request) => {
            request.validate()?;
            Ok(request)
        }
        Err(error) => {
            let value = serde_json::from_slice::<Value>(bytes).ok();
            let request_id = value
                .as_ref()
                .and_then(|value| value.get("request_id"))
                .and_then(Value::as_str)
                .filter(|value| value.len() <= 64)
                .map(str::to_owned);
            let is_dev = value
                .as_ref()
                .and_then(|value| value.get("command"))
                .and_then(Value::as_object)
                .and_then(|command| command.get("command"))
                .and_then(Value::as_str)
                .is_some_and(|command| command.starts_with("dev_"));
            let code = if is_dev {
                LocalErrorCode::UnsupportedCapability
            } else {
                LocalErrorCode::ProtocolViolation
            };
            Err(
                ProtocolError::new(code, format!("invalid local request: {error}"))
                    .with_request_id(request_id),
            )
        }
    }
}

pub fn encode_response(response: &LocalResponse) -> Result<Vec<u8>, ProtocolError> {
    encode(response, MAX_RESPONSE_BYTES)
}

pub fn decode_response(bytes: &[u8]) -> Result<LocalResponse, ProtocolError> {
    check_size(bytes, MAX_RESPONSE_BYTES, "local response exceeds 2 MiB")?;
    serde_json::from_slice(bytes).map_err(|error| {
        ProtocolError::new(
            LocalErrorCode::ProtocolViolation,
            format!("invalid local response: {error}"),
        )
    })
}

fn encode<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, ProtocolError> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        ProtocolError::new(
            LocalErrorCode::ProtocolViolation,
            format!("cannot encode local protocol message: {error}"),
        )
    })?;
    check_size(
        &bytes,
        maximum,
        "local protocol message exceeds its size limit",
    )?;
    Ok(bytes)
}

fn check_message_size(bytes: &[u8]) -> Result<(), ProtocolError> {
    check_size(bytes, MAX_MESSAGE_BYTES, "local request exceeds 64 KiB")
}

fn check_size(bytes: &[u8], maximum: usize, message: &str) -> Result<(), ProtocolError> {
    if bytes.len() > maximum {
        return Err(ProtocolError::new(LocalErrorCode::MessageTooLarge, message));
    }
    Ok(())
}

#[derive(Default)]
pub struct ReplayGuard {
    seen: HashMap<String, Instant>,
}

impl ReplayGuard {
    pub fn accept(&mut self, nonce: &str, now: Instant) -> Result<(), ProtocolError> {
        self.accept_with_capacity(nonce, now, MAX_NONCE_ENTRIES)
    }

    pub fn accept_with_capacity(
        &mut self,
        nonce: &str,
        now: Instant,
        capacity: usize,
    ) -> Result<(), ProtocolError> {
        self.seen
            .retain(|_, accepted_at| now.saturating_duration_since(*accepted_at) < REPLAY_WINDOW);
        if self.seen.contains_key(nonce) {
            return Err(ProtocolError::new(
                LocalErrorCode::ReplayDetected,
                "request nonce was already accepted",
            ));
        }
        if self.seen.len() >= capacity.min(MAX_NONCE_ENTRIES) {
            return Err(ProtocolError::new(
                LocalErrorCode::OperationFailed,
                "nonce replay cache is at capacity",
            )
            .retryable(true));
        }
        self.seen.insert(nonce.to_owned(), now);
        Ok(())
    }
}

pub fn random_nonce() -> Result<String, ProtocolError> {
    let mut bytes = [0_u8; 32];
    fill_random(&mut bytes)?;
    Ok(hex(&bytes))
}

pub fn new_request_id() -> Result<String, ProtocolError> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut seed = [0_u8; 32];
    fill_random(&mut seed)?;
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let digest = Sha256::new()
        .chain_update(seed)
        .chain_update(counter.to_le_bytes())
        .chain_update(now.to_le_bytes())
        .finalize();
    Ok(format!("req-{}", &hex(&digest)[..32]))
}

fn fill_random(bytes: &mut [u8]) -> Result<(), ProtocolError> {
    #[cfg(unix)]
    {
        File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(bytes))
            .map_err(|error| {
                ProtocolError::new(
                    LocalErrorCode::OperationFailed,
                    format!("OS randomness unavailable: {error}"),
                )
            })
    }
    #[cfg(windows)]
    {
        windows_random(bytes)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = bytes;
        Err(ProtocolError::new(
            LocalErrorCode::UnsupportedCapability,
            "OS randomness is unsupported on this platform",
        ))
    }
}

#[cfg(windows)]
fn windows_random(bytes: &mut [u8]) -> Result<(), ProtocolError> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut core::ffi::c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;
    let length = u32::try_from(bytes.len()).map_err(|_| {
        ProtocolError::new(
            LocalErrorCode::OperationFailed,
            "random request is too large",
        )
    })?;
    // SAFETY: the OS writes exactly `length` bytes into the live mutable slice.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(ProtocolError::new(
            LocalErrorCode::OperationFailed,
            format!("BCryptGenRandom failed with NTSTATUS {status:#x}"),
        ));
    }
    Ok(())
}

fn validate_request_id(value: &str) -> Result<(), ProtocolError> {
    let valid = (8..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    if !valid {
        return Err(ProtocolError::new(
            LocalErrorCode::InvalidArgument,
            "request id is invalid",
        ));
    }
    Ok(())
}

fn validate_nonce(value: &str) -> Result<(), ProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolError::new(
            LocalErrorCode::InvalidArgument,
            "nonce must be 32 bytes encoded as lowercase hex",
        ));
    }
    Ok(())
}

fn validate_profile_id(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(ProtocolError::new(
            LocalErrorCode::InvalidArgument,
            "profile id is invalid",
        ));
    }
    Ok(())
}

fn validate_opaque_id(value: &str, label: &str) -> Result<(), ProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolError::new(
            LocalErrorCode::InvalidArgument,
            format!("{label} is invalid"),
        ));
    }
    Ok(())
}

fn validate_label(value: &str, label: &str, maximum: usize) -> Result<(), ProtocolError> {
    if value.trim().is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b" ._+-".contains(&byte))
    {
        return Err(ProtocolError::new(
            LocalErrorCode::InvalidArgument,
            format!("{label} is invalid"),
        ));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(command: LocalCommand) -> LocalRequest {
        LocalRequest::new("req-0123456789abcdef".into(), "01".repeat(32), command)
    }

    #[test]
    fn strict_domain_request_rejects_unknown_fields_and_methods() {
        let arbitrary = br#"{"protocol_major":1,"protocol_minor":0,"request_id":"req-0123456789abcdef","nonce":"0101010101010101010101010101010101010101010101010101010101010101","command":{"command":"invoke","method":"shell","json":{}}}"#;
        assert_eq!(
            decode_request(arbitrary).unwrap_err().code,
            LocalErrorCode::ProtocolViolation
        );

        let mut value = serde_json::to_value(request(LocalCommand::Status {})).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), true.into());
        assert_eq!(
            decode_request(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .code,
            LocalErrorCode::ProtocolViolation
        );
    }

    #[test]
    #[cfg(not(feature = "dev-automation"))]
    fn production_parser_classifies_dev_messages_without_linking_dev_handlers() {
        let probe = br#"{"protocol_major":1,"protocol_minor":0,"request_id":"req-0123456789abcdef","nonce":"0101010101010101010101010101010101010101010101010101010101010101","command":{"command":"dev_start_automation"}}"#;
        assert_eq!(
            decode_request(probe).unwrap_err().code,
            LocalErrorCode::UnsupportedCapability
        );
    }

    #[test]
    #[cfg(feature = "dev-automation")]
    fn dev_protocol_has_fixed_testbed_actions_but_no_remote_live_arm_creation() {
        let request = request(LocalCommand::DevPulseTestbed {
            session_id: "ab".repeat(32),
        });
        assert!(encode_request(&request).is_ok());
        let remote_arm = br#"{"protocol_major":1,"protocol_minor":0,"request_id":"req-0123456789abcdef","nonce":"0101010101010101010101010101010101010101010101010101010101010101","command":{"command":"dev_create_live_game_arm","profile_id":"genshin-impact"}}"#;
        assert_eq!(
            decode_request(remote_arm).unwrap_err().code,
            LocalErrorCode::UnsupportedCapability
        );
    }

    #[test]
    fn replay_and_message_size_fail_closed() {
        let mut guard = ReplayGuard::default();
        let now = Instant::now();
        guard.accept(&"ab".repeat(32), now).unwrap();
        assert_eq!(
            guard.accept(&"ab".repeat(32), now).unwrap_err().code,
            LocalErrorCode::ReplayDetected
        );
        assert_eq!(
            decode_request(&vec![b' '; MAX_MESSAGE_BYTES + 1])
                .unwrap_err()
                .code,
            LocalErrorCode::MessageTooLarge
        );
    }

    #[test]
    fn replay_capacity_can_reserve_entries_without_weakening_duplicate_detection() {
        let mut guard = ReplayGuard::default();
        let now = Instant::now();
        guard.accept_with_capacity("first", now, 1).unwrap();
        assert_eq!(
            guard
                .accept_with_capacity("first", now, 1)
                .unwrap_err()
                .code,
            LocalErrorCode::ReplayDetected
        );
        let capacity = guard.accept_with_capacity("second", now, 1).unwrap_err();
        assert_eq!(capacity.code, LocalErrorCode::OperationFailed);
        assert!(capacity.retryable);
    }

    #[test]
    fn bounded_preview_response_does_not_expand_request_limit() {
        assert_eq!(
            encode_request(&request(LocalCommand::CapturePreview { quality: 0 }))
                .unwrap_err()
                .code,
            LocalErrorCode::InvalidArgument
        );
        let response = LocalResponse::ok(
            "req-0123456789abcdef",
            LocalPayload::Preview {
                mime_type: "image/jpeg".into(),
                data_base64: "a".repeat(MAX_MESSAGE_BYTES),
                width: 640,
                height: 360,
            },
        );
        assert!(encode_response(&response).is_ok());
        assert!(decode_request(&vec![b' '; MAX_MESSAGE_BYTES + 1]).is_err());
    }

    #[test]
    fn command_surface_has_no_raw_execution_coordinates_or_handles() {
        let wire = encode_request(&request(LocalCommand::SelectTarget {
            profile_id: "fairypam-test-window".into(),
            target_id: "ab".repeat(32),
        }))
        .unwrap();
        let wire = String::from_utf8(wire).unwrap();
        for forbidden in ["method", "shell", "path", "hwnd", "keycode", "coordinate"] {
            assert!(!wire.contains(forbidden));
        }
    }

    #[test]
    fn maintenance_command_is_a_fixed_domain_enum() {
        let wire = encode_request(&request(LocalCommand::SetAutostart { enabled: true })).unwrap();
        assert_eq!(
            decode_request(&wire).unwrap().command,
            LocalCommand::SetAutostart { enabled: true }
        );
    }
}
