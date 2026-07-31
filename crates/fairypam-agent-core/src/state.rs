use std::time::Instant;

use crate::platform::{AuthorizationState, LocalAuthorization};
use crate::profile::VerifiedProfile;
use crate::target::{IntegrityLevel, TargetBinding, TargetSnapshot};
use crate::AgentError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentState {
    Starting,
    Disconnected,
    ConnectedIdle,
    ProfileLoaded,
    TargetLocked,
    PreflightPassed,
    DryRun,
    Armed { expires_at: Instant },
    Controlling,
    RecoveringLocal,
    EmergencyStopped,
    FailedSafe,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    StopControl,
    ControlDisconnected,
    FocusLost,
    LeaseExpired,
    GuardianUnhealthy,
    EmergencyStop,
    FailSafe,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    OpenInputGate,
    CloseInputGate,
    ReleaseAll,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Machine {
    current: AgentState,
    control_connected: bool,
    active_profile: Option<VerifiedProfile>,
    active_binding: Option<TargetBinding>,
    active_session: Option<SessionIdentity>,
    authorization_expires_at: Option<Instant>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionIdentity {
    pub agent_id: String,
    pub session_id: String,
    pub generation: u64,
}

/// Opaque proof that the Core state machine currently permits remote input.
///
/// The private field intentionally prevents downstream crates from fabricating
/// this capability from independent booleans.
#[derive(Debug)]
pub struct InputCapability<'a> {
    machine: &'a Machine,
    session: &'a SessionIdentity,
    binding: &'a TargetBinding,
    profile: &'a VerifiedProfile,
    expires_at: Instant,
}

impl InputCapability<'_> {
    pub fn is_valid_for(&self, now: Instant, session: &SessionIdentity) -> bool {
        self.expires_at > now
            && self.machine.current == AgentState::Controlling
            && self.machine.active_session.as_ref() == Some(self.session)
            && self.machine.active_binding.as_ref() == Some(self.binding)
            && self.session == session
    }

    pub fn is_valid_for_target(
        &self,
        now: Instant,
        session: &SessionIdentity,
        binding: &TargetBinding,
    ) -> bool {
        self.is_valid_for(now, session) && self.binding == binding
    }

    pub fn is_valid_for_target_and_profile(
        &self,
        now: Instant,
        session: &SessionIdentity,
        binding: &TargetBinding,
        profile_content_sha256: &str,
    ) -> bool {
        self.is_valid_for_target(now, session, binding)
            && self.profile.content_sha256() == profile_content_sha256
    }
}

impl Default for Machine {
    fn default() -> Self {
        Self::new()
    }
}

impl Machine {
    pub const fn new() -> Self {
        Self {
            current: AgentState::Starting,
            control_connected: false,
            active_profile: None,
            active_binding: None,
            active_session: None,
            authorization_expires_at: None,
        }
    }

    pub const fn current(&self) -> &AgentState {
        &self.current
    }

    pub fn issue_input_capability<'a>(
        &'a self,
        now: Instant,
        snapshot: &TargetSnapshot,
        remote_session_valid: bool,
    ) -> Result<InputCapability<'a>, AgentError> {
        let authorization_expires_at = self.authorization_expires_at;
        let session = self.active_session.as_ref();
        let binding = self.active_binding.as_ref();
        let profile = self.active_profile.as_ref();
        let permitted = self.current == AgentState::Controlling
            && remote_session_valid
            && authorization_expires_at.is_some_and(|expires_at| expires_at > now)
            && profile.is_some()
            && binding.is_some_and(|binding| binding == &snapshot.binding)
            && session.is_some()
            && snapshot.foreground
            && !snapshot.minimized
            && snapshot.capturable;
        if !permitted {
            return Err(AgentError::new(
                "input.capability_denied",
                "input requires Controlling state, the current target, foreground focus, capture readiness, and a valid remote session",
            ));
        }
        Ok(InputCapability {
            machine: self,
            session: session.expect("checked above"),
            binding: binding.expect("checked above"),
            profile: profile.expect("checked above"),
            expires_at: authorization_expires_at.expect("checked above"),
        })
    }

    pub fn start_completed(&mut self) -> Result<Vec<Effect>, AgentError> {
        self.require_state(&AgentState::Starting, "start_completed")?;
        self.current = AgentState::Disconnected;
        Ok(Vec::new())
    }

    pub fn control_connected(
        &mut self,
        session: SessionIdentity,
    ) -> Result<Vec<Effect>, AgentError> {
        self.require_state(&AgentState::Disconnected, "control_connected")?;
        if session.agent_id.is_empty() || session.session_id.is_empty() || session.generation == 0 {
            return Err(AgentError::new(
                "session.invalid",
                "control session identity must be complete",
            ));
        }
        self.control_connected = true;
        self.active_session = Some(session);
        self.current = AgentState::ConnectedIdle;
        Ok(Vec::new())
    }

    pub fn activate_profile(
        &mut self,
        profile: &VerifiedProfile,
    ) -> Result<Vec<Effect>, AgentError> {
        self.require_state(&AgentState::ConnectedIdle, "activate_profile")?;
        self.active_profile = Some(profile.clone());
        self.active_binding = None;
        self.current = AgentState::ProfileLoaded;
        Ok(Vec::new())
    }

    pub fn lock_target(&mut self, binding: TargetBinding) -> Result<Vec<Effect>, AgentError> {
        self.require_state(&AgentState::ProfileLoaded, "lock_target")?;
        let profile = self.active_profile.as_ref().ok_or_else(|| {
            AgentError::new(
                "state.verified_profile_required",
                "target lock requires an active VerifiedProfile",
            )
        })?;
        if !binding_matches_profile(&binding, profile) {
            return Err(AgentError::new(
                "target.profile_mismatch",
                "target binding does not satisfy the active signed Profile",
            ));
        }
        self.active_binding = Some(binding);
        self.current = AgentState::TargetLocked;
        Ok(Vec::new())
    }

    pub fn preflight_passed(
        &mut self,
        snapshot: TargetSnapshot,
    ) -> Result<Vec<Effect>, AgentError> {
        self.require_state(&AgentState::TargetLocked, "preflight_passed")?;
        let binding = self.active_binding.as_ref().ok_or_else(|| {
            AgentError::new(
                "state.target_binding_required",
                "preflight requires the active target binding",
            )
        })?;
        if snapshot.binding != *binding
            || !snapshot.foreground
            || snapshot.minimized
            || !snapshot.capturable
        {
            return Err(AgentError::new(
                "target.preflight_failed",
                "target identity, focus, visibility, or capture preflight failed",
            ));
        }
        self.current = AgentState::PreflightPassed;
        Ok(Vec::new())
    }

    pub fn enter_dry_run(&mut self) -> Result<Vec<Effect>, AgentError> {
        self.require_state(&AgentState::PreflightPassed, "enter_dry_run")?;
        if self.active_profile.is_none() || self.active_binding.is_none() {
            return Err(AgentError::new(
                "state.preflight_proof_required",
                "DryRun requires verified Profile and target preflight proofs",
            ));
        }
        self.current = AgentState::DryRun;
        Ok(Vec::new())
    }

    pub fn request_arm(
        &mut self,
        authorization: &dyn LocalAuthorization,
        now: Instant,
        requested_expires_at: Instant,
    ) -> Result<Vec<Effect>, AgentError> {
        if self.current != AgentState::DryRun
            || !self.control_connected
            || self.active_profile.is_none()
            || self.active_binding.is_none()
        {
            return Err(invalid_transition(&self.current, "request_arm"));
        }
        let expires_at = authorized_expiry(authorization, now)?.min(requested_expires_at);
        if expires_at <= now {
            return Err(AgentError::new(
                "authorization.expired",
                "local authorization is already expired",
            ));
        }
        self.current = AgentState::Armed { expires_at };
        Ok(Vec::new())
    }

    pub fn begin_control(&mut self, now: Instant) -> Result<Vec<Effect>, AgentError> {
        let AgentState::Armed { expires_at } = self.current else {
            return Err(invalid_transition(&self.current, "begin_control"));
        };
        if expires_at <= now {
            self.current = AgentState::DryRun;
            return Err(AgentError::new(
                "authorization.expired",
                "arming authorization expired before control began",
            ));
        }
        self.authorization_expires_at = Some(expires_at);
        self.current = AgentState::Controlling;
        Ok(vec![Effect::OpenInputGate])
    }

    pub fn renew_control_authorization(
        &mut self,
        authorization: &dyn LocalAuthorization,
        now: Instant,
        requested_expires_at: Instant,
    ) -> Result<(), AgentError> {
        self.require_state(&AgentState::Controlling, "renew_control_authorization")?;
        let expires_at = authorized_expiry(authorization, now)?.min(requested_expires_at);
        if expires_at <= now {
            return Err(AgentError::new(
                "authorization.expired",
                "control authorization renewal is already expired",
            ));
        }
        self.authorization_expires_at = Some(expires_at);
        Ok(())
    }

    pub fn local_reset(
        &mut self,
        authorization: &dyn LocalAuthorization,
        now: Instant,
    ) -> Result<Vec<Effect>, AgentError> {
        self.require_state(&AgentState::EmergencyStopped, "local_reset")?;
        authorized_expiry(authorization, now)?;
        self.clear_session_context();
        self.current = if self.control_connected {
            AgentState::ConnectedIdle
        } else {
            AgentState::Disconnected
        };
        Ok(Vec::new())
    }

    pub fn apply(&mut self, event: Event) -> Result<Vec<Effect>, AgentError> {
        match event {
            Event::ControlDisconnected => {
                self.control_connected = false;
                self.clear_session_context();
                if !matches!(
                    self.current,
                    AgentState::EmergencyStopped | AgentState::FailedSafe
                ) {
                    self.current = AgentState::Disconnected;
                }
                Ok(safety_effects())
            }
            Event::EmergencyStop if self.current == AgentState::FailedSafe => Ok(safety_effects()),
            Event::EmergencyStop => {
                self.authorization_expires_at = None;
                self.current = AgentState::EmergencyStopped;
                Ok(safety_effects())
            }
            Event::FailSafe => {
                self.clear_session_context();
                self.current = AgentState::FailedSafe;
                Ok(safety_effects())
            }
            Event::FocusLost | Event::LeaseExpired | Event::GuardianUnhealthy
                if matches!(
                    self.current,
                    AgentState::Armed { .. } | AgentState::Controlling
                ) =>
            {
                self.authorization_expires_at = None;
                self.current = AgentState::DryRun;
                Ok(safety_effects())
            }
            Event::StopControl if self.current == AgentState::Controlling => {
                self.authorization_expires_at = None;
                self.current = AgentState::DryRun;
                Ok(safety_effects())
            }
            other => Err(invalid_transition(&self.current, event_name(&other))),
        }
    }

    fn require_state(&self, expected: &AgentState, operation: &str) -> Result<(), AgentError> {
        if &self.current != expected {
            return Err(invalid_transition(&self.current, operation));
        }
        Ok(())
    }

    fn clear_session_context(&mut self) {
        self.active_profile = None;
        self.active_binding = None;
        self.active_session = None;
        self.authorization_expires_at = None;
    }
}

fn binding_matches_profile(binding: &TargetBinding, profile: &VerifiedProfile) -> bool {
    let profile = profile.profile();
    let target = &profile.target;
    binding.profile_id == profile.id
        && binding.profile_version == profile.version
        && contains_ignore_ascii_case(&target.process_names, &binding.process_name)
        && contains_ignore_ascii_case(&target.process_path_sha256, &binding.process_path_sha256)
        && contains_ignore_ascii_case(&target.window_classes, &binding.window_class)
        && target
            .title_patterns
            .iter()
            .any(|pattern| wildcard_match(pattern, &binding.window_title))
        && binding.client_rect.width >= target.minimum_client_width
        && binding.client_rect.height >= target.minimum_client_height
        && binding.dpi >= target.minimum_dpi
        && (!target.require_elevated
            || matches!(
                binding.integrity,
                IntegrityLevel::High | IntegrityLevel::System
            ))
}

fn contains_ignore_ascii_case(values: &[String], candidate: &str) -> bool {
    values
        .iter()
        .any(|value| value.eq_ignore_ascii_case(candidate))
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let value = value.to_lowercase();
    let parts: Vec<_> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }
    let mut remaining = value.as_str();
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let Some(position) = remaining.find(part) else {
            return false;
        };
        if index == 0 && !pattern.starts_with('*') && position != 0 {
            return false;
        }
        remaining = &remaining[position + part.len()..];
    }
    pattern.ends_with('*') || remaining.is_empty()
}

fn authorized_expiry(
    authorization: &dyn LocalAuthorization,
    now: Instant,
) -> Result<Instant, AgentError> {
    let AuthorizationState::Granted { expires_at } = authorization.current(now) else {
        return Err(AgentError::new(
            "authorization.denied",
            "local authorization does not permit this operation",
        ));
    };
    if expires_at <= now {
        return Err(AgentError::new(
            "authorization.expired",
            "local authorization is already expired",
        ));
    }
    Ok(expires_at)
}

fn safety_effects() -> Vec<Effect> {
    vec![Effect::CloseInputGate, Effect::ReleaseAll]
}

fn invalid_transition(state: &AgentState, event: &str) -> AgentError {
    AgentError::new(
        "state.invalid_transition",
        format!("operation {event} is invalid from {state:?}"),
    )
}

const fn event_name(event: &Event) -> &'static str {
    match event {
        Event::StopControl => "stop_control",
        Event::ControlDisconnected => "control_disconnected",
        Event::FocusLost => "focus_lost",
        Event::LeaseExpired => "lease_expired",
        Event::GuardianUnhealthy => "guardian_unhealthy",
        Event::EmergencyStop => "emergency_stop",
        Event::FailSafe => "fail_safe",
    }
}

#[cfg(test)]
mod title_pattern_tests {
    use super::wildcard_match;

    #[test]
    fn title_pattern_is_anchored_and_supports_unicode_wildcards() {
        assert!(wildcard_match("原神*", "原神 6.7"));
        assert!(!wildcard_match("原神*", "Launcher 原神"));
        assert!(!wildcard_match("*原神", "原神 Running"));
    }
}
