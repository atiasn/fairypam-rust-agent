use std::collections::BTreeSet;
use std::time::Instant;

use fairypam_agent_core::profile::VerifiedProfile;
use fairypam_agent_core::state::InputCapability;
pub use fairypam_agent_core::state::SessionIdentity as SessionKey;
use thiserror::Error;

use crate::{
    ActionId, ActionMap, InputPlatform, ReleaseReason, ResolvedAction, SemanticMouseButton,
};

#[derive(Clone, Debug)]
pub struct InputLease {
    pub session: SessionKey,
    pub sequence: u64,
    pub expires_at: Instant,
    pub desired_holds: BTreeSet<ActionId>,
}

pub struct InputPermit<'a> {
    capability: InputCapability<'a>,
}

impl<'a> InputPermit<'a> {
    pub const fn from_capability(capability: InputCapability<'a>) -> Self {
        Self { capability }
    }

    fn is_valid_for(&self, now: Instant, session: &SessionKey) -> bool {
        self.capability.is_valid_for(now, session)
    }

    pub fn is_valid_for_target(
        &self,
        now: Instant,
        session: &SessionKey,
        binding: &fairypam_agent_core::target::TargetBinding,
    ) -> bool {
        self.capability.is_valid_for_target(now, session, binding)
    }

    pub fn is_valid_for_target_and_profile(
        &self,
        now: Instant,
        session: &SessionKey,
        binding: &fairypam_agent_core::target::TargetBinding,
        profile_content_sha256: &str,
    ) -> bool {
        self.capability.is_valid_for_target_and_profile(
            now,
            session,
            binding,
            profile_content_sha256,
        )
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct SafetyError {
    code: &'static str,
    message: String,
}

impl SafetyError {
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

pub trait GuardianClient: Send {
    fn register_intent(
        &mut self,
        sequence: u64,
        holds: &BTreeSet<ActionId>,
    ) -> Result<(), SafetyError>;
    fn commit_holds(
        &mut self,
        sequence: u64,
        holds: &BTreeSet<ActionId>,
    ) -> Result<(), SafetyError>;
    fn heartbeat(&mut self, sequence: u64) -> Result<(), SafetyError>;
    fn release_all(&mut self, reason: ReleaseReason) -> Result<(), SafetyError>;
}

pub struct LeaseExecutor<P, G> {
    actions: ActionMap,
    platform: P,
    guardian: G,
    active_session: Option<SessionKey>,
    sequence: u64,
    expires_at: Option<Instant>,
    held_actions: BTreeSet<ActionId>,
    guarded_actions: BTreeSet<ActionId>,
    input_gate_open: bool,
    last_release_reason: Option<ReleaseReason>,
}

impl<P: InputPlatform, G: GuardianClient> LeaseExecutor<P, G> {
    pub fn new(profile: &VerifiedProfile, platform: P, guardian: G) -> Result<Self, SafetyError> {
        Ok(Self::with_action_map(
            ActionMap::from_verified_profile(profile)?,
            platform,
            guardian,
        ))
    }

    fn with_action_map(actions: ActionMap, platform: P, guardian: G) -> Self {
        Self {
            actions,
            platform,
            guardian,
            active_session: None,
            sequence: 0,
            expires_at: None,
            held_actions: BTreeSet::new(),
            guarded_actions: BTreeSet::new(),
            input_gate_open: false,
            last_release_reason: None,
        }
    }

    pub fn apply_lease(
        &mut self,
        lease: InputLease,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        let result = self.apply_lease_inner(lease, permit, now);
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                let reason = if error.code() == "input.lease_expired" {
                    ReleaseReason::LeaseExpired
                } else if error.code().starts_with("guardian.") {
                    ReleaseReason::GuardianFailure
                } else if error.code().starts_with("input.platform")
                    || error.code() == "input.send_failed"
                {
                    ReleaseReason::PlatformFailure
                } else {
                    ReleaseReason::EmergencyStop
                };
                Err(self.fail_closed(reason, error))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_physical_frame(
        &mut self,
        session: SessionKey,
        sequence: u64,
        expires_at: Instant,
        keys: &[(u16, bool)],
        buttons: &[SemanticMouseButton],
        wheel_delta: i32,
        wheel_point: Option<(u32, u32)>,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<bool, SafetyError> {
        let (desired_holds, pulse_actions) = self.actions.physical_frame_actions(keys, buttons)?;
        if pulse_actions.len() > 1
            || (!pulse_actions.is_empty()
                && (!desired_holds.is_empty() || wheel_delta != 0 || wheel_point.is_some()))
        {
            return Err(SafetyError::new(
                "input.frame_invalid",
                "a physical pulse must be the only side effect in its input frame",
            ));
        }
        if wheel_delta != 0
            && !self.actions.wheel_limit().is_some_and(|limit| {
                wheel_delta.unsigned_abs() <= limit as u32 && wheel_delta % 120 == 0
            })
        {
            return Err(SafetyError::new(
                "input.wheel_not_allowed",
                "wheel delta is outside the verified Profile policy",
            ));
        }
        if wheel_point.is_some_and(|(x_ppm, y_ppm)| {
            wheel_delta == 0 || x_ppm > 1_000_000 || y_ppm > 1_000_000
        }) {
            return Err(SafetyError::new(
                "input.wheel_point_invalid",
                "wheel point must be normalized and accompany a wheel delta",
            ));
        }
        let holds_active = !desired_holds.is_empty();
        self.apply_lease(
            InputLease {
                session: session.clone(),
                sequence,
                expires_at,
                desired_holds,
            },
            permit,
            now,
        )?;
        if let Some(action) = pulse_actions.first() {
            self.execute_pulse(action, &session, permit, now)?;
        }
        if wheel_delta == 0 {
            return Ok(holds_active);
        }
        match wheel_point {
            Some((x_ppm, y_ppm)) => {
                self.platform
                    .wheel_at_client_point(x_ppm, y_ppm, wheel_delta, expires_at)
            }
            None => self.platform.wheel(wheel_delta, expires_at),
        }
        .map(|()| holds_active)
        .map_err(|error| {
            let reason = if error.code() == "input.lease_expired" {
                ReleaseReason::LeaseExpired
            } else {
                ReleaseReason::PlatformFailure
            };
            self.fail_closed(reason, error)
        })
    }

    pub fn arm_guarded_physical_frame(
        &mut self,
        session: SessionKey,
        sequence: u64,
        expires_at: Instant,
        keys: &[(u16, bool)],
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        let result =
            self.arm_guarded_physical_frame_inner(session, sequence, expires_at, keys, permit, now);
        result.map_err(|error| self.fail_closed(ReleaseReason::EmergencyStop, error))
    }

    fn arm_guarded_physical_frame_inner(
        &mut self,
        session: SessionKey,
        sequence: u64,
        expires_at: Instant,
        keys: &[(u16, bool)],
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        if !permit.is_valid_for(now, &session) || expires_at <= now {
            return Err(SafetyError::new(
                "input.permit_invalid",
                "guarded input requires a current permit and lease",
            ));
        }
        if self
            .active_session
            .as_ref()
            .is_some_and(|active| active != &session)
        {
            self.release_all(ReleaseReason::SessionChanged)?;
            self.sequence = 0;
        }
        if sequence == 0
            || sequence <= self.sequence
            || self.input_gate_open
            || !self.held_actions.is_empty()
            || !self.guarded_actions.is_empty()
        {
            return Err(SafetyError::new(
                "input.sequence_invalid",
                "guarded input must arm once with a new sequence",
            ));
        }
        let guarded_actions = self.actions.physical_actions(keys, &[])?;
        if guarded_actions.is_empty()
            || guarded_actions.iter().any(|action| {
                !matches!(self.hold_action(action), Ok(ResolvedAction::HoldKey { .. }))
            })
        {
            return Err(SafetyError::new(
                "input.action_kind_invalid",
                "guarded input accepts physical hold keys only",
            ));
        }
        self.platform.validate_before_input()?;
        self.guardian.register_intent(sequence, &guarded_actions)?;
        self.guardian.commit_holds(sequence, &guarded_actions)?;
        self.active_session = Some(session);
        self.sequence = sequence;
        self.expires_at = Some(expires_at);
        self.held_actions.clear();
        self.guarded_actions = guarded_actions;
        self.input_gate_open = true;
        Ok(())
    }

    pub fn renew_guarded_physical_frame(
        &mut self,
        session: &SessionKey,
        sequence: u64,
        expires_at: Instant,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        let result = (|| {
            self.require_guarded_gate(session, permit, now)?;
            if sequence <= self.sequence || expires_at <= now {
                return Err(SafetyError::new(
                    "input.sequence_invalid",
                    "guarded input renewal must advance its sequence and lease",
                ));
            }
            self.guardian.heartbeat(sequence)?;
            self.sequence = sequence;
            self.expires_at = Some(expires_at);
            Ok(())
        })();
        result.map_err(|error| self.fail_closed(ReleaseReason::GuardianFailure, error))
    }

    pub fn apply_guarded_physical_frame(
        &mut self,
        session: &SessionKey,
        keys: &[(u16, bool)],
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        let result = (|| {
            self.require_guarded_gate(session, permit, now)?;
            let desired = self.actions.physical_actions(keys, &[])?;
            if !desired.is_subset(&self.guarded_actions) {
                return Err(SafetyError::new(
                    "input.action_not_guarded",
                    "physical key is outside the committed Guardian release set",
                ));
            }
            let mut transitions = Vec::new();
            for action in self.held_actions.difference(&desired) {
                match self.hold_action(action)? {
                    ResolvedAction::HoldKey {
                        scan_code,
                        extended,
                    } => transitions.push((scan_code, extended, false)),
                    _ => unreachable!("guarded actions are physical hold keys"),
                }
            }
            for action in desired.difference(&self.held_actions) {
                match self.hold_action(action)? {
                    ResolvedAction::HoldKey {
                        scan_code,
                        extended,
                    } => transitions.push((scan_code, extended, true)),
                    _ => unreachable!("guarded actions are physical hold keys"),
                }
            }
            if !transitions.is_empty() {
                self.platform.apply_guarded_key_transitions(&transitions)?;
            }
            self.held_actions = desired;
            Ok(())
        })();
        result.map_err(|error| self.fail_closed(ReleaseReason::PlatformFailure, error))
    }

    fn apply_lease_inner(
        &mut self,
        lease: InputLease,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        if !permit.is_valid_for(now, &lease.session) {
            return Err(SafetyError::new(
                "input.permit_invalid",
                "the Core input capability is expired or does not match the current control session",
            ));
        }
        if lease.expires_at <= now {
            return Err(SafetyError::new(
                "input.lease_expired",
                "input lease is already expired",
            ));
        }
        if self
            .active_session
            .as_ref()
            .is_some_and(|session| session != &lease.session)
        {
            self.release_all(ReleaseReason::SessionChanged)?;
            self.sequence = 0;
        }
        if lease.sequence == 0 || lease.sequence <= self.sequence {
            return Err(SafetyError::new(
                "input.sequence_invalid",
                "input lease sequence must increase monotonically",
            ));
        }
        for action in &lease.desired_holds {
            self.hold_action(action)?;
        }
        self.platform.validate_before_input()?;
        self.guardian
            .register_intent(lease.sequence, &lease.desired_holds)?;

        let previous = self.held_actions.clone();
        self.held_actions.extend(lease.desired_holds.clone());
        self.apply_hold_difference(&previous, &lease.desired_holds)?;
        self.held_actions = lease.desired_holds.clone();
        self.guarded_actions.clear();
        self.guardian
            .commit_holds(lease.sequence, &lease.desired_holds)?;
        self.active_session = Some(lease.session);
        self.sequence = lease.sequence;
        self.expires_at = Some(lease.expires_at);
        self.input_gate_open = true;
        Ok(())
    }

    fn apply_hold_difference(
        &mut self,
        previous: &BTreeSet<ActionId>,
        desired: &BTreeSet<ActionId>,
    ) -> Result<(), SafetyError> {
        for action in previous.difference(desired) {
            match self.hold_action(action)? {
                ResolvedAction::HoldKey {
                    scan_code,
                    extended,
                }
                | ResolvedAction::PulseKey {
                    scan_code,
                    extended,
                } => {
                    self.platform.release_key(scan_code, extended)?;
                }
                ResolvedAction::ClientPointClick { button } => {
                    self.platform.release_mouse_button(button)?;
                }
                _ => unreachable!("hold_action rejects non-hold actions"),
            }
        }
        for action in desired.difference(previous) {
            match self.hold_action(action)? {
                ResolvedAction::HoldKey {
                    scan_code,
                    extended,
                }
                | ResolvedAction::PulseKey {
                    scan_code,
                    extended,
                } => {
                    self.platform.press_key(scan_code, extended)?;
                }
                ResolvedAction::ClientPointClick { button } => {
                    self.platform.press_mouse_button(button)?;
                }
                _ => unreachable!("hold_action rejects non-hold actions"),
            }
        }
        Ok(())
    }

    fn hold_action(&self, action: &ActionId) -> Result<ResolvedAction, SafetyError> {
        match self.actions.resolve(action)? {
            value @ (ResolvedAction::HoldKey { .. }
            | ResolvedAction::PulseKey { .. }
            | ResolvedAction::ClientPointClick { .. }) => Ok(value.clone()),
            _ => Err(SafetyError::new(
                "input.action_kind_invalid",
                "only physical hold actions may appear in a desired-state frame",
            )),
        }
    }

    pub fn tick(&mut self, now: Instant) -> Result<(), SafetyError> {
        if self.expires_at.is_some_and(|expires_at| now >= expires_at) {
            return self.release_all(ReleaseReason::LeaseExpired);
        }
        if self.input_gate_open {
            if let Err(error) = self.guardian.heartbeat(self.sequence) {
                let _ = self.release_all(ReleaseReason::GuardianFailure);
                return Err(error);
            }
        }
        Ok(())
    }

    pub fn release_all(&mut self, reason: ReleaseReason) -> Result<(), SafetyError> {
        self.input_gate_open = false;
        let mut first_error = None;
        if let Err(error) = self
            .platform
            .emergency_release(&self.actions.all_scan_codes())
        {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.guardian.release_all(reason) {
            first_error.get_or_insert(error);
        }
        if first_error.is_none() {
            self.held_actions.clear();
            self.guarded_actions.clear();
        }
        self.expires_at = None;
        self.last_release_reason = Some(reason);
        first_error.map_or(Ok(()), Err)
    }

    pub fn execute_pulse(
        &mut self,
        action: &ActionId,
        session: &SessionKey,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        let result = self.execute_pulse_inner(action, session, permit, now);
        result.map_err(|error| self.fail_closed(ReleaseReason::PlatformFailure, error))
    }

    fn execute_pulse_inner(
        &mut self,
        action: &ActionId,
        session: &SessionKey,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        self.require_open_gate(session, permit, now)?;
        match self.actions.resolve(action)? {
            ResolvedAction::PulseKey {
                scan_code,
                extended,
            } => self.platform.pulse_key(*scan_code, *extended),
            _ => Err(SafetyError::new(
                "input.action_kind_invalid",
                "action is not a pulse",
            )),
        }
    }

    pub fn execute_relative_mouse(
        &mut self,
        action: &ActionId,
        delta_x: i32,
        delta_y: i32,
        session: &SessionKey,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        let result =
            self.execute_relative_mouse_inner(action, delta_x, delta_y, session, permit, now);
        result.map_err(|error| self.fail_closed(ReleaseReason::PlatformFailure, error))
    }

    fn execute_relative_mouse_inner(
        &mut self,
        action: &ActionId,
        delta_x: i32,
        delta_y: i32,
        session: &SessionKey,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        self.require_open_gate(session, permit, now)?;
        match self.actions.resolve(action)? {
            ResolvedAction::RelativeMouse { maximum_delta }
                if delta_x.unsigned_abs() <= *maximum_delta as u32
                    && delta_y.unsigned_abs() <= *maximum_delta as u32 =>
            {
                self.platform.relative_mouse(delta_x, delta_y)
            }
            ResolvedAction::RelativeMouse { .. } => Err(SafetyError::new(
                "input.mouse_delta_exceeded",
                "relative mouse delta exceeds the signed profile limit",
            )),
            _ => Err(SafetyError::new(
                "input.action_kind_invalid",
                "action is not relative mouse input",
            )),
        }
    }

    pub fn execute_client_point(
        &mut self,
        button: SemanticMouseButton,
        x_ppm: u32,
        y_ppm: u32,
        session: &SessionKey,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        let action = self.actions.action_for_button(button)?;
        let result = self.execute_client_point_inner(&action, x_ppm, y_ppm, session, permit, now);
        result.map_err(|error| self.fail_closed(ReleaseReason::PlatformFailure, error))
    }

    fn execute_client_point_inner(
        &mut self,
        action: &ActionId,
        x_ppm: u32,
        y_ppm: u32,
        session: &SessionKey,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        self.require_open_gate(session, permit, now)?;
        if x_ppm > 1_000_000 || y_ppm > 1_000_000 {
            return Err(SafetyError::new(
                "input.client_point_invalid",
                "client point must be normalized to the target client area",
            ));
        }
        match self.actions.resolve(action)? {
            ResolvedAction::ClientPointClick { button } => {
                self.platform.client_point_click(*button, x_ppm, y_ppm)
            }
            _ => Err(SafetyError::new(
                "input.action_kind_invalid",
                "action is not a client point click",
            )),
        }
    }

    fn require_open_gate(
        &self,
        session: &SessionKey,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        if self.input_gate_open && permit.is_valid_for(now, session) {
            Ok(())
        } else {
            Err(SafetyError::new(
                "input.gate_closed",
                "input gate is closed",
            ))
        }
    }

    fn require_guarded_gate(
        &self,
        session: &SessionKey,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        if self.guarded_actions.is_empty()
            || self.active_session.as_ref() != Some(session)
            || self.expires_at.is_none()
            || self.expires_at.is_some_and(|expires_at| expires_at <= now)
        {
            return Err(SafetyError::new(
                "input.gate_closed",
                "guarded input gate is closed",
            ));
        }
        self.require_open_gate(session, permit, now)
    }

    fn fail_closed(&mut self, reason: ReleaseReason, original: SafetyError) -> SafetyError {
        match self.release_all(reason) {
            Ok(()) => original,
            Err(release_error) => SafetyError::new(
                "input.fail_closed_failed",
                format!(
                    "{}; emergency release also failed: {}",
                    original, release_error
                ),
            ),
        }
    }

    pub const fn platform(&self) -> &P {
        &self.platform
    }

    pub const fn guardian(&self) -> &G {
        &self.guardian
    }

    pub const fn held_actions(&self) -> &BTreeSet<ActionId> {
        &self.held_actions
    }

    pub const fn input_gate_open(&self) -> bool {
        self.input_gate_open
    }

    pub const fn last_release_reason(&self) -> Option<ReleaseReason> {
        self.last_release_reason
    }
}
