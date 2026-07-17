//! Explicit, short-lived local authorization for the cleiagent live-input gate.
//!
//! This module does not exist in default or release builds. Enabling the feature
//! is necessary but insufficient: the operator must also type a phrase that
//! binds the exact build and Profile before any authorization is granted.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use fairypam_agent_core::platform::{AuthorizationState, LocalAuthorization};
use fairypam_agent_core::AgentError;

const MAX_AUTHORIZATION_WINDOW: Duration = Duration::from_secs(30);

pub const BUILD_ID: &str = env!(
    "FAIRYPAM_BUILD_ID",
    "e2e-live-input requires an exact FAIRYPAM_BUILD_ID at compile time"
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestArmRequest {
    pub build_id: String,
    pub profile_id: String,
    pub allowed_actions: BTreeSet<String>,
    pub expires_at: Instant,
}

#[derive(Clone, Debug)]
pub struct TestArmAuthorization {
    build_id: String,
    profile_id: String,
    allowed_actions: BTreeSet<String>,
    expires_at: Instant,
}

impl TestArmAuthorization {
    pub fn expected_confirmation(build_id: &str, profile_id: &str) -> String {
        format!("ARM {build_id} {profile_id}")
    }

    pub fn from_interactive_confirmation(
        request: TestArmRequest,
        typed_confirmation: &str,
        now: Instant,
    ) -> Result<Self, AgentError> {
        if request.build_id != BUILD_ID {
            return Err(AgentError::new(
                "authorization.build_mismatch",
                "Test Arm build id does not match this binary",
            ));
        }
        if request.profile_id.trim().is_empty() || request.allowed_actions.is_empty() {
            return Err(AgentError::new(
                "authorization.scope_invalid",
                "Test Arm requires one Profile and at least one allowed action",
            ));
        }
        if request.expires_at <= now
            || request.expires_at.saturating_duration_since(now) > MAX_AUTHORIZATION_WINDOW
        {
            return Err(AgentError::new(
                "authorization.window_invalid",
                "Test Arm authorization must expire within 30 seconds",
            ));
        }
        let expected = Self::expected_confirmation(&request.build_id, &request.profile_id);
        if typed_confirmation != expected {
            return Err(AgentError::new(
                "authorization.confirmation_failed",
                "interactive Test Arm confirmation did not match the exact build and Profile",
            ));
        }
        Ok(Self {
            build_id: request.build_id,
            profile_id: request.profile_id,
            allowed_actions: request.allowed_actions,
            expires_at: request.expires_at,
        })
    }

    pub fn permits(&self, build_id: &str, profile_id: &str, action_id: &str, now: Instant) -> bool {
        now < self.expires_at
            && build_id == self.build_id
            && profile_id == self.profile_id
            && self.allowed_actions.contains(action_id)
    }
}

impl LocalAuthorization for TestArmAuthorization {
    fn current(&self, now: Instant) -> AuthorizationState {
        if now < self.expires_at {
            AuthorizationState::Granted {
                expires_at: self.expires_at,
            }
        } else {
            AuthorizationState::Denied
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(now: Instant) -> TestArmRequest {
        TestArmRequest {
            build_id: BUILD_ID.into(),
            profile_id: "fairypam-test-window".into(),
            allowed_actions: BTreeSet::from(["move.forward".into()]),
            expires_at: now + Duration::from_secs(30),
        }
    }

    #[test]
    fn exact_confirmation_grants_only_the_bound_scope() {
        let now = Instant::now();
        let request = request(now);
        let phrase =
            TestArmAuthorization::expected_confirmation(&request.build_id, &request.profile_id);
        let authorization =
            TestArmAuthorization::from_interactive_confirmation(request, &phrase, now).unwrap();

        assert!(authorization.permits(BUILD_ID, "fairypam-test-window", "move.forward", now));
        assert!(!authorization.permits(BUILD_ID, "fairypam-test-window", "mouse.primary", now));
        assert_eq!(
            authorization.current(now + Duration::from_secs(31)),
            AuthorizationState::Denied
        );
    }

    #[test]
    fn rejects_mismatched_build_phrase_and_long_window() {
        let now = Instant::now();
        let mut wrong_build = request(now);
        wrong_build.build_id = "other-build".into();
        assert_eq!(
            TestArmAuthorization::from_interactive_confirmation(
                wrong_build,
                "ARM other-build fairypam-test-window",
                now,
            )
            .unwrap_err()
            .code(),
            "authorization.build_mismatch"
        );

        assert_eq!(
            TestArmAuthorization::from_interactive_confirmation(request(now), "no", now)
                .unwrap_err()
                .code(),
            "authorization.confirmation_failed"
        );

        let mut too_long = request(now);
        too_long.expires_at = now + Duration::from_secs(31);
        let phrase =
            TestArmAuthorization::expected_confirmation(&too_long.build_id, &too_long.profile_id);
        assert_eq!(
            TestArmAuthorization::from_interactive_confirmation(too_long, &phrase, now)
                .unwrap_err()
                .code(),
            "authorization.window_invalid"
        );
    }
}
