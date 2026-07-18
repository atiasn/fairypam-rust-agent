use std::time::Instant;

use fairypam_agent_core::platform::{AuthorizationState, DenyAllAuthorization, LocalAuthorization};

#[cfg(feature = "dev-automation")]
mod dev_input;
pub mod execution;
#[cfg(windows)]
mod local_control;
pub mod profile_store;
pub mod runtime;
#[cfg(feature = "e2e-live-input")]
pub mod test_arm;

pub const fn production_authorization() -> DenyAllAuthorization {
    DenyAllAuthorization
}

#[cfg(feature = "dev-automation")]
pub const DEV_BUILD_MARKER: &str = "FAIRYPAM_DEV_AUTOMATION_BUILD_V1";

pub fn production_authorization_state(now: Instant) -> AuthorizationState {
    production_authorization().current(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_binary_is_deny_all() {
        assert_eq!(
            production_authorization_state(Instant::now()),
            AuthorizationState::Denied
        );
    }
}
