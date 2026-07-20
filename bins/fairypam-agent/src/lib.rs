use std::time::Instant;

use fairypam_agent_core::platform::{AuthorizationState, DenyAllAuthorization, LocalAuthorization};

pub mod execution;
pub mod local_control;
pub mod profile_store;
pub mod runtime;
#[cfg(feature = "e2e-live-input")]
pub mod test_arm;

pub const fn production_authorization() -> DenyAllAuthorization {
    DenyAllAuthorization
}

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
