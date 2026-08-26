use std::time::Instant;

use fairypam_agent_core::platform::{AuthorizationState, DenyAllAuthorization, LocalAuthorization};

#[cfg(windows)]
pub mod enrollment;
pub mod execution;
#[cfg(windows)]
mod guardian_channel;
#[cfg(windows)]
mod local_control;
mod managed_game;
mod observability;
mod profile_catalog;
pub mod profile_store;
pub mod runtime;
pub mod runtime_api;
mod task_attempt;
mod telemetry;
mod v3_adapter;

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
