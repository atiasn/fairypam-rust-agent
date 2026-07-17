use std::time::Instant;

use crate::profile::VerifiedProfile;
use crate::target::{TargetBinding, TargetCandidate, TargetSelector, TargetSnapshot};
use crate::AgentError;

pub trait TargetPlatform: Send {
    fn enumerate(&mut self, profile: &VerifiedProfile) -> Result<Vec<TargetCandidate>, AgentError>;

    fn lock(
        &mut self,
        profile: &VerifiedProfile,
        selector: TargetSelector,
    ) -> Result<TargetBinding, AgentError>;

    fn revalidate(&mut self, binding: &TargetBinding) -> Result<TargetSnapshot, AgentError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizationState {
    Denied,
    Granted { expires_at: Instant },
}

pub trait LocalAuthorization: Send + Sync {
    fn current(&self, now: Instant) -> AuthorizationState;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllAuthorization;

impl LocalAuthorization for DenyAllAuthorization {
    fn current(&self, _now: Instant) -> AuthorizationState {
        AuthorizationState::Denied
    }
}
