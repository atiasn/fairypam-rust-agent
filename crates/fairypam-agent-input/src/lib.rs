//! Profile-bound semantic input and lease safety.

mod action;
mod lease;

pub use action::{ActionMap, InputPlatform, ResolvedAction, SemanticMouseButton};
pub use fairypam_agent_guardian_protocol::{ActionId, PhysicalHold, ReleaseReason};
pub use lease::{
    GuardianClient, InputLease, InputPermit, LeaseExecutor, SafetyError, SessionKey,
    CLIENT_POINT_CLICK_HOLD,
};
